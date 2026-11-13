package saml

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	assertionLifetime = 5 * time.Minute
	statusSuccess     = "urn:oasis:names:tc:SAML:2.0:status:Success"
	statusResponder   = "urn:oasis:names:tc:SAML:2.0:status:Responder" // #nosec G101 -- SAML status URN, not a credential
	StatusNoPassive   = "urn:oasis:names:tc:SAML:2.0:status:NoPassive" // #nosec G101 -- SAML status URN, not a credential
	authnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	attrNameFormat    = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	confirmBearer     = "urn:oasis:names:tc:SAML:2.0:cm:bearer" // #nosec G101 -- SAML confirmation-method URN ("bearer"), not a credential
)

// IdP is Keyhaven acting as a SAML identity provider.
type IdP struct {
	EntityID string // {issuer}/saml
	SSOURL   string // {issuer}/saml/sso
	Key      *rsa.PrivateKey
	Cert     *x509.Certificate
	Now      func() time.Time
}

func (idp *IdP) now() time.Time {
	if idp.Now != nil {
		return idp.Now().UTC()
	}
	return time.Now().UTC()
}

// User is the signed-in user an assertion describes.
type User struct {
	ID, Username, DisplayName, Email string
}

// ResponseParams describes one successful sign-in for an app.
type ResponseParams struct {
	Request      *Validated
	User         User
	AuthnInstant time.Time // when the user signed in (passkey ceremony)
	SessionIndex string
}

func newID() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "_" + hex.EncodeToString(b)
}

func samlTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

func (idp *IdP) signer() (*dsig.SigningContext, error) {
	ctx, err := dsig.NewSigningContext(idp.Key, [][]byte{idp.Cert.Raw})
	if err != nil {
		return nil, err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	return ctx, nil
}

// signAfterIssuer adds an enveloped signature to el and places it directly
// after the <saml:Issuer> child, where the SAML schema requires it.
func signAfterIssuer(ctx *dsig.SigningContext, el *etree.Element) error {
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return err
	}
	for i, child := range el.Child {
		if c, ok := child.(*etree.Element); ok && c.Tag == "Issuer" {
			el.InsertChildAt(i+1, sig)
			return nil
		}
	}
	return errors.New("element has no Issuer to sign after")
}

func (idp *IdP) newResponse(inResponseTo, destination string, now time.Time) *etree.Element {
	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", NSProtocol)
	resp.CreateAttr("xmlns:saml", NSAssertion)
	resp.CreateAttr("ID", newID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", samlTime(now))
	resp.CreateAttr("Destination", destination)
	resp.CreateAttr("InResponseTo", inResponseTo)
	resp.CreateElement("saml:Issuer").SetText(idp.EntityID)
	return resp
}

func encode(resp *etree.Element) (string, error) {
	doc := etree.NewDocument()
	doc.SetRoot(resp)
	var buf bytes.Buffer
	if _, err := doc.WriteTo(&buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// Response builds a signed SAML Response (both the Response and the Assertion
// are signed), base64-encoded for the HTTP-POST binding.
func (idp *IdP) Response(p ResponseParams) (string, error) {
	ctx, err := idp.signer()
	if err != nil {
		return "", err
	}
	now := idp.now()
	req := p.Request
	expires := samlTime(now.Add(assertionLifetime))

	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", NSAssertion)
	a.CreateAttr("ID", newID())
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", samlTime(now))
	a.CreateElement("saml:Issuer").SetText(idp.EntityID)

	subject := a.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", req.App.NameIDFormat)
	if req.App.NameIDFormat == NameIDPersistent {
		nameID.CreateAttr("NameQualifier", idp.EntityID)
		nameID.CreateAttr("SPNameQualifier", req.App.EntityID)
		nameID.SetText(p.User.ID)
	} else {
		nameID.SetText(p.User.Username)
	}
	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", confirmBearer)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("InResponseTo", req.RequestID)
	scd.CreateAttr("Recipient", req.ACSURL)
	scd.CreateAttr("NotOnOrAfter", expires)

	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", samlTime(now.Add(-time.Minute)))
	cond.CreateAttr("NotOnOrAfter", expires)
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(req.App.EntityID)

	authn := a.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", samlTime(p.AuthnInstant))
	authn.CreateAttr("SessionIndex", p.SessionIndex)
	authn.CreateAttr("SessionNotOnOrAfter", samlTime(now.Add(8*time.Hour)))
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(authnContextClass)

	attrs := a.CreateElement("saml:AttributeStatement")
	addAttr := func(name, value string) {
		if value == "" {
			return
		}
		at := attrs.CreateElement("saml:Attribute")
		at.CreateAttr("Name", name)
		at.CreateAttr("NameFormat", attrNameFormat)
		v := at.CreateElement("saml:AttributeValue")
		v.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
		v.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
		v.CreateAttr("xsi:type", "xs:string")
		v.SetText(value)
	}
	addAttr("uid", p.User.ID)
	addAttr("username", p.User.Username)
	addAttr("displayName", p.User.DisplayName)
	addAttr("email", p.User.Email)

	if err := signAfterIssuer(ctx, a); err != nil {
		return "", err
	}

	resp := idp.newResponse(req.RequestID, req.ACSURL, now)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", statusSuccess)
	resp.AddChild(a)
	if err := signAfterIssuer(ctx, resp); err != nil {
		return "", err
	}
	return encode(resp)
}

// ErrorResponse builds a signed failure Response (e.g. NoPassive) for a
// validated request, so the app learns why sign-in didn't happen.
func (idp *IdP) ErrorResponse(req *Validated, secondStatus string) (string, error) {
	ctx, err := idp.signer()
	if err != nil {
		return "", err
	}
	resp := idp.newResponse(req.RequestID, req.ACSURL, idp.now())
	sc := resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode")
	sc.CreateAttr("Value", statusResponder)
	sc.CreateElement("samlp:StatusCode").CreateAttr("Value", secondStatus)
	if err := signAfterIssuer(ctx, resp); err != nil {
		return "", err
	}
	return encode(resp)
}

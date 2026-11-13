package saml

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	issuerURL = "https://id.example.com"
	spEntity  = "https://sp.example.com/metadata"
	spACS     = "https://sp.example.com/acs"
)

var (
	bundleOnce sync.Once
	bundle     string
)

func testIdP(t *testing.T) *IdP {
	t.Helper()
	bundleOnce.Do(func() {
		var err error
		if bundle, err = GenerateKeyBundle("Keyhaven test"); err != nil {
			panic(err)
		}
	})
	key, cert, err := ParseKeyBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return &IdP{EntityID: issuerURL + "/saml", SSOURL: issuerURL + "/saml/sso", Key: key, Cert: cert}
}

func testApp() *App {
	return &App{ID: "app1", Name: "Test SP", EntityID: spEntity, ACSURLs: []string{spACS, "https://sp.example.com/acs2"}, NameIDFormat: NameIDPersistent}
}

func lookup(app *App) func(string) (*App, error) {
	return func(id string) (*App, error) {
		if id == app.EntityID {
			return app, nil
		}
		return nil, nil
	}
}

// testSP is an independent SAML implementation acting as the service provider.
func testSP(idp *IdP, audience string) *saml2.SAMLServiceProvider {
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      idp.SSOURL,
		IdentityProviderIssuer:      idp.EntityID,
		ServiceProviderIssuer:       spEntity,
		AssertionConsumerServiceURL: spACS,
		AudienceURI:                 audience,
		NameIdFormat:                NameIDPersistent,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idp.Cert}},
		SPKeyStore:                  dsig.RandomKeyStoreForTest(),
	}
}

var user = User{ID: "u-123", Username: "plunney", DisplayName: "Pat", Email: "pat@example.com"}

func requestFromSP(t *testing.T, sp *saml2.SAMLServiceProvider) *AuthnRequest {
	t.Helper()
	authURL, err := sp.BuildAuthURL("relay-1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	req, err := DecodeRedirect(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("decode SP's redirect request: %v", err)
	}
	return req
}

func TestRoundTripWithIndependentSP(t *testing.T) {
	idp := testIdP(t)
	sp := testSP(idp, spEntity)
	app := testApp()

	for _, binding := range []string{"redirect", "post"} {
		var req *AuthnRequest
		if binding == "redirect" {
			req = requestFromSP(t, sp)
		} else {
			body, err := sp.BuildAuthBodyPost("relay-1")
			if err != nil {
				t.Fatal(err)
			}
			m := regexp.MustCompile(`name="SAMLRequest" value="([^"]+)"`).FindSubmatch(body)
			if m == nil {
				t.Fatalf("no SAMLRequest in POST body: %s", body)
			}
			// The browser HTML-unescapes form values (e.g. &#43; → +) before posting.
			if req, err = DecodePOST(html.UnescapeString(string(m[1]))); err != nil {
				t.Fatalf("decode POST request: %v", err)
			}
		}
		v, err := Validate(req, lookup(app), idp.SSOURL, time.Now())
		if err != nil {
			t.Fatalf("%s: validate: %v", binding, err)
		}
		if v.ACSURL != spACS {
			t.Fatalf("%s: ACS = %q", binding, v.ACSURL)
		}
		resp, err := idp.Response(ResponseParams{Request: v, User: user, AuthnInstant: time.Now(), SessionIndex: "s1"})
		if err != nil {
			t.Fatal(err)
		}
		info, err := sp.RetrieveAssertionInfo(resp)
		if err != nil {
			t.Fatalf("%s: independent SP rejected our response: %v", binding, err)
		}
		if info.NameID != user.ID || info.Values.Get("username") != "plunney" || info.Values.Get("displayName") != "Pat" ||
			info.Values.Get("email") != "pat@example.com" || info.Values.Get("uid") != user.ID {
			t.Fatalf("%s: wrong identity: %+v %+v", binding, info.NameID, info.Values)
		}
		if !info.ResponseSignatureValidated || info.WarningInfo.NotInAudience || info.WarningInfo.InvalidTime {
			t.Fatalf("%s: signature/audience/time problem: %+v", binding, info.WarningInfo)
		}
	}
}

func TestUnspecifiedNameIDUsesUsername(t *testing.T) {
	idp := testIdP(t)
	sp := testSP(idp, spEntity)
	sp.NameIdFormat = NameIDUnspecified
	app := testApp()
	app.NameIDFormat = NameIDUnspecified
	v, err := Validate(requestFromSP(t, sp), lookup(app), idp.SSOURL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := idp.Response(ResponseParams{Request: v, User: user, AuthnInstant: time.Now(), SessionIndex: "s"})
	info, err := sp.RetrieveAssertionInfo(resp)
	if err != nil || info.NameID != "plunney" {
		t.Fatalf("NameID = %q, err %v", info.NameID, err)
	}
}

func decodeResponse(t *testing.T, b64 string) *etree.Document {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(b64)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	return doc
}

func childTags(el *etree.Element) []string {
	var tags []string
	for _, c := range el.ChildElements() {
		tags = append(tags, c.Tag)
	}
	return tags
}

func TestSignaturesFollowIssuer(t *testing.T) {
	idp := testIdP(t)
	v, _ := Validate(requestFromSP(t, testSP(idp, spEntity)), lookup(testApp()), idp.SSOURL, time.Now())
	resp, _ := idp.Response(ResponseParams{Request: v, User: user, AuthnInstant: time.Now(), SessionIndex: "s"})
	doc := decodeResponse(t, resp)
	r := doc.Root()
	if got := strings.Join(childTags(r), ","); got != "Issuer,Signature,Status,Assertion" {
		t.Errorf("Response children = %s", got)
	}
	a := r.SelectElement("Assertion")
	if got := strings.Join(childTags(a), ","); got != "Issuer,Signature,Subject,Conditions,AuthnStatement,AttributeStatement" {
		t.Errorf("Assertion children = %s", got)
	}
}

func TestTamperedResponseRejected(t *testing.T) {
	idp := testIdP(t)
	sp := testSP(idp, spEntity)
	v, _ := Validate(requestFromSP(t, sp), lookup(testApp()), idp.SSOURL, time.Now())
	resp, _ := idp.Response(ResponseParams{Request: v, User: user, AuthnInstant: time.Now(), SessionIndex: "s"})
	raw, _ := base64.StdEncoding.DecodeString(resp)
	forged := bytes.Replace(raw, []byte(">plunney<"), []byte(">admin<"), 1)
	if bytes.Equal(forged, raw) {
		t.Fatal("test did not modify the response")
	}
	if _, err := sp.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString(forged)); err == nil {
		t.Fatal("a tampered assertion must be rejected")
	}

	// A response signed by a different key is rejected too.
	other, _ := GenerateKeyBundle("attacker")
	k, c, _ := ParseKeyBundle(other)
	evil := &IdP{EntityID: idp.EntityID, SSOURL: idp.SSOURL, Key: k, Cert: c}
	resp2, _ := evil.Response(ResponseParams{Request: v, User: user, AuthnInstant: time.Now(), SessionIndex: "s"})
	if _, err := sp.RetrieveAssertionInfo(resp2); err == nil {
		t.Fatal("a response signed by another key must be rejected")
	}
}

func TestAudienceIsBoundToApp(t *testing.T) {
	idp := testIdP(t)
	v, _ := Validate(requestFromSP(t, testSP(idp, spEntity)), lookup(testApp()), idp.SSOURL, time.Now())
	resp, _ := idp.Response(ResponseParams{Request: v, User: user, AuthnInstant: time.Now(), SessionIndex: "s"})
	// The same response replayed to a different app must fail its audience check.
	other := testSP(idp, "https://other-app.example.com")
	info, err := other.RetrieveAssertionInfo(resp)
	if err == nil && !info.WarningInfo.NotInAudience {
		t.Fatal("an assertion for one app must not be accepted by another")
	}
}

func TestNoPassiveErrorResponse(t *testing.T) {
	idp := testIdP(t)
	sp := testSP(idp, spEntity)
	v, _ := Validate(requestFromSP(t, sp), lookup(testApp()), idp.SSOURL, time.Now())
	resp, err := idp.ErrorResponse(v, StatusNoPassive)
	if err != nil {
		t.Fatal(err)
	}
	// Failure responses carry no assertion (per spec). gosaml2 checks for an
	// assertion before the status, so verify signature and status directly.
	doc := decodeResponse(t, resp)
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idp.Cert}})
	if _, err := vc.Validate(doc.Root()); err != nil {
		t.Fatalf("error response signature invalid: %v", err)
	}
	codes := doc.FindElements("//StatusCode")
	if len(codes) != 2 || codes[0].SelectAttrValue("Value", "") != statusResponder || codes[1].SelectAttrValue("Value", "") != StatusNoPassive {
		t.Fatalf("unexpected status codes")
	}
	if doc.FindElement("//Assertion") != nil {
		t.Fatal("failure response must not contain an assertion")
	}
	if doc.Root().SelectAttrValue("InResponseTo", "") != v.RequestID || doc.Root().SelectAttrValue("Destination", "") != spACS {
		t.Fatal("error response not bound to the request")
	}
}

func rawRequest(mod func(string) string) string {
	x := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="%s" xmlns:saml="%s" ID="_abc123" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="%s"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		NSProtocol, NSAssertion, time.Now().UTC().Format(time.RFC3339), issuerURL+"/saml/sso", spACS, BindingPOST, spEntity)
	if mod != nil {
		x = mod(x)
	}
	return base64.StdEncoding.EncodeToString([]byte(x))
}

func TestValidationFailures(t *testing.T) {
	idp := testIdP(t)
	app := testApp()
	repl := func(old, new string) func(string) string {
		return func(s string) string { return strings.Replace(s, old, new, 1) }
	}
	cases := map[string]func(string) string{
		"unknown service provider":  repl(">"+spEntity+"<", ">https://evil.example/sp<"),
		"unregistered ACS URL":      repl(`AssertionConsumerServiceURL="`+spACS, `AssertionConsumerServiceURL="https://evil.example/acs`),
		"wrong destination":         repl(`Destination="`+issuerURL, `Destination="https://other-idp.example`),
		"stale request":             repl(time.Now().UTC().Format(time.RFC3339), time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)),
		"request from the future":   repl(time.Now().UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)),
		"redirect response binding": repl(BindingPOST, BindingRedirect),
		"missing ID":                repl(`ID="_abc123"`, `ID=""`),
		"SAML 1.1":                  repl(`Version="2.0"`, `Version="1.1"`),
		"two issuers":               repl(`</saml:Issuer>`, `</saml:Issuer><saml:Issuer>https://evil.example/sp</saml:Issuer>`),
		"issuer in foreign namespace": func(s string) string {
			return strings.Replace(strings.Replace(s, "<saml:Issuer>", `<x:Issuer xmlns:x="urn:evil">`, 1), "</saml:Issuer>", "</x:Issuer>", 1)
		},
		"unsupported NameID format": repl(`</samlp:AuthnRequest>`, `<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>`),
		"ACS index out of range": func(s string) string {
			s = strings.Replace(s, `AssertionConsumerServiceURL="`+spACS+`"`, `AssertionConsumerServiceIndex="7"`, 1)
			return s
		},
	}
	for name, mod := range cases {
		req, err := DecodePOST(rawRequest(mod))
		if err == nil {
			_, err = Validate(req, lookup(app), idp.SSOURL, time.Now())
		}
		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: want ErrInvalidRequest, got %v", name, err)
		}
	}

	// A valid request picks ACS by index, or the first registered URL by default.
	req, _ := DecodePOST(rawRequest(func(s string) string {
		return strings.Replace(s, `AssertionConsumerServiceURL="`+spACS+`"`, `AssertionConsumerServiceIndex="1"`, 1)
	}))
	v, err := Validate(req, lookup(app), idp.SSOURL, time.Now())
	if err != nil || v.ACSURL != "https://sp.example.com/acs2" {
		t.Fatalf("ACS by index: %v %v", v, err)
	}
}

func TestMaliciousInputs(t *testing.T) {
	// DTDs (entity expansion, external entities) are refused outright.
	dtd := base64.StdEncoding.EncodeToString([]byte(`<!DOCTYPE x [<!ENTITY a "aaaa">]><samlp:AuthnRequest xmlns:samlp="` + NSProtocol + `">&a;</samlp:AuthnRequest>`))
	if _, err := DecodePOST(dtd); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("DTD: %v", err)
	}
	// A small DEFLATE payload that inflates to megabytes is refused.
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write(bytes.Repeat([]byte("A"), 5<<20))
	w.Close()
	if _, err := DecodeRedirect(base64.StdEncoding.EncodeToString(buf.Bytes())); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("deflate bomb (%d bytes compressed): %v", buf.Len(), err)
	}
	// Wrong root element namespace, garbage, non-base64.
	for name, in := range map[string]string{
		"wrong namespace": base64.StdEncoding.EncodeToString([]byte(`<AuthnRequest xmlns="urn:evil" ID="_a" Version="2.0"/>`)),
		"not xml":         base64.StdEncoding.EncodeToString([]byte(`hello`)),
		"not base64":      "%%%",
	} {
		if _, err := DecodePOST(in); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestKeyBundleAndMetadata(t *testing.T) {
	idp := testIdP(t)
	if idp.Key.N.BitLen() != 3072 {
		t.Errorf("key size = %d", idp.Key.N.BitLen())
	}
	if time.Until(idp.Cert.NotAfter) < 9*365*24*time.Hour {
		t.Errorf("certificate should be long-lived, expires %v", idp.Cert.NotAfter)
	}
	if fp := Fingerprint(idp.Cert); len(fp) != 95 || strings.Count(fp, ":") != 31 {
		t.Errorf("fingerprint format: %s", fp)
	}
	// A certificate from another key is refused.
	other, _ := GenerateKeyBundle("x")
	keyPart := bundle[:strings.Index(bundle, "-----BEGIN CERTIFICATE-----")]
	certPart := other[strings.Index(other, "-----BEGIN CERTIFICATE-----"):]
	if _, _, err := ParseKeyBundle(keyPart + certPart); err == nil {
		t.Error("mismatched key and certificate must be refused")
	}

	md, err := idp.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(md); err != nil {
		t.Fatal(err)
	}
	if doc.Root().SelectAttrValue("entityID", "") != idp.EntityID {
		t.Error("metadata entityID mismatch")
	}
	certText := doc.FindElement("//X509Certificate").Text()
	if certText != base64.StdEncoding.EncodeToString(idp.Cert.Raw) {
		t.Error("metadata certificate mismatch")
	}
	if n := len(doc.FindElements("//SingleSignOnService")); n != 2 {
		t.Errorf("want 2 SSO bindings, got %d", n)
	}
}

package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	NSDSig      = "http://www.w3.org/2000/09/xmldsig#"

	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

	maxMessageBytes = 64 << 10
	clockSkew       = 5 * time.Minute
)

// ErrInvalidRequest marks AuthnRequests that are malformed or not from a registered app.
var ErrInvalidRequest = errors.New("invalid SAML request")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, a...))
}

// AuthnRequest holds the fields Keyhaven reads. Every element is matched by
// its full namespace, so look-alike elements in foreign namespaces are ignored.
type AuthnRequest struct {
	XMLName                       xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                            string        `xml:"ID,attr"`
	Version                       string        `xml:"Version,attr"`
	IssueInstant                  time.Time     `xml:"IssueInstant,attr"`
	Destination                   string        `xml:"Destination,attr"`
	AssertionConsumerServiceURL   string        `xml:"AssertionConsumerServiceURL,attr"`
	AssertionConsumerServiceIndex *int          `xml:"AssertionConsumerServiceIndex,attr"`
	ProtocolBinding               string        `xml:"ProtocolBinding,attr"`
	ForceAuthn                    bool          `xml:"ForceAuthn,attr"`
	IsPassive                     bool          `xml:"IsPassive,attr"`
	Issuer                        []issuer      `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy                  *nameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

type issuer struct {
	Value string `xml:",chardata"`
}

type nameIDPolicy struct {
	Format string `xml:"Format,attr"`
}

// DecodeRedirect decodes the SAMLRequest query parameter of the HTTP-Redirect
// binding (base64 of raw DEFLATE).
func DecodeRedirect(samlRequest string) (*AuthnRequest, error) {
	compressed, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil || len(compressed) > maxMessageBytes {
		return nil, invalid("SAMLRequest is not valid base64 or is too large")
	}
	// Cap the inflated size so a small "DEFLATE bomb" can't exhaust memory.
	raw, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(compressed)), maxMessageBytes+1))
	if err != nil {
		return nil, invalid("SAMLRequest is not valid DEFLATE data")
	}
	if len(raw) > maxMessageBytes {
		return nil, invalid("SAMLRequest is too large")
	}
	return parse(raw)
}

// DecodePOST decodes the SAMLRequest form field of the HTTP-POST binding.
func DecodePOST(samlRequest string) (*AuthnRequest, error) {
	if len(samlRequest) > maxMessageBytes*4/3+4 {
		return nil, invalid("SAMLRequest is too large")
	}
	raw, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return nil, invalid("SAMLRequest is not valid base64")
	}
	return parse(raw)
}

func parse(raw []byte) (*AuthnRequest, error) {
	lower := bytes.ToLower(raw)
	if bytes.Contains(lower, []byte("<!doctype")) || bytes.Contains(lower, []byte("<!entity")) {
		return nil, invalid("DTDs are not allowed")
	}
	var req AuthnRequest
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	if err := dec.Decode(&req); err != nil {
		return nil, invalid("not a SAML 2.0 AuthnRequest")
	}
	return &req, nil
}

// App is a registered SAML service provider.
type App struct {
	ID           string
	Name         string
	EntityID     string
	ACSURLs      []string
	NameIDFormat string
}

// Validated is an AuthnRequest that passed every check.
type Validated struct {
	RequestID  string
	App        *App
	ACSURL     string
	ForceAuthn bool
	IsPassive  bool
}

var requestIDRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,255}$`)

// Validate checks an AuthnRequest against the registered apps. lookup returns
// the app registered for an entity ID (nil if none). ssoURL is Keyhaven's SSO endpoint.
func Validate(req *AuthnRequest, lookup func(entityID string) (*App, error), ssoURL string, now time.Time) (*Validated, error) {
	if req.Version != "2.0" {
		return nil, invalid("unsupported SAML version %q", req.Version)
	}
	if !requestIDRE.MatchString(req.ID) {
		return nil, invalid("missing or malformed request ID")
	}
	if req.IssueInstant.IsZero() || req.IssueInstant.Before(now.Add(-clockSkew)) || req.IssueInstant.After(now.Add(clockSkew)) {
		return nil, invalid("request is too old or from the future")
	}
	if req.Destination != "" && req.Destination != ssoURL {
		return nil, invalid("request is addressed to %q, not this identity provider", req.Destination)
	}
	if req.ProtocolBinding != "" && req.ProtocolBinding != BindingPOST {
		return nil, invalid("only the HTTP-POST response binding is supported")
	}
	if len(req.Issuer) != 1 || strings.TrimSpace(req.Issuer[0].Value) == "" {
		return nil, invalid("request must have exactly one Issuer")
	}
	app, err := lookup(strings.TrimSpace(req.Issuer[0].Value))
	if err != nil {
		return nil, err
	}
	if app == nil || len(app.ACSURLs) == 0 {
		return nil, invalid("unknown service provider %q", req.Issuer[0].Value)
	}

	// Never send an assertion anywhere the app didn't register in advance.
	acs := app.ACSURLs[0]
	switch {
	case req.AssertionConsumerServiceURL != "":
		if !slices.Contains(app.ACSURLs, req.AssertionConsumerServiceURL) {
			return nil, invalid("ACS URL %q is not registered for this app", req.AssertionConsumerServiceURL)
		}
		acs = req.AssertionConsumerServiceURL
	case req.AssertionConsumerServiceIndex != nil:
		i := *req.AssertionConsumerServiceIndex
		if i < 0 || i >= len(app.ACSURLs) {
			return nil, invalid("ACS index %d is not registered for this app", i)
		}
		acs = app.ACSURLs[i]
	}

	if p := req.NameIDPolicy; p != nil && p.Format != "" && p.Format != NameIDUnspecified && p.Format != app.NameIDFormat {
		return nil, invalid("NameID format %q is not configured for this app", p.Format)
	}
	return &Validated{RequestID: req.ID, App: app, ACSURL: acs, ForceAuthn: req.ForceAuthn, IsPassive: req.IsPassive}, nil
}

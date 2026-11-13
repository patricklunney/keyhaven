package server_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/keyhaven/keyhaven/internal/saml"
	"github.com/keyhaven/keyhaven/internal/store"
)

var (
	samlBundleOnce sync.Once
	samlBundle     string
)

func testSAMLBundle(t *testing.T) string {
	samlBundleOnce.Do(func() {
		var err error
		if samlBundle, err = saml.GenerateKeyBundle("Keyhaven e2e"); err != nil {
			panic(err)
		}
	})
	return samlBundle
}

const (
	spEntityID = "https://sp.test/saml/metadata"
	spACS      = "https://sp.test/saml/acs"
)

// newSP configures an independent SAML SP from Keyhaven's published metadata.
func newSP(t *testing.T, h *harness, acs string) *saml2.SAMLServiceProvider {
	t.Helper()
	code, body, _ := h.page(http.DefaultClient, "/saml/metadata")
	if code != 200 {
		t.Fatalf("metadata: %d", code)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(body); err != nil {
		t.Fatal(err)
	}
	der, _ := base64.StdEncoding.DecodeString(doc.FindElement("//X509Certificate").Text())
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      doc.FindElement("//SingleSignOnService").SelectAttrValue("Location", ""),
		IdentityProviderIssuer:      doc.Root().SelectAttrValue("entityID", ""),
		ServiceProviderIssuer:       spEntityID,
		AssertionConsumerServiceURL: acs,
		AudienceURI:                 spEntityID,
		NameIdFormat:                saml.NameIDPersistent,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}},
		SPKeyStore:                  dsig.RandomKeyStoreForTest(),
	}
}

var (
	formActionRE = regexp.MustCompile(`<form id="saml-post" method="post" action="([^"]+)"`)
	responseRE   = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	relayRE      = regexp.MustCompile(`name="RelayState" value="([^"]+)"`)
)

// postedResponse extracts what the auto-submitting page would POST to the app.
func postedResponse(t *testing.T, body string) (action, samlResponse, relay string) {
	t.Helper()
	a, r := formActionRE.FindStringSubmatch(body), responseRE.FindStringSubmatch(body)
	if a == nil || r == nil {
		t.Fatalf("no SAML POST form in page:\n%.400s", body)
	}
	if m := relayRE.FindStringSubmatch(body); m != nil {
		relay = html.UnescapeString(m[1])
	}
	return html.UnescapeString(a[1]), html.UnescapeString(r[1]), relay
}

func (h *harness) samlStart(c *http.Client, sp *saml2.SAMLServiceProvider, relay string) (int, string, string) {
	h.t.Helper()
	authURL, err := sp.BuildAuthURL(relay)
	if err != nil {
		h.t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	return h.page(c, u.RequestURI())
}

func TestSAMLSingleSignOn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	app, err := h.st.CreateSAMLApp(ctx, "Test SP", spEntityID, []string{spACS}, saml.NameIDPersistent)
	if err != nil {
		t.Fatal(err)
	}
	sp := newSP(t, h, spACS)

	// 1. Not signed in: Keyhaven sends the user to the passkey login, then back.
	browser := h.browser()
	code, _, loc := h.samlStart(browser, sp, "/dashboard?x=1")
	if code != 303 || !strings.HasPrefix(loc, "/login?saml=") {
		t.Fatalf("expected redirect to login, got %d %q", code, loc)
	}
	key := strings.TrimPrefix(loc, "/login?saml=")
	_, loginPage, _ := h.page(browser, loc)
	if !strings.Contains(loginPage, `data-next="/saml/continue?req=`+key+`"`) {
		t.Fatal("login page should continue to the SAML request after sign-in")
	}
	h.register(browser, "samluser")
	user, _ := h.st.GetUserByUsername(ctx, "samluser")

	res, err := browser.Get(h.base + "/saml/continue?req=" + key)
	if err != nil {
		t.Fatal(err)
	}
	csp := res.Header.Get("Content-Security-Policy")
	res.Body.Close()
	if !strings.Contains(csp, "form-action https://sp.test;") {
		t.Fatalf("response page CSP must allow posting only to the ACS origin, got %q", csp)
	}
	code, body, _ := h.page(browser, "/saml/continue?req="+key)
	if code != 400 {
		t.Fatalf("a pending SAML request must be single use, got %d", code)
	}
	_ = body

	// 2. Already signed in: straight back to the app, verified by an independent SP.
	code, body, _ = h.samlStart(browser, sp, "/dashboard?x=1")
	if code != 200 {
		t.Fatalf("signed-in SSO: %d", code)
	}
	action, resp, relay := postedResponse(t, body)
	if action != spACS || relay != "/dashboard?x=1" {
		t.Fatalf("posts to %q with relay %q", action, relay)
	}
	info, err := sp.RetrieveAssertionInfo(resp)
	if err != nil {
		t.Fatalf("independent SP rejected the response: %v", err)
	}
	if info.NameID != user.ID || info.Values.Get("username") != "samluser" || info.WarningInfo.NotInAudience {
		t.Fatalf("assertion: NameID=%q username=%q warnings=%+v", info.NameID, info.Values.Get("username"), info.WarningInfo)
	}

	// 3. HTTP-POST binding for the request.
	postBody, _ := sp.BuildAuthBodyPost("")
	m := regexp.MustCompile(`name="SAMLRequest" value="([^"]+)"`).FindSubmatch(postBody)
	code, body, _ = h.form(browser, "/saml/sso", url.Values{"SAMLRequest": {html.UnescapeString(string(m[1]))}}, "")
	if code != 200 {
		t.Fatalf("POST binding: %d", code)
	}
	if _, resp, _ := postedResponse(t, body); resp == "" {
		t.Fatal("POST binding produced no response")
	}

	// 4. ForceAuthn: an existing session isn't enough; the user must use the passkey again.
	sp.ForceAuthn = true
	code, _, loc = h.samlStart(browser, sp, "")
	if code != 303 || !strings.HasPrefix(loc, "/login?saml=") {
		t.Fatalf("ForceAuthn should require sign-in, got %d %q", code, loc)
	}
	_, _, again := h.page(browser, "/saml/continue?req="+strings.TrimPrefix(loc, "/login?saml="))
	if !strings.HasPrefix(again, "/login?saml=") {
		t.Fatal("ForceAuthn must not accept the pre-existing session")
	}
	sp.ForceAuthn = false

	// 5. IsPassive without a session: a signed NoPassive failure, no login page.
	sp.IsPassive = true
	code, body, _ = h.samlStart(h.browser(), sp, "")
	if code != 200 {
		t.Fatalf("IsPassive: %d", code)
	}
	_, resp, _ = postedResponse(t, body)
	raw, _ := base64.StdEncoding.DecodeString(resp)
	if !strings.Contains(string(raw), saml.StatusNoPassive) || strings.Contains(string(raw), "Assertion") {
		t.Fatal("IsPassive without a session must return NoPassive and no assertion")
	}
	sp.IsPassive = false

	// 6. Unregistered ACS URL or unknown app: error page, never a POST elsewhere.
	evil := newSP(t, h, "https://evil.test/acs")
	code, body, _ = h.samlStart(browser, evil, "")
	if code != 400 || strings.Contains(body, "SAMLResponse") {
		t.Fatalf("unregistered ACS must be refused, got %d", code)
	}
	unknown := newSP(t, h, spACS)
	unknown.ServiceProviderIssuer = "https://unknown.test"
	if code, _, _ := h.samlStart(browser, unknown, ""); code != 400 {
		t.Fatalf("unknown app must be refused, got %d", code)
	}

	// 7. Sign-ins are audited.
	events, _, _ := h.st.ListAudit(ctx, store.AuditFilter{Action: "saml.sso", Limit: 10})
	if len(events) < 2 || events[0].TargetID != app.ID || events[0].ActorID != user.ID {
		t.Fatalf("expected audited SAML sign-ins, got %d", len(events))
	}
}

func TestSAMLAdmin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	rootB := h.browser()
	h.register(rootB, "root")
	root, _ := h.st.GetUserByUsername(ctx, "root")
	h.st.SetAdmin(ctx, root.ID, true)

	code, body, _ := h.page(rootB, "/admin/saml")
	if code != 200 || !strings.Contains(body, "/saml/metadata") || !strings.Contains(body, "SHA-256 fingerprint") {
		t.Fatalf("SAML apps page: %d", code)
	}
	bad := url.Values{"name": {"X"}, "entity_id": {"https://x.test"}, "acs_urls": {"http://evil.test/acs"}, "name_id_format": {saml.NameIDPersistent}}
	if code, body, _ := h.form(rootB, "/admin/saml", bad, h.origin); code != 400 || !strings.Contains(body, "must use https") {
		t.Fatalf("http ACS must be rejected, got %d", code)
	}
	bad.Set("acs_urls", "https://x.test/acs")
	bad.Set("entity_id", "has spaces")
	if code, _, _ := h.form(rootB, "/admin/saml", bad, h.origin); code != 400 {
		t.Fatalf("entity ID with spaces must be rejected, got %d", code)
	}
	good := url.Values{"name": {"Test SP"}, "entity_id": {spEntityID}, "acs_urls": {spACS + "\nhttp://localhost:8091/acs"}, "name_id_format": {saml.NameIDUnspecified}}
	if code, _, _ := h.form(rootB, "/admin/saml", good, ""); code != 403 {
		t.Fatalf("admin POST without Origin must be refused, got %d", code)
	}
	code, _, loc := h.form(rootB, "/admin/saml", good, h.origin)
	if code != 303 || !strings.Contains(loc, "msg=saml_saved") {
		t.Fatalf("create: %d %s", code, loc)
	}
	if code, body, _ := h.form(rootB, "/admin/saml", good, h.origin); code != 400 || !strings.Contains(body, "already registered") {
		t.Fatalf("duplicate entity ID must be rejected, got %d", code)
	}
	app, err := h.st.GetSAMLAppByEntityID(ctx, spEntityID)
	if err != nil || len(app.ACSURLs) != 2 || app.NameIDFormat != saml.NameIDUnspecified {
		t.Fatalf("stored app: %+v %v", app, err)
	}
	if code, _, _ := h.page(rootB, "/admin/saml/"+app.ID); code != 200 {
		t.Fatalf("app page: %d", code)
	}
	h.form(rootB, "/admin/saml/"+app.ID+"/delete", url.Values{"confirm": {"wrong"}}, h.origin)
	if _, err := h.st.GetSAMLApp(ctx, app.ID); err != nil {
		t.Fatal("deleted despite wrong confirmation")
	}
	h.form(rootB, "/admin/saml/"+app.ID+"/delete", url.Values{"confirm": {"Test SP"}}, h.origin)
	if _, err := h.st.GetSAMLApp(ctx, app.ID); err != store.ErrNotFound {
		t.Fatal("not deleted")
	}
	_, body, _ = h.page(rootB, "/admin/audit?category=admin.")
	for _, want := range []string{"Added SAML app", "Deleted SAML app"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit log missing %q", want)
		}
	}

	// Non-admins can't manage SAML apps.
	bob := h.browser()
	h.register(bob, "bob")
	if code, _, _ := h.page(bob, "/admin/saml"); code != 403 {
		t.Fatalf("non-admin: %d", code)
	}
}

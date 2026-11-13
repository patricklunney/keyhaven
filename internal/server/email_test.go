package server_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/keyhaven/keyhaven/internal/saml"
	"github.com/keyhaven/keyhaven/internal/server"
	"github.com/keyhaven/keyhaven/internal/store"
)

func TestNormalizeEmail(t *testing.T) {
	for _, ok := range []string{"pat@example.com", "  pat.l+tag@sub.example.co.uk ", "PAT@Example.COM"} {
		if _, err := server.NormalizeEmail(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "pat", "pat@", "@example.com", "pat@localhost", "Pat <pat@example.com>",
		"pat@example.com, eve@example.com", "pat@example.", "pat@exa mple.com", strings.Repeat("a", 250) + "@example.com"} {
		if _, err := server.NormalizeEmail(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestEmailIsMandatory(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Sign-up requires a valid, unique email.
	for name, body := range map[string]map[string]string{
		"missing email":  {"username": "nomail"},
		"invalid email":  {"username": "badmail", "email": "not-an-email"},
		"display name +": {"username": "named", "email": "Pat <pat@example.com>"},
	} {
		if code, out := h.postJSON(h.browser(), "/webauthn/register/begin", body); code != 400 {
			t.Errorf("%s: got %d %v, want 400", name, code, out)
		}
	}
	h.register(h.browser(), "first") // first@example.com
	if code, _ := h.postJSON(h.browser(), "/webauthn/register/begin", map[string]string{"username": "second", "email": "FIRST@example.com"}); code != 409 {
		t.Errorf("duplicate email (case-insensitive) must be refused, got %d", code)
	}
	first, _ := h.st.GetUserByUsername(ctx, "first")
	if first.Email != "first@example.com" {
		t.Fatalf("email not stored: %q", first.Email)
	}

	// An older account without an email is sent to add one before anything else.
	legacyB := h.browser()
	h.register(legacyB, "legacy")
	legacy, _ := h.st.GetUserByUsername(ctx, "legacy")
	conn := mustConn(t)
	if _, err := conn.Exec(ctx, `UPDATE users SET email=NULL WHERE id=$1`, legacy.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, loc := h.page(legacyB, "/account"); loc != "/account/email?next=%2Faccount" {
		t.Fatalf("account page should require an email first, got %q", loc)
	}

	// OIDC: an app sign-in pauses for the email, then continues with a code.
	client, _, _ := h.st.CreateClient(ctx, "App", []string{"https://app.example/cb"}, nil, true)
	_, challenge := pkce()
	authz := "/authorize?" + url.Values{"response_type": {"code"}, "client_id": {client.ID}, "redirect_uri": {"https://app.example/cb"},
		"scope": {"openid email"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}.Encode()
	_, _, loc := h.page(legacyB, authz)
	if !strings.HasPrefix(loc, "/account/email?next=") {
		t.Fatalf("authorize should require an email first, got %q", loc)
	}
	next, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/account/email?next="))
	if next != authz {
		t.Fatalf("should resume the same authorize request, got %q", next)
	}
	// prompt=none can't show UI: the app gets interaction_required instead.
	_, _, loc = h.page(legacyB, authz+"&prompt=none")
	if u, _ := url.Parse(loc); u == nil || u.Query().Get("error") != "interaction_required" {
		t.Fatalf("prompt=none without email: got %q", loc)
	}

	// The email form is CSRF-protected, validates, and refuses duplicates.
	if code, _, _ := h.form(legacyB, "/account/email", url.Values{"email": {"legacy@example.com"}, "next": {next}}, ""); code != 403 {
		t.Fatalf("email form without Origin must be refused, got %d", code)
	}
	if code, body, _ := h.form(legacyB, "/account/email", url.Values{"email": {"nope"}, "next": {next}}, h.origin); code != 400 || !strings.Contains(body, "valid email") {
		t.Fatalf("invalid email: %d", code)
	}
	if code, body, _ := h.form(legacyB, "/account/email", url.Values{"email": {"First@Example.com"}, "next": {next}}, h.origin); code != 400 || !strings.Contains(body, "already used") {
		t.Fatalf("taken email: %d", code)
	}
	code, _, loc := h.form(legacyB, "/account/email", url.Values{"email": {"legacy@example.com"}, "next": {next}}, h.origin)
	if code != 303 || loc != authz {
		t.Fatalf("after saving, should resume the app sign-in: %d %q", code, loc)
	}
	_, _, loc = h.page(legacyB, loc)
	if u, _ := url.Parse(loc); u == nil || u.Query().Get("code") == "" {
		t.Fatalf("authorize should now issue a code, got %q", loc)
	}

	// The continue URL can never point off-site.
	conn.Exec(ctx, `UPDATE users SET email=NULL WHERE id=$1`, legacy.ID)
	for _, evil := range []string{"https://evil.example", "//evil.example", "/authorizex", "/\\evil.example"} {
		_, _, loc := h.form(legacyB, "/account/email", url.Values{"email": {"legacy@example.com"}, "next": {evil}}, h.origin)
		if loc != "/account" {
			t.Errorf("next=%q must fall back to /account, got %q", evil, loc)
		}
		conn.Exec(ctx, `UPDATE users SET email=NULL WHERE id=$1`, legacy.ID)
	}

	// SAML: same pause before the assertion is issued.
	h.st.CreateSAMLApp(ctx, "SP", spEntityID, []string{spACS}, saml.NameIDPersistent)
	sp := newSP(t, h, spACS)
	_, _, loc = h.samlStart(legacyB, sp, "")
	if !strings.HasPrefix(loc, "/account/email?next=%2Fsaml%2Fcontinue") {
		t.Fatalf("SAML should require an email first, got %q", loc)
	}
	next, _ = url.QueryUnescape(strings.TrimPrefix(loc, "/account/email?next="))
	h.form(legacyB, "/account/email", url.Values{"email": {"legacy@example.com"}, "next": {next}}, h.origin)
	code, body, _ := h.page(legacyB, next)
	if code != 200 {
		t.Fatalf("SAML continue after email: %d", code)
	}
	_, resp, _ := postedResponse(t, body)
	info, err := sp.RetrieveAssertionInfo(resp)
	if err != nil || info.Values.Get("email") != "legacy@example.com" {
		t.Fatalf("assertion should carry the new email: %v %v", info, err)
	}

	// Admin console: an admin without an email is asked first too.
	h.st.SetAdmin(ctx, legacy.ID, true)
	conn.Exec(ctx, `UPDATE users SET email=NULL WHERE id=$1`, legacy.ID)
	if _, _, loc := h.page(legacyB, "/admin/users"); loc != "/account/email?next=%2Fadmin%2Fusers" {
		t.Fatalf("admin console should require an email first, got %q", loc)
	}

	// Changes are audited.
	events, _, _ := h.st.ListAudit(ctx, store.AuditFilter{Action: "user.", Limit: 50})
	found := false
	for _, e := range events {
		found = found || (e.Action == "user.email_set" && e.TargetID == legacy.ID)
	}
	if !found {
		t.Error("setting an email should be audited")
	}
}

func mustConn(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), os.Getenv("KEYHAVEN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

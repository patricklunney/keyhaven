package server_test

// End-to-end test: drives the real HTTP handlers with a software FIDO2
// authenticator, through registration, login and the full OIDC code flow.
// Requires a disposable Postgres: KEYHAVEN_TEST_DATABASE_URL=postgres://...

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jackc/pgx/v5"

	"github.com/keyhaven/keyhaven/internal/config"
	"github.com/keyhaven/keyhaven/internal/server"
	"github.com/keyhaven/keyhaven/internal/store"
	"github.com/keyhaven/keyhaven/internal/tokens"
)

var b64 = base64.RawURLEncoding

// ---------------------------------------------------------------- virtual authenticator

type authenticator struct {
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	signCount  uint32
	rpID       string
	origin     string
}

func newAuthenticator(rpID, origin string) *authenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	rand.Read(id)
	return &authenticator{key: k, credID: id, rpID: rpID, origin: origin}
}

func (a *authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func (a *authenticator) authData(flags byte, attested bool) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	buf := bytes.NewBuffer(rp[:])
	buf.WriteByte(flags)
	binary.Write(buf, binary.BigEndian, a.signCount)
	if attested {
		buf.Write(make([]byte, 16)) // AAGUID
		binary.Write(buf, binary.BigEndian, uint16(len(a.credID)))
		buf.Write(a.credID)
		x, y := make([]byte, 32), make([]byte, 32)
		a.key.PublicKey.X.FillBytes(x)
		a.key.PublicKey.Y.FillBytes(y)
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		buf.Write(cose)
	}
	return buf.Bytes()
}

// create answers navigator.credentials.create().
func (a *authenticator) create(t *testing.T, options map[string]any) map[string]any {
	pk := options["publicKey"].(map[string]any)
	user := pk["user"].(map[string]any)
	var err error
	if a.userHandle, err = b64.DecodeString(user["id"].(string)); err != nil {
		t.Fatalf("user.id: %v", err)
	}
	sel := pk["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "required" || sel["userVerification"] != "required" {
		t.Fatalf("expected discoverable credential with UV required, got %v", sel)
	}
	cd := a.clientData("webauthn.create", pk["challenge"].(string))
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(0x45, true)}) // UP|UV|AT
	return map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(att),
			"transports": []string{"internal"},
		},
	}
}

// get answers navigator.credentials.get().
func (a *authenticator) get(t *testing.T, options map[string]any) map[string]any {
	pk := options["publicKey"].(map[string]any)
	cd := a.clientData("webauthn.get", pk["challenge"].(string))
	ad := a.authData(0x05, false) // UP|UV
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(a.userHandle),
		},
	}
}

// ---------------------------------------------------------------- harness

type harness struct {
	t      *testing.T
	base   string
	st     *store.Store
	origin string
}

func newHarness(t *testing.T) *harness {
	dsn := os.Getenv("KEYHAVEN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("KEYHAVEN_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)

	var handler http.Handler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)

	base := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	cfg := &config.Config{
		Issuer: base, RPID: "localhost", RPDisplayName: "Test", RPOrigins: []string{base},
		DatabaseURL: dsn, AllowSignup: true, Dev: true,
		SessionTTL: time.Hour, AccessTokenTTL: time.Minute, IDTokenTTL: time.Minute, RefreshTokenTTL: time.Hour,
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := tokens.GenerateKeyPEM()
	signer, err := tokens.NewSigner(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(cfg, st, signer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	handler = srv.Handler()
	return &harness{t: t, base: base, st: st, origin: base}
}

// browser returns a cookie-keeping client that does not follow redirects.
func (h *harness) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (h *harness) postJSON(c *http.Client, path string, body any) (int, map[string]any) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", h.base+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", h.origin)
	res, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func (h *harness) get(c *http.Client, path string) *http.Response {
	h.t.Helper()
	res, err := c.Get(h.base + path)
	if err != nil {
		h.t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func (h *harness) token(form url.Values, clientID, secret string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.base+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(clientID, secret)
	} else {
		form.Set("client_id", clientID)
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func pkce() (verifier, challenge string) {
	verifier = store.RandomToken()
	sum := sha256.Sum256([]byte(verifier))
	return verifier, b64.EncodeToString(sum[:])
}

func jwtClaims(t *testing.T, tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, _ := b64.DecodeString(parts[1])
	var c map[string]any
	json.Unmarshal(raw, &c)
	return c
}

func mustStatus(t *testing.T, got, want int, body any) {
	t.Helper()
	if got != want {
		t.Fatalf("status %d, want %d: %v", got, want, body)
	}
}

// ---------------------------------------------------------------- the test

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const redirect = "https://app.example/callback"

	client, secret, err := h.st.CreateClient(ctx, "Test App", []string{redirect}, []string{"https://app.example/bye"}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Discovery and JWKS
	res := h.get(http.DefaultClient, "/.well-known/openid-configuration")
	mustStatus(t, res.StatusCode, 200, "discovery")
	res = h.get(http.DefaultClient, "/.well-known/jwks.json")
	mustStatus(t, res.StatusCode, 200, "jwks")

	// 1. RP sends the user to /authorize; not signed in → /login?req=…
	browser := h.browser()
	verifier, challenge := pkce()
	authz := "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {client.ID}, "redirect_uri": {redirect},
		"scope": {"openid profile offline_access"}, "state": {"xyz"}, "nonce": {"n-123"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()
	res = h.get(browser, authz)
	mustStatus(t, res.StatusCode, 302, "authorize")
	loc, _ := url.Parse(res.Header.Get("Location"))
	if loc.Path != "/login" || loc.Query().Get("req") == "" {
		t.Fatalf("expected redirect to /login?req=…, got %s", loc)
	}
	reqID := loc.Query().Get("req")

	// Pages render
	mustStatus(t, h.get(browser, "/login?req="+reqID).StatusCode, 200, "login page")
	mustStatus(t, h.get(browser, "/register?req="+reqID).StatusCode, 200, "register page")

	// 2. Register a new account with a passkey
	auth := newAuthenticator("localhost", h.origin)
	code, opts := h.postJSON(browser, "/webauthn/register/begin", map[string]string{"username": "alice", "displayName": "Alice Example"})
	mustStatus(t, code, 200, opts)
	code, out := h.postJSON(browser, "/webauthn/register/finish?name=Laptop", auth.create(t, opts))
	mustStatus(t, code, 200, out)

	// Duplicate username is rejected
	code, out = h.postJSON(h.browser(), "/webauthn/register/begin", map[string]string{"username": "ALICE"})
	mustStatus(t, code, 409, out)

	// 3. Resume authorization → code
	res = h.get(browser, "/authorize/continue?req="+reqID)
	mustStatus(t, res.StatusCode, 302, "continue")
	cb, _ := url.Parse(res.Header.Get("Location"))
	if cb.Host != "app.example" || cb.Query().Get("state") != "xyz" || cb.Query().Get("iss") != h.origin {
		t.Fatalf("bad callback: %s", cb)
	}
	authCode := cb.Query().Get("code")

	// Wrong PKCE verifier fails and burns the code
	badForm := url.Values{"grant_type": {"authorization_code"}, "code": {authCode}, "redirect_uri": {redirect}, "code_verifier": {strings.Repeat("a", 43)}}
	code, out = h.token(badForm, client.ID, secret)
	mustStatus(t, code, 400, out)

	// Get a fresh code (session already exists → immediate redirect)
	verifier, challenge = pkce()
	q := url.Values{
		"response_type": {"code"}, "client_id": {client.ID}, "redirect_uri": {redirect},
		"scope": {"openid profile offline_access"}, "state": {"s2"}, "nonce": {"n-456"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	res = h.get(browser, "/authorize?"+q.Encode())
	mustStatus(t, res.StatusCode, 302, "authorize w/ session")
	cb, _ = url.Parse(res.Header.Get("Location"))
	authCode = cb.Query().Get("code")
	if authCode == "" {
		t.Fatalf("expected code, got %s", cb)
	}

	// Wrong client secret
	form := url.Values{"grant_type": {"authorization_code"}, "code": {authCode}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	code, out = h.token(form, client.ID, "wrong")
	mustStatus(t, code, 401, out)

	// 4. Exchange code for tokens
	code, out = h.token(form, client.ID, secret)
	mustStatus(t, code, 200, out)
	idc := jwtClaims(t, out["id_token"].(string))
	if idc["nonce"] != "n-456" || idc["aud"] != client.ID || idc["preferred_username"] != "alice" || idc["iss"] != h.origin {
		t.Fatalf("bad id_token claims: %v", idc)
	}
	access := out["access_token"].(string)
	refresh := out["refresh_token"].(string)

	// Code reuse is rejected
	code, out = h.token(form, client.ID, secret)
	mustStatus(t, code, 400, out)

	// 5. Userinfo
	req, _ := http.NewRequest("GET", h.base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	ures, _ := http.DefaultClient.Do(req)
	var ui map[string]any
	json.NewDecoder(ures.Body).Decode(&ui)
	ures.Body.Close()
	mustStatus(t, ures.StatusCode, 200, ui)
	if ui["sub"] != idc["sub"] || ui["name"] != "Alice Example" {
		t.Fatalf("bad userinfo: %v", ui)
	}

	// 6. Refresh rotates the token (old one is spent), and an ID token is
	// not accepted as an access token.
	newID := out2(t, h, client.ID, secret, refresh, &refresh)
	req, _ = http.NewRequest("GET", h.base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+newID)
	ures, _ = http.DefaultClient.Do(req)
	ures.Body.Close()
	mustStatus(t, ures.StatusCode, 401, "id_token as bearer")

	// 7. Sign in again on a fresh browser with the same passkey
	b2 := h.browser()
	code, opts = h.postJSON(b2, "/webauthn/login/begin", nil)
	mustStatus(t, code, 200, opts)
	auth.signCount = 5
	code, out = h.postJSON(b2, "/webauthn/login/finish", auth.get(t, opts))
	mustStatus(t, code, 200, out)
	mustStatus(t, h.get(b2, "/account").StatusCode, 200, "account page")

	// prompt=none with a session → code without UI
	_, ch3 := pkce()
	q.Set("code_challenge", ch3)
	q.Set("prompt", "none")
	res = h.get(b2, "/authorize?"+q.Encode())
	cb, _ = url.Parse(res.Header.Get("Location"))
	if cb.Query().Get("code") == "" {
		t.Fatalf("prompt=none should issue a code: %s", cb)
	}
	// prompt=none without a session → login_required
	res = h.get(h.browser(), "/authorize?"+q.Encode())
	cb, _ = url.Parse(res.Header.Get("Location"))
	if cb.Query().Get("error") != "login_required" {
		t.Fatalf("expected login_required: %s", cb)
	}

	// 8. A replayed / cloned authenticator (counter goes backwards) is rejected
	b3 := h.browser()
	_, opts = h.postJSON(b3, "/webauthn/login/begin", nil)
	auth.signCount = 2
	code, out = h.postJSON(b3, "/webauthn/login/finish", auth.get(t, opts))
	mustStatus(t, code, 403, out)

	// 9. CSRF: state-changing requests without our Origin are refused
	r2, _ := http.NewRequest("POST", h.base+"/webauthn/login/begin", nil)
	r2.Header.Set("Origin", "https://evil.example")
	rr, _ := http.DefaultClient.Do(r2)
	rr.Body.Close()
	mustStatus(t, rr.StatusCode, 403, "cross-origin")

	// 10. Authorize rejects unregistered redirect URIs without redirecting
	bad := url.Values{"response_type": {"code"}, "client_id": {client.ID}, "redirect_uri": {"https://evil.example/cb"},
		"scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	mustStatus(t, h.get(browser, "/authorize?"+bad.Encode()).StatusCode, 400, "bad redirect")

	// …and missing PKCE is an error redirect
	noPKCE := url.Values{"response_type": {"code"}, "client_id": {client.ID}, "redirect_uri": {redirect}, "scope": {"openid"}}
	res = h.get(browser, "/authorize?"+noPKCE.Encode())
	cb, _ = url.Parse(res.Header.Get("Location"))
	if cb.Query().Get("error") != "invalid_request" {
		t.Fatalf("expected invalid_request for missing PKCE: %s", cb)
	}

	// 11. Logout ends the session and honours registered post-logout URIs
	res = h.get(b2, "/end_session?client_id="+client.ID+"&post_logout_redirect_uri="+url.QueryEscape("https://app.example/bye")+"&state=k")
	mustStatus(t, res.StatusCode, 302, "end_session")
	if !strings.HasPrefix(res.Header.Get("Location"), "https://app.example/bye?state=k") {
		t.Fatalf("bad logout redirect: %s", res.Header.Get("Location"))
	}
	if loc := h.get(b2, "/account").Header.Get("Location"); loc != "/login" {
		t.Fatalf("session should be gone, got redirect %q", loc)
	}
}

// out2 performs a refresh grant, stores the rotated refresh token in *next and
// returns the new ID token. It also checks the previous refresh token is spent.
func out2(t *testing.T, h *harness, clientID, secret, refresh string, next *string) string {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	code, out := h.token(form, clientID, secret)
	mustStatus(t, code, 200, out)
	*next = out["refresh_token"].(string)
	if *next == refresh {
		t.Fatal("refresh token was not rotated")
	}
	code, again := h.token(form, clientID, secret)
	mustStatus(t, code, 400, again)
	return out["id_token"].(string)
}

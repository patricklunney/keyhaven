package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/keyhaven/keyhaven/internal/store"
	"github.com/keyhaven/keyhaven/internal/tokens"
)

const (
	kindAuthRequest  = "auth_request"
	kindAuthCode     = "auth_code"
	kindRefreshToken = "refresh_token"

	authRequestTTL = 10 * time.Minute
	authCodeTTL    = 60 * time.Second
)

var supportedScopes = []string{"openid", "profile", "email", "offline_access"}

// authRequest is a validated /authorize request waiting for the user to sign in.
type authRequest struct {
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	Scope         string    `json:"scope"`
	State         string    `json:"state"`
	Nonce         string    `json:"nonce"`
	CodeChallenge string    `json:"code_challenge"`
	ForceLogin    bool      `json:"force_login"`
	CreatedAt     time.Time `json:"created_at"`
}

type authCode struct {
	ClientID      string    `json:"client_id"`
	UserID        string    `json:"user_id"`
	RedirectURI   string    `json:"redirect_uri"`
	Scope         string    `json:"scope"`
	Nonce         string    `json:"nonce"`
	CodeChallenge string    `json:"code_challenge"`
	AuthTime      time.Time `json:"auth_time"`
}

type refreshGrant struct {
	ClientID string    `json:"client_id"`
	UserID   string    `json:"user_id"`
	Scope    string    `json:"scope"`
	AuthTime time.Time `json:"auth_time"`
}

// ---------------------------------------------------------------- discovery

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	iss := s.cfg.Issuer
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         iss + "/authorize",
		"token_endpoint":                                 iss + "/token",
		"userinfo_endpoint":                              iss + "/userinfo",
		"jwks_uri":                                       iss + "/.well-known/jwks.json",
		"end_session_endpoint":                           iss + "/end_session",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"ES256"},
		"scopes_supported":                               supportedScopes,
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"claims_supported":                               []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "name", "preferred_username", "email"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(s.signer.JWKS())
}

// ---------------------------------------------------------------- authorize

// GET /authorize — authorization code flow with mandatory PKCE (S256).
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	// Until client_id and redirect_uri are validated, errors must not redirect.
	client, err := s.store.GetClient(ctx, q.Get("client_id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.errorPage(w, http.StatusBadRequest, "Unknown application", "The application that sent you here is not registered with this sign-in service.")
			return
		}
		s.internalError(w, "load client", err)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		s.errorPage(w, http.StatusBadRequest, "Invalid redirect", "The application's redirect_uri is not registered.")
		return
	}

	state := q.Get("state")
	fail := func(code, desc string) { s.redirectError(w, r, redirectURI, state, code, desc) }

	if q.Get("request") != "" || q.Get("request_uri") != "" {
		fail("request_not_supported", "request objects are not supported")
		return
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	if rm := q.Get("response_mode"); rm != "" && rm != "query" {
		fail("invalid_request", "only response_mode=query is supported")
		return
	}
	scopes := strings.Fields(q.Get("scope"))
	if !slices.Contains(scopes, "openid") {
		fail("invalid_scope", "the openid scope is required")
		return
	}
	scopes = slices.DeleteFunc(scopes, func(sc string) bool { return !slices.Contains(supportedScopes, sc) })
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" || len(challenge) < 43 || len(challenge) > 128 {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	nonce := q.Get("nonce")
	if len(nonce) > 512 || len(state) > 1024 {
		fail("invalid_request", "nonce or state too long")
		return
	}

	prompt := strings.Fields(q.Get("prompt"))
	req := authRequest{
		ClientID:      client.ID,
		RedirectURI:   redirectURI,
		Scope:         strings.Join(scopes, " "),
		State:         state,
		Nonce:         nonce,
		CodeChallenge: challenge,
		ForceLogin:    slices.Contains(prompt, "login"),
		CreatedAt:     time.Now(),
	}

	sess := s.currentSession(r)
	if slices.Contains(prompt, "none") {
		if sess == nil || req.ForceLogin {
			fail("login_required", "the user is not signed in")
			return
		}
		if u, err := s.store.GetUser(ctx, sess.UserID); err != nil || u.Email == "" {
			fail("interaction_required", "the user must add an email address")
			return
		}
		s.issueCode(w, r, &req, sess)
		return
	}
	if sess != nil && !req.ForceLogin {
		if !s.requireEmail(w, r, sess.UserID, r.URL.RequestURI()) {
			return
		}
		s.issueCode(w, r, &req, sess)
		return
	}

	key := store.RandomToken()
	if err := s.store.PutEphemeral(ctx, kindAuthRequest, key, "", &req, authRequestTTL); err != nil {
		s.internalError(w, "save auth request", err)
		return
	}
	http.Redirect(w, r, "/login?req="+url.QueryEscape(key), http.StatusFound)
}

// GET /authorize/continue?req=… — resumes a pending request after sign-in.
func (s *Server) handleAuthorizeContinue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := r.URL.Query().Get("req")
	var req authRequest
	if err := s.store.GetEphemeral(ctx, kindAuthRequest, key, &req); err != nil {
		s.errorPage(w, http.StatusBadRequest, "Sign-in link expired", "Return to the application and start signing in again.")
		return
	}
	sess := s.currentSession(r)
	if sess == nil || (req.ForceLogin && sess.CreatedAt.Before(req.CreatedAt)) {
		http.Redirect(w, r, "/login?req="+url.QueryEscape(key), http.StatusFound)
		return
	}
	if !s.requireEmail(w, r, sess.UserID, r.URL.RequestURI()) {
		return
	}
	if err := s.store.TakeEphemeral(ctx, kindAuthRequest, key, &req); err != nil {
		s.errorPage(w, http.StatusBadRequest, "Sign-in link expired", "Return to the application and start signing in again.")
		return
	}
	s.issueCode(w, r, &req, sess)
}

func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, req *authRequest, sess *store.Session) {
	code := store.RandomToken()
	ac := authCode{
		ClientID: req.ClientID, UserID: sess.UserID, RedirectURI: req.RedirectURI, Scope: req.Scope,
		Nonce: req.Nonce, CodeChallenge: req.CodeChallenge, AuthTime: sess.CreatedAt,
	}
	if err := s.store.PutEphemeral(r.Context(), kindAuthCode, code, sess.UserID, &ac, authCodeTTL); err != nil {
		s.internalError(w, "save auth code", err)
		return
	}
	u, _ := url.Parse(req.RedirectURI)
	v := u.Query()
	v.Set("code", code)
	if req.State != "" {
		v.Set("state", req.State)
	}
	v.Set("iss", s.cfg.Issuer) // RFC 9207 mix-up protection
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, _ := url.Parse(redirectURI)
	v := u.Query()
	v.Set("error", code)
	v.Set("error_description", desc)
	if state != "" {
		v.Set("state", state)
	}
	v.Set("iss", s.cfg.Issuer)
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---------------------------------------------------------------- token

func (s *Server) tokenError(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// allowClientOrigin lets a browser-based (public) client read the token
// response cross-origin, but only from an origin it registered a redirect URI
// for. No cookies are involved, so credentials are never allowed.
func allowClientOrigin(w http.ResponseWriter, r *http.Request, client *store.Client) {
	w.Header().Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	if origin == "" || !client.Public() {
		return
	}
	for _, uri := range client.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil || u.Host == "" {
			continue
		}
		if origin == u.Scheme+"://"+u.Host {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			return
		}
	}
}

// authenticateClient supports client_secret_basic, client_secret_post and none (public + PKCE).
func (s *Server) authenticateClient(r *http.Request) (*store.Client, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		// RFC 6749 §2.3.1: credentials are form-urlencoded before Basic encoding.
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secret, err2 = url.QueryUnescape(secret)
		if err1 != nil || err2 != nil {
			return nil, false
		}
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id == "" {
		return nil, false
	}
	c, err := s.store.GetClient(r.Context(), id)
	if err != nil {
		return nil, false
	}
	if c.Public() {
		return c, secret == ""
	}
	if secret == "" || subtle.ConstantTimeCompare(store.HashSecret(secret), c.SecretHash) != 1 {
		return nil, false
	}
	return c, true
}

// POST /token
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	client, ok := s.authenticateClient(r)
	if !ok {
		s.tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	allowClientOrigin(w, r, client)
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, r, client)
	case "refresh_token":
		s.grantRefreshToken(w, r, client)
	default:
		s.tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "supported: authorization_code, refresh_token")
	}
}

func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request, client *store.Client) {
	var ac authCode
	if err := s.store.TakeEphemeral(r.Context(), kindAuthCode, r.PostForm.Get("code"), &ac); err != nil {
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "code is invalid, expired or already used")
		return
	}
	if ac.ClientID != client.ID || ac.RedirectURI != r.PostForm.Get("redirect_uri") {
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "code was issued to a different client or redirect_uri")
		return
	}
	verifier := r.PostForm.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if len(verifier) < 43 || len(verifier) > 128 ||
		subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(ac.CodeChallenge)) != 1 {
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	s.issueTokens(w, r, client, ac.UserID, ac.Scope, ac.Nonce, ac.AuthTime)
}

func (s *Server) grantRefreshToken(w http.ResponseWriter, r *http.Request, client *store.Client) {
	var g refreshGrant
	// Refresh tokens rotate: the presented token is consumed and a new one issued.
	if err := s.store.TakeEphemeral(r.Context(), kindRefreshToken, r.PostForm.Get("refresh_token"), &g); err != nil {
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	}
	if g.ClientID != client.ID {
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token was issued to a different client")
		return
	}
	scope := g.Scope
	if req := strings.Fields(r.PostForm.Get("scope")); len(req) > 0 {
		granted := strings.Fields(g.Scope)
		for _, sc := range req {
			if !slices.Contains(granted, sc) {
				s.tokenError(w, http.StatusBadRequest, "invalid_scope", "requested scope exceeds original grant")
				return
			}
		}
		scope = strings.Join(req, " ")
	}
	s.issueTokens(w, r, client, g.UserID, scope, "", g.AuthTime)
}

func (s *Server) issueTokens(w http.ResponseWriter, r *http.Request, client *store.Client, userID, scope, nonce string, authTime time.Time) {
	ctx := r.Context()
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		s.tokenError(w, http.StatusBadRequest, "invalid_grant", "user no longer exists")
		return
	}
	now := time.Now()
	scopes := strings.Fields(scope)

	access, err := s.signer.Sign(tokens.TypeAccessToken, map[string]any{
		"iss": s.cfg.Issuer, "sub": user.ID, "aud": s.cfg.Issuer + "/userinfo", "client_id": client.ID,
		"scope": scope, "iat": now.Unix(), "exp": now.Add(s.cfg.AccessTokenTTL).Unix(),
		"auth_time": authTime.Unix(), "jti": store.RandomHex(16),
	})
	if err != nil {
		s.log.Error("sign access token", "err", err)
		s.tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	resp := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(s.cfg.AccessTokenTTL.Seconds()),
		"scope":        scope,
	}

	if slices.Contains(scopes, "openid") {
		idClaims := map[string]any{
			"iss": s.cfg.Issuer, "sub": user.ID, "aud": client.ID, "azp": client.ID,
			"iat": now.Unix(), "exp": now.Add(s.cfg.IDTokenTTL).Unix(), "auth_time": authTime.Unix(),
			"amr": []string{"hwk", "user"}, "at_hash": tokens.HalfHash(access),
		}
		if nonce != "" {
			idClaims["nonce"] = nonce
		}
		for k, v := range profileClaims(user, scopes) {
			idClaims[k] = v
		}
		idToken, err := s.signer.Sign(tokens.TypeIDToken, idClaims)
		if err != nil {
			s.log.Error("sign id token", "err", err)
			s.tokenError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		resp["id_token"] = idToken
	}

	if slices.Contains(scopes, "offline_access") {
		rt := store.RandomToken()
		g := refreshGrant{ClientID: client.ID, UserID: user.ID, Scope: scope, AuthTime: authTime}
		if err := s.store.PutEphemeral(ctx, kindRefreshToken, rt, user.ID, &g, s.cfg.RefreshTokenTTL); err != nil {
			s.log.Error("save refresh token", "err", err)
			s.tokenError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		resp["refresh_token"] = rt
	}

	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, resp)
}

func profileClaims(u *store.User, scopes []string) map[string]any {
	c := map[string]any{}
	if slices.Contains(scopes, "profile") {
		c["name"] = u.DisplayName
		c["preferred_username"] = u.Username
	}
	if slices.Contains(scopes, "email") && u.Email != "" {
		c["email"] = u.Email
		c["email_verified"] = false
	}
	return c
}

// ---------------------------------------------------------------- userinfo

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || tok == "" {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		s.jsonError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	claims, err := s.signer.Verify(tok, tokens.TypeAccessToken, s.cfg.Issuer)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		s.jsonError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	sub, _ := claims["sub"].(string)
	user, err := s.store.GetUser(r.Context(), sub)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		s.jsonError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	scope, _ := claims["scope"].(string)
	out := profileClaims(user, strings.Fields(scope))
	out["sub"] = user.ID
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- logout

// GET /end_session — OIDC RP-initiated logout.
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if tok := s.cookie(r, sessionCookie); tok != "" {
		_ = s.store.DeleteSession(r.Context(), tok)
	}
	s.clearCookie(w, sessionCookie)

	target := q.Get("post_logout_redirect_uri")
	if target != "" {
		clientID := q.Get("client_id")
		if hint := q.Get("id_token_hint"); hint != "" {
			if aud := s.idTokenHintAudience(hint); aud != "" {
				clientID = aud
			}
		}
		if c, err := s.store.GetClient(r.Context(), clientID); err == nil && slices.Contains(c.PostLogoutRedirectURIs, target) {
			u, _ := url.Parse(target)
			if st := q.Get("state"); st != "" {
				v := u.Query()
				v.Set("state", st)
				u.RawQuery = v.Encode()
			}
			// #nosec G710 -- target is one of this client's pre-registered post-logout redirect URIs (checked above)
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	s.render(w, http.StatusOK, "logged_out.html", map[string]any{"RP": s.cfg.RPDisplayName})
}

// idTokenHintAudience returns the aud of an ID token we issued. Expired tokens are
// accepted as hints, so only the signature is checked.
func (s *Server) idTokenHintAudience(hint string) string {
	claims, err := s.signer.VerifySignatureOnly(hint, tokens.TypeIDToken, s.cfg.Issuer)
	if err != nil {
		return ""
	}
	aud, _ := claims["aud"].(string)
	return aud
}

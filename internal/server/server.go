// Package server implements Keyhaven's HTTP surface: the WebAuthn (FIDO2)
// relying party, the OpenID Connect provider and the user-facing pages.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/keyhaven/keyhaven/internal/config"
	"github.com/keyhaven/keyhaven/internal/saml"
	"github.com/keyhaven/keyhaven/internal/store"
	"github.com/keyhaven/keyhaven/internal/tokens"
	"github.com/keyhaven/keyhaven/web"
)

type Server struct {
	cfg    *config.Config
	store  *store.Store
	signer *tokens.Signer
	wa     *webauthn.WebAuthn
	tmpl   *template.Template
	log    *slog.Logger
	saml   *saml.IdP // nil when SAML is disabled (no KEYHAVEN_SAML_KEY)
}

func New(cfg *config.Config, st *store.Store, signer *tokens.Signer, log *slog.Logger) (*Server, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("").Funcs(templateFuncs).ParseFS(web.Templates, "templates/*.html")
	if err != nil {
		return nil, err
	}
	srv := &Server{cfg: cfg, store: st, signer: signer, wa: wa, tmpl: tmpl, log: log}
	if cfg.SAMLKeyPEM != "" {
		key, cert, err := saml.ParseKeyBundle(cfg.SAMLKeyPEM)
		if err != nil {
			return nil, err
		}
		srv.saml = &saml.IdP{EntityID: cfg.Issuer + "/saml", SSOURL: cfg.Issuer + "/saml/sso", Key: key, Cert: cert}
	}
	return srv, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health & static
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(web.Static)))

	// OpenID Connect provider
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("GET /authorize/continue", s.handleAuthorizeContinue)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /userinfo", s.handleUserinfo)
	mux.HandleFunc("POST /userinfo", s.handleUserinfo)
	mux.HandleFunc("GET /end_session", s.handleEndSession)

	// SAML 2.0 identity provider (see saml.go); 404 unless KEYHAVEN_SAML_KEY is set
	mux.HandleFunc("GET /saml/metadata", s.handleSAMLMetadata)
	mux.HandleFunc("GET /saml/sso", s.handleSAMLSSO)
	mux.HandleFunc("POST /saml/sso", s.handleSAMLSSO)
	mux.HandleFunc("GET /saml/continue", s.handleSAMLContinue)

	// FIDO2 / WebAuthn relying party (JSON API used by the pages)
	mux.Handle("POST /webauthn/register/begin", s.sameOrigin(s.handleRegisterBegin))
	mux.Handle("POST /webauthn/register/finish", s.sameOrigin(s.handleRegisterFinish))
	mux.Handle("POST /webauthn/login/begin", s.sameOrigin(s.handleLoginBegin))
	mux.Handle("POST /webauthn/login/finish", s.sameOrigin(s.handleLoginFinish))

	// Pages
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/account", http.StatusFound) })
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("GET /register", s.handleRegisterPage)
	mux.HandleFunc("GET /account", s.handleAccountPage)
	mux.Handle("POST /account/passkeys/delete", s.sameOrigin(s.handleDeletePasskey))
	mux.HandleFunc("GET /account/email", s.handleEmailPage)
	mux.Handle("POST /account/email", s.sameOrigin(s.handleSetEmail))
	mux.Handle("POST /logout", s.sameOrigin(s.handleLogout))

	// Admin console (administrators only; see admin.go)
	mux.Handle("GET /admin", s.admin(s.handleAdminDashboard))
	mux.Handle("GET /admin/users", s.admin(s.handleAdminUsers))
	mux.Handle("GET /admin/users/{id}", s.admin(s.handleAdminUser))
	mux.Handle("POST /admin/users/{id}/delete", s.adminPost(s.handleAdminDeleteUser))
	mux.Handle("POST /admin/users/{id}/role", s.adminPost(s.handleAdminSetRole))
	mux.Handle("POST /admin/users/{id}/revoke", s.adminPost(s.handleAdminRevokeSessions))
	mux.Handle("POST /admin/users/{id}/passkeys/delete", s.adminPost(s.handleAdminDeletePasskey))
	mux.Handle("GET /admin/clients", s.admin(s.handleAdminClients))
	mux.Handle("GET /admin/clients/new", s.admin(s.handleAdminNewClient))
	mux.Handle("POST /admin/clients", s.adminPost(s.handleAdminCreateClient))
	mux.Handle("GET /admin/clients/{id}", s.admin(s.handleAdminClient))
	mux.Handle("POST /admin/clients/{id}", s.adminPost(s.handleAdminUpdateClient))
	mux.Handle("POST /admin/clients/{id}/secret", s.adminPost(s.handleAdminRotateSecret))
	mux.Handle("POST /admin/clients/{id}/delete", s.adminPost(s.handleAdminDeleteClient))
	mux.Handle("GET /admin/audit", s.admin(s.handleAdminAudit))
	mux.Handle("GET /admin/saml", s.admin(s.handleAdminSAMLApps))
	mux.Handle("GET /admin/saml/new", s.admin(s.handleAdminNewSAMLApp))
	mux.Handle("POST /admin/saml", s.adminPost(s.handleAdminCreateSAMLApp))
	mux.Handle("GET /admin/saml/{id}", s.admin(s.handleAdminSAMLApp))
	mux.Handle("POST /admin/saml/{id}", s.adminPost(s.handleAdminUpdateSAMLApp))
	mux.Handle("POST /admin/saml/{id}/delete", s.adminPost(s.handleAdminDeleteSAMLApp))

	return s.securityHeaders(s.logRequests(mux))
}

var actionLabels = map[string]string{
	"user.register":              "Signed up",
	"user.login":                 "Signed in",
	"user.login_blocked":         "Sign-in blocked",
	"passkey.add":                "Added a passkey",
	"passkey.remove":             "Removed a passkey",
	"admin.user.delete":          "Deleted user",
	"admin.user.promote":         "Granted admin to",
	"admin.user.demote":          "Removed admin from",
	"admin.user.revoke_sessions": "Signed out everywhere:",
	"admin.passkey.remove":       "Removed a passkey of",
	"admin.client.create":        "Created application",
	"admin.client.update":        "Updated application",
	"admin.client.rotate_secret": "Rotated secret of",
	"admin.client.delete":        "Deleted application",
	"admin.saml_app.create":      "Added SAML app",
	"admin.saml_app.update":      "Updated SAML app",
	"admin.saml_app.delete":      "Deleted SAML app",
	"saml.sso":                   "Signed in to SAML app",
	"user.email_set":             "Added an email",
	"user.email_change":          "Changed their email",
}

var templateFuncs = template.FuncMap{
	"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"ago": func(t time.Time) string {
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return strconv.Itoa(int(d.Minutes())) + "m ago"
		case d < 48*time.Hour:
			return strconv.Itoa(int(d.Hours())) + "h ago"
		}
		return strconv.Itoa(int(d.Hours()/24)) + "d ago"
	},
	"actionLabel": func(a string) string {
		if l, ok := actionLabels[a]; ok {
			return l
		}
		return a
	},
	"isAdminAction": func(a string) bool { return strings.HasPrefix(a, "admin.") },
	"dict": func(kv ...any) map[string]any {
		m := make(map[string]any, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			m[fmt.Sprint(kv[i])] = kv[i+1]
		}
		return m
	},
	"details": func(m map[string]any) string {
		if len(m) == 0 {
			return ""
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			v := m[k]
			if list, ok := v.([]any); ok {
				strs := make([]string, len(list))
				for i, x := range list {
					strs[i] = fmt.Sprint(x)
				}
				v = strings.Join(strs, ", ")
			}
			parts = append(parts, strings.ReplaceAll(k, "_", " ")+": "+fmt.Sprint(v))
		}
		return strings.Join(parts, " · ")
	},
}

// ---------------------------------------------------------------- middleware

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		// same-origin (not no-referrer): with no-referrer, browsers send
		// "Origin: null" on plain HTML form POSTs, which breaks the CSRF check.
		// Cross-site requests still get no referrer.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if s.cfg.SecureCookies() {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" {
			return
		}
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(), "remote", clientIP(r))
	})
}

// sameOrigin rejects state-changing browser requests that did not originate
// from one of our own pages (CSRF protection on top of SameSite cookies).
func (s *Server) sameOrigin(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isSameOrigin(r) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		h(w, r)
	})
}

// isSameOrigin accepts a request whose Origin is our issuer. Browsers send
// "Origin: null" for form POSTs in some privacy contexts; those are accepted only
// when the browser-set Sec-Fetch-Site header (which pages can't forge) says
// the request came from our own origin.
func (s *Server) isSameOrigin(r *http.Request) bool {
	switch origin := r.Header.Get("Origin"); origin {
	case s.cfg.Issuer:
		return true
	case "null":
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	return false
}

func clientIP(r *http.Request) string {
	// The ALB appends the true client IP as the last X-Forwarded-For entry.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return r.RemoteAddr
}

// ---------------------------------------------------------------- sessions & cookies

func (s *Server) cookieName(base string) string {
	if s.cfg.SecureCookies() {
		return "__Host-" + base // bound to this exact host, Secure, Path=/
	}
	return base
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	// #nosec G124 -- HttpOnly and SameSite are always set; Secure follows the issuer scheme (false only for an http:// dev issuer)
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(name),
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	// #nosec G124 -- deletion cookie; same attributes as setCookie
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(name), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.SecureCookies(), SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) cookie(r *http.Request, name string) string {
	c, err := r.Cookie(s.cookieName(name))
	if err != nil {
		return ""
	}
	return c.Value
}

const sessionCookie = "kh_session"

// currentSession returns the signed-in session, or nil.
func (s *Server) currentSession(r *http.Request) *store.Session {
	tok := s.cookie(r, sessionCookie)
	if tok == "" {
		return nil
	}
	sess, err := s.store.GetSession(r.Context(), tok)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("load session", "err", err)
		}
		return nil
	}
	return sess
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID string) error {
	// Replace any existing session (prevents session fixation).
	if old := s.cookie(r, sessionCookie); old != "" {
		_ = s.store.DeleteSession(r.Context(), old)
	}
	tok, err := s.store.CreateSession(r.Context(), userID, s.cfg.SessionTTL)
	if err != nil {
		return err
	}
	s.setCookie(w, sessionCookie, tok, s.cfg.SessionTTL)
	return nil
}

// ---------------------------------------------------------------- audit

// audit records a security event. Failures are logged but never block the request.
func (s *Server) audit(r *http.Request, actor *store.User, action, targetType, targetID, targetName string, details map[string]any) {
	e := store.AuditEvent{
		Action: action, TargetType: targetType, TargetID: targetID, TargetName: targetName,
		Details: details, IP: clientIP(r),
	}
	if actor != nil {
		e.ActorID, e.ActorName = actor.ID, actor.Username
	}
	if err := s.store.AddAudit(r.Context(), e); err != nil {
		s.log.Error("write audit event", "action", action, "err", err)
	}
}

// ---------------------------------------------------------------- responses

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("render template", "template", name, "err", err)
	}
}

func (s *Server) errorPage(w http.ResponseWriter, status int, title, detail string) {
	s.render(w, status, "error.html", map[string]any{"Title": title, "Detail": detail, "RP": s.cfg.RPDisplayName})
}

func (s *Server) internalError(w http.ResponseWriter, where string, err error) {
	s.log.Error(where, "err", err)
	s.errorPage(w, http.StatusInternalServerError, "Something went wrong", "Please try again in a moment.")
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ok"))
}

// safeReq returns a pending authorization request id only if it looks like one of ours.
func safeReq(v string) string {
	if len(v) == 0 || len(v) > 128 {
		return ""
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return ""
		}
	}
	return v
}

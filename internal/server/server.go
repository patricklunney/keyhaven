// Package server implements Keyhaven's HTTP surface: the WebAuthn (FIDO2)
// relying party, the OpenID Connect provider and the user-facing pages.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/keyhaven/keyhaven/internal/config"
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
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	}).ParseFS(web.Templates, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, store: st, signer: signer, wa: wa, tmpl: tmpl, log: log}, nil
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
	mux.Handle("POST /logout", s.sameOrigin(s.handleLogout))

	return s.securityHeaders(s.logRequests(mux))
}

// ---------------------------------------------------------------- middleware

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
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
		origin := r.Header.Get("Origin")
		if origin == "" || origin != s.cfg.Issuer {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		h(w, r)
	})
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
	w.Write([]byte("ok")) //nolint:errcheck
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

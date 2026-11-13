package server

import (
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/keyhaven/keyhaven/internal/store"
)

// Email is required on every account (not verified: apps receive
// email_verified=false). Accounts created before it was required are sent to
// /account/email at their next sign-in, before they can continue anywhere.

const maxEmailLen = 254

// NormalizeEmail checks that s is a single plain address (no display name)
// and returns it trimmed.
func NormalizeEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("Enter your email address.")
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s || addr.Name != "" || len(s) > maxEmailLen {
		return "", errors.New("Enter a valid email address, like name@example.com.")
	}
	at := strings.LastIndex(s, "@")
	if at < 1 || !strings.Contains(s[at+1:], ".") || strings.HasSuffix(s, ".") {
		return "", errors.New("Enter a valid email address, like name@example.com.")
	}
	return s, nil
}

// safeContinue allows returning only to Keyhaven's own pages that resume a
// sign-in or open the account/admin areas (never an external URL).
func safeContinue(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return false
	}
	for _, area := range []string{"/account", "/admin"} {
		if p == area || strings.HasPrefix(p, area+"/") || strings.HasPrefix(p, area+"?") {
			return true
		}
	}
	for _, resume := range []string{"/authorize?", "/authorize/continue?", "/saml/continue?"} {
		if strings.HasPrefix(p, resume) {
			return true
		}
	}
	return false
}

// requireEmail sends a signed-in user without an email to the email page,
// to come back to `next` afterwards. It returns false if it redirected.
func (s *Server) requireEmail(w http.ResponseWriter, r *http.Request, userID, next string) bool {
	u, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		s.internalError(w, "load user", err)
		return false
	}
	if u.Email != "" {
		return true
	}
	if !safeContinue(next) {
		next = "/account"
	}
	http.Redirect(w, r, "/account/email?next="+url.QueryEscape(next), http.StatusSeeOther)
	return false
}

// GET /account/email
func (s *Server) handleEmailPage(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u, err := s.store.GetUser(r.Context(), sess.UserID)
	if err != nil {
		s.internalError(w, "load user", err)
		return
	}
	next := r.URL.Query().Get("next")
	if !safeContinue(next) {
		next = "/account"
	}
	s.render(w, http.StatusOK, "email.html", map[string]any{
		"RP": s.cfg.RPDisplayName, "Email": u.Email, "Required": u.Email == "", "Next": next,
	})
}

// POST /account/email (same-origin only)
func (s *Server) handleSetEmail(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u, err := s.store.GetUser(r.Context(), sess.UserID)
	if err != nil {
		s.internalError(w, "load user", err)
		return
	}
	next := r.PostFormValue("next")
	if !safeContinue(next) {
		next = "/account"
	}
	email, err := NormalizeEmail(r.PostFormValue("email"))
	if err == nil {
		err = s.store.SetUserEmail(r.Context(), u.ID, email)
		if errors.Is(err, store.ErrEmailTaken) {
			err = errors.New("That email is already used by another account.")
		} else if err != nil {
			s.internalError(w, "set email", err)
			return
		}
	}
	if err != nil {
		s.render(w, http.StatusBadRequest, "email.html", map[string]any{
			"RP": s.cfg.RPDisplayName, "Email": r.PostFormValue("email"), "Required": u.Email == "",
			"Next": next, "Error": err.Error(),
		})
		return
	}
	action := "user.email_change"
	if u.Email == "" {
		action = "user.email_set"
	}
	s.audit(r, u, action, "user", u.ID, u.Username, map[string]any{"email": email})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/keyhaven/keyhaven/internal/store"
)

type pageData struct {
	RP          string
	Req         string // pending authorization request id, if any
	AllowSignup bool
	Next        string // where the page's script navigates after success
	Reauth      bool   // the admin console asked the user to confirm it's them
}

func (s *Server) nextURL(req string) string {
	if req != "" {
		return "/authorize/continue?req=" + req
	}
	return "/account"
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	req := safeReq(r.URL.Query().Get("req"))
	next := s.nextURL(req)
	if n := r.URL.Query().Get("next"); req == "" && safeAdminPath(n) {
		next = n
	}
	if sr := safeReq(r.URL.Query().Get("saml")); sr != "" && req == "" {
		next = "/saml/continue?req=" + sr
	}
	s.render(w, http.StatusOK, "login.html", pageData{
		RP: s.cfg.RPDisplayName, Req: req, AllowSignup: s.cfg.AllowSignup, Next: next,
		Reauth: r.URL.Query().Get("reauth") == "1",
	})
}

// safeAdminPath allows post-login navigation only to local admin console paths.
func safeAdminPath(p string) bool {
	if p != "/admin" && !strings.HasPrefix(p, "/admin/") {
		return false
	}
	return !strings.ContainsAny(p, "\\\r\n") && !strings.Contains(p, "//")
}

func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	req := safeReq(r.URL.Query().Get("req"))
	if !s.cfg.AllowSignup {
		s.errorPage(w, http.StatusForbidden, "Sign-up is disabled", "Ask an administrator to create your account.")
		return
	}
	s.render(w, http.StatusOK, "register.html", pageData{
		RP: s.cfg.RPDisplayName, Req: req, AllowSignup: true, Next: s.nextURL(req),
	})
}

type passkeyView struct {
	ID       string
	Name     string
	Created  string
	LastUsed string
	Synced   bool
}

func (s *Server) handleAccountPage(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !s.requireEmail(w, r, sess.UserID, "/account") {
		return
	}
	u, err := s.store.GetUser(r.Context(), sess.UserID)
	if err != nil {
		s.internalError(w, "load user", err)
		return
	}
	creds, err := s.store.ListCredentials(r.Context(), u.ID)
	if err != nil {
		s.internalError(w, "list credentials", err)
		return
	}
	views := make([]passkeyView, 0, len(creds))
	for _, c := range creds {
		v := passkeyView{
			ID:      base64.RawURLEncoding.EncodeToString(c.ID),
			Name:    c.Name,
			Created: c.CreatedAt.UTC().Format("2006-01-02"),
			Synced:  c.Flags.BackupEligible,
		}
		if c.LastUsedAt != nil {
			v.LastUsed = c.LastUsedAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		views = append(views, v)
	}
	s.render(w, http.StatusOK, "account.html", map[string]any{
		"RP": s.cfg.RPDisplayName, "User": u, "IsAdmin": u.IsAdmin, "Passkeys": views, "CanDelete": len(views) > 1,
		"Flash": r.URL.Query().Get("msg"),
	})
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(r.FormValue("id"))
	if err != nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	switch err := s.store.DeleteCredential(r.Context(), sess.UserID, id); {
	case errors.Is(err, store.ErrLastPasskey):
		http.Redirect(w, r, "/account?msg=last", http.StatusSeeOther)
		return
	case err != nil && !errors.Is(err, store.ErrNotFound):
		s.internalError(w, "delete credential", err)
		return
	}
	s.log.Info("passkey removed", "user_id", sess.UserID)
	if u, err := s.store.GetUser(r.Context(), sess.UserID); err == nil {
		s.audit(r, u, "passkey.remove", "user", u.ID, u.Username, nil)
	}
	http.Redirect(w, r, "/account?msg=removed", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if tok := s.cookie(r, sessionCookie); tok != "" {
		_ = s.store.DeleteSession(r.Context(), tok)
	}
	s.clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

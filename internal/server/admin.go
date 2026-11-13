package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/keyhaven/keyhaven/internal/store"
)

// ---------------------------------------------------------------- access control

type adminHandler func(w http.ResponseWriter, r *http.Request, me *store.User)

// admin restricts a handler to administrators with a recently authenticated session.
// The admin flag is re-read from the database on every request, so revoking the
// role takes effect immediately.
func (s *Server) admin(h adminHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := "/admin"
		if r.Method == http.MethodGet && safeAdminPath(r.URL.RequestURI()) {
			next = r.URL.RequestURI()
		}
		sess := s.currentSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
			return
		}
		me, err := s.store.GetUser(r.Context(), sess.UserID)
		if err != nil {
			s.internalError(w, "load admin user", err)
			return
		}
		if !me.IsAdmin {
			s.errorPage(w, http.StatusForbidden, "Administrators only", "Your account doesn't have access to the admin console.")
			return
		}
		if time.Since(sess.CreatedAt) > s.cfg.AdminReauth {
			http.Redirect(w, r, "/login?reauth=1&next="+url.QueryEscape(next), http.StatusSeeOther)
			return
		}
		if me.Email == "" {
			if r.Method != http.MethodGet {
				next = "/admin"
			}
			http.Redirect(w, r, "/account/email?next="+url.QueryEscape(next), http.StatusSeeOther)
			return
		}
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		h(w, r, me)
	})
}

// adminPost is admin plus same-origin (CSRF) enforcement for state changes.
func (s *Server) adminPost(h adminHandler) http.Handler {
	return s.sameOrigin(s.admin(h).ServeHTTP)
}

// ---------------------------------------------------------------- rendering

var flashMessages = map[string]string{
	"user_deleted":     "User deleted.",
	"role_granted":     "Administrator role granted.",
	"role_revoked":     "Administrator role removed.",
	"sessions_revoked": "User signed out everywhere. Their refresh tokens were revoked.",
	"passkey_removed":  "Passkey removed.",
	"client_saved":     "Application saved.",
	"client_deleted":   "Application deleted.",
	"saml_saved":       "SAML app saved.",
	"saml_deleted":     "SAML app deleted.",
	"self_delete":      "You can't delete your own account from the admin console.",
	"self_demote":      "You can't remove your own administrator role. Ask another administrator.",
	"last_admin":       "At least one administrator is required.",
	"confirm":          "Confirmation text didn't match. Nothing was changed.",
}

func (s *Server) adminRender(w http.ResponseWriter, r *http.Request, status int, name, nav string, me *store.User, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["RP"] = s.cfg.RPDisplayName
	data["Me"] = me
	data["Nav"] = nav
	data["Issuer"] = s.cfg.Issuer
	if msg, ok := flashMessages[r.URL.Query().Get("msg")]; ok {
		data["Flash"] = msg
		data["FlashError"] = strings.HasPrefix(msg, "You can't") || strings.HasPrefix(msg, "At least") || strings.HasPrefix(msg, "Confirmation")
	}
	s.render(w, status, name, data)
}

type pager struct {
	Page, Pages, Total int
	Prev, Next         string
}

func paginate(r *http.Request, total, limit int) (pager, int) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pages := max(1, (total+limit-1)/limit)
	page = min(max(page, 1), pages)
	link := func(p int) string {
		q := r.URL.Query()
		q.Set("page", strconv.Itoa(p))
		q.Del("msg")
		return r.URL.Path + "?" + q.Encode()
	}
	pg := pager{Page: page, Pages: pages, Total: total}
	if page > 1 {
		pg.Prev = link(page - 1)
	}
	if page < pages {
		pg.Next = link(page + 1)
	}
	return pg, (page - 1) * limit
}

// ---------------------------------------------------------------- dashboard

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request, me *store.User) {
	ctx := r.Context()
	stats, err := s.store.Stats(ctx)
	if err != nil {
		s.internalError(w, "stats", err)
		return
	}
	recent, _, err := s.store.SearchUsers(ctx, "", 5, 0)
	if err != nil {
		s.internalError(w, "recent users", err)
		return
	}
	events, _, err := s.store.ListAudit(ctx, store.AuditFilter{Limit: 10})
	if err != nil {
		s.internalError(w, "recent events", err)
		return
	}
	s.adminRender(w, r, http.StatusOK, "admin_dashboard.html", "dashboard", me, map[string]any{
		"Stats": stats, "RecentUsers": recent, "Events": events,
	})
}

// ---------------------------------------------------------------- users

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request, me *store.User) {
	const limit = 25
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	_, total, err := s.store.SearchUsers(r.Context(), q, 1, 0)
	if err != nil {
		s.internalError(w, "count users", err)
		return
	}
	pg, offset := paginate(r, total, limit)
	users, _, err := s.store.SearchUsers(r.Context(), q, limit, offset)
	if err != nil {
		s.internalError(w, "search users", err)
		return
	}
	s.adminRender(w, r, http.StatusOK, "admin_users.html", "users", me, map[string]any{
		"Users": users, "Q": q, "Pager": pg,
	})
}

func (s *Server) loadTargetUser(w http.ResponseWriter, r *http.Request) *store.User {
	u, err := s.store.GetUser(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, http.StatusNotFound, "User not found", "This account may have been deleted.")
		return nil
	}
	if err != nil {
		s.internalError(w, "load user", err)
		return nil
	}
	return u
}

func (s *Server) handleAdminUser(w http.ResponseWriter, r *http.Request, me *store.User) {
	ctx := r.Context()
	u := s.loadTargetUser(w, r)
	if u == nil {
		return
	}
	creds, err := s.store.ListCredentials(ctx, u.ID)
	if err != nil {
		s.internalError(w, "list credentials", err)
		return
	}
	views := make([]passkeyView, 0, len(creds))
	for _, c := range creds {
		v := passkeyView{
			ID: base64.RawURLEncoding.EncodeToString(c.ID), Name: c.Name,
			Created: c.CreatedAt.UTC().Format("2006-01-02"), Synced: c.Flags.BackupEligible,
		}
		if c.LastUsedAt != nil {
			v.LastUsed = c.LastUsedAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		views = append(views, v)
	}
	sessions, err := s.store.CountUserSessions(ctx, u.ID)
	if err != nil {
		s.internalError(w, "count sessions", err)
		return
	}
	events, _, err := s.store.ListAudit(ctx, store.AuditFilter{TargetID: u.ID, Limit: 20})
	if err != nil {
		s.internalError(w, "user events", err)
		return
	}
	s.adminRender(w, r, http.StatusOK, "admin_user.html", "users", me, map[string]any{
		"User": u, "Passkeys": views, "Sessions": sessions, "Events": events, "IsSelf": u.ID == me.ID,
	})
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request, me *store.User) {
	u := s.loadTargetUser(w, r)
	if u == nil {
		return
	}
	back := "/admin/users/" + url.PathEscape(u.ID)
	if u.ID == me.ID {
		http.Redirect(w, r, back+"?msg=self_delete", http.StatusSeeOther)
		return
	}
	if r.PostFormValue("confirm") != u.Username {
		http.Redirect(w, r, back+"?msg=confirm", http.StatusSeeOther)
		return
	}
	if u.IsAdmin {
		// Deleting an admin is a demotion too; never leave the system without one.
		if err := s.store.SetAdmin(r.Context(), u.ID, false); errors.Is(err, store.ErrLastAdmin) {
			http.Redirect(w, r, back+"?msg=last_admin", http.StatusSeeOther)
			return
		}
	}
	if err := s.store.DeleteUser(r.Context(), u.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, "delete user", err)
		return
	}
	s.audit(r, me, "admin.user.delete", "user", u.ID, u.Username, map[string]any{"passkeys": len(u.Credentials)})
	http.Redirect(w, r, "/admin/users?msg=user_deleted", http.StatusSeeOther)
}

func (s *Server) handleAdminSetRole(w http.ResponseWriter, r *http.Request, me *store.User) {
	u := s.loadTargetUser(w, r)
	if u == nil {
		return
	}
	back := "/admin/users/" + url.PathEscape(u.ID)
	grant := r.PostFormValue("admin") == "1"
	if !grant && u.ID == me.ID {
		http.Redirect(w, r, back+"?msg=self_demote", http.StatusSeeOther)
		return
	}
	switch err := s.store.SetAdmin(r.Context(), u.ID, grant); {
	case errors.Is(err, store.ErrLastAdmin):
		http.Redirect(w, r, back+"?msg=last_admin", http.StatusSeeOther)
		return
	case err != nil:
		s.internalError(w, "set admin", err)
		return
	}
	action, msg := "admin.user.promote", "role_granted"
	if !grant {
		action, msg = "admin.user.demote", "role_revoked"
	}
	s.audit(r, me, action, "user", u.ID, u.Username, nil)
	http.Redirect(w, r, back+"?msg="+msg, http.StatusSeeOther)
}

func (s *Server) handleAdminRevokeSessions(w http.ResponseWriter, r *http.Request, me *store.User) {
	u := s.loadTargetUser(w, r)
	if u == nil {
		return
	}
	if err := s.store.RevokeUserSessions(r.Context(), u.ID); err != nil {
		s.internalError(w, "revoke sessions", err)
		return
	}
	s.audit(r, me, "admin.user.revoke_sessions", "user", u.ID, u.Username, nil)
	http.Redirect(w, r, "/admin/users/"+url.PathEscape(u.ID)+"?msg=sessions_revoked", http.StatusSeeOther)
}

func (s *Server) handleAdminDeletePasskey(w http.ResponseWriter, r *http.Request, me *store.User) {
	ctx := r.Context()
	u := s.loadTargetUser(w, r)
	if u == nil {
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("id"))
	if err != nil {
		http.Error(w, "bad passkey id", http.StatusBadRequest)
		return
	}
	name := ""
	if creds, err := s.store.ListCredentials(ctx, u.ID); err == nil {
		for _, c := range creds {
			if string(c.ID) == string(credID) {
				name = c.Name
			}
		}
	}
	if err := s.store.AdminDeleteCredential(ctx, u.ID, credID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, "delete passkey", err)
		return
	}
	s.audit(r, me, "admin.passkey.remove", "user", u.ID, u.Username, map[string]any{"passkey": name})
	http.Redirect(w, r, "/admin/users/"+url.PathEscape(u.ID)+"?msg=passkey_removed", http.StatusSeeOther)
}

// ---------------------------------------------------------------- applications (OIDC clients)

func (s *Server) handleAdminClients(w http.ResponseWriter, r *http.Request, me *store.User) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		s.internalError(w, "list clients", err)
		return
	}
	s.adminRender(w, r, http.StatusOK, "admin_clients.html", "clients", me, map[string]any{"Clients": clients})
}

type clientForm struct {
	Name, Type, RedirectURIs, PostLogoutURIs, Error string
}

func (s *Server) handleAdminNewClient(w http.ResponseWriter, r *http.Request, me *store.User) {
	s.adminRender(w, r, http.StatusOK, "admin_client_new.html", "clients", me, map[string]any{
		"Form": clientForm{Type: "confidential"},
	})
}

// parseClientForm validates the shared fields of the create and edit forms.
func parseClientForm(r *http.Request) (f clientForm, redirects, postLogout []string, ok bool) {
	f = clientForm{
		Name:           strings.TrimSpace(r.PostFormValue("name")),
		Type:           r.PostFormValue("type"),
		RedirectURIs:   r.PostFormValue("redirect_uris"),
		PostLogoutURIs: r.PostFormValue("post_logout_uris"),
	}
	if f.Name == "" || utf8.RuneCountInString(f.Name) > 100 {
		f.Error = "Name is required (up to 100 characters)."
		return f, nil, nil, false
	}
	var err error
	if redirects, err = ParseRedirectURIs(f.RedirectURIs, true); err != nil {
		f.Error = "Redirect URIs: " + err.Error()
		return f, nil, nil, false
	}
	if postLogout, err = ParseRedirectURIs(f.PostLogoutURIs, false); err != nil {
		f.Error = "Post-logout URIs: " + err.Error()
		return f, nil, nil, false
	}
	return f, redirects, postLogout, true
}

func (s *Server) handleAdminCreateClient(w http.ResponseWriter, r *http.Request, me *store.User) {
	f, redirects, postLogout, ok := parseClientForm(r)
	if f.Type != "public" {
		f.Type = "confidential"
	}
	if !ok {
		s.adminRender(w, r, http.StatusBadRequest, "admin_client_new.html", "clients", me, map[string]any{"Form": f})
		return
	}
	c, secret, err := s.store.CreateClient(r.Context(), f.Name, redirects, postLogout, f.Type == "public")
	if err != nil {
		s.internalError(w, "create client", err)
		return
	}
	s.audit(r, me, "admin.client.create", "client", c.ID, c.Name, map[string]any{"type": f.Type, "redirect_uris": redirects})
	s.adminRender(w, r, http.StatusOK, "admin_client_secret.html", "clients", me, map[string]any{
		"Client": c, "Secret": secret, "Created": true,
	})
}

func (s *Server) loadClient(w http.ResponseWriter, r *http.Request) *store.Client {
	c, err := s.store.GetClient(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, http.StatusNotFound, "Application not found", "It may have been deleted.")
		return nil
	}
	if err != nil {
		s.internalError(w, "load client", err)
		return nil
	}
	return c
}

func (s *Server) clientPage(w http.ResponseWriter, r *http.Request, me *store.User, c *store.Client, f clientForm, status int) {
	events, _, err := s.store.ListAudit(r.Context(), store.AuditFilter{TargetType: "client", TargetID: c.ID, Limit: 20})
	if err != nil {
		s.internalError(w, "client events", err)
		return
	}
	s.adminRender(w, r, status, "admin_client.html", "clients", me, map[string]any{
		"Client": c, "Form": f, "Events": events,
	})
}

func (s *Server) handleAdminClient(w http.ResponseWriter, r *http.Request, me *store.User) {
	c := s.loadClient(w, r)
	if c == nil {
		return
	}
	s.clientPage(w, r, me, c, clientForm{
		Name: c.Name, RedirectURIs: strings.Join(c.RedirectURIs, "\n"), PostLogoutURIs: strings.Join(c.PostLogoutRedirectURIs, "\n"),
	}, http.StatusOK)
}

func (s *Server) handleAdminUpdateClient(w http.ResponseWriter, r *http.Request, me *store.User) {
	c := s.loadClient(w, r)
	if c == nil {
		return
	}
	f, redirects, postLogout, ok := parseClientForm(r)
	if !ok {
		s.clientPage(w, r, me, c, f, http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateClient(r.Context(), c.ID, f.Name, redirects, postLogout); err != nil {
		s.internalError(w, "update client", err)
		return
	}
	s.audit(r, me, "admin.client.update", "client", c.ID, f.Name, map[string]any{
		"redirect_uris": redirects, "post_logout_uris": postLogout,
	})
	http.Redirect(w, r, "/admin/clients/"+url.PathEscape(c.ID)+"?msg=client_saved", http.StatusSeeOther)
}

func (s *Server) handleAdminRotateSecret(w http.ResponseWriter, r *http.Request, me *store.User) {
	c := s.loadClient(w, r)
	if c == nil {
		return
	}
	secret, err := s.store.RotateClientSecret(r.Context(), c.ID)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "public applications have no secret", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.internalError(w, "rotate secret", err)
		return
	}
	s.audit(r, me, "admin.client.rotate_secret", "client", c.ID, c.Name, nil)
	s.adminRender(w, r, http.StatusOK, "admin_client_secret.html", "clients", me, map[string]any{
		"Client": c, "Secret": secret, "Created": false,
	})
}

func (s *Server) handleAdminDeleteClient(w http.ResponseWriter, r *http.Request, me *store.User) {
	c := s.loadClient(w, r)
	if c == nil {
		return
	}
	if r.PostFormValue("confirm") != c.Name {
		http.Redirect(w, r, "/admin/clients/"+url.PathEscape(c.ID)+"?msg=confirm", http.StatusSeeOther)
		return
	}
	if err := s.store.DeleteClient(r.Context(), c.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, "delete client", err)
		return
	}
	s.audit(r, me, "admin.client.delete", "client", c.ID, c.Name, nil)
	http.Redirect(w, r, "/admin/clients?msg=client_deleted", http.StatusSeeOther)
}

// ---------------------------------------------------------------- audit log

var auditCategories = []struct{ Value, Label string }{
	{"", "All events"},
	{"user.", "Sign-ups & sign-ins"},
	{"passkey.", "Passkey changes by users"},
	{"admin.", "Admin actions"},
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request, me *store.User) {
	const limit = 50
	cat := r.URL.Query().Get("category")
	valid := false
	for _, c := range auditCategories {
		valid = valid || c.Value == cat
	}
	if !valid {
		cat = ""
	}
	_, total, err := s.store.ListAudit(r.Context(), store.AuditFilter{Action: cat, Limit: 1})
	if err != nil {
		s.internalError(w, "count audit", err)
		return
	}
	pg, offset := paginate(r, total, limit)
	events, _, err := s.store.ListAudit(r.Context(), store.AuditFilter{Action: cat, Limit: limit, Offset: offset})
	if err != nil {
		s.internalError(w, "list audit", err)
		return
	}
	s.adminRender(w, r, http.StatusOK, "admin_audit.html", "audit", me, map[string]any{
		"Events": events, "Category": cat, "Categories": auditCategories, "Pager": pg,
	})
}

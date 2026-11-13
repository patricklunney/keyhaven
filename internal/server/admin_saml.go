package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/keyhaven/keyhaven/internal/saml"
	"github.com/keyhaven/keyhaven/internal/store"
)

var nameIDFormats = []struct{ Value, Label string }{
	{saml.NameIDPersistent, "Persistent: Keyhaven user ID (recommended, never changes)"},
	{saml.NameIDUnspecified, "Unspecified: username"},
}

type samlAppForm struct {
	Name, EntityID, ACSURLs, NameIDFormat, Error string
}

// samlIdPInfo is what admins paste into the application's SAML settings.
func (s *Server) samlIdPInfo() map[string]any {
	if s.saml == nil {
		return nil
	}
	return map[string]any{
		"EntityID":    s.saml.EntityID,
		"SSOURL":      s.saml.SSOURL,
		"MetadataURL": s.cfg.Issuer + "/saml/metadata",
		"Fingerprint": saml.Fingerprint(s.saml.Cert),
		"Expires":     s.saml.Cert.NotAfter,
	}
}

// ValidateEntityID accepts URLs and URNs without whitespace or control characters.
func ValidateEntityID(id string) error {
	if id == "" || len(id) > 1024 {
		return errors.New("entity ID is required (up to 1024 characters)")
	}
	for _, r := range id {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errors.New("entity ID must not contain spaces or control characters")
		}
	}
	return nil
}

// ParseACSURLs validates Assertion Consumer Service URLs: https, or http on localhost.
func ParseACSURLs(text string) ([]string, error) {
	urls, err := ParseRedirectURIs(text, true)
	if err != nil {
		return nil, err
	}
	for _, u := range urls {
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			return nil, fmt.Errorf("%q: ACS URLs must be https (or http on localhost)", u)
		}
	}
	return urls, nil
}

func parseSAMLAppForm(r *http.Request) (f samlAppForm, acs []string, ok bool) {
	f = samlAppForm{
		Name:         strings.TrimSpace(r.PostFormValue("name")),
		EntityID:     strings.TrimSpace(r.PostFormValue("entity_id")),
		ACSURLs:      r.PostFormValue("acs_urls"),
		NameIDFormat: r.PostFormValue("name_id_format"),
	}
	if f.Name == "" || utf8.RuneCountInString(f.Name) > 100 {
		f.Error = "Name is required (up to 100 characters)."
		return f, nil, false
	}
	if err := ValidateEntityID(f.EntityID); err != nil {
		f.Error = "Entity ID: " + err.Error()
		return f, nil, false
	}
	var err error
	if acs, err = ParseACSURLs(f.ACSURLs); err != nil {
		f.Error = "ACS URLs: " + err.Error()
		return f, nil, false
	}
	if f.NameIDFormat != saml.NameIDPersistent && f.NameIDFormat != saml.NameIDUnspecified {
		f.Error = "Choose a NameID format."
		return f, nil, false
	}
	return f, acs, true
}

func (s *Server) handleAdminSAMLApps(w http.ResponseWriter, r *http.Request, me *store.User) {
	apps, err := s.store.ListSAMLApps(r.Context())
	if err != nil {
		s.internalError(w, "list saml apps", err)
		return
	}
	s.adminRender(w, r, http.StatusOK, "admin_saml_apps.html", "saml", me, map[string]any{
		"Apps": apps, "IdP": s.samlIdPInfo(),
	})
}

func (s *Server) handleAdminNewSAMLApp(w http.ResponseWriter, r *http.Request, me *store.User) {
	s.adminRender(w, r, http.StatusOK, "admin_saml_app_new.html", "saml", me, map[string]any{
		"Form": samlAppForm{NameIDFormat: saml.NameIDPersistent}, "Formats": nameIDFormats, "IdP": s.samlIdPInfo(),
	})
}

func (s *Server) handleAdminCreateSAMLApp(w http.ResponseWriter, r *http.Request, me *store.User) {
	f, acs, ok := parseSAMLAppForm(r)
	if ok {
		app, err := s.store.CreateSAMLApp(r.Context(), f.Name, f.EntityID, acs, f.NameIDFormat)
		switch {
		case errors.Is(err, store.ErrEntityIDTaken):
			f.Error = "An app with this entity ID is already registered."
		case err != nil:
			s.internalError(w, "create saml app", err)
			return
		default:
			s.audit(r, me, "admin.saml_app.create", "saml_app", app.ID, app.Name,
				map[string]any{"entity_id": app.EntityID, "acs_urls": acs})
			http.Redirect(w, r, "/admin/saml/"+url.PathEscape(app.ID)+"?msg=saml_saved", http.StatusSeeOther)
			return
		}
	}
	s.adminRender(w, r, http.StatusBadRequest, "admin_saml_app_new.html", "saml", me, map[string]any{
		"Form": f, "Formats": nameIDFormats, "IdP": s.samlIdPInfo(),
	})
}

func (s *Server) loadSAMLApp(w http.ResponseWriter, r *http.Request) *store.SAMLApp {
	a, err := s.store.GetSAMLApp(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, http.StatusNotFound, "SAML app not found", "It may have been deleted.")
		return nil
	}
	if err != nil {
		s.internalError(w, "load saml app", err)
		return nil
	}
	return a
}

func (s *Server) samlAppPage(w http.ResponseWriter, r *http.Request, me *store.User, a *store.SAMLApp, f samlAppForm, status int) {
	events, _, err := s.store.ListAudit(r.Context(), store.AuditFilter{TargetType: "saml_app", TargetID: a.ID, Limit: 20})
	if err != nil {
		s.internalError(w, "saml app events", err)
		return
	}
	s.adminRender(w, r, status, "admin_saml_app.html", "saml", me, map[string]any{
		"App": a, "Form": f, "Formats": nameIDFormats, "IdP": s.samlIdPInfo(), "Events": events,
	})
}

func (s *Server) handleAdminSAMLApp(w http.ResponseWriter, r *http.Request, me *store.User) {
	a := s.loadSAMLApp(w, r)
	if a == nil {
		return
	}
	s.samlAppPage(w, r, me, a, samlAppForm{
		Name: a.Name, EntityID: a.EntityID, ACSURLs: strings.Join(a.ACSURLs, "\n"), NameIDFormat: a.NameIDFormat,
	}, http.StatusOK)
}

func (s *Server) handleAdminUpdateSAMLApp(w http.ResponseWriter, r *http.Request, me *store.User) {
	a := s.loadSAMLApp(w, r)
	if a == nil {
		return
	}
	f, acs, ok := parseSAMLAppForm(r)
	if ok {
		err := s.store.UpdateSAMLApp(r.Context(), a.ID, f.Name, f.EntityID, acs, f.NameIDFormat)
		switch {
		case errors.Is(err, store.ErrEntityIDTaken):
			f.Error = "Another app already uses this entity ID."
		case err != nil:
			s.internalError(w, "update saml app", err)
			return
		default:
			s.audit(r, me, "admin.saml_app.update", "saml_app", a.ID, f.Name,
				map[string]any{"entity_id": f.EntityID, "acs_urls": acs, "name_id_format": f.NameIDFormat})
			http.Redirect(w, r, "/admin/saml/"+url.PathEscape(a.ID)+"?msg=saml_saved", http.StatusSeeOther)
			return
		}
	}
	s.samlAppPage(w, r, me, a, f, http.StatusBadRequest)
}

func (s *Server) handleAdminDeleteSAMLApp(w http.ResponseWriter, r *http.Request, me *store.User) {
	a := s.loadSAMLApp(w, r)
	if a == nil {
		return
	}
	if r.PostFormValue("confirm") != a.Name {
		http.Redirect(w, r, "/admin/saml/"+url.PathEscape(a.ID)+"?msg=confirm", http.StatusSeeOther)
		return
	}
	if err := s.store.DeleteSAMLApp(r.Context(), a.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, "delete saml app", err)
		return
	}
	s.audit(r, me, "admin.saml_app.delete", "saml_app", a.ID, a.Name, map[string]any{"entity_id": a.EntityID})
	http.Redirect(w, r, "/admin/saml?msg=saml_deleted", http.StatusSeeOther)
}

package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/keyhaven/keyhaven/internal/saml"
	"github.com/keyhaven/keyhaven/internal/store"
)

const (
	kindSAMLRequest = "saml_request"
	samlRequestTTL  = 10 * time.Minute
	maxRelayState   = 1024
)

// samlPending is a validated AuthnRequest waiting for the user to sign in.
type samlPending struct {
	RequestID  string    `json:"request_id"`
	AppID      string    `json:"app_id"`
	ACSURL     string    `json:"acs_url"`
	ForceAuthn bool      `json:"force_authn"`
	IsPassive  bool      `json:"is_passive"`
	RelayState string    `json:"relay_state"`
	CreatedAt  time.Time `json:"created_at"`
}

func toSAMLApp(a *store.SAMLApp) *saml.App {
	return &saml.App{ID: a.ID, Name: a.Name, EntityID: a.EntityID, ACSURLs: a.ACSURLs, NameIDFormat: a.NameIDFormat}
}

func (s *Server) samlLookup(ctx context.Context) func(string) (*saml.App, error) {
	return func(entityID string) (*saml.App, error) {
		a, err := s.store.GetSAMLAppByEntityID(ctx, entityID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return toSAMLApp(a), nil
	}
}

func (s *Server) samlEnabled(w http.ResponseWriter, r *http.Request) bool {
	if s.saml == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

// GET /saml/metadata
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if !s.samlEnabled(w, r) {
		return
	}
	md, err := s.saml.Metadata()
	if err != nil {
		s.internalError(w, "saml metadata", err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(md)
}

// GET|POST /saml/sso — SP-initiated sign-in (HTTP-Redirect or HTTP-POST binding).
func (s *Server) handleSAMLSSO(w http.ResponseWriter, r *http.Request) {
	if !s.samlEnabled(w, r) {
		return
	}
	var (
		req        *saml.AuthnRequest
		relayState string
		err        error
	)
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		if err := r.ParseForm(); err != nil {
			s.errorPage(w, http.StatusBadRequest, "Invalid sign-in request", "The application sent a malformed SAML request.")
			return
		}
		req, err = saml.DecodePOST(r.PostForm.Get("SAMLRequest"))
		relayState = r.PostForm.Get("RelayState")
	} else {
		req, err = saml.DecodeRedirect(r.URL.Query().Get("SAMLRequest"))
		relayState = r.URL.Query().Get("RelayState")
	}
	var v *saml.Validated
	if err == nil {
		v, err = saml.Validate(req, s.samlLookup(r.Context()), s.saml.SSOURL, time.Now())
	}
	if err == nil && len(relayState) > maxRelayState {
		err = errors.New("RelayState too long")
	}
	if err != nil {
		if errors.Is(err, saml.ErrInvalidRequest) || err.Error() == "RelayState too long" {
			s.log.Info("saml request rejected", "reason", err.Error(), "remote", clientIP(r))
			s.errorPage(w, http.StatusBadRequest, "Invalid sign-in request",
				"The application that sent you here isn't registered with this sign-in service, or its request was invalid.")
			return
		}
		s.internalError(w, "saml validate", err)
		return
	}

	p := samlPending{
		RequestID: v.RequestID, AppID: v.App.ID, ACSURL: v.ACSURL, ForceAuthn: v.ForceAuthn,
		IsPassive: v.IsPassive, RelayState: relayState, CreatedAt: time.Now(),
	}
	sess := s.currentSession(r)
	needsEmail := false
	if sess != nil && !p.ForceAuthn {
		u, err := s.store.GetUser(r.Context(), sess.UserID)
		if err != nil {
			s.internalError(w, "load user", err)
			return
		}
		if u.Email != "" {
			s.samlRespond(w, r, &p, sess)
			return
		}
		needsEmail = true
	}
	if p.IsPassive {
		// The app asked us not to interact with the user.
		s.samlPostError(w, r, &p, saml.StatusNoPassive)
		return
	}
	key := store.RandomToken()
	if err := s.store.PutEphemeral(r.Context(), kindSAMLRequest, key, "", &p, samlRequestTTL); err != nil {
		s.internalError(w, "save saml request", err)
		return
	}
	if needsEmail {
		http.Redirect(w, r, "/account/email?next="+url.QueryEscape("/saml/continue?req="+key), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login?saml="+url.QueryEscape(key), http.StatusSeeOther)
}

// GET /saml/continue?req=… — resumes a pending SAML request after sign-in.
func (s *Server) handleSAMLContinue(w http.ResponseWriter, r *http.Request) {
	if !s.samlEnabled(w, r) {
		return
	}
	key := r.URL.Query().Get("req")
	var p samlPending
	if err := s.store.GetEphemeral(r.Context(), kindSAMLRequest, key, &p); err != nil {
		s.errorPage(w, http.StatusBadRequest, "Sign-in link expired", "Return to the application and start signing in again.")
		return
	}
	sess := s.currentSession(r)
	if sess == nil || (p.ForceAuthn && sess.CreatedAt.Before(p.CreatedAt)) {
		http.Redirect(w, r, "/login?saml="+url.QueryEscape(key), http.StatusSeeOther)
		return
	}
	if !s.requireEmail(w, r, sess.UserID, r.URL.RequestURI()) {
		return
	}
	if err := s.store.TakeEphemeral(r.Context(), kindSAMLRequest, key, &p); err != nil {
		s.errorPage(w, http.StatusBadRequest, "Sign-in link expired", "Return to the application and start signing in again.")
		return
	}
	s.samlRespond(w, r, &p, sess)
}

func (s *Server) samlValidated(ctx context.Context, p *samlPending) (*saml.Validated, error) {
	app, err := s.store.GetSAMLApp(ctx, p.AppID) // the app may have been deleted meanwhile
	if err != nil {
		return nil, err
	}
	return &saml.Validated{RequestID: p.RequestID, App: toSAMLApp(app), ACSURL: p.ACSURL, ForceAuthn: p.ForceAuthn, IsPassive: p.IsPassive}, nil
}

func (s *Server) samlRespond(w http.ResponseWriter, r *http.Request, p *samlPending, sess *store.Session) {
	v, err := s.samlValidated(r.Context(), p)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, http.StatusBadRequest, "Application removed", "This application is no longer registered.")
		return
	}
	if err != nil {
		s.internalError(w, "load saml app", err)
		return
	}
	u, err := s.store.GetUser(r.Context(), sess.UserID)
	if err != nil {
		s.internalError(w, "load user", err)
		return
	}
	resp, err := s.saml.Response(saml.ResponseParams{
		Request:      v,
		User:         saml.User{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Email: u.Email},
		AuthnInstant: sess.CreatedAt,
		SessionIndex: "_" + store.RandomHex(16),
	})
	if err != nil {
		s.internalError(w, "build saml response", err)
		return
	}
	s.audit(r, u, "saml.sso", "saml_app", v.App.ID, v.App.Name, map[string]any{"acs": v.ACSURL})
	s.renderSAMLPost(w, v.ACSURL, resp, p.RelayState)
}

func (s *Server) samlPostError(w http.ResponseWriter, r *http.Request, p *samlPending, status string) {
	v, err := s.samlValidated(r.Context(), p)
	if err != nil {
		s.internalError(w, "load saml app", err)
		return
	}
	resp, err := s.saml.ErrorResponse(v, status)
	if err != nil {
		s.internalError(w, "build saml error response", err)
		return
	}
	s.renderSAMLPost(w, v.ACSURL, resp, p.RelayState)
}

// renderSAMLPost auto-submits the response to the app's (registered) ACS URL.
// The page's CSP allows form submission to that exact origin only.
func (s *Server) renderSAMLPost(w http.ResponseWriter, acs, samlResponse, relayState string) {
	u, err := url.Parse(acs)
	if err != nil || u.Host == "" {
		s.internalError(w, "saml acs", errors.New("invalid ACS URL"))
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "+
		"form-action "+u.Scheme+"://"+u.Host+"; frame-ancestors 'none'; base-uri 'none'")
	s.render(w, http.StatusOK, "saml_post.html", map[string]any{
		"RP": s.cfg.RPDisplayName, "ACS": acs, "SAMLResponse": samlResponse, "RelayState": relayState,
	})
}

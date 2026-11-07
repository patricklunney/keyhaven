package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/keyhaven/keyhaven/internal/store"
)

const (
	ceremonyCookie = "kh_ceremony"
	ceremonyTTL    = 5 * time.Minute
	kindCeremony   = "webauthn_ceremony"
)

var usernameRE = regexp.MustCompile(`^[a-zA-Z0-9._@+-]{3,64}$`)

// ceremony is the server-side state carried between begin and finish.
type ceremony struct {
	Type    string               `json:"type"` // "register" | "login"
	Session webauthn.SessionData `json:"session"`

	// Registration of a brand new account.
	NewUser *pendingUser `json:"new_user,omitempty"`
	// Registration of an additional passkey on an existing (signed-in) account.
	ExistingUserID string `json:"existing_user_id,omitempty"`
}

type pendingUser struct {
	ID          string `json:"id"`
	Handle      []byte `json:"handle"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

func (s *Server) saveCeremony(w http.ResponseWriter, r *http.Request, c *ceremony) error {
	key := store.RandomToken()
	if err := s.store.PutEphemeral(r.Context(), kindCeremony, key, "", c, ceremonyTTL); err != nil {
		return err
	}
	s.setCookie(w, ceremonyCookie, key, ceremonyTTL)
	return nil
}

func (s *Server) takeCeremony(w http.ResponseWriter, r *http.Request, typ string) (*ceremony, error) {
	key := s.cookie(r, ceremonyCookie)
	s.clearCookie(w, ceremonyCookie)
	if key == "" {
		return nil, store.ErrNotFound
	}
	var c ceremony
	if err := s.store.TakeEphemeral(r.Context(), kindCeremony, key, &c); err != nil {
		return nil, err
	}
	if c.Type != typ {
		return nil, store.ErrNotFound
	}
	return &c, nil
}

// passkeyOptions enforces discoverable credentials with user verification: a
// passkey is the only factor, so the authenticator must verify the user.
func passkeyRegistrationOptions(exclude []webauthn.Credential) []webauthn.RegistrationOption {
	opts := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	}
	if len(exclude) > 0 {
		descs := make([]protocol.CredentialDescriptor, 0, len(exclude))
		for _, c := range exclude {
			descs = append(descs, c.Descriptor())
		}
		opts = append(opts, webauthn.WithExclusions(descs))
	}
	return opts
}

// POST /webauthn/register/begin  {"username": "...", "displayName": "..."}
// When already signed in, this adds a passkey to the current account instead.
func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var user webauthn.User
	c := &ceremony{Type: "register"}

	if sess := s.currentSession(r); sess != nil {
		u, err := s.store.GetUser(ctx, sess.UserID)
		if err != nil {
			s.log.Error("load user", "err", err)
			s.jsonError(w, http.StatusInternalServerError, "server error")
			return
		}
		user, c.ExistingUserID = u, u.ID
	} else {
		if !s.cfg.AllowSignup {
			s.jsonError(w, http.StatusForbidden, "Sign-up is disabled on this server.")
			return
		}
		var body struct {
			Username    string `json:"username"`
			DisplayName string `json:"displayName"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		body.Username = strings.TrimSpace(body.Username)
		body.DisplayName = strings.TrimSpace(body.DisplayName)
		if !usernameRE.MatchString(body.Username) {
			s.jsonError(w, http.StatusBadRequest, "Username must be 3-64 characters: letters, numbers and . _ @ + -")
			return
		}
		if body.DisplayName == "" {
			body.DisplayName = body.Username
		}
		if utf8.RuneCountInString(body.DisplayName) > 64 {
			s.jsonError(w, http.StatusBadRequest, "Display name must be 64 characters or fewer.")
			return
		}
		taken, err := s.store.UsernameExists(ctx, body.Username)
		if err != nil {
			s.log.Error("check username", "err", err)
			s.jsonError(w, http.StatusInternalServerError, "server error")
			return
		}
		if taken {
			s.jsonError(w, http.StatusConflict, "That username is already taken.")
			return
		}
		u := store.NewUser(body.Username, body.DisplayName)
		user = u
		c.NewUser = &pendingUser{ID: u.ID, Handle: u.Handle, Username: u.Username, DisplayName: u.DisplayName}
	}

	creation, session, err := s.wa.BeginRegistration(user, passkeyRegistrationOptions(user.WebAuthnCredentials())...)
	if err != nil {
		s.log.Error("begin registration", "err", err)
		s.jsonError(w, http.StatusInternalServerError, "server error")
		return
	}
	c.Session = *session
	if err := s.saveCeremony(w, r, c); err != nil {
		s.log.Error("save ceremony", "err", err)
		s.jsonError(w, http.StatusInternalServerError, "server error")
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

// POST /webauthn/register/finish?name=<label>   body: PublicKeyCredential JSON
func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.takeCeremony(w, r, "register")
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "Registration expired, please try again.")
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" || utf8.RuneCountInString(name) > 64 {
		name = "Passkey"
	}

	if c.ExistingUserID != "" {
		// Adding a passkey: the same account must still be signed in.
		sess := s.currentSession(r)
		if sess == nil || sess.UserID != c.ExistingUserID {
			s.jsonError(w, http.StatusUnauthorized, "Your session has ended. Sign in again.")
			return
		}
		u, err := s.store.GetUser(ctx, c.ExistingUserID)
		if err != nil {
			s.log.Error("load user", "err", err)
			s.jsonError(w, http.StatusInternalServerError, "server error")
			return
		}
		cred, err := s.wa.FinishRegistration(u, c.Session, r)
		if err != nil {
			s.webauthnFailure(w, "finish registration", err)
			return
		}
		if err := s.store.AddCredential(ctx, u.ID, cred, name); err != nil {
			s.log.Error("add credential", "err", err)
			s.jsonError(w, http.StatusInternalServerError, "server error")
			return
		}
		s.log.Info("passkey added", "user_id", u.ID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	if c.NewUser == nil {
		s.jsonError(w, http.StatusBadRequest, "invalid ceremony")
		return
	}
	u := &store.User{ID: c.NewUser.ID, Handle: c.NewUser.Handle, Username: c.NewUser.Username, DisplayName: c.NewUser.DisplayName}
	cred, err := s.wa.FinishRegistration(u, c.Session, r)
	if err != nil {
		s.webauthnFailure(w, "finish registration", err)
		return
	}
	if err := s.store.CreateUserWithCredential(ctx, u, cred, name); err != nil {
		if errors.Is(err, store.ErrUsernameTaken) {
			s.jsonError(w, http.StatusConflict, "That username is already taken.")
			return
		}
		s.log.Error("create user", "err", err)
		s.jsonError(w, http.StatusInternalServerError, "server error")
		return
	}
	if err := s.startSession(w, r, u.ID); err != nil {
		s.log.Error("start session", "err", err)
		s.jsonError(w, http.StatusInternalServerError, "server error")
		return
	}
	s.log.Info("user registered", "user_id", u.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /webauthn/login/begin — discoverable (username-less) passkey login.
func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.log.Error("begin login", "err", err)
		s.jsonError(w, http.StatusInternalServerError, "server error")
		return
	}
	if err := s.saveCeremony(w, r, &ceremony{Type: "login", Session: *session}); err != nil {
		s.log.Error("save ceremony", "err", err)
		s.jsonError(w, http.StatusInternalServerError, "server error")
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// POST /webauthn/login/finish   body: PublicKeyCredential JSON
func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.takeCeremony(w, r, "login")
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "Sign-in expired, please try again.")
		return
	}

	var found *store.User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, err := s.store.GetUserByHandle(ctx, userHandle)
		if err != nil {
			return nil, err
		}
		found = u
		return u, nil
	}
	_, cred, err := s.wa.FinishPasskeyLogin(handler, c.Session, r)
	if err != nil {
		s.webauthnFailure(w, "finish login", err)
		return
	}
	if cred.Authenticator.CloneWarning {
		// The signature counter went backwards: a cloned authenticator may exist.
		s.log.Warn("passkey clone warning; rejecting login", "user_id", found.ID)
		s.jsonError(w, http.StatusForbidden, "This passkey failed a security check. Use another passkey.")
		return
	}
	if err := s.store.TouchCredential(ctx, cred); err != nil {
		s.log.Error("update credential", "err", err)
	}
	if err := s.startSession(w, r, found.ID); err != nil {
		s.log.Error("start session", "err", err)
		s.jsonError(w, http.StatusInternalServerError, "server error")
		return
	}
	s.log.Info("user signed in", "user_id", found.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) webauthnFailure(w http.ResponseWriter, where string, err error) {
	var perr *protocol.Error
	if errors.As(err, &perr) {
		s.log.Info(where+" rejected", "type", perr.Type, "detail", perr.DevInfo)
	} else {
		s.log.Info(where+" rejected", "err", err)
	}
	s.jsonError(w, http.StatusBadRequest, "The passkey could not be verified. Please try again.")
}

// Package store persists Keyhaven state in PostgreSQL.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var (
	ErrNotFound      = errors.New("not found")
	ErrUsernameTaken = errors.New("username already taken")
	ErrEmailTaken    = errors.New("email already in use")
	ErrLastPasskey   = errors.New("cannot remove the last passkey on an account")
)

type Store struct{ pool *pgxpool.Pool }

func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close()                         { s.pool.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate applies embedded migrations. A Postgres advisory lock makes it safe
// for several tasks to start at once.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	const lockID = 7_342_001
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockID) //nolint:errcheck

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		version, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("bad migration name %q", e.Name())
		}
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", e.Name(), err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Cleanup removes expired sessions and ephemeral records.
func (s *Store) Cleanup(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM ephemeral WHERE expires_at < now()`)
	return err
}

// ---------------------------------------------------------------- users

type User struct {
	ID          string
	Handle      []byte
	Username    string
	DisplayName string
	Email       string
	IsAdmin     bool
	CreatedAt   time.Time
	Credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.Handle }
func (u *User) WebAuthnName() string                       { return u.Username }
func (u *User) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// NewUser builds an unsaved user with fresh random identifiers.
func NewUser(username, displayName string) *User {
	return &User{ID: RandomHex(16), Handle: RandomBytes(32), Username: username, DisplayName: displayName}
}

func (s *Store) EmailExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE lower(email)=lower($1))`, email).Scan(&exists)
	return exists, err
}

// SetUserEmail sets (or changes) a user's email; ErrEmailTaken if another account uses it.
func (s *Store) SetUserEmail(ctx context.Context, userID, email string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET email=$2 WHERE id=$1`, userID, email)
	if isUniqueViolation(err) {
		return ErrEmailTaken
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) UsernameExists(ctx context.Context, username string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE lower(username)=lower($1))`, username).Scan(&exists)
	return exists, err
}

// CreateUserWithCredential inserts a new user and their first passkey atomically.
func (s *Store) CreateUserWithCredential(ctx context.Context, u *User, cred *webauthn.Credential, credName string) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, handle, username, display_name, email) VALUES ($1,$2,$3,$4,NULLIF($5,''))`,
			u.ID, u.Handle, u.Username, u.DisplayName, u.Email)
		if isUniqueViolation(err) {
			if violatedConstraint(err) == "users_email_lower_idx" {
				return ErrEmailTaken
			}
			return ErrUsernameTaken
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO credentials (id, user_id, name, data) VALUES ($1,$2,$3,$4)`, cred.ID, u.ID, credName, data)
		return err
	})
}

const userCols = `id, handle, username, display_name, COALESCE(email,''), is_admin, created_at`

func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	return s.getUser(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id)
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return s.getUser(ctx, `SELECT `+userCols+` FROM users WHERE lower(username)=lower($1)`, username)
}

func (s *Store) GetUserByHandle(ctx context.Context, handle []byte) (*User, error) {
	return s.getUser(ctx, `SELECT `+userCols+` FROM users WHERE handle=$1`, handle)
}

func (s *Store) getUser(ctx context.Context, q string, arg any) (*User, error) {
	u := &User{}
	err := s.pool.QueryRow(ctx, q, arg).Scan(&u.ID, &u.Handle, &u.Username, &u.DisplayName, &u.Email, &u.IsAdmin, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	creds, err := s.ListCredentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	for _, c := range creds {
		u.Credentials = append(u.Credentials, c.Credential)
	}
	return u, nil
}

type UserSummary struct {
	ID, Username, DisplayName, Email string
	IsAdmin                          bool
	CreatedAt                        time.Time
	LastSeen                         *time.Time // most recent passkey use
	Passkeys                         int
}

// SearchUsers lists users matching q (username or display name, case-insensitive),
// newest first, and returns the total number of matches.
func (s *Store) SearchUsers(ctx context.Context, q string, limit, offset int) ([]UserSummary, int, error) {
	pattern := "%" + escapeLike(q) + "%"
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username ILIKE $1 OR display_name ILIKE $1 OR email ILIKE $1`, pattern).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.pool.Query(ctx, `SELECT u.id, u.username, u.display_name, COALESCE(u.email,''), u.is_admin, u.created_at, max(c.last_used_at), count(c.id)
		FROM users u LEFT JOIN credentials c ON c.user_id=u.id
		WHERE u.username ILIKE $1 OR u.display_name ILIKE $1 OR u.email ILIKE $1
		GROUP BY u.id ORDER BY u.created_at DESC LIMIT $2 OFFSET $3`, pattern, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	users, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (UserSummary, error) {
		var u UserSummary
		err := r.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.IsAdmin, &u.CreatedAt, &u.LastSeen, &u.Passkeys)
		return u, err
	})
	return users, total, err
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------- credentials

type StoredCredential struct {
	webauthn.Credential
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

func (s *Store) ListCredentials(ctx context.Context, userID string) ([]StoredCredential, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, data, created_at, last_used_at FROM credentials WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (StoredCredential, error) {
		var c StoredCredential
		var data []byte
		if err := r.Scan(&c.Name, &data, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return c, err
		}
		err := json.Unmarshal(data, &c.Credential)
		return c, err
	})
}

func (s *Store) AddCredential(ctx context.Context, userID string, cred *webauthn.Credential, name string) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO credentials (id, user_id, name, data) VALUES ($1,$2,$3,$4)`, cred.ID, userID, name, data)
	return err
}

// TouchCredential records a successful assertion (updated sign count, flags, last use).
func (s *Store) TouchCredential(ctx context.Context, cred *webauthn.Credential) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE credentials SET data=$2, last_used_at=now() WHERE id=$1`, cred.ID, data)
	return err
}

func (s *Store) DeleteCredential(ctx context.Context, userID string, credID []byte) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var n int
		// Lock the user's credential rows so two concurrent deletes can't remove the last two.
		rows, err := tx.Query(ctx, `SELECT 1 FROM credentials WHERE user_id=$1 FOR UPDATE`, userID)
		if err != nil {
			return err
		}
		for rows.Next() {
			n++
		}
		rows.Close()
		if n <= 1 {
			return ErrLastPasskey
		}
		tag, err := tx.Exec(ctx, `DELETE FROM credentials WHERE user_id=$1 AND id=$2`, userID, credID)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// ---------------------------------------------------------------- sessions

type Session struct {
	UserID    string
	CreatedAt time.Time
}

// CreateSession returns a new opaque session token.
func (s *Store) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	token := RandomToken()
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1,$2,$3)`,
		hashKey(token), userID, time.Now().Add(ttl))
	return token, err
}

func (s *Store) GetSession(ctx context.Context, token string) (*Session, error) {
	sess := &Session{}
	err := s.pool.QueryRow(ctx, `SELECT user_id, created_at FROM sessions WHERE token_hash=$1 AND expires_at > now()`,
		hashKey(token)).Scan(&sess.UserID, &sess.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sess, err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, hashKey(token))
	return err
}

// ---------------------------------------------------------------- clients

type Client struct {
	ID                     string
	Name                   string
	SecretHash             []byte
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	CreatedAt              time.Time
}

func (c *Client) Public() bool { return len(c.SecretHash) == 0 }

// CreateClient registers a client. It returns the plaintext secret (empty for public clients),
// which is shown once and never stored.
func (s *Store) CreateClient(ctx context.Context, name string, redirectURIs, postLogoutURIs []string, public bool) (*Client, string, error) {
	c := &Client{ID: RandomHex(16), Name: name, RedirectURIs: redirectURIs, PostLogoutRedirectURIs: postLogoutURIs}
	var secret string
	if !public {
		secret = RandomToken()
		c.SecretHash = HashSecret(secret)
	}
	if c.PostLogoutRedirectURIs == nil {
		c.PostLogoutRedirectURIs = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO clients (id, name, secret_hash, redirect_uris, post_logout_redirect_uris) VALUES ($1,$2,$3,$4,$5)`,
		c.ID, c.Name, c.SecretHash, c.RedirectURIs, c.PostLogoutRedirectURIs)
	return c, secret, err
}

func (s *Store) GetClient(ctx context.Context, id string) (*Client, error) {
	c := &Client{}
	err := s.pool.QueryRow(ctx, `SELECT id, name, secret_hash, redirect_uris, post_logout_redirect_uris, created_at FROM clients WHERE id=$1`, id).
		Scan(&c.ID, &c.Name, &c.SecretHash, &c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, secret_hash, redirect_uris, post_logout_redirect_uris, created_at FROM clients ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Client, error) {
		var c Client
		err := r.Scan(&c.ID, &c.Name, &c.SecretHash, &c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.CreatedAt)
		return c, err
	})
}

func (s *Store) DeleteClient(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM clients WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------- ephemeral records

// PutEphemeral stores v under (kind, key) until ttl elapses. userID may be empty.
func (s *Store) PutEphemeral(ctx context.Context, kind, key, userID string, v any, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO ephemeral (kind, key_hash, user_id, data, expires_at) VALUES ($1,$2,NULLIF($3,''),$4,$5)`,
		kind, hashKey(key), userID, data, time.Now().Add(ttl))
	return err
}

// GetEphemeral reads an unexpired record without consuming it.
func (s *Store) GetEphemeral(ctx context.Context, kind, key string, out any) error {
	var data []byte
	err := s.pool.QueryRow(ctx, `SELECT data FROM ephemeral WHERE kind=$1 AND key_hash=$2 AND expires_at > now()`,
		kind, hashKey(key)).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// TakeEphemeral atomically reads and deletes a record, guaranteeing single use.
func (s *Store) TakeEphemeral(ctx context.Context, kind, key string, out any) error {
	var data []byte
	var expires time.Time
	err := s.pool.QueryRow(ctx, `DELETE FROM ephemeral WHERE kind=$1 AND key_hash=$2 RETURNING data, expires_at`,
		kind, hashKey(key)).Scan(&data, &expires)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && time.Now().After(expires)) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// DeleteUserEphemeral removes all records of a kind belonging to a user (e.g. refresh tokens).
func (s *Store) DeleteUserEphemeral(ctx context.Context, kind, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM ephemeral WHERE kind=$1 AND user_id=$2`, kind, userID)
	return err
}

// ---------------------------------------------------------------- helpers

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func RandomHex(n int) string { return hex.EncodeToString(RandomBytes(n)) }

// RandomToken returns ~256 bits of randomness as URL-safe base32 text.
func RandomToken() string { return rand.Text() + rand.Text() }

// HashSecret hashes a high-entropy secret. SHA-256 is appropriate because the
// inputs are random 256-bit values, not user-chosen passwords.
func HashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func hashKey(k string) []byte { return HashSecret(k) }

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func violatedConstraint(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}

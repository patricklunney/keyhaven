package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrLastAdmin = errors.New("cannot remove the last administrator")

// ---------------------------------------------------------------- admin role

// SetAdmin grants or revokes the administrator role. Revoking the last admin is refused.
func (s *Store) SetAdmin(ctx context.Context, userID string, admin bool) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if !admin {
			// Serialize demotions so two admins can't demote each other concurrently.
			if _, err := tx.Exec(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
				return err
			}
			var others int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE is_admin AND id<>$1`, userID).Scan(&others); err != nil {
				return err
			}
			if others == 0 {
				return ErrLastAdmin
			}
		}
		tag, err := tx.Exec(ctx, `UPDATE users SET is_admin=$2 WHERE id=$1`, userID, admin)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// ---------------------------------------------------------------- dashboard

type Stats struct {
	Users, Admins, Passkeys, Clients, ActiveSessions, SignupsLast7d, SignInsLast24h int
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM users),
		(SELECT count(*) FROM users WHERE is_admin),
		(SELECT count(*) FROM credentials),
		(SELECT count(*) FROM clients),
		(SELECT count(*) FROM sessions WHERE expires_at > now()),
		(SELECT count(*) FROM users WHERE created_at > now() - interval '7 days'),
		(SELECT count(*) FROM audit_events WHERE action='user.login' AND at > now() - interval '24 hours')`).
		Scan(&st.Users, &st.Admins, &st.Passkeys, &st.Clients, &st.ActiveSessions, &st.SignupsLast7d, &st.SignInsLast24h)
	return st, err
}

// ---------------------------------------------------------------- users

func (s *Store) CountUserSessions(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1 AND expires_at > now()`, userID).Scan(&n)
	return n, err
}

// RevokeUserSessions signs the user out everywhere: browser sessions, refresh
// tokens and unredeemed authorization codes. Outstanding access tokens expire
// on their own (short TTL).
func (s *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM ephemeral WHERE user_id=$1`, userID)
		return err
	})
}

// AdminDeleteCredential removes any passkey, including a user's last one
// (the user will then need an admin-reset account to sign in again).
func (s *Store) AdminDeleteCredential(ctx context.Context, userID string, credID []byte) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM credentials WHERE user_id=$1 AND id=$2`, userID, credID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------- clients

func (s *Store) UpdateClient(ctx context.Context, id, name string, redirectURIs, postLogoutURIs []string) error {
	if postLogoutURIs == nil {
		postLogoutURIs = []string{}
	}
	tag, err := s.pool.Exec(ctx, `UPDATE clients SET name=$2, redirect_uris=$3, post_logout_redirect_uris=$4 WHERE id=$1`,
		id, name, redirectURIs, postLogoutURIs)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RotateClientSecret issues a new secret for a confidential client; the old one stops working immediately.
func (s *Store) RotateClientSecret(ctx context.Context, id string) (string, error) {
	secret := RandomToken()
	tag, err := s.pool.Exec(ctx, `UPDATE clients SET secret_hash=$2 WHERE id=$1 AND secret_hash IS NOT NULL`, id, HashSecret(secret))
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	return secret, nil
}

// ---------------------------------------------------------------- audit log

type AuditEvent struct {
	ID         int64
	At         time.Time
	ActorID    string
	ActorName  string
	Action     string
	TargetType string
	TargetID   string
	TargetName string
	Details    map[string]any
	IP         string
}

func (s *Store) AddAudit(ctx context.Context, e AuditEvent) error {
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	details, err := json.Marshal(e.Details)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO audit_events (actor_id, actor_name, action, target_type, target_id, target_name, details, ip)
		VALUES (NULLIF($1,''),NULLIF($2,''),$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),$7,NULLIF($8,''))`,
		e.ActorID, e.ActorName, e.Action, e.TargetType, e.TargetID, e.TargetName, details, e.IP)
	return err
}

type AuditFilter struct {
	Action     string // exact action, or prefix ending in "." (e.g. "client.")
	TargetType string
	TargetID   string
	Limit      int
	Offset     int
}

func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEvent, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	action := f.Action
	if action != "" && action[len(action)-1] == '.' {
		action = escapeLike(action) + "%"
	} else {
		action = escapeLike(action)
	}
	if f.Action == "" {
		action = "%"
	}
	where := `action LIKE $1 AND ($2='' OR target_type=$2) AND ($3='' OR target_id=$3 OR actor_id=$3)`
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE `+where, action, f.TargetType, f.TargetID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id, at, COALESCE(actor_id,''), COALESCE(actor_name,''), action,
		COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(target_name,''), details, COALESCE(ip,'')
		FROM audit_events WHERE `+where+` ORDER BY at DESC, id DESC LIMIT $4 OFFSET $5`,
		action, f.TargetType, f.TargetID, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	events, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEvent, error) {
		var e AuditEvent
		var details []byte
		if err := r.Scan(&e.ID, &e.At, &e.ActorID, &e.ActorName, &e.Action, &e.TargetType, &e.TargetID, &e.TargetName, &details, &e.IP); err != nil {
			return e, err
		}
		err := json.Unmarshal(details, &e.Details)
		return e, err
	})
	return events, total, err
}

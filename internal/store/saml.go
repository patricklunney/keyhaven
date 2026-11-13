package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrEntityIDTaken = errors.New("a SAML app with this entity ID already exists")

// SAMLApp is a registered SAML 2.0 service provider.
type SAMLApp struct {
	ID           string
	Name         string
	EntityID     string
	ACSURLs      []string
	NameIDFormat string
	CreatedAt    time.Time
}

const samlCols = `id, name, entity_id, acs_urls, name_id_format, created_at`

func scanSAMLApp(row pgx.Row) (*SAMLApp, error) {
	a := &SAMLApp{}
	err := row.Scan(&a.ID, &a.Name, &a.EntityID, &a.ACSURLs, &a.NameIDFormat, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) CreateSAMLApp(ctx context.Context, name, entityID string, acsURLs []string, nameIDFormat string) (*SAMLApp, error) {
	a := &SAMLApp{ID: RandomHex(16), Name: name, EntityID: entityID, ACSURLs: acsURLs, NameIDFormat: nameIDFormat}
	err := s.pool.QueryRow(ctx, `INSERT INTO saml_apps (id, name, entity_id, acs_urls, name_id_format) VALUES ($1,$2,$3,$4,$5) RETURNING created_at`,
		a.ID, a.Name, a.EntityID, a.ACSURLs, a.NameIDFormat).Scan(&a.CreatedAt)
	if isUniqueViolation(err) {
		return nil, ErrEntityIDTaken
	}
	return a, err
}

func (s *Store) GetSAMLApp(ctx context.Context, id string) (*SAMLApp, error) {
	return scanSAMLApp(s.pool.QueryRow(ctx, `SELECT `+samlCols+` FROM saml_apps WHERE id=$1`, id))
}

func (s *Store) GetSAMLAppByEntityID(ctx context.Context, entityID string) (*SAMLApp, error) {
	return scanSAMLApp(s.pool.QueryRow(ctx, `SELECT `+samlCols+` FROM saml_apps WHERE entity_id=$1`, entityID))
}

func (s *Store) ListSAMLApps(ctx context.Context) ([]SAMLApp, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+samlCols+` FROM saml_apps ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SAMLApp, error) {
		a, err := scanSAMLApp(r)
		if err != nil {
			return SAMLApp{}, err
		}
		return *a, nil
	})
}

func (s *Store) UpdateSAMLApp(ctx context.Context, id, name, entityID string, acsURLs []string, nameIDFormat string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE saml_apps SET name=$2, entity_id=$3, acs_urls=$4, name_id_format=$5 WHERE id=$1`,
		id, name, entityID, acsURLs, nameIDFormat)
	if isUniqueViolation(err) {
		return ErrEntityIDTaken
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DeleteSAMLApp(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM saml_apps WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

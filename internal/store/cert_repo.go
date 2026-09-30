package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// CertRecord mirrors the certificates table.
type CertRecord struct {
	Name            string
	CA              string
	Domains         []string
	SpecFingerprint string
	FullchainPEM    string
	KeyPEM          string
	NotAfter        time.Time
	Fingerprint     string
	IssuedAt        time.Time
	UpdatedAt       time.Time
}

// CertRepo reads and writes the certificates table.
type CertRepo struct{ db *sql.DB }

func (r *CertRepo) execer(tx *sql.Tx) interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

func (r *CertRepo) queryer(tx *sql.Tx) interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

// Get returns the CertRecord for name, or sql.ErrNoRows if not found.
func (r *CertRepo) Get(ctx context.Context, name string, tx *sql.Tx) (*CertRecord, error) {
	const q = `SELECT name,ca,domains_json,spec_fingerprint,fullchain_pem,key_pem,not_after,fingerprint,issued_at,updated_at
	           FROM certificates WHERE name=?`
	row := r.queryer(tx).QueryRowContext(ctx, q, name)
	return scanCert(row)
}

// List returns all certificate records.
func (r *CertRepo) List(ctx context.Context, tx *sql.Tx) ([]*CertRecord, error) {
	const q = `SELECT name,ca,domains_json,spec_fingerprint,fullchain_pem,key_pem,not_after,fingerprint,issued_at,updated_at
	           FROM certificates ORDER BY name`
	rows, err := r.queryer(tx).QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CertRecord
	for rows.Next() {
		rec, err := scanCertRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ListSummaries returns every certificate record ordered by name, as List
// does, but reads only Name, SpecFingerprint, Fingerprint and NotAfter and
// leaves the other fields empty. GET /v1/sync reads it for every waiting
// client at each change, and needs neither the PEM material nor the rest.
func (r *CertRepo) ListSummaries(ctx context.Context) ([]*CertRecord, error) {
	const q = `SELECT name,spec_fingerprint,fingerprint,not_after FROM certificates ORDER BY name`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CertRecord
	for rows.Next() {
		var rec CertRecord
		var notAfter sql.NullString
		if err := rows.Scan(&rec.Name, &rec.SpecFingerprint, &rec.Fingerprint, &notAfter); err != nil {
			return nil, err
		}
		if notAfter.Valid && notAfter.String != "" {
			if t, err := time.Parse(time.RFC3339, notAfter.String); err == nil {
				rec.NotAfter = t
			}
		}
		out = append(out, &rec)
	}
	return out, rows.Err()
}

// Upsert inserts or replaces the certificate record.
func (r *CertRepo) Upsert(ctx context.Context, rec *CertRecord, tx *sql.Tx) error {
	domainsJSON, err := json.Marshal(rec.Domains)
	if err != nil {
		return fmt.Errorf("marshal domains: %w", err)
	}
	const q = `INSERT INTO certificates(name,ca,domains_json,spec_fingerprint,fullchain_pem,key_pem,not_after,fingerprint,issued_at,updated_at)
	           VALUES(?,?,?,?,?,?,?,?,?,?)
	           ON CONFLICT(name) DO UPDATE SET
	             ca=excluded.ca, domains_json=excluded.domains_json, spec_fingerprint=excluded.spec_fingerprint,
	             fullchain_pem=excluded.fullchain_pem, key_pem=excluded.key_pem,
	             not_after=excluded.not_after, fingerprint=excluded.fingerprint,
	             issued_at=excluded.issued_at, updated_at=excluded.updated_at`
	now := time.Now().UTC()
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = now
	}
	_, err = r.execer(tx).ExecContext(ctx, q,
		rec.Name, rec.CA, string(domainsJSON), rec.SpecFingerprint,
		rec.FullchainPEM, rec.KeyPEM,
		nullTime(rec.NotAfter), rec.Fingerprint,
		nullTime(rec.IssuedAt), rec.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

func scanCert(row *sql.Row) (*CertRecord, error) {
	var rec CertRecord
	var domainsJSON string
	var notAfter, issuedAt, updatedAt sql.NullString
	if err := row.Scan(&rec.Name, &rec.CA, &domainsJSON, &rec.SpecFingerprint, &rec.FullchainPEM, &rec.KeyPEM,
		&notAfter, &rec.Fingerprint, &issuedAt, &updatedAt); err != nil {
		return nil, err
	}
	return parseCertRecord(&rec, domainsJSON, notAfter, issuedAt, updatedAt)
}

func scanCertRow(rows *sql.Rows) (*CertRecord, error) {
	var rec CertRecord
	var domainsJSON string
	var notAfter, issuedAt, updatedAt sql.NullString
	if err := rows.Scan(&rec.Name, &rec.CA, &domainsJSON, &rec.SpecFingerprint, &rec.FullchainPEM, &rec.KeyPEM,
		&notAfter, &rec.Fingerprint, &issuedAt, &updatedAt); err != nil {
		return nil, err
	}
	return parseCertRecord(&rec, domainsJSON, notAfter, issuedAt, updatedAt)
}

func parseCertRecord(rec *CertRecord, domainsJSON string, notAfter, issuedAt, updatedAt sql.NullString) (*CertRecord, error) {
	if err := json.Unmarshal([]byte(domainsJSON), &rec.Domains); err != nil {
		return nil, fmt.Errorf("unmarshal domains: %w", err)
	}
	if notAfter.Valid && notAfter.String != "" {
		t, err := time.Parse(time.RFC3339, notAfter.String)
		if err == nil {
			rec.NotAfter = t
		}
	}
	if issuedAt.Valid && issuedAt.String != "" {
		t, err := time.Parse(time.RFC3339, issuedAt.String)
		if err == nil {
			rec.IssuedAt = t
		}
	}
	if updatedAt.Valid && updatedAt.String != "" {
		t, err := time.Parse(time.RFC3339, updatedAt.String)
		if err == nil {
			rec.UpdatedAt = t
		}
	}
	return rec, nil
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

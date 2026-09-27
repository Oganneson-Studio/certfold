package store

import (
	"context"
	"database/sql"
)

// AccountRecord mirrors the acme_accounts table.
type AccountRecord struct {
	CA               string
	Directory        string
	Email            string
	KeyPEM           string
	RegistrationJSON string
}

// AccountRepo provides CRUD for the acme_accounts table.
type AccountRepo struct{ db *sql.DB }

func (r *AccountRepo) execer(tx *sql.Tx) interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

func (r *AccountRepo) queryer(tx *sql.Tx) interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

// Get returns the ACME account for the given CA name, or sql.ErrNoRows.
func (r *AccountRepo) Get(ctx context.Context, ca string, tx *sql.Tx) (*AccountRecord, error) {
	const q = `SELECT ca,directory,email,key_pem,registration_json FROM acme_accounts WHERE ca=?`
	row := r.queryer(tx).QueryRowContext(ctx, q, ca)
	var rec AccountRecord
	if err := row.Scan(&rec.CA, &rec.Directory, &rec.Email, &rec.KeyPEM, &rec.RegistrationJSON); err != nil {
		return nil, err
	}
	return &rec, nil
}

// List returns all ACME account records.
func (r *AccountRepo) List(ctx context.Context, tx *sql.Tx) ([]*AccountRecord, error) {
	const q = `SELECT ca,directory,email,key_pem,registration_json FROM acme_accounts ORDER BY ca`
	rows, err := r.queryer(tx).QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccountRecord
	for rows.Next() {
		var rec AccountRecord
		if err := rows.Scan(&rec.CA, &rec.Directory, &rec.Email, &rec.KeyPEM, &rec.RegistrationJSON); err != nil {
			return nil, err
		}
		out = append(out, &rec)
	}
	return out, rows.Err()
}

// Upsert inserts or replaces an ACME account record.
func (r *AccountRepo) Upsert(ctx context.Context, rec *AccountRecord, tx *sql.Tx) error {
	const q = `INSERT INTO acme_accounts(ca,directory,email,key_pem,registration_json)
	           VALUES(?,?,?,?,?)
	           ON CONFLICT(ca) DO UPDATE SET
	             directory=excluded.directory, email=excluded.email, key_pem=excluded.key_pem,
	             registration_json=excluded.registration_json`
	_, err := r.execer(tx).ExecContext(ctx, q, rec.CA, rec.Directory, rec.Email, rec.KeyPEM, rec.RegistrationJSON)
	return err
}

// Delete removes an ACME account by CA name.
func (r *AccountRepo) Delete(ctx context.Context, ca string, tx *sql.Tx) error {
	_, err := r.execer(tx).ExecContext(ctx, `DELETE FROM acme_accounts WHERE ca=?`, ca)
	return err
}

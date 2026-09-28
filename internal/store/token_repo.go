package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrTokenAlreadyUsed = errors.New("enrollment token is already used or does not exist")

// TokenRecord mirrors the enrollment_tokens table.
type TokenRecord struct {
	TokenID    string
	Name       string
	SecretHash string
	ExpiresAt  time.Time
	UsedAt     time.Time // zero means unused
	CreatedAt  time.Time
}

// TokenRepo provides CRUD for the enrollment_tokens table.
type TokenRepo struct{ db *sql.DB }

func (r *TokenRepo) execer(tx *sql.Tx) interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

func (r *TokenRepo) queryer(tx *sql.Tx) interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

// Get returns the token record for tokenID, or sql.ErrNoRows if not found.
func (r *TokenRepo) Get(ctx context.Context, tokenID string, tx *sql.Tx) (*TokenRecord, error) {
	const q = `SELECT token_id,name,secret_hash,expires_at,used_at,created_at
	           FROM enrollment_tokens WHERE token_id=?`
	row := r.queryer(tx).QueryRowContext(ctx, q, tokenID)
	return scanToken(row)
}

// List returns all token records ordered by creation time.
func (r *TokenRepo) List(ctx context.Context, tx *sql.Tx) ([]*TokenRecord, error) {
	const q = `SELECT token_id,name,secret_hash,expires_at,used_at,created_at
	           FROM enrollment_tokens ORDER BY created_at DESC`
	rows, err := r.queryer(tx).QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TokenRecord
	for rows.Next() {
		rec, err := scanTokenRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Upsert inserts or replaces a token record.
func (r *TokenRepo) Upsert(ctx context.Context, rec *TokenRecord, tx *sql.Tx) error {
	const q = `INSERT INTO enrollment_tokens(token_id,name,secret_hash,expires_at,used_at,created_at)
	           VALUES(?,?,?,?,?,?)
	           ON CONFLICT(token_id) DO UPDATE SET
	             name=excluded.name, secret_hash=excluded.secret_hash,
	             expires_at=excluded.expires_at, used_at=excluded.used_at`
	_, err := r.execer(tx).ExecContext(ctx, q,
		rec.TokenID, rec.Name, rec.SecretHash,
		rec.ExpiresAt.UTC().Format(time.RFC3339),
		nullTime(rec.UsedAt),
		rec.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// MarkUsed atomically consumes an unused token. Concurrent callers cannot both
// succeed for the same token ID.
func (r *TokenRepo) MarkUsed(ctx context.Context, tokenID string, tx *sql.Tx) error {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := r.execer(tx).ExecContext(ctx,
		`UPDATE enrollment_tokens SET used_at=? WHERE token_id=? AND used_at IS NULL`, now, tokenID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrTokenAlreadyUsed
	}
	return nil
}

// Delete removes a token by ID, or returns sql.ErrNoRows if not found.
func (r *TokenRepo) Delete(ctx context.Context, tokenID string, tx *sql.Tx) error {
	result, err := r.execer(tx).ExecContext(ctx, `DELETE FROM enrollment_tokens WHERE token_id=?`, tokenID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanToken(row *sql.Row) (*TokenRecord, error) {
	var rec TokenRecord
	var expiresAt, usedAt, createdAt sql.NullString
	if err := row.Scan(&rec.TokenID, &rec.Name, &rec.SecretHash,
		&expiresAt, &usedAt, &createdAt); err != nil {
		return nil, err
	}
	parseTokenTimes(&rec, expiresAt, usedAt, createdAt)
	return &rec, nil
}

func scanTokenRow(rows *sql.Rows) (*TokenRecord, error) {
	var rec TokenRecord
	var expiresAt, usedAt, createdAt sql.NullString
	if err := rows.Scan(&rec.TokenID, &rec.Name, &rec.SecretHash,
		&expiresAt, &usedAt, &createdAt); err != nil {
		return nil, err
	}
	parseTokenTimes(&rec, expiresAt, usedAt, createdAt)
	return &rec, nil
}

func parseTokenTimes(rec *TokenRecord, expiresAt, usedAt, createdAt sql.NullString) {
	if expiresAt.Valid && expiresAt.String != "" {
		if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil {
			rec.ExpiresAt = t
		}
	}
	if usedAt.Valid && usedAt.String != "" {
		if t, err := time.Parse(time.RFC3339, usedAt.String); err == nil {
			rec.UsedAt = t
		}
	}
	if createdAt.Valid && createdAt.String != "" {
		if t, err := time.Parse(time.RFC3339, createdAt.String); err == nil {
			rec.CreatedAt = t
		}
	}
}

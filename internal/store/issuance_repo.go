package store

import (
	"context"
	"database/sql"
	"time"
)

// IssuanceStatus mirrors the issuance_status table: the outcome of the latest
// issuance attempt of one certificate. Zero times are stored as NULL.
type IssuanceStatus struct {
	Name          string
	Failures      int
	LastError     string
	LastAttemptAt time.Time
	NextAttemptAt time.Time
}

// IssuanceRepo provides CRUD for the issuance_status table.
type IssuanceRepo struct{ db *sql.DB }

func (r *IssuanceRepo) execer(tx *sql.Tx) interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

func (r *IssuanceRepo) queryer(tx *sql.Tx) interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

// Get returns the IssuanceStatus for name, or sql.ErrNoRows if not found.
func (r *IssuanceRepo) Get(ctx context.Context, name string, tx *sql.Tx) (*IssuanceStatus, error) {
	const q = `SELECT name,failures,last_error,last_attempt_at,next_attempt_at
	           FROM issuance_status WHERE name=?`
	row := r.queryer(tx).QueryRowContext(ctx, q, name)
	return scanIssuance(row)
}

// List returns all issuance status records.
func (r *IssuanceRepo) List(ctx context.Context, tx *sql.Tx) ([]*IssuanceStatus, error) {
	const q = `SELECT name,failures,last_error,last_attempt_at,next_attempt_at
	           FROM issuance_status ORDER BY name`
	rows, err := r.queryer(tx).QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*IssuanceStatus
	for rows.Next() {
		rec, err := scanIssuanceRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Upsert inserts or replaces the issuance status of rec.Name.
func (r *IssuanceRepo) Upsert(ctx context.Context, rec *IssuanceStatus, tx *sql.Tx) error {
	const q = `INSERT INTO issuance_status(name,failures,last_error,last_attempt_at,next_attempt_at)
	           VALUES(?,?,?,?,?)
	           ON CONFLICT(name) DO UPDATE SET
	             failures=excluded.failures, last_error=excluded.last_error,
	             last_attempt_at=excluded.last_attempt_at, next_attempt_at=excluded.next_attempt_at`
	_, err := r.execer(tx).ExecContext(ctx, q,
		rec.Name, rec.Failures, rec.LastError,
		nullTime(rec.LastAttemptAt), nullTime(rec.NextAttemptAt),
	)
	return err
}

// ClearBackoff resets the failure count and next attempt time of every
// certificate. The last error and last attempt time are kept.
func (r *IssuanceRepo) ClearBackoff(ctx context.Context, tx *sql.Tx) error {
	_, err := r.execer(tx).ExecContext(ctx, `UPDATE issuance_status SET failures=0, next_attempt_at=NULL`)
	return err
}

func scanIssuance(row *sql.Row) (*IssuanceStatus, error) {
	var rec IssuanceStatus
	var lastAttemptAt, nextAttemptAt sql.NullString
	if err := row.Scan(&rec.Name, &rec.Failures, &rec.LastError, &lastAttemptAt, &nextAttemptAt); err != nil {
		return nil, err
	}
	parseIssuanceTimes(&rec, lastAttemptAt, nextAttemptAt)
	return &rec, nil
}

func scanIssuanceRow(rows *sql.Rows) (*IssuanceStatus, error) {
	var rec IssuanceStatus
	var lastAttemptAt, nextAttemptAt sql.NullString
	if err := rows.Scan(&rec.Name, &rec.Failures, &rec.LastError, &lastAttemptAt, &nextAttemptAt); err != nil {
		return nil, err
	}
	parseIssuanceTimes(&rec, lastAttemptAt, nextAttemptAt)
	return &rec, nil
}

func parseIssuanceTimes(rec *IssuanceStatus, lastAttemptAt, nextAttemptAt sql.NullString) {
	if lastAttemptAt.Valid && lastAttemptAt.String != "" {
		if t, err := time.Parse(time.RFC3339, lastAttemptAt.String); err == nil {
			rec.LastAttemptAt = t
		}
	}
	if nextAttemptAt.Valid && nextAttemptAt.String != "" {
		if t, err := time.Parse(time.RFC3339, nextAttemptAt.String); err == nil {
			rec.NextAttemptAt = t
		}
	}
}

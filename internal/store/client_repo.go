package store

import (
	"context"
	"database/sql"
	"time"
)

// ClientRecord mirrors the clients table.
type ClientRecord struct {
	Name               string
	Fingerprint        string
	EnrolledAt         time.Time
	LastSeen           time.Time
	PendingFingerprint string
	PendingNotAfter    time.Time
}

// ClientRepo provides CRUD for the clients table.
type ClientRepo struct{ db *sql.DB }

func (r *ClientRepo) execer(tx *sql.Tx) interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

func (r *ClientRepo) queryer(tx *sql.Tx) interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
} {
	if tx != nil {
		return tx
	}
	return r.db
}

// Get returns the ClientRecord for name, or sql.ErrNoRows if not found.
func (r *ClientRepo) Get(ctx context.Context, name string, tx *sql.Tx) (*ClientRecord, error) {
	const q = `SELECT name,fingerprint,enrolled_at,last_seen,
	                  pending_fingerprint,pending_not_after
	           FROM clients WHERE name=?`
	row := r.queryer(tx).QueryRowContext(ctx, q, name)
	return scanClient(row)
}

// List returns all client records.
func (r *ClientRepo) List(ctx context.Context, tx *sql.Tx) ([]*ClientRecord, error) {
	const q = `SELECT name,fingerprint,enrolled_at,last_seen,
	                  pending_fingerprint,pending_not_after
	           FROM clients ORDER BY name`
	rows, err := r.queryer(tx).QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ClientRecord
	for rows.Next() {
		rec, err := scanClientRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Upsert inserts or replaces a client record.
func (r *ClientRepo) Upsert(ctx context.Context, rec *ClientRecord, tx *sql.Tx) error {
	const q = `INSERT INTO clients(name,fingerprint,enrolled_at,last_seen,
	                              pending_fingerprint,pending_not_after)
	           VALUES(?,?,?,?,?,?)
	           ON CONFLICT(name) DO UPDATE SET
	             fingerprint=excluded.fingerprint, enrolled_at=excluded.enrolled_at,
	             last_seen=excluded.last_seen,
	             pending_fingerprint=excluded.pending_fingerprint,
	             pending_not_after=excluded.pending_not_after`
	_, err := r.execer(tx).ExecContext(ctx, q,
		rec.Name, rec.Fingerprint,
		rec.EnrolledAt.UTC().Format(time.RFC3339),
		nullTime(rec.LastSeen),
		rec.PendingFingerprint, nullTime(rec.PendingNotAfter),
	)
	return err
}

// StagePendingIdentity records a newly issued client certificate without
// invalidating the currently active identity. The pending fingerprint is
// promoted on the first authenticated request that presents it.
func (r *ClientRepo) StagePendingIdentity(ctx context.Context, name, fingerprint string, notAfter time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE clients
		SET pending_fingerprint=?, pending_not_after=?
		WHERE name=?`, fingerprint, notAfter.UTC().Format(time.RFC3339), name)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// PromotePendingIdentity atomically activates fingerprint when it is still a
// valid pending identity. The previous active fingerprint is discarded.
func (r *ClientRepo) PromotePendingIdentity(ctx context.Context, name, fingerprint string, now time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE clients
		SET fingerprint=pending_fingerprint, pending_fingerprint='', pending_not_after=NULL
		WHERE name=? AND pending_fingerprint=? AND pending_not_after>?`,
		name, fingerprint, now.UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// MarkSeen records that the client name, authenticated with the certificate
// fingerprint, was seen at the given time. It is one conditional UPDATE, so it
// never recreates a concurrently removed client and never rewrites other
// columns such as a concurrently staged identity. It returns sql.ErrNoRows when
// no client has that name and active fingerprint.
func (r *ClientRepo) MarkSeen(ctx context.Context, name, fingerprint string, at time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE clients
		SET last_seen=?
		WHERE name=? AND fingerprint=?`,
		at.UTC().Format(time.RFC3339), name, fingerprint)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete removes a client by name, or returns sql.ErrNoRows if not found.
func (r *ClientRepo) Delete(ctx context.Context, name string, tx *sql.Tx) error {
	result, err := r.execer(tx).ExecContext(ctx, `DELETE FROM clients WHERE name=?`, name)
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

func scanClient(row *sql.Row) (*ClientRecord, error) {
	var rec ClientRecord
	var enrolledAt, lastSeen, pendingNotAfter sql.NullString
	if err := row.Scan(&rec.Name, &rec.Fingerprint, &enrolledAt, &lastSeen,
		&rec.PendingFingerprint, &pendingNotAfter); err != nil {
		return nil, err
	}
	parseClientTimes(&rec, enrolledAt, lastSeen, pendingNotAfter)
	return &rec, nil
}

func scanClientRow(rows *sql.Rows) (*ClientRecord, error) {
	var rec ClientRecord
	var enrolledAt, lastSeen, pendingNotAfter sql.NullString
	if err := rows.Scan(&rec.Name, &rec.Fingerprint, &enrolledAt, &lastSeen,
		&rec.PendingFingerprint, &pendingNotAfter); err != nil {
		return nil, err
	}
	parseClientTimes(&rec, enrolledAt, lastSeen, pendingNotAfter)
	return &rec, nil
}

func parseClientTimes(rec *ClientRecord, enrolledAt, lastSeen, pendingNotAfter sql.NullString) {
	if enrolledAt.Valid && enrolledAt.String != "" {
		if t, err := time.Parse(time.RFC3339, enrolledAt.String); err == nil {
			rec.EnrolledAt = t
		}
	}
	if lastSeen.Valid && lastSeen.String != "" {
		if t, err := time.Parse(time.RFC3339, lastSeen.String); err == nil {
			rec.LastSeen = t
		}
	}
	if pendingNotAfter.Valid && pendingNotAfter.String != "" {
		if t, err := time.Parse(time.RFC3339, pendingNotAfter.String); err == nil {
			rec.PendingNotAfter = t
		}
	}
}

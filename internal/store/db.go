package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Oganneson-Studio/sigil/internal/securefile"
	_ "modernc.org/sqlite"
)

const currentSchemaVersion = 5

// DB wraps *sql.DB and exposes typed repositories.
type DB struct {
	db       *sql.DB
	Certs    *CertRepo
	Clients  *ClientRepo
	Tokens   *TokenRepo
	Accounts *AccountRepo
	Issuance *IssuanceRepo
}

// Open opens (or creates) the SQLite database at dsn, runs auto-migration,
// and returns a ready-to-use *DB. dsn is a file path, optionally followed by
// "?" and connection parameters, or ":memory:" for in-process tests.
func Open(dsn string) (*DB, error) {
	path, _, _ := strings.Cut(dsn, "?")
	if path == ":memory:" {
		path = ""
	}
	if err := prepareDatabaseFiles(path); err != nil {
		return nil, fmt.Errorf("prepare sqlite %s: %w", dsn, err)
	}

	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dsn, err)
	}
	raw.SetMaxOpenConns(1) // sqlite write serialization
	if _, err := raw.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("pragma: %w", err)
	}
	if err := migrate(raw); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// SQLite has created -wal and -shm by now. On Windows they inherit the
	// DACL of the directory; this gives them a protected one.
	if err := protectSQLiteFiles(path); err != nil {
		_ = raw.Close()
		return nil, err
	}
	d := &DB{db: raw}
	d.Certs = &CertRepo{db: raw}
	d.Clients = &ClientRepo{db: raw}
	d.Tokens = &TokenRepo{db: raw}
	d.Accounts = &AccountRepo{db: raw}
	d.Issuance = &IssuanceRepo{db: raw}
	return d, nil
}

// prepareDatabaseFiles avoids creating the database at path with
// SQLite's process-default permissions, and protects the files of an existing
// one again. An in-memory database, whose path is empty, has no files.
func prepareDatabaseFiles(path string) error {
	if path == "" {
		return nil
	}
	if err := prepareSQLiteDirectory(path); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return protectSQLiteFiles(path)
}

// prepareSQLiteDirectory creates the directory of the database at
// databasePath private when it does not exist, and refuses one that is not.
// SQLite deletes -wal and -shm and creates them again as connections close
// and open, long after Open has protected them, and on Windows they inherit
// the DACL of the directory. An existing directory is not changed: it may be
// one like /var/lib or C:\ProgramData, and on Windows the change would reach
// everything in it.
func prepareSQLiteDirectory(databasePath string) error {
	dir := filepath.Dir(databasePath)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := securefile.EnsurePrivateDirectory(dir); err != nil {
			return fmt.Errorf("create sqlite directory %s: %w", dir, err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect sqlite directory %s: %w", dir, err)
	}
	// Also after creating it: another account may have created it first.
	if err := securefile.CheckPrivateDirectory(dir); err != nil {
		return fmt.Errorf("%w. Or remove it for sigils to create it again", err)
	}
	return nil
}

// protectSQLiteFiles protects the database at databasePath, and those of its
// -wal, -shm and -journal files that exist. An empty path is an in-memory
// database.
func protectSQLiteFiles(databasePath string) error {
	if databasePath == "" {
		return nil
	}
	if err := securefile.ProtectFile(databasePath); err != nil {
		return fmt.Errorf("protect sqlite file %s: %w", databasePath, err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		path := databasePath + suffix
		if err := securefile.ProtectFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("protect sqlite file %s: %w", path, err)
		}
	}
	return nil
}

// Close releases underlying database resources.
func (d *DB) Close() error { return d.db.Close() }

// BeginTx starts a transaction. Pass the returned *sql.Tx to repo methods
// that accept it.
func (d *DB) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return d.db.BeginTx(ctx, nil)
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var ver int
	err := db.QueryRow(`SELECT version FROM schema_version LIMIT 1`).Scan(&ver)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	// Migrations only go forward; this binary cannot know what a newer one
	// changed.
	if ver > currentSchemaVersion {
		return fmt.Errorf("the database has schema version %d, newer than version %d that this sigils knows: a newer sigils has upgraded it, and upgrades cannot be undone", ver, currentSchemaVersion)
	}
	for ver < currentSchemaVersion {
		ver++
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := applyMigration(tx, ver); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration v%d: %w", ver, err)
		}
		if _, err := tx.Exec(`DELETE FROM schema_version; INSERT INTO schema_version(version) VALUES (?)`, ver); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

type migrationExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func applyMigration(db migrationExecer, ver int) error {
	switch ver {
	case 1:
		_, err := db.Exec(schemav1)
		return err
	case 2:
		_, err := db.Exec(`
ALTER TABLE clients ADD COLUMN pending_fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN pending_not_after DATETIME;
`)
		return err
	case 3:
		_, err := db.Exec(`
ALTER TABLE certificates ADD COLUMN spec_fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE acme_accounts ADD COLUMN directory TEXT NOT NULL DEFAULT '';
`)
		return err
	case 4:
		_, err := db.Exec(`
CREATE TABLE issuance_status (
    name            TEXT    PRIMARY KEY,
    failures        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT '',
    last_attempt_at DATETIME,
    next_attempt_at DATETIME
);
`)
		return err
	case 5:
		_, err := db.Exec(`
ALTER TABLE clients DROP COLUMN push_endpoint;
ALTER TABLE clients DROP COLUMN push_token;
`)
		return err
	default:
		return fmt.Errorf("unknown migration version %d", ver)
	}
}

const schemav1 = `
CREATE TABLE IF NOT EXISTS certificates (
    name          TEXT    PRIMARY KEY,
    ca            TEXT    NOT NULL,
    domains_json  TEXT    NOT NULL DEFAULT '[]',
    fullchain_pem TEXT    NOT NULL DEFAULT '',
    key_pem       TEXT    NOT NULL DEFAULT '',
    not_after     DATETIME,
    fingerprint   TEXT    NOT NULL DEFAULT '',
    issued_at     DATETIME,
    updated_at    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS clients (
    name          TEXT    PRIMARY KEY,
    fingerprint   TEXT    NOT NULL UNIQUE,
    enrolled_at   DATETIME NOT NULL,
    last_seen     DATETIME,
    push_endpoint TEXT    NOT NULL DEFAULT '',
    push_token    TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_id    TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL,
    secret_hash TEXT    NOT NULL,
    expires_at  DATETIME NOT NULL,
    used_at     DATETIME,
    created_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS acme_accounts (
    ca                TEXT PRIMARY KEY,
    email             TEXT NOT NULL,
    key_pem           TEXT NOT NULL DEFAULT '',
    registration_json TEXT NOT NULL DEFAULT ''
);
`

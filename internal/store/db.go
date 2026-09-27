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

const currentSchemaVersion = 3

// DB wraps *sql.DB and exposes typed repositories.
type DB struct {
	db       *sql.DB
	Certs    *CertRepo
	Clients  *ClientRepo
	Tokens   *TokenRepo
	Accounts *AccountRepo
}

// Open opens (or creates) the SQLite database at dsn, runs auto-migration,
// and returns a ready-to-use *DB. Use ":memory:" for in-process tests.
func Open(dsn string) (*DB, error) {
	if err := preparePlainDatabaseFiles(dsn); err != nil {
		return nil, fmt.Errorf("prepare sqlite %s: %w", dsn, err)
	}

	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dsn, err)
	}
	raw.SetMaxOpenConns(1) // sqlite write serialization
	databasePath, err := mainDatabasePath(raw)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("resolve sqlite path: %w", err)
	}
	if err := prepareSQLiteDirectory(databasePath); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := protectSQLiteFile(databasePath); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if _, err := raw.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("pragma: %w", err)
	}
	if err := migrate(raw); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := protectSQLiteFiles(databasePath); err != nil {
		_ = raw.Close()
		return nil, err
	}
	d := &DB{db: raw}
	d.Certs = &CertRepo{db: raw}
	d.Clients = &ClientRepo{db: raw}
	d.Tokens = &TokenRepo{db: raw}
	d.Accounts = &AccountRepo{db: raw}
	return d, nil
}

// preparePlainDatabaseFiles avoids creating a regular filename with SQLite's
// process-default permissions. URI filenames are resolved and protected after
// the connection opens; in-memory databases do not have files to protect.
func preparePlainDatabaseFiles(dsn string) error {
	if strings.HasPrefix(dsn, "file:") {
		return nil
	}
	path, _, _ := strings.Cut(dsn, "?")
	if path == "" || path == ":memory:" {
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

func prepareSQLiteDirectory(databasePath string) error {
	if databasePath == "" {
		return nil
	}
	dir := filepath.Clean(filepath.Dir(databasePath))
	if dir == "." || filepath.Dir(dir) == dir {
		return nil
	}
	if info, err := os.Stat(dir); err == nil {
		// Shared temporary directories must retain their sticky-bit semantics.
		if info.Mode()&os.ModeSticky != 0 {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect sqlite directory %s: %w", dir, err)
	}
	if err := securefile.EnsurePrivateDirectory(dir); err != nil {
		return fmt.Errorf("protect sqlite directory %s: %w", dir, err)
	}
	return nil
}

func mainDatabasePath(db *sql.DB) (string, error) {
	var seq int
	var name, path string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		return "", err
	}
	if name != "main" {
		return "", fmt.Errorf("first database is %q, want main", name)
	}
	return path, nil
}

func protectSQLiteFiles(databasePath string) error {
	if databasePath == "" {
		return nil
	}
	if err := protectSQLiteFile(databasePath); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		path := databasePath + suffix
		if err := securefile.ProtectFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("protect sqlite file %s: %w", path, err)
		}
	}
	return nil
}

func protectSQLiteFile(path string) error {
	if path == "" {
		return nil
	}
	if err := securefile.ProtectFile(path); err != nil {
		return fmt.Errorf("protect sqlite file %s: %w", path, err)
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

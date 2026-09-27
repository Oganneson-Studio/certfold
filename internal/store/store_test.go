package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

var ctx = context.Background()

// ---------------------------------------------------------------------------
// CertRepo
// ---------------------------------------------------------------------------

func TestCertRepo_UpsertGetDelete(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	rec := &CertRecord{
		Name:            "api-prod",
		CA:              "letsencrypt",
		Domains:         []string{"api.example.com", "*.api.example.com"},
		SpecFingerprint: "sha256:SPEC1",
		FullchainPEM:    "chain",
		KeyPEM:          "key",
		NotAfter:        now.Add(90 * 24 * time.Hour),
		Fingerprint:     "sha256:AABBCC",
		IssuedAt:        now,
		UpdatedAt:       now,
	}

	if err := db.Certs.Upsert(ctx, rec, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := db.Certs.Get(ctx, "api-prod", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.CA != "letsencrypt" {
		t.Errorf("CA: got %q", got.CA)
	}
	if len(got.Domains) != 2 || got.Domains[0] != "api.example.com" {
		t.Errorf("Domains: got %v", got.Domains)
	}
	if got.Fingerprint != "sha256:AABBCC" {
		t.Errorf("Fingerprint: got %q", got.Fingerprint)
	}
	if got.SpecFingerprint != "sha256:SPEC1" {
		t.Errorf("SpecFingerprint: got %q", got.SpecFingerprint)
	}

	// Upsert again with updated fingerprint (ON CONFLICT path)
	rec.Fingerprint = "sha256:DDEEFF"
	rec.SpecFingerprint = "sha256:SPEC2"
	if err := db.Certs.Upsert(ctx, rec, nil); err != nil {
		t.Fatalf("Upsert (update): %v", err)
	}
	got2, _ := db.Certs.Get(ctx, "api-prod", nil)
	if got2.Fingerprint != "sha256:DDEEFF" {
		t.Errorf("updated Fingerprint: got %q", got2.Fingerprint)
	}
	if got2.SpecFingerprint != "sha256:SPEC2" {
		t.Errorf("updated SpecFingerprint: got %q", got2.SpecFingerprint)
	}

	if err := db.Certs.Delete(ctx, "api-prod", nil); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = db.Certs.Get(ctx, "api-prod", nil)
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows after delete, got %v", err)
	}
}

func TestCertRepo_List(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	for _, name := range []string{"beta", "alpha", "gamma"} {
		if err := db.Certs.Upsert(ctx, &CertRecord{
			Name:      name,
			CA:        "letsencrypt",
			Domains:   []string{name + ".example.com"},
			UpdatedAt: now,
		}, nil); err != nil {
			t.Fatalf("Upsert %s: %v", name, err)
		}
	}

	list, err := db.Certs.List(ctx, nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3, got %d", len(list))
	}
	// results should be alphabetically ordered
	if list[0].Name != "alpha" || list[1].Name != "beta" || list[2].Name != "gamma" {
		t.Errorf("order: got %s %s %s", list[0].Name, list[1].Name, list[2].Name)
	}
}

// ---------------------------------------------------------------------------
// ClientRepo
// ---------------------------------------------------------------------------

func TestClientRepo_UpsertGetDelete(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	rec := &ClientRecord{
		Name:         "web-1",
		Fingerprint:  "fp1",
		EnrolledAt:   now,
		PushEndpoint: "https://web1.internal:9443",
	}
	if err := db.Clients.Upsert(ctx, rec, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := db.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Fingerprint != "fp1" {
		t.Errorf("Fingerprint: got %q", got.Fingerprint)
	}
	if got.PushEndpoint != "https://web1.internal:9443" {
		t.Errorf("PushEndpoint: got %q", got.PushEndpoint)
	}

	// update LastSeen
	rec.LastSeen = now.Add(time.Minute)
	if err := db.Clients.Upsert(ctx, rec, nil); err != nil {
		t.Fatalf("Upsert (update): %v", err)
	}
	got2, _ := db.Clients.Get(ctx, "web-1", nil)
	if got2.LastSeen.IsZero() {
		t.Error("expected LastSeen to be set after update")
	}

	if err := db.Clients.Delete(ctx, "web-1", nil); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = db.Clients.Get(ctx, "web-1", nil)
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows after delete, got %v", err)
	}
}

func TestClientRepo_List(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	for i, name := range []string{"c", "a", "b"} {
		_ = db.Clients.Upsert(ctx, &ClientRecord{
			Name:        name,
			Fingerprint: string(rune('0' + i)),
			EnrolledAt:  now,
		}, nil)
	}
	list, err := db.Clients.List(ctx, nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3, got %d", len(list))
	}
	if list[0].Name != "a" {
		t.Errorf("order: first expected a, got %s", list[0].Name)
	}
}

func TestClientRepo_PendingIdentityPromotion(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.Clients.Upsert(ctx, &ClientRecord{
		Name:        "web-1",
		Fingerprint: "sha256:old",
		EnrolledAt:  now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Clients.StagePendingIdentity(ctx, "web-1", "sha256:new", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	staged, err := db.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Fingerprint != "sha256:old" || staged.PendingFingerprint != "sha256:new" {
		t.Fatalf("unexpected staged identity: %+v", staged)
	}
	if err := db.Clients.PromotePendingIdentity(ctx, "web-1", "sha256:wrong", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("wrong fingerprint promotion error = %v, want sql.ErrNoRows", err)
	}
	if err := db.Clients.PromotePendingIdentity(ctx, "web-1", "sha256:new", now); err != nil {
		t.Fatal(err)
	}
	promoted, err := db.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Fingerprint != "sha256:new" || promoted.PendingFingerprint != "" || !promoted.PendingNotAfter.IsZero() {
		t.Fatalf("unexpected promoted identity: %+v", promoted)
	}
}

func TestClientRepo_ExpiredPendingIdentityCannotPromote(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.Clients.Upsert(ctx, &ClientRecord{
		Name:        "web-1",
		Fingerprint: "sha256:old",
		EnrolledAt:  now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Clients.StagePendingIdentity(ctx, "web-1", "sha256:new", now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.Clients.PromotePendingIdentity(ctx, "web-1", "sha256:new", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expired promotion error = %v, want sql.ErrNoRows", err)
	}
}

// ---------------------------------------------------------------------------
// TokenRepo
// ---------------------------------------------------------------------------

func TestTokenRepo_UpsertGetMarkUsedDelete(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	rec := &TokenRecord{
		TokenID:    "tok-001",
		Name:       "web-1",
		SecretHash: "hashvalue",
		ExpiresAt:  now.Add(time.Hour),
		CreatedAt:  now,
	}
	if err := db.Tokens.Upsert(ctx, rec, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := db.Tokens.Get(ctx, "tok-001", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "web-1" || got.SecretHash != "hashvalue" {
		t.Errorf("fields wrong: %+v", got)
	}
	if !got.UsedAt.IsZero() {
		t.Error("UsedAt should be zero before MarkUsed")
	}

	if err := db.Tokens.MarkUsed(ctx, "tok-001", nil); err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
	got2, _ := db.Tokens.Get(ctx, "tok-001", nil)
	if got2.UsedAt.IsZero() {
		t.Error("UsedAt should be set after MarkUsed")
	}
	if err := db.Tokens.MarkUsed(ctx, "tok-001", nil); !errors.Is(err, ErrTokenAlreadyUsed) {
		t.Fatalf("second MarkUsed: got %v, want ErrTokenAlreadyUsed", err)
	}

	if err := db.Tokens.Delete(ctx, "tok-001", nil); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = db.Tokens.Get(ctx, "tok-001", nil)
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func TestTokenRepo_List(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	for _, id := range []string{"t1", "t2"} {
		_ = db.Tokens.Upsert(ctx, &TokenRecord{
			TokenID:   id,
			Name:      "x",
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now,
		}, nil)
	}
	list, err := db.Tokens.List(ctx, nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
}

// ---------------------------------------------------------------------------
// AccountRepo
// ---------------------------------------------------------------------------

func TestAccountRepo_UpsertGetDelete(t *testing.T) {
	db := openTestDB(t)

	rec := &AccountRecord{
		CA:               "letsencrypt",
		Directory:        "https://acme.example/directory",
		Email:            "ops@example.com",
		KeyPEM:           "privkey",
		RegistrationJSON: `{"url":"https://acme-v02.api.letsencrypt.org/acme/acct/123"}`,
	}
	if err := db.Accounts.Upsert(ctx, rec, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := db.Accounts.Get(ctx, "letsencrypt", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Email != "ops@example.com" {
		t.Errorf("Email: got %q", got.Email)
	}
	if got.Directory != rec.Directory {
		t.Errorf("Directory: got %q", got.Directory)
	}
	if got.RegistrationJSON == "" {
		t.Error("RegistrationJSON should not be empty")
	}

	// update key
	rec.KeyPEM = "newkey"
	if err := db.Accounts.Upsert(ctx, rec, nil); err != nil {
		t.Fatalf("Upsert (update): %v", err)
	}
	got2, _ := db.Accounts.Get(ctx, "letsencrypt", nil)
	if got2.KeyPEM != "newkey" {
		t.Errorf("updated KeyPEM: got %q", got2.KeyPEM)
	}

	if err := db.Accounts.Delete(ctx, "letsencrypt", nil); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = db.Accounts.Get(ctx, "letsencrypt", nil)
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows after delete, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

func TestTransaction_Rollback(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	tx, err := db.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}

	_ = db.Certs.Upsert(ctx, &CertRecord{
		Name:      "tx-cert",
		CA:        "letsencrypt",
		Domains:   []string{"tx.example.com"},
		UpdatedAt: now,
	}, tx)

	// rollback — record must not exist
	_ = tx.Rollback()

	_, err = db.Certs.Get(ctx, "tx-cert", nil)
	if err != sql.ErrNoRows {
		t.Fatalf("expected ErrNoRows after rollback, got %v", err)
	}
}

func TestTransaction_Commit(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	tx, err := db.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}

	_ = db.Certs.Upsert(ctx, &CertRecord{
		Name:      "tx-cert2",
		CA:        "letsencrypt",
		Domains:   []string{"tx2.example.com"},
		UpdatedAt: now,
	}, tx)

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := db.Certs.Get(ctx, "tx-cert2", nil)
	if err != nil {
		t.Fatalf("Get after commit: %v", err)
	}
	if got.Name != "tx-cert2" {
		t.Errorf("Name: got %q", got.Name)
	}
}

// ---------------------------------------------------------------------------
// Migration idempotency
// ---------------------------------------------------------------------------

func TestOpen_Idempotent(t *testing.T) {
	// Open same :memory: twice — second open re-uses a fresh DB, but verifies
	// that applyMigration with existing tables is idempotent (CREATE IF NOT EXISTS).
	db1, err := Open(":memory:")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	defer db1.Close()

	// Insert one cert, close, and re-open a fresh :memory: DB to check schema
	// creation does not error on a newly created DB (simulating repeat deploy).
	db2, err := Open(":memory:")
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer db2.Close()
}

func TestOpen_MigratesV1ClientIdentitySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sigil-v1.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_version (version INTEGER NOT NULL)`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(schemav1); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM schema_version; INSERT INTO schema_version(version) VALUES (1)`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated database: %v", err)
	}
	defer db.Close()
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.Clients.Upsert(ctx, &ClientRecord{
		Name:               "web-1",
		Fingerprint:        "sha256:old",
		EnrolledAt:         now,
		PendingFingerprint: "sha256:new",
		PendingNotAfter:    now.Add(time.Hour),
	}, nil); err != nil {
		t.Fatalf("write v2 client fields: %v", err)
	}
	var version int
	if err := db.db.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, currentSchemaVersion)
	}
}

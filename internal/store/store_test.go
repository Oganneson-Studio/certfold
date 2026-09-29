package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
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

func TestCertRepo_UpsertGet(t *testing.T) {
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

	if _, err := db.Certs.Get(ctx, "api-stage", nil); err != sql.ErrNoRows {
		t.Fatalf("Get of a missing certificate: error = %v, want sql.ErrNoRows", err)
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
		Name:        "web-1",
		Fingerprint: "fp1",
		EnrolledAt:  now,
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

func TestClientRepo_MarkSeenTouchesOnlyMatchingIdentity(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.Clients.Upsert(ctx, &ClientRecord{
		Name:        "web-1",
		Fingerprint: "sha256:active",
		EnrolledAt:  now.Add(-time.Hour),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Clients.StagePendingIdentity(ctx, "web-1", "sha256:pending", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := db.Clients.MarkSeen(ctx, "web-1", "sha256:pending", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("mark seen with a non-active fingerprint: error = %v, want sql.ErrNoRows", err)
	}
	if err := db.Clients.MarkSeen(ctx, "web-2", "sha256:active", now); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("mark seen for a missing client: error = %v, want sql.ErrNoRows", err)
	}
	if _, err := db.Clients.Get(ctx, "web-2", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("mark seen created a client: Get error = %v", err)
	}

	if err := db.Clients.MarkSeen(ctx, "web-1", "sha256:active", now); err != nil {
		t.Fatalf("MarkSeen: %v", err)
	}
	got, err := db.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", got.LastSeen, now)
	}
	if got.Fingerprint != "sha256:active" || got.PendingFingerprint != "sha256:pending" ||
		!got.PendingNotAfter.Equal(now.Add(time.Hour)) || !got.EnrolledAt.Equal(now.Add(-time.Hour)) {
		t.Fatalf("MarkSeen changed more than last_seen: %+v", got)
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

func TestAccountRepo_UpsertGet(t *testing.T) {
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

	if _, err := db.Accounts.Get(ctx, "zerossl", nil); err != sql.ErrNoRows {
		t.Fatalf("Get of a missing account: error = %v, want sql.ErrNoRows", err)
	}
}

// ---------------------------------------------------------------------------
// IssuanceRepo
// ---------------------------------------------------------------------------

func TestIssuanceRepo_UpsertGetList(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := db.Issuance.Get(ctx, "api-prod", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Get before Upsert: error = %v, want sql.ErrNoRows", err)
	}

	failed := &IssuanceStatus{
		Name:          "api-prod",
		Failures:      2,
		LastError:     "obtain certificate: rate limited",
		LastAttemptAt: now,
		NextAttemptAt: now.Add(10 * time.Minute),
	}
	if err := db.Issuance.Upsert(ctx, failed, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := db.Issuance.Get(ctx, "api-prod", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != failed.Name || got.Failures != failed.Failures || got.LastError != failed.LastError ||
		!got.LastAttemptAt.Equal(failed.LastAttemptAt) || !got.NextAttemptAt.Equal(failed.NextAttemptAt) {
		t.Fatalf("Get = %+v, want %+v", got, failed)
	}

	// Upsert again (ON CONFLICT path) with a zero NextAttemptAt, then add a
	// record that has never been attempted.
	succeeded := &IssuanceStatus{Name: "api-prod", LastAttemptAt: now.Add(time.Hour)}
	if err := db.Issuance.Upsert(ctx, succeeded, nil); err != nil {
		t.Fatalf("Upsert (update): %v", err)
	}
	if err := db.Issuance.Upsert(ctx, &IssuanceStatus{Name: "alpha"}, nil); err != nil {
		t.Fatalf("Upsert alpha: %v", err)
	}

	list, err := db.Issuance.List(ctx, nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 || list[0].Name != "alpha" || list[1].Name != "api-prod" {
		t.Fatalf("List = %+v, want alpha then api-prod", list)
	}
	if list[0].Failures != 0 || list[0].LastError != "" || !list[0].LastAttemptAt.IsZero() || !list[0].NextAttemptAt.IsZero() {
		t.Errorf("alpha = %+v, want zero values", list[0])
	}
	if list[1].Failures != 0 || list[1].LastError != "" ||
		!list[1].LastAttemptAt.Equal(succeeded.LastAttemptAt) || !list[1].NextAttemptAt.IsZero() {
		t.Errorf("updated api-prod = %+v, want %+v", list[1], succeeded)
	}

	// Zero times are stored as NULL, not as a formatted zero timestamp.
	for _, tc := range []struct {
		name, column string
	}{
		{"alpha", "last_attempt_at"},
		{"alpha", "next_attempt_at"},
		{"api-prod", "next_attempt_at"},
	} {
		var isNull bool
		if err := db.db.QueryRow(`SELECT `+tc.column+` IS NULL FROM issuance_status WHERE name=?`, tc.name).Scan(&isNull); err != nil {
			t.Fatalf("%s.%s: %v", tc.name, tc.column, err)
		}
		if !isNull {
			t.Errorf("%s.%s is not NULL", tc.name, tc.column)
		}
	}
}

func TestIssuanceRepo_ClearBackoffKeepsLastAttempt(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	records := []*IssuanceStatus{
		{Name: "api-prod", Failures: 3, LastError: "dns: timeout", LastAttemptAt: now, NextAttemptAt: now.Add(20 * time.Minute)},
		{Name: "internal", Failures: 1, LastError: "acme: unauthorized", LastAttemptAt: now.Add(-time.Minute), NextAttemptAt: now.Add(4 * time.Minute)},
	}
	for _, rec := range records {
		if err := db.Issuance.Upsert(ctx, rec, nil); err != nil {
			t.Fatalf("Upsert %s: %v", rec.Name, err)
		}
	}

	if err := db.Issuance.ClearBackoff(ctx, nil); err != nil {
		t.Fatalf("ClearBackoff: %v", err)
	}

	for _, want := range records {
		got, err := db.Issuance.Get(ctx, want.Name, nil)
		if err != nil {
			t.Fatalf("Get %s: %v", want.Name, err)
		}
		if got.Failures != 0 || !got.NextAttemptAt.IsZero() {
			t.Errorf("%s backoff not cleared: %+v", want.Name, got)
		}
		if got.LastError != want.LastError || !got.LastAttemptAt.Equal(want.LastAttemptAt) {
			t.Errorf("%s last attempt changed: got %+v, want error %q at %v", want.Name, got, want.LastError, want.LastAttemptAt)
		}
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

func TestOpen_MigratesV3IssuanceStatusSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sigil-v3.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_version (version INTEGER NOT NULL)`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	for ver := 1; ver <= 3; ver++ {
		if err := applyMigration(raw, ver); err != nil {
			_ = raw.Close()
			t.Fatalf("migration v%d: %v", ver, err)
		}
	}
	if _, err := raw.Exec(`DELETE FROM schema_version; INSERT INTO schema_version(version) VALUES (3);
		INSERT INTO certificates(name,ca,spec_fingerprint) VALUES ('api-prod','letsencrypt','sha256:SPEC')`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	checkVersion := func(db *DB) {
		t.Helper()
		var version int
		if err := db.db.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		if version != currentSchemaVersion {
			t.Fatalf("schema version = %d, want %d", version, currentSchemaVersion)
		}
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated database: %v", err)
	}
	checkVersion(db)
	cert, err := db.Certs.Get(ctx, "api-prod", nil)
	if err != nil {
		t.Fatalf("v3 certificate after migration: %v", err)
	}
	if cert.SpecFingerprint != "sha256:SPEC" {
		t.Errorf("v3 certificate after migration: %+v", cert)
	}
	now := time.Now().UTC().Truncate(time.Second)
	want := &IssuanceStatus{Name: "api-prod", Failures: 1, LastError: "boom", LastAttemptAt: now, NextAttemptAt: now.Add(5 * time.Minute)}
	if err := db.Issuance.Upsert(ctx, want, nil); err != nil {
		t.Fatalf("write v4 issuance status: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Opening the migrated database again applies no migration.
	db, err = Open(path)
	if err != nil {
		t.Fatalf("reopen migrated database: %v", err)
	}
	defer db.Close()
	checkVersion(db)
	got, err := db.Issuance.Get(ctx, "api-prod", nil)
	if err != nil {
		t.Fatalf("issuance status after reopen: %v", err)
	}
	if got.Failures != want.Failures || got.LastError != want.LastError ||
		!got.LastAttemptAt.Equal(want.LastAttemptAt) || !got.NextAttemptAt.Equal(want.NextAttemptAt) {
		t.Errorf("issuance status after reopen = %+v, want %+v", got, want)
	}
}

// Migration v5 drops the push columns of clients, which nothing reads since
// the server stopped pushing, and keeps every client with the rest of its
// record.
func TestOpen_MigratesV4DropsClientPushColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sigil-v4.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_version (version INTEGER NOT NULL)`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	for ver := 1; ver <= 4; ver++ {
		if err := applyMigration(raw, ver); err != nil {
			_ = raw.Close()
			t.Fatalf("migration v%d: %v", ver, err)
		}
	}
	if _, err := raw.Exec(`DELETE FROM schema_version; INSERT INTO schema_version(version) VALUES (4);
		INSERT INTO clients(name,fingerprint,enrolled_at,last_seen,push_endpoint,push_token,pending_fingerprint,pending_not_after) VALUES
		('web-1','sha256:web-1','2026-01-02T03:04:05Z','2026-02-03T04:05:06Z',
		 'https://web-1.example.com/v1/push/notify','0123456789abcdef0123456789abcdef','sha256:renewed','2026-03-04T05:06:07Z'),
		('web-2','sha256:web-2','2026-01-02T03:04:05Z',NULL,'','','',NULL)`); err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	enrolledAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	want := []ClientRecord{
		{
			Name: "web-1", Fingerprint: "sha256:web-1", EnrolledAt: enrolledAt,
			LastSeen:           time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
			PendingFingerprint: "sha256:renewed",
			PendingNotAfter:    time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		},
		{Name: "web-2", Fingerprint: "sha256:web-2", EnrolledAt: enrolledAt},
	}
	check := func(db *DB) {
		t.Helper()
		var version int
		if err := db.db.QueryRow(`SELECT version FROM schema_version`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		if version != currentSchemaVersion {
			t.Fatalf("schema version = %d, want %d", version, currentSchemaVersion)
		}

		rows, err := db.db.Query(`PRAGMA table_info(clients)`)
		if err != nil {
			t.Fatal(err)
		}
		var columns []string
		for rows.Next() {
			var cid, notNull, pk int
			var name, typ string
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			columns = append(columns, name)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if wantColumns := []string{"name", "fingerprint", "enrolled_at", "last_seen", "pending_fingerprint", "pending_not_after"}; !slices.Equal(columns, wantColumns) {
			t.Fatalf("clients columns = %v, want %v", columns, wantColumns)
		}

		clients, err := db.Clients.List(ctx, nil)
		if err != nil {
			t.Fatalf("list clients: %v", err)
		}
		if len(clients) != len(want) {
			t.Fatalf("clients after migration = %d, want %d", len(clients), len(want))
		}
		for i, got := range clients {
			w := want[i]
			if got.Name != w.Name || got.Fingerprint != w.Fingerprint || !got.EnrolledAt.Equal(w.EnrolledAt) ||
				!got.LastSeen.Equal(w.LastSeen) || got.PendingFingerprint != w.PendingFingerprint ||
				!got.PendingNotAfter.Equal(w.PendingNotAfter) {
				t.Errorf("client after migration = %+v, want %+v", *got, w)
			}
		}
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated database: %v", err)
	}
	check(db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Opening the migrated database again applies no migration.
	db, err = Open(path)
	if err != nil {
		t.Fatalf("reopen migrated database: %v", err)
	}
	defer db.Close()
	check(db)
}

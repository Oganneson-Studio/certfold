package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

// TestDeleteReportsMissingRecord covers removing a client or an enrollment
// token that does not exist, such as a mistyped name: Delete returns
// sql.ErrNoRows rather than report a removal, and the records that exist
// stay. Removing a record twice finds nothing the second time.
func TestDeleteReportsMissingRecord(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := db.Clients.Upsert(ctx, &ClientRecord{Name: "web-1", Fingerprint: "fp1", EnrolledAt: now}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Tokens.Upsert(ctx, &TokenRecord{
		TokenID:   "tok-001",
		Name:      "web-2",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}

	if err := db.Clients.Delete(ctx, "web-9", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Delete of a missing client: error = %v, want sql.ErrNoRows", err)
	}
	if err := db.Tokens.Delete(ctx, "tok-009", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Delete of a missing token: error = %v, want sql.ErrNoRows", err)
	}
	if _, err := db.Clients.Get(ctx, "web-1", nil); err != nil {
		t.Fatalf("Get of the client that exists: %v", err)
	}
	if _, err := db.Tokens.Get(ctx, "tok-001", nil); err != nil {
		t.Fatalf("Get of the token that exists: %v", err)
	}

	if err := db.Clients.Delete(ctx, "web-1", nil); err != nil {
		t.Fatalf("Delete of the client: %v", err)
	}
	if err := db.Clients.Delete(ctx, "web-1", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("second Delete of the client: error = %v, want sql.ErrNoRows", err)
	}
	if err := db.Tokens.Delete(ctx, "tok-001", nil); err != nil {
		t.Fatalf("Delete of the token: %v", err)
	}
	if err := db.Tokens.Delete(ctx, "tok-001", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("second Delete of the token: error = %v, want sql.ErrNoRows", err)
	}
}

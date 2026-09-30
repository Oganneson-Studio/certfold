package scheduler

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/store"
)

// An issued certificate is stored together with its issuance status or not at
// all: when the status cannot be written, the certificate is not stored and
// the stored callback does not run.
func TestCertificateIsNotStoredWithoutItsStatus(t *testing.T) {
	// A directory that store.Open creates: it refuses one that is not private.
	path := filepath.Join(t.TempDir(), "data", "sigils.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// A second connection makes every new issuance status fail to insert.
	other, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	if _, err := other.Exec(`CREATE TRIGGER refuse_status BEFORE INSERT ON issuance_status
BEGIN SELECT RAISE(ABORT, 'status write refused'); END`); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	mi := &mockIssuer{result: successResult(t, now.Add(90*24*time.Hour))}
	r := New(mi, db, func() { calls.Add(1) }, func() time.Time { return now })

	// RenewNamed rather than a tick: a call inside the transaction that is not
	// given it waits forever, which receive turns into a failure.
	renewed := renewAsync(context.Background(), r, static(minimalCfg("api-prod", nil)), "api-prod")
	if err := receive(t, renewed, "RenewNamed"); err == nil || !strings.Contains(err.Error(), "status write refused") {
		t.Fatalf("RenewNamed error = %v, want the refused status write", err)
	}
	if mi.calls != 1 {
		t.Fatalf("Issue calls = %d, want 1", mi.calls)
	}
	assertNoCert(t, db, "api-prod")
	if got := calls.Load(); got != 0 {
		t.Fatalf("stored calls = %d, want 0", got)
	}
}

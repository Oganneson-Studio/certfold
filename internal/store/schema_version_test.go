package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// A database that a newer sigils migrated past currentSchemaVersion is
// refused, not used as if it had this binary's schema.
func TestOpenRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(privateDirectory(t), "sigils.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	newer := currentSchemaVersion + 1
	if _, err := db.db.Exec(`UPDATE schema_version SET version=?`, newer); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(path)
	if err == nil {
		_ = db.Close()
		t.Fatalf("Open accepted a database at schema version %d; this binary knows up to %d", newer, currentSchemaVersion)
	}
	want := fmt.Sprintf("schema version %d, newer than version %d", newer, currentSchemaVersion)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Open error = %v, want one naming both versions (%s)", err, want)
	}
}

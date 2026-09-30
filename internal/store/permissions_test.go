package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenProtectsSQLiteFiles(t *testing.T) {
	for _, tt := range []struct {
		name   string
		params string
	}{
		{name: "path"},
		{name: "path with parameters", params: "?_pragma=busy_timeout(10000)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			makeSQLiteDirectoryBroad(t, dir)
			path := filepath.Join(dir, "sigils.db")
			db, err := Open(path + tt.params)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer db.Close()
			assertPrivateSQLiteDirectory(t, filepath.Dir(path))

			for _, suffix := range []string{"", "-wal", "-shm"} {
				filePath := path + suffix
				if _, err := os.Stat(filePath); err != nil {
					t.Fatalf("stat %s: %v", filepath.Base(filePath), err)
				}
				assertPrivateSQLiteFile(t, filePath)
			}
		})
	}
}

func TestOpenCreatesMissingPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private", "store")
	path := filepath.Join(dir, "sigils.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	assertPrivateSQLiteDirectory(t, dir)
	assertPrivateSQLiteFile(t, path)
}

func TestOpenPreservesExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sigils.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := db.db.Exec("CREATE TABLE sentinel (value TEXT NOT NULL); INSERT INTO sentinel VALUES ('kept')"); err != nil {
		t.Fatalf("seed database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer db.Close()
	var value string
	if err := db.db.QueryRow("SELECT value FROM sentinel").Scan(&value); err != nil {
		t.Fatalf("read preserved value: %v", err)
	}
	if value != "kept" {
		t.Fatalf("value = %q, want kept", value)
	}
}

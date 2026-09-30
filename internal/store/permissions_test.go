package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/securefile"
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
			path := filepath.Join(t.TempDir(), "data", "sigils.db")
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

// TestOpenRefusesDirectoryOthersMayAccess covers a data_dir that exists but is
// not private. SQLite creates -wal and -shm in it again whenever a connection
// opens after all were closed, and on Windows they inherit its DACL, so other
// accounts could read the private keys in them. Open refuses it with the fix
// and changes nothing: it may be a directory like /var/lib or C:\ProgramData.
func TestOpenRefusesDirectoryOthersMayAccess(t *testing.T) {
	dir := privateDirectory(t)
	makeSQLiteDirectoryBroad(t, dir)
	before := directorySecurity(t, dir)

	db, err := Open(filepath.Join(dir, "sigils.db"))
	if err == nil {
		_ = db.Close()
		t.Fatal("Open used a directory that other accounts may access")
	}
	for _, want := range []string{dir, "remove it for sigils to create it again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to contain %q", err, want)
		}
	}
	if after := directorySecurity(t, dir); after != before {
		t.Errorf("Open changed the directory from %s to %s", before, after)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("Open left %v (%v) in the directory it refused", entries, err)
	}
}

func TestOpenPreservesExistingDatabase(t *testing.T) {
	path := filepath.Join(privateDirectory(t), "sigils.db")
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

// privateDirectory returns a new private directory, as Open requires of one
// that exists. The temporary directory is not one on Windows, where it
// inherits an entry for the user, which an elevated process does not trust.
func privateDirectory(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	if err := securefile.EnsurePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

package securefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileCreatesAndReplacesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "client.yaml")
	if err := WriteFile(path, []byte("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFile(path, []byte("second")); err != nil {
		t.Fatalf("replacement write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Fatalf("contents = %q, want second", data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("mode = %#o, want 0600", got)
		}
	}
}

// TestEnsurePrivateDirectoryRefusesFile covers a path where a file stands,
// such as a data_dir mistyped as the path of a file: it must fail as creating
// a directory there fails, and leave the file as it is.
func TestEnsurePrivateDirectoryRefusesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDirectory(path); err == nil {
		t.Fatal("EnsurePrivateDirectory accepted a file")
	}
	if after, err := os.Stat(path); err != nil || after.Mode() != before.Mode() {
		t.Fatalf("mode after = %v (%v), want %v", after.Mode(), err, before.Mode())
	}
}

func TestWriteFileDoesNotChangeExistingParentMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory modes are not available on Windows")
	}
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Mkdir applies the umask; Chmod does not, so the mode is 0755 under any umask.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(dir, "client.yaml"), []byte("private")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("existing parent mode = %#o, want 0755", got)
	}
}

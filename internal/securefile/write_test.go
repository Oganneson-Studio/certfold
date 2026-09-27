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

func TestWriteFileDoesNotChangeExistingParentMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory modes are not available on Windows")
	}
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
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

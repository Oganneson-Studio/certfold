// Package securefile writes private configuration and key material without
// exposing partially written or broadly readable files.
package securefile

import (
	"fmt"
	"os"
	"path/filepath"
)

// ProtectFile applies platform-native private access controls to an existing
// file. On Unix this is mode 0600; on Windows this is a protected DACL.
func ProtectFile(path string) error {
	return secureFile(path)
}

// EnsurePrivateDirectory creates path when needed and applies platform-native
// private access controls. Existing directories are tightened as well.
func EnsurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return secureDirectory(path)
}

// WriteFile atomically replaces path with data. The temporary file gets
// platform-native private access controls from CreateTemp before any data is
// written, and keeps them when it replaces path.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	_, statErr := os.Stat(dir)
	dirWasMissing := os.IsNotExist(statErr)
	if statErr != nil && !dirWasMissing {
		return fmt.Errorf("inspect private directory: %w", statErr)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	if dirWasMissing && dir != "." {
		if err := secureDirectory(dir); err != nil {
			return fmt.Errorf("secure directory: %w", err)
		}
	}

	tmp, err := CreateTemp(dir, ".sigil-private-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := replaceFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace private file: %w", err)
	}
	return nil
}

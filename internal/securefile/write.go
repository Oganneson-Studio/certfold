// Package securefile writes private configuration and key material without
// exposing partially written or broadly readable files.
package securefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ProtectFile applies platform-native private access controls to an existing
// file. On Unix this is mode 0600; on Windows this is a protected DACL.
func ProtectFile(path string) error {
	return secureFile(path)
}

// EnsurePrivateDirectory creates path when needed, private from the moment it
// exists: mode 0700 on Unix; on Windows a protected DACL for the trustees and,
// in a process with Administrators enabled, Administrators as its owner. An
// existing directory is tightened as well, but keeps its owner.
func EnsurePrivateDirectory(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := mkdirPrivate(path); !errors.Is(err, fs.ErrExist) {
		return err
	}
	// MkdirAll fails unless what exists is a directory.
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return secureDirectory(path)
}

// CheckDirectory returns an error when accounts sigil does not trust could
// put files in the existing directory at path, replace or remove the files in
// it, or change who may. It changes nothing: the directory may be one like
// C:\ProgramData, whose permissions are not sigil's to change. A directory
// that does not exist passes, as sigil creates the directories it needs
// private.
//
// On Windows the owner must be SYSTEM, Administrators or, when the process
// runs without Administrators enabled, its user, and no other account may
// write to the directory, delete it or its files, or change its DACL or
// owner. Any account may create a folder in C:\ProgramData and owns what it
// creates. On Unix it checks nothing: the directories sigil uses there are
// under /etc and /var/lib, which only root may write.
func CheckDirectory(path string) error {
	return checkDirectory(path)
}

// CheckPrivateDirectory returns an error unless the directory at path is
// private: on Windows, no account other than those CheckDirectory trusts may
// have any access to it, including access that its files and directories
// inherit; on Unix, the process's effective user owns it and its mode gives
// the group and others nothing. Like CheckDirectory, it changes nothing.
func CheckPrivateDirectory(path string) error {
	return checkPrivateDirectory(path)
}

// WriteFile atomically replaces path with data. The temporary file gets
// platform-native private access controls from CreateTemp before any data is
// written, and keeps them when it replaces path. The errors name path, never
// the temporary file.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	_, statErr := os.Stat(dir)
	dirWasMissing := os.IsNotExist(statErr)
	if statErr != nil && !dirWasMissing {
		return fmt.Errorf("inspect private directory: %w", statErr)
	}
	if dirWasMissing {
		if err := EnsurePrivateDirectory(dir); err != nil {
			return fmt.Errorf("create private directory: %w", err)
		}
	}

	tmp, err := CreateTemp(dir, ".sigil-private-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, withoutTempName(err))
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temporary file for %s: %w", path, withoutTempName(err))
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary file for %s: %w", path, withoutTempName(err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temporary file for %s: %w", path, withoutTempName(err))
	}
	if err := replaceFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace %s: %w", path, withoutTempName(err))
	}
	return nil
}

// withoutTempName returns the cause of err, an error of an operation on the
// temporary file, without the *os.PathError or *os.LinkError around it that
// names the file: the name is random, so a failure that repeats would read
// differently each time, and a daemon that logs an error only when its text
// changes would log it every time. Other errors are returned as they are.
func withoutTempName(err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.Err
	}
	return err
}

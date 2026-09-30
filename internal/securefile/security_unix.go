//go:build !windows

package securefile

import (
	"fmt"
	"os"
	"syscall"
)

// CreateTemp creates a new file in dir with os.CreateTemp, which opens it for
// reading and writing with mode 0600 before anything is written to it.
func CreateTemp(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern) }

func secureDirectory(path string) error { return os.Chmod(path, 0o700) }

// mkdirPrivate creates the directory path with mode 0700, whatever the umask.
func mkdirPrivate(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	return secureDirectory(path)
}

func secureFile(path string) error { return os.Chmod(path, 0o600) }

func replaceFile(source, destination string) error { return os.Rename(source, destination) }

func checkDirectory(string) error { return nil }

func checkPrivateDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	euid := os.Geteuid()
	if owner := info.Sys().(*syscall.Stat_t).Uid; owner != uint32(euid) {
		return fmt.Errorf("%s is owned by uid %d, not by uid %d, the user of this process; check the files in it, then run: chown %d \"%s\"",
			path, owner, euid, euid, path)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s has mode %#o, and only its owner may have access to it; run: chmod 700 \"%s\"",
			path, mode, path)
	}
	return nil
}

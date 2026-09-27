//go:build !windows

package securefile

import "os"

// CreateTemp creates a new file in dir with os.CreateTemp, which opens it for
// reading and writing with mode 0600 before anything is written to it.
func CreateTemp(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern) }

func secureDirectory(path string) error { return os.Chmod(path, 0o700) }

func secureFile(path string) error { return os.Chmod(path, 0o600) }

func replaceFile(source, destination string) error { return os.Rename(source, destination) }

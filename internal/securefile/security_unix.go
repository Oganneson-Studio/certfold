//go:build !windows

package securefile

import "os"

func secureDirectory(path string) error { return os.Chmod(path, 0o700) }

func secureFile(path string) error { return os.Chmod(path, 0o600) }

func replaceFile(source, destination string) error { return os.Rename(source, destination) }

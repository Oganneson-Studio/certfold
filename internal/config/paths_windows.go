//go:build windows

package config

import (
	"os"
	"path/filepath"
)

// DefaultClientDataDir returns the platform default for client.data_dir. It
// is kept apart from the certfolds data directory so both can share a host.
func DefaultClientDataDir() string {
	base := os.Getenv("PROGRAMDATA")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Certfold", "client")
}

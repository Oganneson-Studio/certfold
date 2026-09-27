//go:build !windows

package config

import "runtime"

// DefaultClientDataDir returns the platform default for client.data_dir.
func DefaultClientDataDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/var/sigilc"
	default: // linux
		return "/var/lib/sigilc"
	}
}

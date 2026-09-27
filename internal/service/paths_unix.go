//go:build !windows

package service

import "runtime"

func defaultServerConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/etc/sigil/server.yaml"
	default: // linux
		return "/etc/sigil/server.yaml"
	}
}

func defaultClientConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/etc/sigil/client.yaml"
	default: // linux
		return "/etc/sigil/client.yaml"
	}
}

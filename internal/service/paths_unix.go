//go:build !windows

package service

import "runtime"

func defaultServerConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/etc/certfold/server.yaml"
	default: // linux
		return "/etc/certfold/server.yaml"
	}
}

func defaultClientConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/etc/certfold/client.yaml"
	default: // linux
		return "/etc/certfold/client.yaml"
	}
}

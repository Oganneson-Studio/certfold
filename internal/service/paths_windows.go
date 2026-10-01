//go:build windows

package service

import "os"

func defaultServerConfigPath() string {
	return programDataPath("server.yaml")
}

func defaultClientConfigPath() string {
	return programDataPath("client.yaml")
}

func programDataPath(filename string) string {
	base := os.Getenv("PROGRAMDATA")
	if base == "" {
		base = `C:\ProgramData`
	}
	return base + `\Certfold\` + filename
}

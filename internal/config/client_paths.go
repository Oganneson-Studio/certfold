package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ReadClientField reads the value of key in the client section of the
// client.yaml at path, as ReadServerPaths does the paths of server.yaml:
// sigilc enroll compares name and server_url with its token, and CLI
// commands locate the daemon with ipc_socket. It expands ${VAR} only in this
// value and does not validate the file, so the variables other values
// reference, such as a PKCS#12 password that only the service's environment
// sets, need not be set in the caller's environment, which sudo does not
// pass on. The value is expanded exactly as LoadClient expands it, and a
// relative ipc_socket is refused as LoadClient refuses it. An empty value
// means the key is not set.
func ReadClientField(path, key string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		Client map[string]yaml.Node `yaml:"client"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	n := doc.Client[key]
	value, err := expandedString(&n, "client."+key)
	if err != nil {
		return "", err
	}
	if key == "ipc_socket" && value != "" {
		if err := checkAbsolute(value); err != nil {
			return "", fmt.Errorf("client.ipc_socket: %w", err)
		}
	}
	return value, nil
}

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ReadClientIPCSocket reads client.ipc_socket from the client.yaml at path so
// CLI commands can locate the daemon, as ReadServerPaths does for sigils. It
// expands ${VAR} only in this value and does not validate the file, so the
// variables other values reference, such as a PKCS#12 password that only the
// service's environment sets, need not be set in the caller's environment.
// The value is expanded exactly as LoadClient expands it. An empty result
// means the field is not set.
func ReadClientIPCSocket(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		Client struct {
			IPCSocket yaml.Node `yaml:"ipc_socket"`
		} `yaml:"client"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	return expandedString(&doc.Client.IPCSocket, "client.ipc_socket")
}

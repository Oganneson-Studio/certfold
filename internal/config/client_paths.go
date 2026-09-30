package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ClientBasics are the values of client.yaml that CLI commands read without
// loading it: the client it enrolls as, the server it enrolls with, and
// client.ipc_socket, where its daemon listens. An empty value means the field
// is not set.
type ClientBasics struct {
	Name      string
	ServerURL string
	IPCSocket string
}

// ReadClientBasics reads client.name, client.server_url and
// client.ipc_socket from the client.yaml at path, as ReadServerPaths does
// the paths of server.yaml: sigilc enroll compares the first two with its
// token, and CLI commands locate the daemon with the third. It expands
// ${VAR} only in these values and does not validate the file, so the
// variables other values reference, such as a PKCS#12 password that only the
// service's environment sets, need not be set in the caller's environment,
// which sudo does not pass on. The values are expanded exactly as LoadClient
// expands them.
func ReadClientBasics(path string) (*ClientBasics, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		Client struct {
			Name      yaml.Node `yaml:"name"`
			ServerURL yaml.Node `yaml:"server_url"`
			IPCSocket yaml.Node `yaml:"ipc_socket"`
		} `yaml:"client"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var b ClientBasics
	if b.Name, err = expandedString(&doc.Client.Name, "client.name"); err != nil {
		return nil, err
	}
	if b.ServerURL, err = expandedString(&doc.Client.ServerURL, "client.server_url"); err != nil {
		return nil, err
	}
	if b.IPCSocket, err = expandedString(&doc.Client.IPCSocket, "client.ipc_socket"); err != nil {
		return nil, err
	}
	return &b, nil
}

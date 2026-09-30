package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ReadClientFields reads the values of keys in the client section of the
// client.yaml at path, in their order, as ReadServerPaths does the paths of
// server.yaml: sigilc enroll compares name and server_url with its token, and
// CLI commands locate the daemon with ipc_socket. It expands ${VAR} only in
// these values and does not validate the file, so the variables other values
// reference, such as a PKCS#12 password that only the service's environment
// sets, need not be set in the caller's environment, which sudo does not pass
// on. The values are expanded exactly as LoadClient expands them. An empty
// value means the key is not set.
func ReadClientFields(path string, keys ...string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		Client map[string]yaml.Node `yaml:"client"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	values := make([]string, len(keys))
	for i, key := range keys {
		n := doc.Client[key]
		if values[i], err = expandedString(&n, "client."+key); err != nil {
			return nil, err
		}
	}
	return values, nil
}

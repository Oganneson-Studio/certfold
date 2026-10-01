package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeClientYAML(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// readClientFields reads name, server_url and ipc_socket with
// ReadClientField.
func readClientFields(t *testing.T, path string) []string {
	t.Helper()
	var values []string
	for _, key := range []string{"name", "server_url", "ipc_socket"} {
		v, err := ReadClientField(path, key)
		if err != nil {
			t.Fatalf("ReadClientField %s: %v", key, err)
		}
		values = append(values, v)
	}
	return values
}

// ReadClientField reads the name, server URL and socket that LoadClient
// reads, but does not need the variables that the rest of client.yaml
// references.
func TestReadClientFieldAgreesWithLoadClient(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string // the client section of client.yaml
		value string // value of SIGIL_TEST_VALUE
		want  []string
	}{
		{
			name: "plain values, no socket",
			yaml: "client:\n  name: web-1\n  server_url: \"https://sigil.example.com:8443\"\n",
			want: []string{"web-1", "https://sigil.example.com:8443", ""},
		},
		{
			name:  "comment marker inside a plain value",
			yaml:  "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: ${SIGIL_TEST_VALUE}\n",
			value: absPath("/run/sigil/a.sock #x"),
			want:  []string{"web-1", "https://sigil.example.com", absPath("/run/sigil/a.sock #x")},
		},
		{
			name:  "backslashes inside a double-quoted value",
			yaml:  "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: \"${SIGIL_TEST_VALUE}\"\n",
			value: absPath(`/run/\\.\pipe\custom`),
			want:  []string{"web-1", "https://sigil.example.com", absPath(`/run/\\.\pipe\custom`)},
		},
		{
			name:  "name and server URL from variables",
			yaml:  "client:\n  name: web-${SIGIL_TEST_VALUE}\n  server_url: \"https://sigil-${SIGIL_TEST_VALUE}.example.com:${SIGIL_TEST_UNSET_PORT:-8443}\"\n",
			value: "2",
			want:  []string{"web-2", "https://sigil-2.example.com:8443", ""},
		},
		{
			name: "default of an unset variable",
			yaml: "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: \"${SIGIL_TEST_UNSET_SOCKET:-" + absPath("/run/sigil/d.sock") + "}\"\n",
			want: []string{"web-1", "https://sigil.example.com", absPath("/run/sigil/d.sock")},
		},
		{
			name: "escaped dollar",
			yaml: "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: \"" + absPath("/run/$$sigil.sock") + "\"\n",
			want: []string{"web-1", "https://sigil.example.com", absPath("/run/$sigil.sock")},
		},
		{
			name:  "alias of an anchored value with a variable",
			yaml:  "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  data_dir: &d " + absPath("/run/sigil-${SIGIL_TEST_VALUE}") + "\n  ipc_socket: *d\n",
			value: "3",
			want:  []string{"web-1", "https://sigil.example.com", absPath("/run/sigil-3")},
		},
		{
			name:  "merge key",
			yaml:  "client:\n  <<: {name: \"web-${SIGIL_TEST_VALUE}\", server_url: \"https://sigil.example.com\"}\n  ipc_socket: " + absPath("/run/sigil/m.sock") + "\n",
			value: "4",
			want:  []string{"web-4", "https://sigil.example.com", absPath("/run/sigil/m.sock")},
		},
		{
			name:  "anchored merge key, overridden by the mapping",
			yaml:  "client:\n  <<: &base {name: web-1, server_url: \"https://${SIGIL_TEST_VALUE}.example.com\"}\n  name: web-5\n",
			value: "sigil",
			want:  []string{"web-5", "https://sigil.example.com", ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SIGIL_TEST_VALUE", tt.value)
			path := writeClientYAML(t, tt.yaml)

			cfg, err := LoadClient(path)
			if err != nil {
				t.Fatalf("LoadClient: %v", err)
			}
			if loaded := []string{cfg.Client.Name, cfg.Client.ServerURL, cfg.Client.IPCSocket}; !slices.Equal(loaded, tt.want) {
				t.Errorf("LoadClient read %q, want %q", loaded, tt.want)
			}
			if got := readClientFields(t, path); !slices.Equal(got, tt.want) {
				t.Errorf("ReadClientField read %q, want %q", got, tt.want)
			}
		})
	}
}

// A PKCS#12 password may come from a variable that only the service's
// environment sets, which sudo does not pass to the CLI; so may any value
// other than the one read, the name too when only the socket is read.
func TestReadClientFieldDoesNotRequireOtherVariables(t *testing.T) {
	path := writeClientYAML(t, `client:
  name: ${SIGIL_TEST_UNSET_NAME}
  server_url: https://sigil.example.com:8443
  ipc_socket: `+absPath("/run/sigil/custom.sock")+`
  data_dir: ${SIGIL_TEST_UNSET_DATA_DIR}
certificates:
  api:
    outputs:
      - format: pkcs12
        path: `+absPath("/etc/ssl/api.p12")+`
        password: ${SIGIL_TEST_UNSET_P12_PASSWORD}
`)
	got, err := ReadClientField(path, "ipc_socket")
	if err != nil {
		t.Fatalf("ReadClientField: %v", err)
	}
	if want := absPath("/run/sigil/custom.sock"); got != want {
		t.Errorf("ReadClientField = %q, want %s", got, want)
	}
	if _, err := LoadClient(path); err == nil || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET_") {
		t.Fatalf("LoadClient should still require the other variables, got %v", err)
	}
}

func TestReadClientFieldRejectsUnsetVariable(t *testing.T) {
	for _, tt := range []struct{ key, yaml string }{
		{"name", "client:\n  name: ${SIGIL_TEST_UNSET}\n  server_url: https://sigil.example.com\n"},
		{"server_url", "client:\n  name: web-1\n  server_url: ${SIGIL_TEST_UNSET}\n"},
		{"ipc_socket", validClientYAML + "  ipc_socket: ${SIGIL_TEST_UNSET}\n"},
	} {
		t.Run(tt.key, func(t *testing.T) {
			_, err := ReadClientField(writeClientYAML(t, tt.yaml), tt.key)
			if err == nil || !strings.Contains(err.Error(), "client."+tt.key) || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET") {
				t.Fatalf("ReadClientField error = %v, want one about SIGIL_TEST_UNSET in client.%s", err, tt.key)
			}
		})
	}
}

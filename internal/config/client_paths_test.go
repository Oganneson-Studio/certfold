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

// ReadClientFields reads the name, server URL and socket that LoadClient
// reads, but does not need the variables that the rest of client.yaml
// references.
func TestReadClientFieldsAgreesWithLoadClient(t *testing.T) {
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
			value: "/run/sigil/a.sock #x",
			want:  []string{"web-1", "https://sigil.example.com", "/run/sigil/a.sock #x"},
		},
		{
			name:  "backslashes inside a double-quoted value",
			yaml:  "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: \"${SIGIL_TEST_VALUE}\"\n",
			value: `\\.\pipe\custom`,
			want:  []string{"web-1", "https://sigil.example.com", `\\.\pipe\custom`},
		},
		{
			name:  "name and server URL from variables",
			yaml:  "client:\n  name: web-${SIGIL_TEST_VALUE}\n  server_url: \"https://sigil-${SIGIL_TEST_VALUE}.example.com:${SIGIL_TEST_UNSET_PORT:-8443}\"\n",
			value: "2",
			want:  []string{"web-2", "https://sigil-2.example.com:8443", ""},
		},
		{
			name: "default of an unset variable",
			yaml: "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: \"${SIGIL_TEST_UNSET_SOCKET:-/run/sigil/d.sock}\"\n",
			want: []string{"web-1", "https://sigil.example.com", "/run/sigil/d.sock"},
		},
		{
			name: "escaped dollar",
			yaml: "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: \"/run/$$sigil.sock\"\n",
			want: []string{"web-1", "https://sigil.example.com", "/run/$sigil.sock"},
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
			got, err := ReadClientFields(path, "name", "server_url", "ipc_socket")
			if err != nil {
				t.Fatalf("ReadClientFields: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ReadClientFields = %q, want %q", got, tt.want)
			}
		})
	}
}

// A PKCS#12 password may come from a variable that only the service's
// environment sets, which sudo does not pass to the CLI; so may any value
// other than the ones read, the name too when only the socket is read.
func TestReadClientFieldsDoesNotRequireOtherVariables(t *testing.T) {
	path := writeClientYAML(t, `client:
  name: ${SIGIL_TEST_UNSET_NAME}
  server_url: https://sigil.example.com:8443
  ipc_socket: /run/sigil/custom.sock
  data_dir: ${SIGIL_TEST_UNSET_DATA_DIR}
certificates:
  api:
    outputs:
      - format: pkcs12
        path: /etc/ssl/api.p12
        password: ${SIGIL_TEST_UNSET_P12_PASSWORD}
`)
	got, err := ReadClientFields(path, "ipc_socket")
	if err != nil {
		t.Fatalf("ReadClientFields: %v", err)
	}
	if want := []string{"/run/sigil/custom.sock"}; !slices.Equal(got, want) {
		t.Errorf("ReadClientFields = %q, want %q", got, want)
	}
	if _, err := LoadClient(path); err == nil || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET_") {
		t.Fatalf("LoadClient should still require the other variables, got %v", err)
	}
}

func TestReadClientFieldsRejectsUnsetVariable(t *testing.T) {
	for _, tt := range []struct{ field, yaml string }{
		{"client.name", "client:\n  name: ${SIGIL_TEST_UNSET}\n  server_url: https://sigil.example.com\n"},
		{"client.server_url", "client:\n  name: web-1\n  server_url: ${SIGIL_TEST_UNSET}\n"},
		{"client.ipc_socket", validClientYAML + "  ipc_socket: ${SIGIL_TEST_UNSET}\n"},
	} {
		t.Run(tt.field, func(t *testing.T) {
			_, err := ReadClientFields(writeClientYAML(t, tt.yaml), "name", "server_url", "ipc_socket")
			if err == nil || !strings.Contains(err.Error(), tt.field) || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET") {
				t.Fatalf("ReadClientFields error = %v, want one about SIGIL_TEST_UNSET in %s", err, tt.field)
			}
		})
	}
}

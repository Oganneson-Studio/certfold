package config

import (
	"os"
	"path/filepath"
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

// ReadClientBasics reads the name, server URL and socket that LoadClient
// reads, but does not need the variables that the rest of client.yaml
// references.
func TestReadClientBasicsAgreesWithLoadClient(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string // the client section of client.yaml
		value string // value of SIGIL_TEST_VALUE
		want  ClientBasics
	}{
		{
			name: "plain values, no socket",
			yaml: "client:\n  name: web-1\n  server_url: \"https://sigil.example.com:8443\"\n",
			want: ClientBasics{Name: "web-1", ServerURL: "https://sigil.example.com:8443"},
		},
		{
			name:  "comment marker inside a plain value",
			yaml:  "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: ${SIGIL_TEST_VALUE}\n",
			value: "/run/sigil/a.sock #x",
			want:  ClientBasics{Name: "web-1", ServerURL: "https://sigil.example.com", IPCSocket: "/run/sigil/a.sock #x"},
		},
		{
			name:  "backslashes inside a double-quoted value",
			yaml:  "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: \"${SIGIL_TEST_VALUE}\"\n",
			value: `\\.\pipe\custom`,
			want:  ClientBasics{Name: "web-1", ServerURL: "https://sigil.example.com", IPCSocket: `\\.\pipe\custom`},
		},
		{
			name:  "name and server URL from variables",
			yaml:  "client:\n  name: web-${SIGIL_TEST_VALUE}\n  server_url: \"https://sigil-${SIGIL_TEST_VALUE}.example.com:${SIGIL_TEST_UNSET_PORT:-8443}\"\n",
			value: "2",
			want:  ClientBasics{Name: "web-2", ServerURL: "https://sigil-2.example.com:8443"},
		},
		{
			name: "default of an unset variable",
			yaml: "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: \"${SIGIL_TEST_UNSET_SOCKET:-/run/sigil/d.sock}\"\n",
			want: ClientBasics{Name: "web-1", ServerURL: "https://sigil.example.com", IPCSocket: "/run/sigil/d.sock"},
		},
		{
			name: "escaped dollar",
			yaml: "client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: \"/run/$$sigil.sock\"\n",
			want: ClientBasics{Name: "web-1", ServerURL: "https://sigil.example.com", IPCSocket: "/run/$sigil.sock"},
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
			loaded := ClientBasics{Name: cfg.Client.Name, ServerURL: cfg.Client.ServerURL, IPCSocket: cfg.Client.IPCSocket}
			if loaded != tt.want {
				t.Errorf("LoadClient read %+v, want %+v", loaded, tt.want)
			}
			got, err := ReadClientBasics(path)
			if err != nil {
				t.Fatalf("ReadClientBasics: %v", err)
			}
			if *got != tt.want {
				t.Errorf("ReadClientBasics = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

// A PKCS#12 password may come from a variable that only the service's
// environment sets, which sudo does not pass to the CLI.
func TestReadClientBasicsDoesNotRequireOtherVariables(t *testing.T) {
	path := writeClientYAML(t, validClientYAML+`  ipc_socket: /run/sigil/custom.sock
  data_dir: ${SIGIL_TEST_UNSET_DATA_DIR}
certificates:
  api:
    outputs:
      - format: pkcs12
        path: /etc/ssl/api.p12
        password: ${SIGIL_TEST_UNSET_P12_PASSWORD}
`)
	got, err := ReadClientBasics(path)
	if err != nil {
		t.Fatalf("ReadClientBasics: %v", err)
	}
	want := ClientBasics{Name: "web-1", ServerURL: "https://sigil.example.com:8443", IPCSocket: "/run/sigil/custom.sock"}
	if *got != want {
		t.Errorf("ReadClientBasics = %+v, want %+v", *got, want)
	}
	if _, err := LoadClient(path); err == nil || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET_") {
		t.Fatalf("LoadClient should still require the other variables, got %v", err)
	}
}

func TestReadClientBasicsRejectsUnsetVariable(t *testing.T) {
	for _, tt := range []struct{ field, yaml string }{
		{"client.name", "client:\n  name: ${SIGIL_TEST_UNSET}\n  server_url: https://sigil.example.com\n"},
		{"client.server_url", "client:\n  name: web-1\n  server_url: ${SIGIL_TEST_UNSET}\n"},
		{"client.ipc_socket", validClientYAML + "  ipc_socket: ${SIGIL_TEST_UNSET}\n"},
	} {
		t.Run(tt.field, func(t *testing.T) {
			_, err := ReadClientBasics(writeClientYAML(t, tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.field) || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET") {
				t.Fatalf("ReadClientBasics error = %v, want one about SIGIL_TEST_UNSET in %s", err, tt.field)
			}
		})
	}
}

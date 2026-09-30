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

// ReadClientIPCSocket finds the socket that LoadClient finds, but does not
// need the variables that the rest of client.yaml references.
func TestReadClientIPCSocketAgreesWithLoadClient(t *testing.T) {
	tests := []struct {
		name  string
		line  string // the ipc_socket line of client.yaml
		value string // value of SIGIL_TEST_VALUE
		want  string
	}{
		{name: "absent", want: ""},
		{name: "comment marker inside a plain value", line: "ipc_socket: ${SIGIL_TEST_VALUE}", value: "/run/sigil/a.sock #x", want: "/run/sigil/a.sock #x"},
		{name: "backslashes inside a double-quoted value", line: `ipc_socket: "${SIGIL_TEST_VALUE}"`, value: `\\.\pipe\custom`, want: `\\.\pipe\custom`},
		{name: "default of an unset variable", line: `ipc_socket: "${SIGIL_TEST_UNSET_SOCKET:-/run/sigil/d.sock}"`, want: "/run/sigil/d.sock"},
		{name: "escaped dollar", line: `ipc_socket: "/run/$$sigil.sock"`, want: "/run/$sigil.sock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SIGIL_TEST_VALUE", tt.value)
			src := validClientYAML
			if tt.line != "" {
				src += "  " + tt.line + "\n"
			}
			path := writeClientYAML(t, src)

			cfg, err := LoadClient(path)
			if err != nil {
				t.Fatalf("LoadClient: %v", err)
			}
			if cfg.Client.IPCSocket != tt.want {
				t.Errorf("LoadClient ipc_socket = %q, want %q", cfg.Client.IPCSocket, tt.want)
			}
			got, err := ReadClientIPCSocket(path)
			if err != nil {
				t.Fatalf("ReadClientIPCSocket: %v", err)
			}
			if got != tt.want {
				t.Errorf("ReadClientIPCSocket = %q, want %q", got, tt.want)
			}
		})
	}
}

// A PKCS#12 password may come from a variable that only the service's
// environment sets, which sudo does not pass to the CLI.
func TestReadClientIPCSocketDoesNotRequireOtherVariables(t *testing.T) {
	path := writeClientYAML(t, validClientYAML+`  ipc_socket: /run/sigil/custom.sock
certificates:
  api:
    outputs:
      - format: pkcs12
        path: /etc/ssl/api.p12
        password: ${SIGIL_TEST_UNSET_P12_PASSWORD}
`)
	got, err := ReadClientIPCSocket(path)
	if err != nil {
		t.Fatalf("ReadClientIPCSocket: %v", err)
	}
	if got != "/run/sigil/custom.sock" {
		t.Errorf("ipc_socket = %q, want /run/sigil/custom.sock", got)
	}
	if _, err := LoadClient(path); err == nil || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET_P12_PASSWORD") {
		t.Fatalf("LoadClient should still require the password variable, got %v", err)
	}
}

func TestReadClientIPCSocketRejectsUnsetVariable(t *testing.T) {
	path := writeClientYAML(t, validClientYAML+"  ipc_socket: ${SIGIL_TEST_UNSET_SOCKET}\n")
	_, err := ReadClientIPCSocket(path)
	if err == nil || !strings.Contains(err.Error(), "client.ipc_socket") || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET_SOCKET") {
		t.Fatalf("expected unset ipc_socket variable error, got %v", err)
	}
}

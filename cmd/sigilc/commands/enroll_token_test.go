package commands

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A token that sigils did not make may carry a client name or a server URL
// that a terminal would take for a command: enroll refuses it before it
// writes client.yaml, which would keep both for sigilc status to print.
func TestEnrollRefusesTokenWithControlCharacters(t *testing.T) {
	for _, tc := range []struct {
		name, clientName, serverURL, want string
	}{
		{"client name", "web\x1b]0;pwned\a", "https://127.0.0.1:1", `invalid client name "web\x1b]0;pwned\a"`},
		{"server URL", "web-1", "https://127.0.0.1:1/\u009b2J", `server URL: must not contain '\u009b'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"server_url": tc.serverURL, "name": tc.clientName})
			if err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(t.TempDir(), "client.yaml")
			root := NewRootCmd()
			root.SetArgs([]string{"--config", cfgPath, "enroll", "--token", base64.RawURLEncoding.EncodeToString(raw)})
			if err := root.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("enroll error = %v, want %s", err, tc.want)
			}
			if _, err := os.Stat(cfgPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("enroll left client.yaml behind: %v", err)
			}
		})
	}
}

package commands

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// A token that sigils did not make may carry a client name or a server URL
// that a terminal would take for a command: enroll refuses it before it
// writes client.yaml, which would keep both for sigilc status to print.
// The token may come from --token or from SIGILC_TOKEN, and either way it is
// checked before client.yaml is written.
func TestEnrollRefusesTokenWithControlCharacters(t *testing.T) {
	for _, tc := range []struct {
		name, clientName, serverURL, want string
	}{
		{"client name", "web\x1b]0;pwned\a", "https://127.0.0.1:1", `invalid client name "web\x1b]0;pwned\a"`},
		{"server URL", "web-1", "https://127.0.0.1:1/\u009b2J", `server URL: must not contain '\u009b'`},
	} {
		raw, err := json.Marshal(map[string]string{"server_url": tc.serverURL, "name": tc.clientName})
		if err != nil {
			t.Fatal(err)
		}
		token := base64.RawURLEncoding.EncodeToString(raw)
		for _, from := range []string{"flag", "environment"} {
			t.Run(tc.name+" from "+from, func(t *testing.T) {
				cfgPath := filepath.Join(t.TempDir(), "client.yaml")
				args := []string{"--config", cfgPath, "enroll"}
				if from == "flag" {
					t.Setenv("SIGILC_TOKEN", "")
					args = append(args, "--token", token)
				} else {
					t.Setenv("SIGILC_TOKEN", token)
				}
				root := NewRootCmd()
				root.SetArgs(args)
				if err := root.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("enroll error = %v, want %s", err, tc.want)
				}
				if _, err := os.Stat(cfgPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("enroll left client.yaml behind: %v", err)
				}
			})
		}
	}
}

// TestEnrollNeedsAToken checks that enroll without --token and SIGILC_TOKEN
// says how to give it one, and writes nothing.
func TestEnrollNeedsAToken(t *testing.T) {
	t.Setenv("SIGILC_TOKEN", "")
	cfgPath := filepath.Join(t.TempDir(), "client.yaml")
	root := NewRootCmd()
	root.SetArgs([]string{"--config", cfgPath, "enroll"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "SIGILC_TOKEN") || !strings.Contains(err.Error(), "--token") {
		t.Fatalf("enroll error = %v, want one that names SIGILC_TOKEN and --token", err)
	}
	if _, err := os.Stat(cfgPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("enroll left client.yaml behind: %v", err)
	}
}

// TestEnrollTakesTokenFromEnvironment checks that without --token, enroll
// takes the token from SIGILC_TOKEN, as the install scripts pass it.
func TestEnrollTakesTokenFromEnvironment(t *testing.T) {
	srv := newSigningEnrollServer(t)
	cfgPath := privateConfigPath(t)
	t.Setenv("SIGILC_TOKEN", srv.token(t, "web-1"))
	if _, err := runSigilcErr(t, "--config", cfgPath, "enroll"); err != nil {
		t.Fatalf("enroll with SIGILC_TOKEN: %v", err)
	}
	if n := srv.requests.Load(); n != 1 {
		t.Fatalf("server got %d requests, want 1", n)
	}
	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Client.Name != "web-1" || cfg.Identity.ClientCert == "" {
		t.Fatalf("client.yaml names %q, client certificate set: %t; want web-1 with one", cfg.Client.Name, cfg.Identity.ClientCert != "")
	}
}

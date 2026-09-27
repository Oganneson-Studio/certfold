package config

import (
	"strings"
	"testing"
	"time"
)

func TestExpandEnv(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) {
			v, ok := m[k]
			return v, ok
		}
	}

	tests := []struct {
		name    string
		in      string
		lookup  func(string) (string, bool)
		want    string
		wantErr string
	}{
		{
			name:   "no substitution",
			in:     "hello: world",
			lookup: env(nil),
			want:   "hello: world",
		},
		{
			name:   "simple var",
			in:     "token: ${TOKEN}",
			lookup: env(map[string]string{"TOKEN": "abc123"}),
			want:   "token: abc123",
		},
		{
			name:   "default when unset",
			in:     "token: ${MISSING:-fallback}",
			lookup: env(nil),
			want:   "token: fallback",
		},
		{
			name:   "default ignored when set",
			in:     "token: ${TOKEN:-fallback}",
			lookup: env(map[string]string{"TOKEN": "real"}),
			want:   "token: real",
		},
		{
			name:   "literal dollar via $$",
			in:     "regex: $$start",
			lookup: env(nil),
			want:   "regex: $start",
		},
		{
			name:   "lonely dollar passes through",
			in:     "price: $5",
			lookup: env(nil),
			want:   "price: $5",
		},
		{
			name:    "unset without default errors",
			in:      "token: ${MISSING}",
			lookup:  env(nil),
			wantErr: `environment variable "MISSING" is not set`,
		},
		{
			name:    "unterminated braces error",
			in:      "broken: ${OPEN",
			lookup:  env(nil),
			wantErr: "unterminated",
		},
		{
			name:    "empty name errors",
			in:      "bad: ${}",
			lookup:  env(nil),
			wantErr: "empty variable name",
		},
		{
			name:   "multiple substitutions",
			in:     "a: ${A}, b: ${B:-def}, c: ${C}",
			lookup: env(map[string]string{"A": "1", "C": "3"}),
			want:   "a: 1, b: def, c: 3",
		},
		{
			name:   "default with empty value",
			in:     "x: ${X:-}",
			lookup: env(nil),
			want:   "x: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandEnv(tt.in, tt.lookup)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

// withServerSection replaces the data_dir line of validServerYAML with lines.
func withServerSection(lines string) string {
	return strings.Replace(validServerYAML, `data_dir: "/var/lib/sigils"`, lines, 1)
}

// Environment values are inserted after YAML parsing, so YAML syntax inside a
// value is never interpreted, and LoadServer and ReadServerPaths agree.
func TestEnvValuesAreLiteralScalars(t *testing.T) {
	tests := []struct {
		name   string
		server string // replaces the data_dir line of validServerYAML
		value  string // value of SIGIL_TEST_VALUE
		ipc    bool   // the value under test is ipc_socket, not data_dir
		want   string
	}{
		{
			name:   "backslash escape after a variable in a double-quoted value",
			server: `data_dir: "${SIGIL_TEST_VALUE}\\Sigil"`,
			value:  `C:\ProgramData`,
			want:   `C:\ProgramData\Sigil`,
		},
		{
			name: "comment marker inside a plain value",
			server: `data_dir: "/var/lib/sigils"
  ipc_socket: ${SIGIL_TEST_VALUE}`,
			value: "/run/sigil/a.sock #x",
			ipc:   true,
			want:  "/run/sigil/a.sock #x",
		},
		{
			name: "backslashes inside a double-quoted value",
			server: `data_dir: "/var/lib/sigils"
  ipc_socket: "${SIGIL_TEST_VALUE}"`,
			value: `\\.\pipe\custom`,
			ipc:   true,
			want:  `\\.\pipe\custom`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SIGIL_TEST_VALUE", tt.value)
			src := withServerSection(tt.server)

			cfg, err := ParseServer([]byte(src))
			if err != nil {
				t.Fatalf("ParseServer: %v", err)
			}
			got := cfg.Server.DataDir
			if tt.ipc {
				got = cfg.Server.IPCSocket
			}
			if got != tt.want {
				t.Errorf("ParseServer value = %q, want %q", got, tt.want)
			}

			dataDir, ipcSocket, err := ReadServerPaths(writeServerYAML(t, src))
			if err != nil {
				t.Fatalf("ReadServerPaths: %v", err)
			}
			got = dataDir
			if tt.ipc {
				got = ipcSocket
			}
			if got != tt.want {
				t.Errorf("ReadServerPaths value = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnvValueCannotAddYAMLStructure(t *testing.T) {
	t.Setenv("SIGIL_TEST_DOMAINS", "[a.example.com, b.example.com]")
	src := strings.Replace(validServerYAML, `domains: ["internal.example.com"]`, `domains: ${SIGIL_TEST_DOMAINS}`, 1)
	if _, err := ParseServer([]byte(src)); err == nil {
		t.Fatal("an environment value was parsed as a YAML sequence")
	}

	t.Setenv("SIGIL_TEST_DATA_DIR", "/srv/sigils\nfoo_bar: 1")
	cfg, err := ParseServer([]byte(withServerSection(`data_dir: ${SIGIL_TEST_DATA_DIR}`)))
	if err != nil {
		t.Fatalf("ParseServer: %v", err)
	}
	if cfg.Server.DataDir != "/srv/sigils\nfoo_bar: 1" {
		t.Fatalf("data_dir = %q", cfg.Server.DataDir)
	}
}

func TestEnvValuesInPlainScalarsResolveTheirType(t *testing.T) {
	t.Setenv("SIGIL_TEST_DAYS", "21")
	t.Setenv("SIGIL_TEST_TOKEN", "12345")
	src := strings.Replace(validServerYAML, "renew_days_before: 14", "renew_days_before: ${SIGIL_TEST_DAYS}", 1)
	src = strings.Replace(src, `api_token: "tok"`, `api_token: "${SIGIL_TEST_TOKEN}"`, 1)
	src = strings.Replace(src, `eab_hmac: "h"`, `eab_hmac: "h$$1"`, 1)
	cfg, err := ParseServer([]byte(src))
	if err != nil {
		t.Fatalf("ParseServer: %v", err)
	}
	if got := cfg.Certificates[1].RenewDaysBefore; got != 21 {
		t.Errorf("renew_days_before = %d, want 21", got)
	}
	// A quoted value stays a string even when it looks like a number.
	if got := cfg.DNSProviders["cf_main"].Config["api_token"]; got != "12345" {
		t.Errorf("api_token = %#v, want string 12345", got)
	}
	if got := cfg.ACME.CAs["zerossl"].EABHMAC; got != "h$1" {
		t.Errorf("eab_hmac = %q, want h$1", got)
	}

	t.Setenv("SIGIL_TEST_PULL", "90s")
	t.Setenv("SIGIL_TEST_RENEW", "48h")
	clientSrc := strings.Replace(validClientYAML, `pull_interval: "1h"`, `pull_interval: ${SIGIL_TEST_PULL}
  identity_renew_before: ${SIGIL_TEST_RENEW}`, 1)
	clientCfg, err := ParseClient([]byte(clientSrc))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if clientCfg.Client.PullInterval != 90*time.Second || clientCfg.Client.IdentityRenewBefore != 48*time.Hour {
		t.Errorf("pull_interval = %v, identity_renew_before = %v", clientCfg.Client.PullInterval, clientCfg.Client.IdentityRenewBefore)
	}
}

func TestEnvExpansionErrorNamesTheValuePath(t *testing.T) {
	tests := []struct {
		name string
		src  string
		path string
	}{
		{
			name: "mapping value",
			src:  strings.Replace(validServerYAML, `api_token: "tok"`, `api_token: "${SIGIL_TEST_UNSET_VALUE}"`, 1),
			path: "dns_providers.cf_main.api_token",
		},
		{
			name: "sequence item",
			// Inside [...] a ${...} value must be quoted: '{' is flow syntax.
			src:  strings.Replace(validServerYAML, "subscribers: [web-1, web-2]", `subscribers: [web-1, "${SIGIL_TEST_UNSET_VALUE}"]`, 1),
			path: "certificates[0].subscribers[1]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseServer([]byte(tt.src))
			if err == nil || !strings.Contains(err.Error(), tt.path+`: environment variable "SIGIL_TEST_UNSET_VALUE" is not set`) {
				t.Fatalf("expected an unset variable error at %s, got %v", tt.path, err)
			}
		})
	}
}

func TestEnvExpansionIgnoresComments(t *testing.T) {
	src := "# set ${SIGIL_TEST_UNSET_IN_COMMENT} before starting\n" + validServerYAML
	if _, err := ParseServer([]byte(src)); err != nil {
		t.Fatalf("a variable in a comment was expanded: %v", err)
	}
}

func TestEnvExpansionKeepsLongValues(t *testing.T) {
	long := strings.Repeat("secret words: #1 ", 10)
	t.Setenv("SIGIL_TEST_LONG", long)
	src := strings.Replace(validServerYAML, `eab_hmac: "h"`, `eab_hmac: ${SIGIL_TEST_LONG}`, 1)
	cfg, err := ParseServer([]byte(src))
	if err != nil {
		t.Fatalf("ParseServer: %v", err)
	}
	if got := cfg.ACME.CAs["zerossl"].EABHMAC; got != long {
		t.Fatalf("eab_hmac = %q, want %q", got, long)
	}
}

func TestEnvExpansionExpandsAnchoredValuesOnce(t *testing.T) {
	src := strings.Replace(validServerYAML, `eab_kid: "k"`, `eab_kid: &eab "a$$$$b"`, 1)
	src = strings.Replace(src, `eab_hmac: "h"`, `eab_hmac: *eab`, 1)
	cfg, err := ParseServer([]byte(src))
	if err != nil {
		t.Fatalf("ParseServer: %v", err)
	}
	ca := cfg.ACME.CAs["zerossl"]
	if ca.EABKID != "a$$b" || ca.EABHMAC != "a$$b" {
		t.Fatalf("eab_kid = %q, eab_hmac = %q, want a$$b for both", ca.EABKID, ca.EABHMAC)
	}
}

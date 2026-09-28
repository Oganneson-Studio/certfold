package config

import (
	"math/rand/v2"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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

func TestReadServerPathsExpandsAliasesLikeLoadServer(t *testing.T) {
	t.Setenv("SIGIL_TEST_HOST", "sigil.example.com")
	// Both paths alias one anchored value. "$$$$" shows that each path gets
	// the value expanded exactly once.
	path := writeServerYAML(t, withServerSection(`public_url: &base "https://${SIGIL_TEST_HOST}/$$$$"
  data_dir: *base
  ipc_socket: *base`))
	const want = "https://sigil.example.com/$$"

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.Server.DataDir != want || cfg.Server.IPCSocket != want {
		t.Fatalf("LoadServer data_dir = %q, ipc_socket = %q, want %q", cfg.Server.DataDir, cfg.Server.IPCSocket, want)
	}
	dataDir, ipcSocket, err := ReadServerPaths(path)
	if err != nil {
		t.Fatalf("ReadServerPaths: %v", err)
	}
	if dataDir != want || ipcSocket != want {
		t.Fatalf("ReadServerPaths data_dir = %q, ipc_socket = %q, want %q", dataDir, ipcSocket, want)
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
	t.Setenv("SIGIL_TEST_SKIP", "true")
	t.Setenv("SIGIL_TEST_TOKEN", "12345")
	src := strings.Replace(validServerYAML, `api_token: "tok"`,
		`api_token: "${SIGIL_TEST_TOKEN}"`+"\n    skip_propagation_check: ${SIGIL_TEST_SKIP}", 1)
	src = strings.Replace(src, `eab_hmac: "h"`, `eab_hmac: "h$$1"`, 1)
	cfg, err := ParseServer([]byte(src))
	if err != nil {
		t.Fatalf("ParseServer: %v", err)
	}
	if !cfg.DNSProviders["cf_main"].SkipPropagationCheck {
		t.Error("skip_propagation_check = false, want true")
	}
	// A quoted value stays a string even when it looks like a number.
	if got := cfg.DNSProviders["cf_main"].Config["api_token"]; got != "12345" {
		t.Errorf("api_token = %#v, want string 12345", got)
	}
	if got := cfg.ACME.CAs["zerossl"].EABHMAC; got != "h$1" {
		t.Errorf("eab_hmac = %q, want h$1", got)
	}

	t.Setenv("SIGIL_TEST_RENEW", "48h")
	clientSrc := strings.Replace(validClientYAML, `server_url: "https://sigil.example.com:8443"`, `server_url: "https://sigil.example.com:8443"
  identity_renew_before: ${SIGIL_TEST_RENEW}`, 1)
	clientCfg, err := ParseClient([]byte(clientSrc))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if clientCfg.Client.IdentityRenewBefore != 48*time.Hour {
		t.Errorf("identity_renew_before = %v, want 48h", clientCfg.Client.IdentityRenewBefore)
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

// Environment values are inserted verbatim. Nothing is trimmed, although the
// same text written literally in a plain scalar would lose its outer spaces.
func TestEnvValuesAreNotTrimmed(t *testing.T) {
	const value = "  spaced secret \n"
	t.Setenv("SIGIL_TEST_VALUE", value)
	src := strings.Replace(validServerYAML, `eab_hmac: "h"`, `eab_hmac: ${SIGIL_TEST_VALUE}`, 1)
	cfg, err := ParseServer([]byte(src))
	if err != nil {
		t.Fatalf("ParseServer: %v", err)
	}
	if got := cfg.ACME.CAs["zerossl"].EABHMAC; got != value {
		t.Fatalf("eab_hmac = %q, want %q", got, value)
	}
}

func TestEnvExpansionLeavesKeysAlone(t *testing.T) {
	src := strings.Replace(validServerYAML, "dns_providers:\n", `dns_providers:
  "p${SIGIL_TEST_UNSET_KEY}":
    type: route53
`, 1)
	cfg, err := ParseServer([]byte(src))
	if err != nil {
		t.Fatalf("a mapping key was expanded: %v", err)
	}
	if _, ok := cfg.DNSProviders["p${SIGIL_TEST_UNSET_KEY}"]; !ok {
		t.Fatalf("dns provider keys = %v", cfg.DNSProviders)
	}
}

// yaml.v3 does not re-emit every block scalar exactly, so decodeWithEnv must
// keep these values even when a document has no environment references.
func TestDecodeWithEnvKeepsBlockScalars(t *testing.T) {
	for raw, want := range map[string]string{
		"s: |\n\n  a\n":          "\na\n",
		"s: |+\n  keep\n\n# c\n": "keep\n\n",
	} {
		var got struct {
			S string `yaml:"s"`
		}
		if err := decodeWithEnv([]byte(raw), &got); err != nil {
			t.Fatalf("decodeWithEnv(%q): %v", raw, err)
		}
		if got.S != want {
			t.Errorf("decodeWithEnv(%q) = %q, want %q", raw, got.S, want)
		}
	}
}

// decodeWithEnv encodes the expanded tree again for its strict decode. For
// random environment values in every scalar style, that must decode exactly
// what decoding the expanded tree directly gives.
func TestDecodeWithEnvMatchesExpandedTree(t *testing.T) {
	const iterations = 20000
	templates := []string{
		"s: ${SIGIL_TEST_FUZZ}\n",
		"s: \"${SIGIL_TEST_FUZZ}\"\n",
		"s: '${SIGIL_TEST_FUZZ}'\n",
		"s: |\n  ${SIGIL_TEST_FUZZ}\n",
		"s: >\n  ${SIGIL_TEST_FUZZ}\n",
		"s: |-\n  ${SIGIL_TEST_FUZZ}\n",
		"s: >-\n  ${SIGIL_TEST_FUZZ}\n",
		"s: |+\n  ${SIGIL_TEST_FUZZ}\n\n",
		"m:\n  k: ${SIGIL_TEST_FUZZ}\n",
		"l:\n  - ${SIGIL_TEST_FUZZ}\n",
	}
	// Blanks, every YAML line break (NEL, LS and PS are added by code point),
	// YAML indicator characters, and a few characters that resolve to numbers
	// or null.
	alphabet := append([]rune("ab01.~ \t\n\r:#-?[]{},&*!|>'\"%@`\\$"), 0x85, 0x2028, 0x2029)
	rng := rand.New(rand.NewPCG(1, 2)) // fixed seed: failures are reproducible
	t.Setenv("SIGIL_TEST_FUZZ", "x")   // restores the variable after the test

	failures := 0
	for i := range iterations {
		runes := make([]rune, 1+rng.IntN(12))
		for j := range runes {
			runes[j] = alphabet[rng.IntN(len(alphabet))]
		}
		value := string(runes)
		if err := os.Setenv("SIGIL_TEST_FUZZ", value); err != nil {
			t.Fatal(err)
		}
		raw := []byte(templates[i%len(templates)])

		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if err := expandEnvNode(&doc, ""); err != nil {
			t.Fatal(err)
		}
		var want map[string]any
		if err := doc.Decode(&want); err != nil {
			t.Fatalf("decode expanded tree for %q in %q: %v", value, raw, err)
		}

		var got map[string]any
		err := decodeWithEnv(raw, &got)
		if err != nil || !reflect.DeepEqual(got, want) {
			failures++
			if failures <= 5 {
				t.Errorf("value %q in %q: decodeWithEnv = %#v (err %v), want %#v", value, raw, got, err, want)
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d of %d values changed", failures, iterations)
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

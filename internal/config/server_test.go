package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// absPath makes path, a Unix absolute path, absolute on the OS running the
// test: on Windows it puts it on drive C:. Windows takes the slashes of
// C:/var/lib for separators, and YAML reads slashes as they are in any
// quoting, unlike backslashes.
func absPath(path string) string {
	if runtime.GOOS == "windows" {
		return "C:" + path
	}
	return path
}

// validDataDirLine is the line of validServerYAML that sets server.data_dir.
var validDataDirLine = `data_dir: "` + absPath("/var/lib/sigils") + `"`

var validServerYAML = `
server:
  listen: ":8443"
  ` + validDataDirLine + `

acme:
  email: "ops@example.com"
  default_ca: letsencrypt
  cas:
    letsencrypt:
      directory: "https://acme-v02.api.letsencrypt.org/directory"
    zerossl:
      directory: "https://acme.zerossl.com/v2/DV90"
      eab_kid: "k"
      eab_hmac: "h"

dns_providers:
  cf-main:
    type: cloudflare
    api_token: "tok"
  aliyun-a:
    type: aliyun
    access_key: "k"
    access_secret: "s"

certificates:
  - name: api-prod
    domains: ["api.example.com", "*.api.example.com"]
    ca: letsencrypt
    dns_provider: cf-main
    subscribers: [web-1, web-2]
  - name: internal
    domains: ["internal.example.com"]
    ca: zerossl
    dns_provider: aliyun-a
    key_type: rsa4096
`

func TestParseServer_Valid(t *testing.T) {
	cfg, err := ParseServer([]byte(validServerYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != ":8443" {
		t.Errorf("listen: got %q", cfg.Server.Listen)
	}
	if cfg.Server.DataDir != absPath("/var/lib/sigils") {
		t.Errorf("data_dir: got %q", cfg.Server.DataDir)
	}
	if len(cfg.Certificates) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(cfg.Certificates))
	}
	if cfg.Certificates[0].KeyType != DefaultKeyType {
		t.Errorf("cert[0] key_type default: got %q", cfg.Certificates[0].KeyType)
	}
	if cfg.Certificates[1].KeyType != "rsa4096" {
		t.Errorf("cert[1] explicit key_type: got %q", cfg.Certificates[1].KeyType)
	}
	if cfg.DNSProviders["cf-main"].Config["api_token"] != "tok" {
		t.Errorf("cf-main api_token: got %v", cfg.DNSProviders["cf-main"].Config["api_token"])
	}
}

func TestParseServer_EnvInterpolation(t *testing.T) {
	t.Setenv("EAB_KID", "kid-from-env")
	t.Setenv("EAB_HMAC", "hmac-from-env")
	src := strings.ReplaceAll(validServerYAML,
		`eab_kid: "k"`, `eab_kid: "${EAB_KID}"`)
	src = strings.ReplaceAll(src,
		`eab_hmac: "h"`, `eab_hmac: "${EAB_HMAC}"`)
	cfg, err := ParseServer([]byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ACME.CAs["zerossl"].EABKID != "kid-from-env" {
		t.Errorf("EAB_KID interpolation: got %q", cfg.ACME.CAs["zerossl"].EABKID)
	}
}

func TestParseServer_ValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{
			name:   "missing data_dir",
			mutate: func(s string) string { return strings.Replace(s, validDataDirLine, "", 1) },
			want:   "server.data_dir",
		},
		{
			name:   "missing email",
			mutate: func(s string) string { return strings.Replace(s, `email: "ops@example.com"`, "", 1) },
			want:   "acme.email",
		},
		{
			name:   "default_ca refers to unknown CA",
			mutate: func(s string) string { return strings.Replace(s, `default_ca: letsencrypt`, `default_ca: nope`, 1) },
			want:   "acme.default_ca",
		},
		{
			name:   "cert ca refers to unknown CA",
			mutate: func(s string) string { return strings.Replace(s, `ca: letsencrypt`, `ca: nope`, 1) },
			want:   `unknown CA "nope"`,
		},
		{
			name:   "cert dns_provider refers to unknown provider",
			mutate: func(s string) string { return strings.Replace(s, `dns_provider: cf-main`, `dns_provider: ghost`, 1) },
			want:   `unknown DNS provider "ghost"`,
		},
		{
			name:   "duplicate cert name",
			mutate: func(s string) string { return strings.Replace(s, "- name: internal", "- name: api-prod", 1) },
			want:   "duplicate certificate name",
		},
		{
			name:   "invalid key_type",
			mutate: func(s string) string { return strings.Replace(s, "key_type: rsa4096", "key_type: rsa1024", 1) },
			want:   "invalid key_type",
		},
		{
			name:   "unknown DNS provider type",
			mutate: func(s string) string { return strings.Replace(s, "type: cloudflare", "type: madeup", 1) },
			want:   `unknown DNS provider type`,
		},
		{
			name:   "eab_kid without eab_hmac",
			mutate: func(s string) string { return strings.Replace(s, `eab_hmac: "h"`, "", 1) },
			want:   "eab_kid and eab_hmac must be set together",
		},
		{
			name:   "invalid domain",
			mutate: func(s string) string { return strings.Replace(s, "internal.example.com", "not_a_domain..bad", 1) },
			want:   "invalid domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseServer([]byte(tt.mutate(validServerYAML)))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got: %v", tt.want, err)
			}
		})
	}
}

func TestParseServer_ClientNamesMustBeLowercaseDNSLabels(t *testing.T) {
	src := strings.Replace(validServerYAML, "subscribers: [web-1, web-2]", "subscribers: [web-1, Web-2]", 1)
	_, err := ParseServer([]byte(src))
	if err == nil || !strings.Contains(err.Error(), `certificates[0].subscribers[1]: invalid client name "Web-2"`) {
		t.Fatalf("expected subscriber name error, got %v", err)
	}

	e2eNames := strings.Replace(validServerYAML, "subscribers: [web-1, web-2]", "subscribers: [web-1, expiry-test, revoke-test]", 1)
	if _, err := ParseServer([]byte(e2eNames)); err != nil {
		t.Fatalf("E2E client names rejected: %v", err)
	}
}

func TestParseServer_UnknownFieldRejected(t *testing.T) {
	bad := validServerYAML + "\nfoo_bar: 1\n"
	_, err := ParseServer([]byte(bad))
	if err == nil {
		t.Fatal("expected error for unknown top-level field, got nil")
	}
}

// Releases before GET /v1/sync had a clients section; it is rejected as an
// unknown field, not read.
func TestParseServer_ClientsSectionRejected(t *testing.T) {
	src := validServerYAML + `
clients:
  - name: web-1
`
	_, err := ParseServer([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "field clients not found") {
		t.Fatalf("expected clients to be rejected as an unknown field, got %v", err)
	}
}

func TestParseServer_UnknownACMEFieldRejected(t *testing.T) {
	bad := strings.Replace(validServerYAML, "  default_ca: letsencrypt",
		"  default_ca: letsencrypt\n  dns_resolver: [\"1.1.1.1\"]", 1)
	_, err := ParseServer([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "dns_resolver") {
		t.Fatalf("expected unknown acme field error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// acme.dns_resolvers
// ---------------------------------------------------------------------------

func withDNSResolvers(resolvers ...string) string {
	quoted := make([]string, len(resolvers))
	for i, r := range resolvers {
		quoted[i] = strconv.Quote(r)
	}
	return strings.Replace(validServerYAML, "  default_ca: letsencrypt",
		"  default_ca: letsencrypt\n  dns_resolvers: ["+strings.Join(quoted, ", ")+"]", 1)
}

func TestParseServer_DNSResolvers(t *testing.T) {
	valid := []string{
		"1.1.1.1",
		"1.1.1.1:53",
		"2001:db8::1",
		"[2001:db8::1]:5353",
		"dns.example.com",
		"challtestsrv:8053",
	}
	cfg, err := ParseServer([]byte(withDNSResolvers(valid...)))
	if err != nil {
		t.Fatalf("valid resolvers rejected: %v", err)
	}
	if !slices.Equal(cfg.ACME.DNSResolvers, valid) {
		t.Fatalf("dns_resolvers = %q, want %q", cfg.ACME.DNSResolvers, valid)
	}

	for _, resolver := range []string{
		"",
		"[::1]", // lego would turn it into "[[::1]]:53"
		"1.1.1.1:0",
		"1.1.1.1:65536",
		"1.1.1.1:dns",
		"dns.example.com:",
		"udp://1.1.1.1",
		"1.1.1.0/24",
		"dns .example.com",
		" 1.1.1.1",
	} {
		t.Run(strconv.Quote(resolver), func(t *testing.T) {
			_, err := ParseServer([]byte(withDNSResolvers("1.1.1.1", resolver)))
			if err == nil || !strings.Contains(err.Error(), "acme.dns_resolvers[1]: invalid DNS resolver") {
				t.Fatalf("expected invalid resolver error, got %v", err)
			}
		})
	}
}

// server.listen is host:port with a decimal port, which PublicBaseURL puts
// in the URL it derives when server.public_url is not set.
func TestParseServer_Listen(t *testing.T) {
	for _, listen := range []string{
		":8443",
		"0.0.0.0:8443",
		"[::]:8443",
		"127.0.0.1:1",
		"sigil.internal:65535",
	} {
		src := strings.Replace(validServerYAML, `listen: ":8443"`, "listen: "+strconv.Quote(listen), 1)
		if _, err := ParseServer([]byte(src)); err != nil {
			t.Errorf("listen %q rejected: %v", listen, err)
		}
	}

	for _, listen := range []string{
		":",
		"8443",
		"sigil.internal",
		":0",
		":65536",
		":https",
		":-1",
		"[::1]",
		"::1:8443",
	} {
		t.Run(strconv.Quote(listen), func(t *testing.T) {
			src := strings.Replace(validServerYAML, `listen: ":8443"`, "listen: "+strconv.Quote(listen), 1)
			_, err := ParseServer([]byte(src))
			if want := "server.listen: invalid listen address " + strconv.Quote(listen); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want %s", err, want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DNS provider required-field validation
// ---------------------------------------------------------------------------

// dnsOnlyYAML is a minimal server YAML with only one DNS provider and one cert;
// it is parametrised by the dns_providers block so each sub-test can inject
// its own provider definition.
func dnsServerYAML(providersBlock string) string {
	return `
server:
  listen: ":8443"
  ` + validDataDirLine + `

acme:
  email: "ops@example.com"
  default_ca: le
  cas:
    le:
      directory: "https://acme-v02.api.letsencrypt.org/directory"

` + providersBlock + `

certificates:
  - name: api-prod
    domains: ["api.example.com"]
    ca: le
    dns_provider: p1
`
}

func TestDNSProvider_Cloudflare_RequiresCredentials(t *testing.T) {
	// No api_token and no auth_email/auth_key.
	src := dnsServerYAML(`dns_providers:
  p1:
    type: cloudflare
`)
	_, err := ParseServer([]byte(src))
	if err == nil {
		t.Fatal("expected error for cloudflare with no credentials, got nil")
	}
	if !strings.Contains(err.Error(), "cloudflare") {
		t.Errorf("expected 'cloudflare' in error, got: %v", err)
	}
}

func TestDNSProvider_Cloudflare_ApiToken_Valid(t *testing.T) {
	src := dnsServerYAML(`dns_providers:
  p1:
    type: cloudflare
    api_token: "my-token"
`)
	_, err := ParseServer([]byte(src))
	if err != nil {
		t.Errorf("cloudflare with api_token: unexpected error: %v", err)
	}
}

func TestDNSProvider_Cloudflare_LegacyCreds_Valid(t *testing.T) {
	src := dnsServerYAML(`dns_providers:
  p1:
    type: cloudflare
    auth_email: "admin@example.com"
    auth_key: "global-api-key"
`)
	_, err := ParseServer([]byte(src))
	if err != nil {
		t.Errorf("cloudflare with auth_email+auth_key: unexpected error: %v", err)
	}
}

func TestDNSProvider_Aliyun_MissingFields(t *testing.T) {
	tests := []struct {
		name  string
		block string
		want  string
	}{
		{
			name: "missing access_key",
			block: `dns_providers:
  p1:
    type: aliyun
    access_secret: "sec"
`,
			want: "access_key",
		},
		{
			name: "missing access_secret",
			block: `dns_providers:
  p1:
    type: aliyun
    access_key: "key"
`,
			want: "access_secret",
		},
		{
			name: "both missing",
			block: `dns_providers:
  p1:
    type: aliyun
`,
			want: "access_key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseServer([]byte(dnsServerYAML(tt.block)))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("expected %q in error, got: %v", tt.want, err)
			}
		})
	}
}

func TestDNSProvider_Aliyun_Valid(t *testing.T) {
	src := dnsServerYAML(`dns_providers:
  p1:
    type: aliyun
    access_key: "key"
    access_secret: "secret"
`)
	_, err := ParseServer([]byte(src))
	if err != nil {
		t.Errorf("aliyun with all fields: unexpected error: %v", err)
	}
}

func TestDNSProvider_Tencentcloud_MissingFields(t *testing.T) {
	tests := []struct {
		name  string
		block string
		want  string
	}{
		{
			name: "missing secret_id",
			block: `dns_providers:
  p1:
    type: tencentcloud
    secret_key: "sk"
`,
			want: "secret_id",
		},
		{
			name: "missing secret_key",
			block: `dns_providers:
  p1:
    type: tencentcloud
    secret_id: "sid"
`,
			want: "secret_key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseServer([]byte(dnsServerYAML(tt.block)))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("expected %q in error, got: %v", tt.want, err)
			}
		})
	}
}

func TestDNSProvider_Route53_PartialKeys(t *testing.T) {
	// access_key without secret_key must fail.
	src := dnsServerYAML(`dns_providers:
  p1:
    type: route53
    access_key: "AKID"
`)
	_, err := ParseServer([]byte(src))
	if err == nil {
		t.Fatal("expected error for route53 with only access_key, got nil")
	}
	if !strings.Contains(err.Error(), "route53") {
		t.Errorf("expected 'route53' in error, got: %v", err)
	}
}

func TestDNSProvider_Route53_NoKeys_Valid(t *testing.T) {
	// No explicit keys — relies on IAM role; should be accepted.
	src := dnsServerYAML(`dns_providers:
  p1:
    type: route53
`)
	_, err := ParseServer([]byte(src))
	if err != nil {
		t.Errorf("route53 with no explicit keys (IAM role): unexpected error: %v", err)
	}
}

func TestDNSProvider_Route53_BothKeys_Valid(t *testing.T) {
	src := dnsServerYAML(`dns_providers:
  p1:
    type: route53
    access_key: "AKID"
    secret_key: "secret"
`)
	_, err := ParseServer([]byte(src))
	if err != nil {
		t.Errorf("route53 with both keys: unexpected error: %v", err)
	}
}

func TestDNSProvider_Gcloud_RequiresProjectOrServiceAccountFile(t *testing.T) {
	tests := []struct {
		name  string
		block string
		want  string // expected error substring; empty means valid
	}{
		{
			name: "neither project nor service_account_file",
			block: `dns_providers:
  p1:
    type: gcloud
`,
			want: "dns_providers.p1: gcloud provider requires project",
		},
		{
			name: "project with application default credentials",
			block: `dns_providers:
  p1:
    type: gcloud
    project: "my-proj"
`,
		},
		{
			name: "service_account_file",
			block: `dns_providers:
  p1:
    type: gcloud
    service_account_file: "` + absPath("/etc/sigil/gcloud.json") + `"
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseServer([]byte(dnsServerYAML(tt.block)))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

// hookPath is an absolute program path on the OS running the test; the
// YAML below single-quotes it so a Windows path needs no escaping.
func hookPath() string {
	if runtime.GOOS == "windows" {
		return `C:\sigil\dns-hook.exe`
	}
	return "/usr/local/bin/dns-hook"
}

func TestDNSProvider_Exec(t *testing.T) {
	tests := []struct {
		name  string
		block string
		want  string // expected error substring; empty means valid
	}{
		{
			name: "command with arguments",
			block: `dns_providers:
  p1:
    type: exec
    command: ['` + hookPath() + `', '--zone', 'example.com']
`,
		},
		{
			name: "missing command",
			block: `dns_providers:
  p1:
    type: exec
`,
			want: `dns_providers.p1.command: required for provider type "exec"`,
		},
		{
			name: "empty argument",
			block: `dns_providers:
  p1:
    type: exec
    command: ['` + hookPath() + `', '']
`,
			want: "dns_providers.p1.command[1]: must not be empty",
		},
		{
			name: "relative program path",
			block: `dns_providers:
  p1:
    type: exec
    command: ['hooks/dns-hook']
`,
			want: "dns_providers.p1.command[0]: must be an absolute program path",
		},
		{
			name: "credential key",
			block: `dns_providers:
  p1:
    type: exec
    command: ['` + hookPath() + `']
    api_token: "tok"
`,
			want: `dns_providers.p1.api_token: unknown field for provider type "exec"`,
		},
		{
			name: "misspelled command",
			block: `dns_providers:
  p1:
    type: exec
    comand: ['` + hookPath() + `']
`,
			want: `dns_providers.p1.comand: unknown field for provider type "exec"`,
		},
		{
			name: "command on another type",
			block: `dns_providers:
  p1:
    type: cloudflare
    api_token: "tok"
    command: ['` + hookPath() + `']
`,
			want: `dns_providers.p1.command: only valid for provider type "exec"`,
		},
		{
			name: "unknown type lists exec",
			block: `dns_providers:
  p1:
    type: madeup
`,
			want: "supported: cloudflare, aliyun, tencentcloud, route53, gcloud, exec",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseServer([]byte(dnsServerYAML(tt.block)))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				want := []string{hookPath(), "--zone", "example.com"}
				if got := cfg.DNSProviders["p1"].Command; !slices.Equal(got, want) {
					t.Fatalf("command = %q, want %q", got, want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestDNSProvider_SkipPropagationCheck(t *testing.T) {
	t.Setenv("SIGIL_TEST_SKIP_PROPAGATION", "true")
	src := dnsServerYAML(`dns_providers:
  p1:
    type: exec
    command: ['` + hookPath() + `']
    skip_propagation_check: ${SIGIL_TEST_SKIP_PROPAGATION}
  p2:
    type: cloudflare
    api_token: "tok"
`)
	cfg, err := ParseServer([]byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.DNSProviders["p1"].SkipPropagationCheck {
		t.Error("skip_propagation_check from ${VAR} did not decode as true")
	}
	if cfg.DNSProviders["p2"].SkipPropagationCheck {
		t.Error("skip_propagation_check should default to false")
	}
}

// ---------------------------------------------------------------------------
// PublicBaseURL
// ---------------------------------------------------------------------------

func TestPublicBaseURL_UsesPublicURL(t *testing.T) {
	src := strings.ReplaceAll(validServerYAML, `listen: ":8443"`,
		"listen: \":8443\"\n  public_url: \"https://sigil.example.com:8443\"")
	cfg, err := ParseServer([]byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.PublicBaseURL(); got != "https://sigil.example.com:8443" {
		t.Errorf("PublicBaseURL: got %q, want %q", got, "https://sigil.example.com:8443")
	}
}

func TestPublicBaseURL_FallsBackToListen(t *testing.T) {
	cfg, err := ParseServer([]byte(validServerYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := cfg.PublicBaseURL()
	if !strings.HasPrefix(got, "https://") {
		t.Errorf("PublicBaseURL fallback should start with https://, got %q", got)
	}
}

func TestPublicBaseURL_InvalidPublicURL(t *testing.T) {
	src := strings.ReplaceAll(validServerYAML, `listen: ":8443"`,
		"listen: \":8443\"\n  public_url: \"http://not-https.com\"")
	_, err := ParseServer([]byte(src))
	if err == nil {
		t.Fatal("expected error for http public_url, got nil")
	}
	if !strings.Contains(err.Error(), "public_url") {
		t.Errorf("expected 'public_url' in error, got: %v", err)
	}
}

func TestServerTLSFilesMustBeConfiguredTogether(t *testing.T) {
	certLine := `tls_cert_file: "` + absPath("/etc/sigil/tls.crt") + `"`
	src := strings.Replace(validServerYAML, validDataDirLine, validDataDirLine+"\n  "+certLine, 1)
	_, err := ParseServer([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "tls_cert_file and tls_key_file") {
		t.Fatalf("expected paired TLS file error, got %v", err)
	}

	src = strings.Replace(src, certLine, certLine+"\n  "+`tls_key_file: "`+absPath("/etc/sigil/tls.key")+`"`, 1)
	if _, err := ParseServer([]byte(src)); err != nil {
		t.Fatalf("valid TLS file config: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ReadServerPaths
// ---------------------------------------------------------------------------

func writeServerYAML(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadServerPaths_DoesNotRequireCredentialVariables(t *testing.T) {
	t.Setenv("SIGIL_TEST_IPC_SOCKET", absPath("/run/sigil/custom.sock"))
	src := strings.Replace(validServerYAML, validDataDirLine, `data_dir: "${SIGIL_TEST_UNSET_DATA_DIR:-`+absPath("/srv/sigils")+`}"
  ipc_socket: "${SIGIL_TEST_IPC_SOCKET}"`, 1)
	src = strings.Replace(src, `api_token: "tok"`, `api_token: "${SIGIL_TEST_UNSET_API_TOKEN}"`, 1)
	path := writeServerYAML(t, src)

	dataDir, ipcSocket, err := ReadServerPaths(path)
	if err != nil {
		t.Fatalf("ReadServerPaths: %v", err)
	}
	if dataDir != absPath("/srv/sigils") {
		t.Errorf("data_dir: got %q", dataDir)
	}
	if ipcSocket != absPath("/run/sigil/custom.sock") {
		t.Errorf("ipc_socket: got %q", ipcSocket)
	}
	if _, err := LoadServer(path); err == nil || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET_API_TOKEN") {
		t.Fatalf("LoadServer should still require the credential variable, got %v", err)
	}
}

func TestReadServerPaths_RejectsUnsetServerVariable(t *testing.T) {
	path := writeServerYAML(t, strings.Replace(validServerYAML,
		validDataDirLine, `data_dir: "${SIGIL_TEST_UNSET_DATA_DIR}"`, 1))
	_, _, err := ReadServerPaths(path)
	if err == nil || !strings.Contains(err.Error(), "server.data_dir") || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET_DATA_DIR") {
		t.Fatalf("expected unset data_dir variable error, got %v", err)
	}
}

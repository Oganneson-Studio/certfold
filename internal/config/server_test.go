package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validServerYAML = `
server:
  listen: ":8443"
  data_dir: "/var/lib/sigils"

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
  cf_main:
    type: cloudflare
    api_token: "tok"
  aliyun_a:
    type: aliyun
    access_key: "k"
    access_secret: "s"

certificates:
  - name: api-prod
    domains: ["api.example.com", "*.api.example.com"]
    ca: letsencrypt
    dns_provider: cf_main
    subscribers: [web-1, web-2]
  - name: internal
    domains: ["internal.example.com"]
    ca: zerossl
    dns_provider: aliyun_a
    key_type: rsa4096
    renew_days_before: 14
`

func TestParseServer_Valid(t *testing.T) {
	cfg, err := ParseServer([]byte(validServerYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != ":8443" {
		t.Errorf("listen: got %q", cfg.Server.Listen)
	}
	if cfg.Server.DataDir != "/var/lib/sigils" {
		t.Errorf("data_dir: got %q", cfg.Server.DataDir)
	}
	if len(cfg.Certificates) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(cfg.Certificates))
	}
	if cfg.Certificates[0].KeyType != DefaultKeyType {
		t.Errorf("cert[0] key_type default: got %q", cfg.Certificates[0].KeyType)
	}
	if cfg.Certificates[0].RenewDaysBefore != DefaultRenewDaysBefore {
		t.Errorf("cert[0] renew_days_before default: got %d", cfg.Certificates[0].RenewDaysBefore)
	}
	if cfg.Certificates[1].KeyType != "rsa4096" {
		t.Errorf("cert[1] explicit key_type: got %q", cfg.Certificates[1].KeyType)
	}
	if cfg.Certificates[1].RenewDaysBefore != 14 {
		t.Errorf("cert[1] explicit renew_days_before: got %d", cfg.Certificates[1].RenewDaysBefore)
	}
	if cfg.DNSProviders["cf_main"].Config["api_token"] != "tok" {
		t.Errorf("cf_main api_token: got %v", cfg.DNSProviders["cf_main"].Config["api_token"])
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
			mutate: func(s string) string { return strings.Replace(s, `data_dir: "/var/lib/sigils"`, "", 1) },
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
			mutate: func(s string) string { return strings.Replace(s, `dns_provider: cf_main`, `dns_provider: ghost`, 1) },
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
			name:   "renew window too large",
			mutate: func(s string) string { return strings.Replace(s, "renew_days_before: 14", "renew_days_before: 100", 1) },
			want:   "renew_days_before",
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

func TestParseServer_UnknownFieldRejected(t *testing.T) {
	bad := validServerYAML + "\nfoo_bar: 1\n"
	_, err := ParseServer([]byte(bad))
	if err == nil {
		t.Fatal("expected error for unknown top-level field, got nil")
	}
}

func TestParseServer_PushEndpointRequiresStrongToken(t *testing.T) {
	withClient := validServerYAML + `
clients:
  - name: web-1
    push_endpoint: "https://web-1.example.com/v1/push/notify"
`
	if _, err := ParseServer([]byte(withClient)); err == nil || !strings.Contains(err.Error(), "push_token") {
		t.Fatalf("expected missing push token error, got %v", err)
	}

	withToken := withClient + `    push_token: "0123456789abcdef0123456789abcdef"
`
	if _, err := ParseServer([]byte(withToken)); err != nil {
		t.Fatalf("valid push registration: %v", err)
	}
}

func TestParseServer_PushTokenRequiresEndpoint(t *testing.T) {
	withClient := validServerYAML + `
clients:
  - name: web-1
    push_token: "0123456789abcdef0123456789abcdef"
`
	if _, err := ParseServer([]byte(withClient)); err == nil || !strings.Contains(err.Error(), "push_endpoint") {
		t.Fatalf("expected missing push endpoint error, got %v", err)
	}
}

func TestParseServer_PushEndpointRejectsQueryCredentials(t *testing.T) {
	withClient := validServerYAML + `
clients:
  - name: web-1
    push_endpoint: "https://web-1.example.com/v1/push/notify?token=secret"
    push_token: "0123456789abcdef0123456789abcdef"
`
	if _, err := ParseServer([]byte(withClient)); err == nil || !strings.Contains(err.Error(), "query") {
		t.Fatalf("expected push endpoint query error, got %v", err)
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
  data_dir: "/var/lib/sigils"

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

func TestDNSProvider_Gcloud_NoFields_Valid(t *testing.T) {
	// gcloud with no explicit config uses ADC — should be accepted.
	src := dnsServerYAML(`dns_providers:
  p1:
    type: gcloud
`)
	_, err := ParseServer([]byte(src))
	if err != nil {
		t.Errorf("gcloud with no explicit fields: unexpected error: %v", err)
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
	src := strings.Replace(validServerYAML, `data_dir: "/var/lib/sigils"`, `data_dir: "/var/lib/sigils"
  tls_cert_file: "/etc/sigil/tls.crt"`, 1)
	_, err := ParseServer([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "tls_cert_file and tls_key_file") {
		t.Fatalf("expected paired TLS file error, got %v", err)
	}

	src = strings.Replace(src, `tls_cert_file: "/etc/sigil/tls.crt"`, `tls_cert_file: "/etc/sigil/tls.crt"
  tls_key_file: "/etc/sigil/tls.key"`, 1)
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
	t.Setenv("SIGIL_TEST_IPC_SOCKET", "/run/sigil/custom.sock")
	src := strings.Replace(validServerYAML, `data_dir: "/var/lib/sigils"`, `data_dir: "${SIGIL_TEST_UNSET_DATA_DIR:-/srv/sigils}"
  ipc_socket: "${SIGIL_TEST_IPC_SOCKET}"`, 1)
	src = strings.Replace(src, `api_token: "tok"`, `api_token: "${SIGIL_TEST_UNSET_API_TOKEN}"`, 1)
	path := writeServerYAML(t, src)

	dataDir, ipcSocket, err := ReadServerPaths(path)
	if err != nil {
		t.Fatalf("ReadServerPaths: %v", err)
	}
	if dataDir != "/srv/sigils" {
		t.Errorf("data_dir: got %q", dataDir)
	}
	if ipcSocket != "/run/sigil/custom.sock" {
		t.Errorf("ipc_socket: got %q", ipcSocket)
	}
	if _, err := LoadServer(path); err == nil || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET_API_TOKEN") {
		t.Fatalf("LoadServer should still require the credential variable, got %v", err)
	}
}

func TestReadServerPaths_RejectsUnsetServerVariable(t *testing.T) {
	path := writeServerYAML(t, strings.Replace(validServerYAML,
		`data_dir: "/var/lib/sigils"`, `data_dir: "${SIGIL_TEST_UNSET_DATA_DIR}"`, 1))
	_, _, err := ReadServerPaths(path)
	if err == nil || !strings.Contains(err.Error(), "server.data_dir") || !strings.Contains(err.Error(), "SIGIL_TEST_UNSET_DATA_DIR") {
		t.Fatalf("expected unset data_dir variable error, got %v", err)
	}
}

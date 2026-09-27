package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testPEMs holds self-signed cert / key material reused across sub-tests.
var testPEMs struct {
	caCert     string
	clientCert string
	clientKey  string
}

func init() {
	ca, caKey := mustSelfSigned("ca")
	cl, clKey := mustSelfSigned("client")
	_ = caKey
	testPEMs.caCert = ca
	testPEMs.clientCert = cl
	testPEMs.clientKey = clKey
}

// mustSelfSigned returns a PEM-encoded self-signed certificate and its private
// key PEM (PKCS8). Panics on error so tests fail fast.
func mustSelfSigned(cn string) (certPEM, keyPEM string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return
}

// validClientYAML is a minimal, fully-valid client configuration.
const validClientYAML = `
client:
  name: web-1
  server_url: "https://sigil.example.com:8443"
  pull_interval: "1h"
`

func withIdentity(base string) string {
	return base + "identity:\n" +
		"  ca_cert: |\n" + indent(testPEMs.caCert) +
		"  client_cert: |\n" + indent(testPEMs.clientCert) +
		"  client_key: |\n" + indent(testPEMs.clientKey)
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Happy-path: valid YAML parses without error
// ---------------------------------------------------------------------------

func TestParseClient_Valid(t *testing.T) {
	cfg, err := ParseClient([]byte(validClientYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Client.Name != "web-1" {
		t.Errorf("name: got %q", cfg.Client.Name)
	}
	if cfg.Client.ServerURL != "https://sigil.example.com:8443" {
		t.Errorf("server_url: got %q", cfg.Client.ServerURL)
	}
	if cfg.Client.PullInterval != time.Hour {
		t.Errorf("pull_interval: got %v", cfg.Client.PullInterval)
	}
}

func TestParseClient_DefaultPullInterval(t *testing.T) {
	src := strings.Replace(validClientYAML, `pull_interval: "1h"`, "", 1)
	cfg, err := ParseClient([]byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Client.PullInterval != DefaultPullInterval {
		t.Errorf("default pull_interval: got %v", cfg.Client.PullInterval)
	}
}

func TestParseClient_DefaultIdentityRenewBefore(t *testing.T) {
	cfg, err := ParseClient([]byte(validClientYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Client.IdentityRenewBefore != DefaultIdentityRenewBefore {
		t.Errorf("default identity_renew_before: got %v", cfg.Client.IdentityRenewBefore)
	}
}

func TestParseClient_DataDir(t *testing.T) {
	cfg, err := ParseClient([]byte(validClientYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Client.DataDir != DefaultClientDataDir() {
		t.Errorf("default data_dir: got %q, want %q", cfg.Client.DataDir, DefaultClientDataDir())
	}

	src := strings.Replace(validClientYAML, `pull_interval: "1h"`, `pull_interval: "1h"
  data_dir: "/srv/sigilc"`, 1)
	cfg, err = ParseClient([]byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Client.DataDir != "/srv/sigilc" {
		t.Errorf("explicit data_dir: got %q", cfg.Client.DataDir)
	}
}

// ---------------------------------------------------------------------------
// Env interpolation
// ---------------------------------------------------------------------------

func TestParseClient_EnvInterpolation(t *testing.T) {
	t.Setenv("SRV_URL", "https://env.example.com:8443")
	src := strings.Replace(validClientYAML,
		`server_url: "https://sigil.example.com:8443"`,
		`server_url: "${SRV_URL}"`, 1)
	cfg, err := ParseClient([]byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Client.ServerURL != "https://env.example.com:8443" {
		t.Errorf("interpolated server_url: got %q", cfg.Client.ServerURL)
	}
}

// ---------------------------------------------------------------------------
// Identity: all-present / all-absent / partial rules
// ---------------------------------------------------------------------------

func TestParseClient_IdentityAllPresent(t *testing.T) {
	_, err := ParseClient([]byte(withIdentity(validClientYAML)))
	if err != nil {
		t.Fatalf("unexpected error with full identity: %v", err)
	}
}

func TestParseClient_IdentityAllAbsent(t *testing.T) {
	_, err := ParseClient([]byte(validClientYAML))
	if err != nil {
		t.Fatalf("unexpected error with no identity (pre-enroll): %v", err)
	}
}

func TestParseClient_IdentityPartialErrors(t *testing.T) {
	onlyCA := validClientYAML + "identity:\n" +
		"  ca_cert: |\n" + indent(testPEMs.caCert)
	_, err := ParseClient([]byte(onlyCA))
	if err == nil {
		t.Fatal("expected error for partial identity, got nil")
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Fatalf("expected error mentioning identity, got: %v", err)
	}
}

func TestParseClient_IdentityInvalidPEM(t *testing.T) {
	badCert := validClientYAML + "identity:\n" +
		"  ca_cert: |\n    -----BEGIN CERTIFICATE-----\n    bm90YmFzZTY0\n    -----END CERTIFICATE-----\n" +
		"  client_cert: |\n" + indent(testPEMs.clientCert) +
		"  client_key: |\n" + indent(testPEMs.clientKey)
	_, err := ParseClient([]byte(badCert))
	if err == nil {
		t.Fatal("expected PEM parse error, got nil")
	}
	if !strings.Contains(err.Error(), "identity.ca_cert") {
		t.Fatalf("expected error mentioning identity.ca_cert, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Outputs: valid / invalid format / pkcs12 password
// ---------------------------------------------------------------------------

func TestParseClient_OutputsValid(t *testing.T) {
	src := validClientYAML + `
outputs:
  api-prod:
    - format: pem-fullchain
      path: /etc/nginx/certs/api.crt
      mode: 420
    - format: pem-key
      path: /etc/nginx/certs/api.key
      mode: 384
    - format: pkcs12
      path: /etc/app/keystore.p12
      password: "secret"
`
	_, err := ParseClient([]byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseClient_OutputsInvalidFormat(t *testing.T) {
	src := validClientYAML + `
outputs:
  api-prod:
    - format: jks
      path: /etc/app/keystore.jks
`
	_, err := ParseClient([]byte(src))
	if err == nil {
		t.Fatal("expected error for unsupported format jks, got nil")
	}
	if !strings.Contains(err.Error(), "format") {
		t.Fatalf("expected error mentioning format, got: %v", err)
	}
}

func TestParseClient_OutputsMissingPath(t *testing.T) {
	src := validClientYAML + `
outputs:
  api-prod:
    - format: pem-cert
`
	_, err := ParseClient([]byte(src))
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Fatalf("expected error mentioning path, got: %v", err)
	}
}

func TestParseClient_OutputsPkcs12RequiresPassword(t *testing.T) {
	src := validClientYAML + `
outputs:
  api-prod:
    - format: pkcs12
      path: /etc/app/keystore.p12
`
	_, err := ParseClient([]byte(src))
	if err == nil {
		t.Fatal("expected error for pkcs12 without password, got nil")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Fatalf("expected error mentioning password, got: %v", err)
	}
}

func TestParseClient_OutputInvalidMode(t *testing.T) {
	src := validClientYAML + `
outputs:
  api-prod:
    - format: pem-cert
      path: /etc/nginx/certs/api.crt
      mode: 1000
`
	_, err := ParseClient([]byte(src))
	if err == nil {
		t.Fatal("expected error for invalid mode, got nil")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Fatalf("expected error mentioning mode, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Validation: required fields, URL scheme, pull_interval floor
// ---------------------------------------------------------------------------

func TestParseClient_ValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{
			name:   "missing name",
			mutate: func(s string) string { return strings.Replace(s, "name: web-1", "", 1) },
			want:   "client.name",
		},
		{
			name: "missing server_url",
			mutate: func(s string) string {
				return strings.Replace(s, `server_url: "https://sigil.example.com:8443"`, "", 1)
			},
			want: "client.server_url",
		},
		{
			name: "server_url must be https",
			mutate: func(s string) string {
				return strings.Replace(s, "https://sigil.example.com:8443", "http://sigil.example.com:8443", 1)
			},
			want: "https",
		},
		{
			name: "pull_interval below 30s",
			mutate: func(s string) string {
				return strings.Replace(s, `pull_interval: "1h"`, `pull_interval: "10s"`, 1)
			},
			want: "pull_interval",
		},
		{
			name: "identity renewal window too short",
			mutate: func(s string) string {
				return strings.Replace(s, `pull_interval: "1h"`, `pull_interval: "1h"
  identity_renew_before: "30m"`, 1)
			},
			want: "identity_renew_before",
		},
		{
			name: "identity renewal window too long",
			mutate: func(s string) string {
				return strings.Replace(s, `pull_interval: "1h"`, `pull_interval: "1h"
  identity_renew_before: "2160h"`, 1)
			},
			want: "identity_renew_before",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseClient([]byte(tt.mutate(validClientYAML)))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got: %v", tt.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unknown fields are rejected
// ---------------------------------------------------------------------------

func TestParseClient_UnknownFieldRejected(t *testing.T) {
	bad := validClientYAML + "\nfoo_bar: 1\n"
	_, err := ParseClient([]byte(bad))
	if err == nil {
		t.Fatal("expected error for unknown top-level field, got nil")
	}
}

func TestParseClient_PushRequiresStrongToken(t *testing.T) {
	withoutToken := strings.Replace(validClientYAML, `pull_interval: "1h"`, `pull_interval: "1h"
  push_listen: "127.0.0.1:9443"`, 1)
	if _, err := ParseClient([]byte(withoutToken)); err == nil || !strings.Contains(err.Error(), "push_token") {
		t.Fatalf("expected missing push token error, got %v", err)
	}

	withToken := strings.Replace(withoutToken, `push_listen: "127.0.0.1:9443"`, `push_listen: "127.0.0.1:9443"
  push_token: "0123456789abcdef0123456789abcdef"`, 1)
	if _, err := ParseClient([]byte(withToken)); err != nil {
		t.Fatalf("valid push config: %v", err)
	}
}

func TestParseClient_PushListenRequiresLoopback(t *testing.T) {
	tests := []struct {
		name    string
		listen  string
		wantErr bool
	}{
		{name: "IPv4 loopback", listen: "127.0.0.1:9443"},
		{name: "IPv4 loopback range", listen: "127.1.2.3:9443"},
		{name: "IPv6 loopback", listen: "[::1]:9443"},
		{name: "empty host wildcard", listen: ":9443", wantErr: true},
		{name: "IPv4 wildcard", listen: "0.0.0.0:9443", wantErr: true},
		{name: "IPv6 wildcard", listen: "[::]:9443", wantErr: true},
		{name: "network interface", listen: "192.0.2.10:9443", wantErr: true},
		{name: "hostname", listen: "localhost:9443", wantErr: true},
		{name: "missing port", listen: "127.0.0.1", wantErr: true},
		{name: "zero port", listen: "127.0.0.1:0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := strings.Replace(validClientYAML, `pull_interval: "1h"`, `pull_interval: "1h"
  push_listen: "`+tt.listen+`"
  push_token: "0123456789abcdef0123456789abcdef"`, 1)
			_, err := ParseClient([]byte(src))
			if tt.wantErr && (err == nil || !strings.Contains(err.Error(), "client.push_listen")) {
				t.Fatalf("expected push_listen error, got %v", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected valid loopback listener, got %v", err)
			}
		})
	}
}

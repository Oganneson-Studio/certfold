package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"runtime"
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

	src := strings.Replace(validClientYAML, `server_url: "https://sigil.example.com:8443"`, `server_url: "https://sigil.example.com:8443"
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
// Certificates: outputs and on_change
// ---------------------------------------------------------------------------

func TestParseClient_OutputsValid(t *testing.T) {
	src := validClientYAML + `
certificates:
  api-prod:
    outputs:
      - format: pem-fullchain
        path: /etc/nginx/certs/api.crt
        mode: 420
      - format: pem-key
        path: /etc/nginx/certs/api.key
        mode: 384
      - format: pkcs12
        path: /etc/app/keystore.p12
        password: "secret"
    on_change: ['` + hookPath() + `', '-s', 'reload']
  api-stage:
    outputs:
      - format: pem-bundle
        path: /etc/nginx/certs/stage.pem
`
	cfg, err := ParseClient([]byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]CertificateOutputs{
		"api-prod": {
			Outputs: []OutputSpec{
				{Format: "pem-fullchain", Path: "/etc/nginx/certs/api.crt", Mode: 0o644},
				{Format: "pem-key", Path: "/etc/nginx/certs/api.key", Mode: 0o600},
				{Format: "pkcs12", Path: "/etc/app/keystore.p12", Password: "secret"},
			},
			OnChange: []string{hookPath(), "-s", "reload"},
		},
		"api-stage": {
			Outputs: []OutputSpec{{Format: "pem-bundle", Path: "/etc/nginx/certs/stage.pem"}},
		},
	}
	if !reflect.DeepEqual(cfg.Certificates, want) {
		t.Fatalf("certificates = %+v, want %+v", cfg.Certificates, want)
	}
}

// Releases before the certificates section had a top-level outputs; it is
// rejected as an unknown field, not read.
func TestParseClient_TopLevelOutputsRejected(t *testing.T) {
	src := validClientYAML + `
outputs:
  api-prod:
    - format: pem-fullchain
      path: /etc/nginx/certs/api.crt
`
	_, err := ParseClient([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "field outputs not found") {
		t.Fatalf("expected top-level outputs to be rejected as an unknown field, got %v", err)
	}
}

func TestParseClient_OnChangeEmptyMeansNoProgram(t *testing.T) {
	for _, tt := range []struct{ name, onChange string }{
		{name: "absent"},
		{name: "null", onChange: "    on_change: null\n"},
		{name: "empty list", onChange: "    on_change: []\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := validClientYAML + `
certificates:
  api-prod:
    outputs:
      - format: pem-fullchain
        path: /etc/nginx/certs/api.crt
` + tt.onChange
			cfg, err := ParseClient([]byte(src))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := cfg.Certificates["api-prod"].OnChange; len(got) != 0 {
				t.Fatalf("on_change = %q, want no program", got)
			}
		})
	}
}

func TestParseClient_CertificatesValidationErrors(t *testing.T) {
	tests := []struct {
		name  string
		block string // entries under certificates:
		want  string
	}{
		{
			name: "invalid format",
			block: `  api-prod:
    outputs:
      - format: jks
        path: /etc/app/keystore.jks
`,
			want: `certificates.api-prod.outputs[0].format: invalid format "jks"`,
		},
		{
			name: "missing path",
			block: `  api-prod:
    outputs:
      - format: pem-cert
`,
			want: "certificates.api-prod.outputs[0].path: must be set",
		},
		{
			name: "pkcs12 without password",
			block: `  api-prod:
    outputs:
      - format: pkcs12
        path: /etc/app/keystore.p12
`,
			want: "certificates.api-prod.outputs[0].password: required for pkcs12 format",
		},
		{
			name: "invalid mode",
			block: `  api-prod:
    outputs:
      - format: pem-cert
        path: /etc/nginx/certs/api.crt
        mode: 1000
`,
			want: "certificates.api-prod.outputs[0].mode: must be a valid octal file mode",
		},
		{
			name: "no outputs",
			block: `  api-prod:
    on_change: ['` + hookPath() + `']
`,
			want: "certificates.api-prod.outputs: must have at least one output",
		},
		{
			name: "empty certificate name",
			block: `  "":
    outputs:
      - format: pem-cert
        path: /etc/nginx/certs/api.crt
`,
			want: `certificates: invalid certificate name ""`,
		},
		{
			// server.yaml names certificates under the rule of client
			// names, so this name could never match one.
			name: "certificate name outside the rule",
			block: `  Api_Prod:
    outputs:
      - format: pem-cert
        path: /etc/nginx/certs/api.crt
`,
			want: `certificates: invalid certificate name "Api_Prod": must be a lowercase DNS label`,
		},
		{
			name: "relative program path",
			block: `  api-prod:
    outputs:
      - format: pem-cert
        path: /etc/nginx/certs/api.crt
    on_change: ['bin/reload', '--all']
`,
			want: "certificates.api-prod.on_change[0]: must be an absolute program path",
		},
		{
			name: "empty program path",
			block: `  api-prod:
    outputs:
      - format: pem-cert
        path: /etc/nginx/certs/api.crt
    on_change: ['']
`,
			want: "certificates.api-prod.on_change[0]: must not be empty",
		},
		{
			name: "empty argument",
			block: `  api-prod:
    outputs:
      - format: pem-cert
        path: /etc/nginx/certs/api.crt
    on_change: ['` + hookPath() + `', '']
`,
			want: "certificates.api-prod.on_change[1]: must not be empty",
		},
		{
			name: "duplicate output path",
			block: `  api-prod:
    outputs:
      - format: pem-cert
        path: /etc/nginx/certs/api.pem
      - format: pem-key
        path: /etc/nginx/certs/api.pem
`,
			want: `certificates.api-prod.outputs[1].path: duplicate output path "/etc/nginx/certs/api.pem" (also at certificates.api-prod.outputs[0])`,
		},
		{
			name: "output path equal once cleaned",
			block: `  api-prod:
    outputs:
      - format: pem-cert
        path: /etc/nginx/certs/api.pem
  api-stage:
    outputs:
      - format: pem-cert
        path: /etc/nginx/./certs/api.pem
`,
			want: `certificates.api-stage.outputs[0].path: duplicate output path "/etc/nginx/./certs/api.pem" (also at certificates.api-prod.outputs[0])`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseClient([]byte(validClientYAML + "certificates:\n" + tt.block))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestParseClient_OutputPathsDifferingInCase(t *testing.T) {
	block := `  api-prod:
    outputs:
      - format: pem-cert
        path: /etc/nginx/certs/Api.pem
      - format: pem-key
        path: /etc/nginx/certs/api.pem
`
	_, err := ParseClient([]byte(validClientYAML + "certificates:\n" + block))
	if runtime.GOOS != "windows" {
		if err != nil {
			t.Fatalf("paths differing in case are two files here, got %v", err)
		}
		return
	}
	want := `certificates.api-prod.outputs[1].path: duplicate output path "/etc/nginx/certs/api.pem" (also at certificates.api-prod.outputs[0])`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}

// ---------------------------------------------------------------------------
// Validation: required fields, URL scheme, identity renewal window
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
			want:   "client.name: must be set",
		},
		{
			// The name is the CN of the client certificate, which sigils
			// issues only for names under the rule.
			name:   "name outside the rule",
			mutate: func(s string) string { return strings.Replace(s, "name: web-1", "name: Web_1", 1) },
			want:   `client.name: invalid client name "Web_1": must be a lowercase DNS label`,
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
			name: "identity renewal window too short",
			mutate: func(s string) string {
				return strings.Replace(s, `server_url: "https://sigil.example.com:8443"`, `server_url: "https://sigil.example.com:8443"
  identity_renew_before: "30m"`, 1)
			},
			want: "identity_renew_before",
		},
		{
			name: "identity renewal window too long",
			mutate: func(s string) string {
				return strings.Replace(s, `server_url: "https://sigil.example.com:8443"`, `server_url: "https://sigil.example.com:8443"
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

// Releases before GET /v1/sync had pull_interval, push_listen and push_token
// under client; they are rejected as unknown fields, not read.
func TestParseClient_RemovedKeysRejected(t *testing.T) {
	for _, line := range []string{
		`pull_interval: "1h"`,
		`push_listen: "127.0.0.1:9443"`,
		`push_token: "0123456789abcdef0123456789abcdef"`,
	} {
		key, _, _ := strings.Cut(line, ":")
		t.Run(key, func(t *testing.T) {
			src := strings.Replace(validClientYAML, `server_url: "https://sigil.example.com:8443"`, `server_url: "https://sigil.example.com:8443"
  `+line, 1)
			_, err := ParseClient([]byte(src))
			if err == nil || !strings.Contains(err.Error(), "field "+key+" not found") {
				t.Fatalf("expected %s to be rejected as an unknown field, got %v", key, err)
			}
		})
	}
}

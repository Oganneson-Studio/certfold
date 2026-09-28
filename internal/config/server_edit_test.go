package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEditTestConfig(t *testing.T, certificates string) string {
	t.Helper()
	t.Setenv("SIGIL_TEST_ACCESS_KEY", "expanded-access-key")
	t.Setenv("SIGIL_TEST_SECRET_KEY", "expanded-secret-key")
	path := filepath.Join(t.TempDir(), "server.yaml")
	raw := `# preserve this operator comment
server:
  listen: ":8443"
  data_dir: "C:/sigil-test"
acme:
  email: "admin@example.com"
  default_ca: "le"
  cas:
    le:
      directory: "https://acme.example.com/directory"
dns_providers:
  route:
    type: route53
    access_key: ${SIGIL_TEST_ACCESS_KEY}
    secret_key: ${SIGIL_TEST_SECRET_KEY}
certificates:
` + certificates
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAddCertificateSpecPreservesPlaceholdersAndUsesDefaultCA(t *testing.T) {
	path := writeEditTestConfig(t, "  []\n")
	spec, err := AddCertificateSpec(path, CertificateSpec{
		Name:        "api-prod",
		Domains:     []string{"api.example.com"},
		DNSProvider: "route",
		KeyType:     "ec256",
		Subscribers: []string{"web-1"},
	})
	if err != nil {
		t.Fatalf("AddCertificateSpec: %v", err)
	}
	if spec.CA != "le" {
		t.Fatalf("CA = %q, want default le", spec.CA)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"# preserve this operator comment", "${SIGIL_TEST_ACCESS_KEY}", "${SIGIL_TEST_SECRET_KEY}"} {
		if !strings.Contains(text, want) {
			t.Errorf("updated config lost %q:\n%s", want, text)
		}
	}
	for _, secret := range []string{"expanded-access-key", "expanded-secret-key"} {
		if strings.Contains(text, secret) {
			t.Errorf("updated config persisted expanded secret %q", secret)
		}
	}

	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("load updated config: %v", err)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Name != "api-prod" || cfg.Certificates[0].CA != "le" {
		t.Fatalf("unexpected certificates: %+v", cfg.Certificates)
	}
}

// Values taken from the command line are not environment references: a '$'
// in them stays literal. No setting of a certificate admits a '$', so such a
// value is refused as it was given, instead of expanding into one that
// passes.
func TestAddCertificateSpecKeepsDollarSignsLiteral(t *testing.T) {
	t.Setenv("SIGIL_TEST_NAME", "api-prod")
	t.Setenv("SIGIL_TEST_PROVIDER", "route")
	path := writeEditTestConfig(t, "  []\n")
	for _, tc := range []struct {
		name, provider, want string
	}{
		{"${SIGIL_TEST_NAME}", "route", `invalid certificate name "${SIGIL_TEST_NAME}"`},
		{"a$$b", "route", `invalid certificate name "a$$b"`},
		{"api-prod", "${SIGIL_TEST_PROVIDER}", `references unknown DNS provider "${SIGIL_TEST_PROVIDER}"`},
	} {
		_, err := AddCertificateSpec(path, CertificateSpec{
			Name:        tc.name,
			Domains:     []string{"api.example.com"},
			DNSProvider: tc.provider,
			KeyType:     "ec256",
		})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("AddCertificateSpec(%q, %q): error = %v, want %s", tc.name, tc.provider, err, tc.want)
		}
	}
}

func TestAddCertificateSpecFailureLeavesFileUnchanged(t *testing.T) {
	path := writeEditTestConfig(t, `  - name: api-prod
    domains: [api.example.com]
    ca: le
    dns_provider: route
    key_type: ec256
`)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = AddCertificateSpec(path, CertificateSpec{
		Name:        "api-prod",
		Domains:     []string{"other.example.com"},
		DNSProvider: "route",
		KeyType:     "ec256",
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate add error = %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, before) {
		t.Fatal("duplicate add modified server.yaml")
	}

	_, err = AddCertificateSpec(path, CertificateSpec{
		Name:        "bad-provider",
		Domains:     []string{"bad.example.com"},
		DNSProvider: "missing",
		KeyType:     "ec256",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown DNS provider") {
		t.Fatalf("invalid add error = %v", err)
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(after, before) {
		t.Fatal("invalid add modified server.yaml")
	}
}

func TestRemoveCertificateSpecIsExactAndFailureLeavesFileUnchanged(t *testing.T) {
	path := writeEditTestConfig(t, `  - name: api-prod
    domains: [api.example.com]
    ca: le
    dns_provider: route
    key_type: ec256
  - name: api-stage
    domains: [stage.example.com]
    ca: le
    dns_provider: route
    key_type: ec256
`)
	if err := RemoveCertificateSpec(path, "api-prod"); err != nil {
		t.Fatalf("RemoveCertificateSpec: %v", err)
	}
	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Name != "api-stage" {
		t.Fatalf("unexpected certificates after remove: %+v", cfg.Certificates)
	}

	before, _ := os.ReadFile(path)
	err = RemoveCertificateSpec(path, "API-STAGE")
	if err == nil || !strings.Contains(err.Error(), `cert "API-STAGE" not found`) {
		t.Fatalf("missing remove error = %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, before) {
		t.Fatal("missing remove modified server.yaml")
	}
}

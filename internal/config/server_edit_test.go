package config

import (
	"errors"
	"strings"
	"testing"
)

func editTestConfig(t *testing.T, certificates string) []byte {
	t.Helper()
	t.Setenv("SIGIL_TEST_ACCESS_KEY", "expanded-access-key")
	t.Setenv("SIGIL_TEST_SECRET_KEY", "expanded-secret-key")
	return []byte(`# preserve this operator comment
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
` + certificates)
}

func TestAddCertificateSpecPreservesPlaceholdersAndUsesDefaultCA(t *testing.T) {
	raw, cfg, err := AddCertificateSpec(editTestConfig(t, "  []\n"), CertificateSpec{
		Name:        "api-prod",
		Domains:     []string{"api.example.com"},
		DNSProvider: "route",
		KeyType:     "ec256",
		Subscribers: []string{"web-1"},
	})
	if err != nil {
		t.Fatalf("AddCertificateSpec: %v", err)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Name != "api-prod" || cfg.Certificates[0].CA != "le" {
		t.Fatalf("unexpected certificates: %+v", cfg.Certificates)
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
	// The returned configuration is the one the returned text parses into.
	parsed, err := ParseServer(raw)
	if err != nil {
		t.Fatalf("parse updated config: %v", err)
	}
	if CertificateSpecFingerprint(parsed, parsed.Certificates[0]) != CertificateSpecFingerprint(cfg, cfg.Certificates[0]) {
		t.Fatalf("updated config parses into %+v, want %+v", parsed.Certificates, cfg.Certificates)
	}
}

// Values taken from the command line are not environment references: a '$'
// in them stays literal. No setting of a certificate admits a '$', so such a
// value is refused as it was given, instead of expanding into one that
// passes.
func TestAddCertificateSpecKeepsDollarSignsLiteral(t *testing.T) {
	t.Setenv("SIGIL_TEST_NAME", "api-prod")
	t.Setenv("SIGIL_TEST_PROVIDER", "route")
	raw := editTestConfig(t, "  []\n")
	for _, tc := range []struct {
		name, provider, want string
	}{
		{"${SIGIL_TEST_NAME}", "route", `invalid certificate name "${SIGIL_TEST_NAME}"`},
		{"a$$b", "route", `invalid certificate name "a$$b"`},
		{"api-prod", "${SIGIL_TEST_PROVIDER}", `references unknown DNS provider "${SIGIL_TEST_PROVIDER}"`},
	} {
		_, _, err := AddCertificateSpec(raw, CertificateSpec{
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

func TestAddCertificateSpecRejectsDuplicateAndInvalidCertificates(t *testing.T) {
	raw := editTestConfig(t, `  - name: api-prod
    domains: [api.example.com]
    ca: le
    dns_provider: route
    key_type: ec256
`)
	_, _, err := AddCertificateSpec(raw, CertificateSpec{
		Name:        "api-prod",
		Domains:     []string{"other.example.com"},
		DNSProvider: "route",
		KeyType:     "ec256",
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate add error = %v", err)
	}

	_, _, err = AddCertificateSpec(raw, CertificateSpec{
		Name:        "bad-provider",
		Domains:     []string{"bad.example.com"},
		DNSProvider: "missing",
		KeyType:     "ec256",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown DNS provider") {
		t.Fatalf("invalid add error = %v", err)
	}
}

func TestRemoveCertificateSpecIsExact(t *testing.T) {
	raw := editTestConfig(t, `  - name: api-prod
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
	raw, cfg, err := RemoveCertificateSpec(raw, "api-prod")
	if err != nil {
		t.Fatalf("RemoveCertificateSpec: %v", err)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Name != "api-stage" {
		t.Fatalf("unexpected certificates after remove: %+v", cfg.Certificates)
	}
	if !strings.Contains(string(raw), "# preserve this operator comment") {
		t.Errorf("updated config lost the comment:\n%s", raw)
	}

	_, _, err = RemoveCertificateSpec(raw, "API-STAGE")
	if err == nil || err.Error() != `cert "API-STAGE" not found` || !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("missing remove error = %v, want ErrCertificateNotFound naming the certificate", err)
	}
}

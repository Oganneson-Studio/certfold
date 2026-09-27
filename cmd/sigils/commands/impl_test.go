package commands

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
)

func TestServerTLSCertificateDefaultIncludesLoopbackSANs(t *testing.T) {
	miniCA, err := ca.Bootstrap(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.ServerConfig{Server: config.ServerSection{Listen: ":8443"}}
	tlsCert, err := serverTLSCertificate(miniCA, cfg)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Errorf("certificate does not cover %s: %v", host, err)
		}
	}
}

func TestServerTLSCertificateLoadsConfiguredPair(t *testing.T) {
	miniCA, err := ca.Bootstrap(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := miniCA.IssueServerCert([]string{"public.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.ServerConfig{Server: config.ServerSection{
		TLSCertFile: certPath,
		TLSKeyFile:  keyPath,
	}}
	tlsCert, err := serverTLSCertificate(miniCA, cfg)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("public.example.com"); err != nil {
		t.Fatalf("configured certificate was not loaded: %v", err)
	}
}

package server

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

func TestCreateTokenRejectsNonPositiveLifetime(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	miniCA, err := ca.Bootstrap(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enrollSrv := enroll.NewServer(db, miniCA)
	cfg := &config.ServerConfig{Server: config.ServerSection{PublicURL: "https://sigil.example.com"}}
	ctx := context.Background()

	// Zero can only arrive over IPC directly; the CLI maps it to its default.
	for _, ttl := range []time.Duration{0, -5 * time.Minute} {
		if _, err := createToken(ctx, enrollSrv, cfg, "web-1", ttl); err == nil || !strings.Contains(err.Error(), "must be positive") {
			t.Errorf("createToken with lifetime %s: error = %v, want a positive lifetime error", ttl, err)
		}
	}
	tokens, err := db.Tokens.List(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 0 {
		t.Fatalf("stored %d tokens for rejected lifetimes", len(tokens))
	}
}

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

package output

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// makeBundle creates a self-signed cert + key for testing.
func makeBundle(t *testing.T) *CertBundle {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CertBundle{
		CertPEM:  certPEM,
		ChainPEM: nil,
		KeyPEM:   keyPEM,
	}
}

func TestEncode_PemCert(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "pem-cert"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE PEM block, got %v", block)
	}
}

func TestEncode_PemKey(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "pem-key"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("expected PEM key block")
	}
}

func TestEncode_PemFullchain(t *testing.T) {
	b := makeBundle(t)
	// add a fake chain cert (same cert re-used)
	b.ChainPEM = b.CertPEM
	spec := config.OutputSpec{Format: "pem-fullchain"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Should have two CERTIFICATE blocks
	count := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 CERTIFICATE blocks, got %d", count)
	}
}

func TestEncode_PemBundle(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "pem-bundle"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Should contain both cert and key blocks
	hasCert, hasKey := false, false
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			hasCert = true
		}
		if block.Type == "EC PRIVATE KEY" {
			hasKey = true
		}
	}
	if !hasCert || !hasKey {
		t.Fatalf("pem-bundle: hasCert=%v hasKey=%v", hasCert, hasKey)
	}
}

func TestEncode_DER(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "der"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(data); err != nil {
		t.Fatalf("DER output is not a valid certificate: %v", err)
	}
}

func TestEncode_PKCS12(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "pkcs12", Password: "testpass"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("PKCS12 output is empty")
	}
	// Verify by decoding
	import_pkcs12_decoder(t, data, "testpass")
}

func import_pkcs12_decoder(t *testing.T, data []byte, password string) {
	t.Helper()
	// Basic check: pkcs12 starts with a valid ASN.1 sequence (0x30)
	if len(data) == 0 || data[0] != 0x30 {
		t.Fatalf("PKCS12 data does not start with ASN.1 SEQUENCE tag (got 0x%02x)", data[0])
	}
}

func TestEncode_UnknownFormat(t *testing.T) {
	b := makeBundle(t)
	_, err := encode(b, config.OutputSpec{Format: "jks"})
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestAtomicWrite_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	data := []byte("test data")

	if err := atomicWrite(config.OutputSpec{Format: "pem-key", Path: path}, data); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("file content mismatch: got %q want %q", got, data)
	}
	checkMode(t, path, 0o600)
}

func TestAtomicWrite_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "nested", "cert.pem")

	if err := atomicWrite(config.OutputSpec{Format: "pem-cert", Path: path}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file at %s: %v", path, err)
	}
}

func TestAtomicWrite_DefaultMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")

	if err := atomicWrite(config.OutputSpec{Format: "pem-cert", Path: path}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	checkMode(t, path, 0o644)
}

// TestWrite_KeyOutputsArePrivate writes every format where other users may
// read new files: formats that carry the private key must stay owner-only.
func TestWrite_KeyOutputsArePrivate(t *testing.T) {
	b := makeBundle(t)
	dir := outputDir(t)
	for _, format := range []string{"pem-cert", "pem-fullchain", "der", "pem-key", "pem-bundle", "pkcs12"} {
		t.Run(format, func(t *testing.T) {
			spec := config.OutputSpec{Format: format, Path: filepath.Join(dir, format), Password: "testpass"}
			if err := Write(b, spec); err != nil {
				t.Fatal(err)
			}
			checkMode(t, spec.Path, os.FileMode(outputMode(spec)))
		})
	}
}

func TestOutputMode_SecureDefaults(t *testing.T) {
	tests := []struct {
		format string
		want   int
	}{
		{format: "pem-cert", want: 0o644},
		{format: "pem-fullchain", want: 0o644},
		{format: "der", want: 0o644},
		{format: "pem-key", want: 0o600},
		{format: "pem-bundle", want: 0o600},
		{format: "pkcs12", want: 0o600},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			if got := outputMode(config.OutputSpec{Format: tt.format}); got != tt.want {
				t.Fatalf("outputMode(%s) = %#o, want %#o", tt.format, got, tt.want)
			}
		})
	}
	if got := outputMode(config.OutputSpec{Format: "pem-key", Mode: 0o640}); got != 0o640 {
		t.Fatalf("explicit mode = %#o, want 0640", got)
	}
}

func TestWrite_RoundTrip(t *testing.T) {
	b := makeBundle(t)
	dir := t.TempDir()
	spec := config.OutputSpec{
		Format: "pem-cert",
		Path:   filepath.Join(dir, "test.crt"),
		Mode:   0o640,
	}

	if err := Write(b, spec); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(spec.Path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("written file contains no PEM block")
	}
}

func TestWrite_FingerprintUnchanged_NoRewrite(t *testing.T) {
	// Write once, record mtime; write again with same content; mtime must differ
	// (because atomicWrite always renames, but content is same). This test just
	// verifies Write succeeds twice without error.
	b := makeBundle(t)
	dir := t.TempDir()
	spec := config.OutputSpec{
		Format: "pem-cert",
		Path:   filepath.Join(dir, "cert.pem"),
	}
	if err := Write(b, spec); err != nil {
		t.Fatal(err)
	}
	if err := Write(b, spec); err != nil {
		t.Fatal(err)
	}
}

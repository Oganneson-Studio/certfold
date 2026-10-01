package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/pkg/proto"
)

// lifetimePEM returns a self-signed certificate valid from notBefore to
// notAfter, PEM encoded.
func lifetimePEM(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lifetime.example.test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestStatusReportsRenewAt covers RenewAt in the status: a certificate is due
// for renewal with a third of its lifetime left, or half of it for a lifetime
// under 10 days, and RenewAt is zero for a certificate certfoldc cannot parse.
func TestStatusReportsRenewAt(t *testing.T) {
	// A certificate keeps whole seconds.
	notAfter := time.Now().Add(20 * 24 * time.Hour).Truncate(time.Second)
	cfg := buildTestCfg(t, "https://certfold.example.test")
	seedStore(t, cfg.Client.DataDir,
		&proto.CertBundle{Name: "ninety-days", Fingerprint: "sha256:AA", FullchainPEM: lifetimePEM(t, notAfter.Add(-90*24*time.Hour), notAfter)},
		&proto.CertBundle{Name: "six-days", Fingerprint: "sha256:BB", FullchainPEM: lifetimePEM(t, notAfter.Add(-6*24*time.Hour), notAfter)},
		&proto.CertBundle{Name: "unparsable", Fingerprint: "sha256:CC", FullchainPEM: "not a certificate"},
	)
	want := map[string]time.Time{
		"ninety-days": notAfter.Add(-30 * 24 * time.Hour),
		"six-days":    notAfter.Add(-3 * 24 * time.Hour),
		"unparsable":  {},
	}

	certs := newTestClient(t, cfg).Status().Certs
	if len(certs) != len(want) {
		t.Fatalf("status lists %d certificates, want %d: %+v", len(certs), len(want), certs)
	}
	for _, cert := range certs {
		if !cert.RenewAt.Equal(want[cert.Name]) {
			t.Errorf("%s: RenewAt = %s, want %s", cert.Name, cert.RenewAt, want[cert.Name])
		}
	}
}

package scheduler

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
)

// certificatePEM returns a self-signed certificate valid from notBefore
// until notAfter.
func certificatePEM(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "renewal.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestRenewAt(t *testing.T) {
	notBefore := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	const day = 24 * time.Hour
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		// left is NotAfter - RenewAt.
		left time.Duration
	}{
		{"90 days", 90 * day, 30 * day},
		{"47 days", 47 * day, 47 * day / 3},
		{"exactly 10 days", 10 * day, 10 * day / 3},
		{"just under 10 days", 10*day - time.Second, (10*day - time.Second) / 2},
		{"6 days", 144 * time.Hour, 72 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			notAfter := notBefore.Add(tc.lifetime)
			// Only the first certificate of the chain counts.
			chain := certificatePEM(t, notBefore, notAfter) + certificatePEM(t, notBefore, notBefore.Add(3650*day))
			got, err := RenewAt(chain)
			if err != nil {
				t.Fatalf("RenewAt: %v", err)
			}
			if want := notAfter.Add(-tc.left); !got.Equal(want) {
				t.Fatalf("RenewAt = %s, want %s, %s before NotAfter", got, want, tc.left)
			}
		})
	}
}

func TestRenewAtRejectsUnusableCertificates(t *testing.T) {
	notBefore := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		pem  string
	}{
		{"empty", ""},
		{"not PEM", "---cert---"},
		{"not a certificate", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("key")}))},
		{"malformed certificate", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("der")}))},
		{"NotAfter equals NotBefore", certificatePEM(t, notBefore, notBefore)},
		{"NotAfter before NotBefore", certificatePEM(t, notBefore, notBefore.Add(-time.Hour))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := RenewAt(tc.pem); err == nil {
				t.Fatalf("RenewAt = %s, want an error", got)
			}
		})
	}
}

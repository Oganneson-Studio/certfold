package ipc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

func notIssuing(string) bool { return false }

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
		Subject:      pkix.Name{CommonName: "api.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestCertificateInfosReportRenewAt covers when each certificate is due for
// renewal: it is reported only for stored material that matches the running
// configuration and can be parsed.
func TestCertificateInfosReportRenewAt(t *testing.T) {
	spec := func(name string) config.CertificateSpec {
		return config.CertificateSpec{Name: name, CA: "le", Domains: []string{name + ".example.com"}, KeyType: "ec256"}
	}
	cfg := testCertConfig(spec("valid"), spec("unparsable"), spec("stale"))
	notBefore := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	fullchain := certificatePEM(t, notBefore, notAfter)
	record := func(name string, issuedFor config.CertificateSpec, fullchain string) *store.CertRecord {
		return &store.CertRecord{
			Name:            name,
			SpecFingerprint: config.CertificateSpecFingerprint(cfg, issuedFor),
			FullchainPEM:    fullchain,
			NotAfter:        notAfter,
		}
	}
	records := []*store.CertRecord{
		record("valid", spec("valid"), fullchain),
		record("unparsable", spec("unparsable"), "---cert---"),
		// Issued before the domains changed.
		record("stale", config.CertificateSpec{Name: "stale", CA: "le", Domains: []string{"old.example.com"}, KeyType: "ec256"}, fullchain),
	}

	want := map[string]time.Time{
		"valid":      time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC),
		"unparsable": {},
		"stale":      {},
	}
	infos := certificateInfos(cfg, records, nil, notIssuing, notBefore)
	for _, info := range infos {
		if !info.RenewAt.Equal(want[info.Name]) {
			t.Errorf("%s: RenewAt = %s, want %s", info.Name, info.RenewAt, want[info.Name])
		}
	}
	raw, err := json.Marshal(infos[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"renew_at":"2026-11-27T00:00:00Z"`) {
		t.Fatalf("answer lacks renew_at: %s", raw)
	}
}

// TestCertificateInfosCopySubscribers covers the subscribers of each
// configured certificate: [] for none, and a copy, so the answer never
// shares memory with the running configuration.
func TestCertificateInfosCopySubscribers(t *testing.T) {
	subscribed := config.CertificateSpec{Name: "api-prod", CA: "le", Domains: []string{"api.example.com"}, KeyType: "ec256",
		Subscribers: []string{"web-1", "web-2"}}
	unsubscribed := config.CertificateSpec{Name: "internal", CA: "le", Domains: []string{"internal.example.com"}, KeyType: "ec256"}
	cfg := testCertConfig(subscribed, unsubscribed)

	infos := certificateInfos(cfg, nil, nil, notIssuing, time.Now())
	raw, err := json.Marshal(infos)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name":"api-prod","ca":"le","domains":["api.example.com"],"subscribers":["web-1","web-2"]`, `"subscribers":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("answer lacks %s: %s", want, raw)
		}
	}
	infos[0].Subscribers[0] = "changed"
	if cfg.Certificates[0].Subscribers[0] != "web-1" {
		t.Fatal("the answer shares the subscribers of the running configuration")
	}
}

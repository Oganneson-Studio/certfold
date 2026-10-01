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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/store"
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

// TestCertificateInfosReportRenewalPlan covers when each certificate is due
// for renewal: the daemon's renewal plan says so for stored material that
// matches the running configuration, and is asked about no other.
func TestCertificateInfosReportRenewalPlan(t *testing.T) {
	spec := func(name string) config.CertificateSpec {
		return config.CertificateSpec{Name: name, CA: "le", Domains: []string{name + ".example.com"}, KeyType: "ec256"}
	}
	cfg := testCertConfig(spec("valid"), spec("stale"), spec("new"))
	notBefore := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	fullchain := certificatePEM(t, notBefore, notAfter)
	record := func(name string, issuedFor config.CertificateSpec) *store.CertRecord {
		return &store.CertRecord{
			Name:            name,
			SpecFingerprint: config.CertificateSpecFingerprint(cfg, issuedFor),
			FullchainPEM:    fullchain,
			NotAfter:        notAfter,
		}
	}
	records := []*store.CertRecord{
		record("valid", spec("valid")),
		// Issued before the domains changed.
		record("stale", config.CertificateSpec{Name: "stale", CA: "le", Domains: []string{"old.example.com"}, KeyType: "ec256"}),
	}
	// Not the time renewal.RenewAt gives the certificate, 2026-11-27.
	planned := time.Date(2026, 12, 10, 0, 0, 0, 0, time.UTC)
	var asked []string
	plan := func(record *store.CertRecord) (time.Time, string) {
		asked = append(asked, record.Name)
		return planned, "ari"
	}

	infos := certificateInfos(cfg, records, nil, notIssuing, plan, notBefore)
	if !slices.Equal(asked, []string{"valid"}) {
		t.Fatalf("the plan was asked about %q, want only the matching record", asked)
	}
	for _, info := range infos {
		wantAt, wantSource := time.Time{}, ""
		if info.Name == "valid" {
			wantAt, wantSource = planned, "ari"
		}
		if !info.RenewAt.Equal(wantAt) || info.RenewSource != wantSource {
			t.Errorf("%s: RenewAt, RenewSource = %s, %q; want %s, %q", info.Name, info.RenewAt, info.RenewSource, wantAt, wantSource)
		}
	}
	raw, err := json.Marshal(infos)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"renew_at":"2026-12-10T00:00:00Z","renew_source":"ari"`) {
		t.Fatalf("answer lacks renew_at and renew_source: %s", raw)
	}
	if n := strings.Count(string(raw), `"renew_source"`); n != 1 {
		t.Fatalf("answer has %d renew_source fields, want one for the matching record: %s", n, raw)
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

	// Without stored records there is no renewal plan to ask.
	infos := certificateInfos(cfg, nil, nil, notIssuing, nil, time.Now())
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

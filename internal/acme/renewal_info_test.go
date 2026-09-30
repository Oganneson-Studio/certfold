package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// ariTestAKI has bytes that base64url encodes with '-' and '_'.
var ariTestAKI = []byte{0xfb, 0xff, 0xbf, 0x01, 0x02, 0x03, 0x04, 0x05}

// ariTestSerial has its high bit set, so its DER encoding starts with an
// extra zero byte, which the RFC 9773 identifier keeps.
var ariTestSerial = new(big.Int).SetBytes([]byte{0x8f, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70})

// ariTestCert returns a certificate with ariTestSerial and the authority key
// identifier aki (none when nil), valid until notAfter.
func ariTestCert(t *testing.T, aki []byte, notAfter time.Time) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:   ariTestSerial,
		Subject:        pkix.Name{CommonName: "api.example.com"},
		DNSNames:       []string{"api.example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       notAfter,
		AuthorityKeyId: aki,
	}
	// Self-signed, so the template's authority key identifier is kept.
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// decodeARICertID splits an RFC 9773 identifier into the authority key
// identifier and the serial number it names. The serial part must be the
// content octets of a DER INTEGER: without the zero byte in front of a high
// bit it reads as a negative number.
func decodeARICertID(id string) ([]byte, *big.Int, error) {
	akiPart, serialPart, ok := strings.Cut(id, ".")
	if !ok {
		return nil, nil, fmt.Errorf("identifier %q has no dot", id)
	}
	aki, err := base64.RawURLEncoding.DecodeString(akiPart)
	if err != nil {
		return nil, nil, fmt.Errorf("authority key identifier: %w", err)
	}
	content, err := base64.RawURLEncoding.DecodeString(serialPart)
	if err != nil {
		return nil, nil, fmt.Errorf("serial: %w", err)
	}
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, Bytes: content})
	if err != nil {
		return nil, nil, err
	}
	var serial *big.Int
	if _, err := asn1.Unmarshal(der, &serial); err != nil {
		return nil, nil, fmt.Errorf("serial is not a DER integer: %w", err)
	}
	return aki, serial, nil
}

// checkARICertID reports whether id names leaf.
func checkARICertID(t *testing.T, id string, leaf *x509.Certificate) {
	t.Helper()
	aki, serial, err := decodeARICertID(id)
	if err != nil {
		t.Fatalf("certID %q: %v", id, err)
	}
	if string(aki) != string(leaf.AuthorityKeyId) {
		t.Errorf("certID %q names authority key identifier %x, want %x", id, aki, leaf.AuthorityKeyId)
	}
	if serial.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("certID %q names serial %x, want %x", id, serial, leaf.SerialNumber)
	}
}

// renewalInfoCA serves renewal info from a fakeACME and records the
// identifiers it is asked about.
type renewalInfoCA struct {
	*fakeACME
	idsMu sync.Mutex
	ids   []string
}

// newRenewalInfoCA answers every renewal info request with status, the
// Retry-After header retryAfter (none when empty) and body.
func newRenewalInfoCA(t *testing.T, status int, retryAfter, body string) *renewalInfoCA {
	t.Helper()
	ca := &renewalInfoCA{fakeACME: newFakeACME(t, 1)}
	ca.offerRenewalInfo(func(w http.ResponseWriter, r *http.Request) {
		ca.idsMu.Lock()
		ca.ids = append(ca.ids, r.PathValue("id"))
		ca.idsMu.Unlock()
		if status == http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "application/problem+json")
		}
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	})
	return ca
}

func (ca *renewalInfoCA) requestedIDs() []string {
	ca.idsMu.Lock()
	defer ca.idsMu.Unlock()
	return append([]string(nil), ca.ids...)
}

// assertNoAccount checks that the CA saw no new-account request and no
// failed signature check.
func (f *fakeACME) assertNoAccount(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, problem := range f.problems {
		t.Errorf("fake ACME server: %s", problem)
	}
	if len(f.accounts) != 0 {
		t.Errorf("%d new-account requests, want 0", len(f.accounts))
	}
}

func windowJSON(start, end time.Time) string {
	return fmt.Sprintf(`{"suggestedWindow":{"start":%q,"end":%q},"explanationURL":"https://ca.example/why"}`,
		start.Format(time.RFC3339), end.Format(time.RFC3339))
}

func renewalInfoConfig(directory string) (*config.ServerConfig, config.CertificateSpec) {
	cfg := &config.ServerConfig{
		ACME: config.ACMESection{
			Email:     "ops@example.com",
			DefaultCA: "fake",
			CAs:       map[string]config.CAEntry{"fake": {Directory: directory}},
		},
		// Never run: every order fails before the challenge.
		DNSProviders: map[string]config.DNSProvider{"hook": {Type: "exec", Command: []string{"/usr/local/bin/dns-hook"}}},
	}
	spec := config.CertificateSpec{Name: "api", Domains: []string{"api.example.com"}, CA: "fake", DNSProvider: "hook", KeyType: "ec256"}
	return cfg, spec
}

func TestRenewalInfoReturnsTheCAWindow(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	leaf, certPEM := ariTestCert(t, ariTestAKI, now.Add(90*24*time.Hour))
	start, end := now.Add(58*24*time.Hour), now.Add(60*24*time.Hour)
	ca := newRenewalInfoCA(t, http.StatusOK, "21600", windowJSON(start, end))
	cfg, spec := renewalInfoConfig(ca.URL + "/dir")

	// RenewalInfo needs no account store.
	info, err := NewIssuer(context.Background(), nil).RenewalInfo(cfg, spec, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Start.Equal(start) || !info.End.Equal(end) {
		t.Errorf("window [%s, %s), want [%s, %s)", info.Start, info.End, start, end)
	}
	if info.RetryAfter != 6*time.Hour {
		t.Errorf("RetryAfter = %s, want 6h", info.RetryAfter)
	}
	if info.ExplanationURL != "https://ca.example/why" {
		t.Errorf("ExplanationURL = %q", info.ExplanationURL)
	}
	ids := ca.requestedIDs()
	if len(ids) != 1 {
		t.Fatalf("renewal info requested for %q, want one certificate", ids)
	}
	checkARICertID(t, ids[0], leaf)
	if want, _ := certificate.MakeARICertID(leaf); ids[0] != want {
		t.Errorf("certID %q, want %q", ids[0], want)
	}
	ca.assertNoAccount(t)
}

func TestRenewalInfoWithoutRenewalInfoInTheDirectory(t *testing.T) {
	_, certPEM := ariTestCert(t, ariTestAKI, time.Now().Add(90*24*time.Hour))
	ca := newFakeACME(t, 1)
	cfg, spec := renewalInfoConfig(ca.URL + "/dir")

	_, err := NewIssuer(context.Background(), nil).RenewalInfo(cfg, spec, certPEM)
	if !errors.Is(err, ErrNoRenewalInfo) {
		t.Fatalf("error = %v, want ErrNoRenewalInfo", err)
	}
	ca.assertNoAccount(t)
}

func TestRenewalInfoWithoutAuthorityKeyIdentifier(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	_, certPEM := ariTestCert(t, nil, now.Add(90*24*time.Hour))
	ca := newRenewalInfoCA(t, http.StatusOK, "", windowJSON(now.Add(time.Hour), now.Add(2*time.Hour)))
	cfg, spec := renewalInfoConfig(ca.URL + "/dir")

	_, err := NewIssuer(context.Background(), nil).RenewalInfo(cfg, spec, certPEM)
	if !errors.Is(err, ErrNoRenewalInfo) {
		t.Fatalf("error = %v, want ErrNoRenewalInfo", err)
	}
	if ids := ca.requestedIDs(); len(ids) != 0 {
		t.Errorf("renewal info requested for %q", ids)
	}
	ca.assertNoAccount(t)
}

// lego decodes a problem document as a zero window, which would mean "renew
// now".
func TestRenewalInfoRejectsProblemDocuments(t *testing.T) {
	_, certPEM := ariTestCert(t, ariTestAKI, time.Now().Add(90*24*time.Hour))
	ca := newRenewalInfoCA(t, http.StatusNotFound, "",
		`{"type":"urn:ietf:params:acme:error:malformed","detail":"no such certificate","status":404}`)
	cfg, spec := renewalInfoConfig(ca.URL + "/dir")

	info, err := NewIssuer(context.Background(), nil).RenewalInfo(cfg, spec, certPEM)
	if err == nil {
		t.Fatalf("got window [%s, %s), want an error", info.Start, info.End)
	}
	if errors.Is(err, ErrNoRenewalInfo) {
		t.Errorf("error = %v, which reads as a CA without renewal info", err)
	}
	ca.assertNoAccount(t)
}

func TestRenewalInfoChecksTheWindow(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	notAfter := now.Add(90 * 24 * time.Hour)
	day := 24 * time.Hour
	tests := []struct {
		name       string
		start, end time.Time
		retryAfter string
		wantErr    bool
		wantEnd    time.Time
		wantRetry  time.Duration
	}{
		{name: "end before start", start: now.Add(60 * day), end: now.Add(58 * day), wantErr: true},
		{name: "empty window", start: now.Add(60 * day), end: now.Add(60 * day), wantErr: true},
		{name: "start at expiry", start: notAfter, end: notAfter.Add(day), wantErr: true},
		{name: "end after expiry", start: notAfter.Add(-day), end: notAfter.Add(day), retryAfter: "60", wantEnd: notAfter, wantRetry: time.Minute},
		{name: "no Retry-After", start: now.Add(58 * day), end: now.Add(60 * day), wantEnd: now.Add(60 * day)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, certPEM := ariTestCert(t, ariTestAKI, notAfter)
			ca := newRenewalInfoCA(t, http.StatusOK, tt.retryAfter, windowJSON(tt.start, tt.end))
			cfg, spec := renewalInfoConfig(ca.URL + "/dir")

			info, err := NewIssuer(context.Background(), nil).RenewalInfo(cfg, spec, certPEM)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "invalid renewal window") {
					t.Fatalf("error = %v, want an invalid renewal window", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !info.Start.Equal(tt.start) || !info.End.Equal(tt.wantEnd) {
				t.Errorf("window [%s, %s), want [%s, %s)", info.Start, info.End, tt.start, tt.wantEnd)
			}
			if info.RetryAfter != tt.wantRetry {
				t.Errorf("RetryAfter = %s, want %s", info.RetryAfter, tt.wantRetry)
			}
		})
	}
}

func TestIssueNamesTheReplacedCertificate(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	leaf, certPEM := ariTestCert(t, ariTestAKI, notAfter)
	_, noAKI := ariTestCert(t, nil, notAfter)
	tests := []struct {
		name         string
		renewalInfo  bool // the directory offers renewalInfo
		replacing    []byte
		wantReplaces bool
	}{
		{name: "replacing", renewalInfo: true, replacing: certPEM, wantReplaces: true},
		{name: "CA without renewal info", replacing: certPEM},
		{name: "nothing to replace", renewalInfo: true},
		{name: "no authority key identifier", renewalInfo: true, replacing: noAKI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newFakeACME(t, 1)
			if tt.renewalInfo {
				ca.offerRenewalInfo(func(w http.ResponseWriter, r *http.Request) {
					t.Errorf("Issue asked for renewal info: %s", r.URL)
				})
			}
			db, err := store.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			cfg, spec := renewalInfoConfig(ca.URL + "/dir")

			// The fake CA fails the order.
			_, issueErr := NewIssuer(context.Background(), db.Accounts).Issue(context.Background(), cfg, spec, tt.replacing)

			ca.mu.Lock()
			defer ca.mu.Unlock()
			if len(ca.orderPayloads) != 1 {
				t.Fatalf("%d verified orders, want 1; Issue error: %v", len(ca.orderPayloads), issueErr)
			}
			var order map[string]any
			if err := json.Unmarshal(ca.orderPayloads[0], &order); err != nil {
				t.Fatal(err)
			}
			replaces, sent := order["replaces"].(string)
			if sent != tt.wantReplaces {
				t.Fatalf("order %s: replaces sent %v, want %v", ca.orderPayloads[0], sent, tt.wantReplaces)
			}
			if sent {
				checkARICertID(t, replaces, leaf)
			}
		})
	}
}

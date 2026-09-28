package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
)

// manInTheMiddle starts a TLS server whose certificate, which no CA signed,
// holds a DNS name with an escape sequence, and returns its URL with the
// host localhost, which that name does not match. crypto/x509 checks the
// host name before it builds a chain, so the error of the handshake quotes
// the DNS names of the certificate. On Windows it does so only when the
// roots hold more than the system pool, as those of an enrolled client do.
func manInTheMiddle(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "man in the middle"},
		DNSNames:     []string{"x\x1b]0;pwned\a"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	_, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "https://localhost:" + port
}

// assertPrintable fails the test if text holds a control character other
// than the newlines errors.Join puts between errors.
func assertPrintable(t *testing.T, what, text string) {
	t.Helper()
	if i := strings.IndexFunc(text, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }); i >= 0 {
		t.Fatalf("%s keeps a control character: %q", what, text)
	}
}

// A man in the middle needs no certificate the client trusts to put text of
// its choosing into the error of a sync: neither the error Fetch returns,
// which the IPC API hands to a terminal, nor LastError may keep its control
// characters.
func TestManInTheMiddleErrorIsPrintable(t *testing.T) {
	now := time.Now()
	cfg := buildTestCfg(t, manInTheMiddle(t))
	withIdentity(t, cfg, newTestIdentityCA(t, now), now, now.Add(90*24*time.Hour))
	c := newTestClient(t, cfg)

	err := c.Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "certificate is valid for x ]0;pwned , not localhost") {
		t.Fatalf("Fetch error = %q, want the host name error with the DNS name of the certificate", err)
	}
	assertPrintable(t, "Fetch error", err.Error())
	var hostnameErr x509.HostnameError
	if !errors.As(err, &hostnameErr) {
		t.Fatalf("Fetch error %q no longer wraps the host name error", err)
	}
	if got := c.Status().LastError; got != err.Error() {
		t.Fatalf("LastError = %q, want the error of Fetch", got)
	}
}

// Reload gets its configuration from config.LoadClient, which checks the
// identity, so none of its errors quote more than the PEM block types of an
// identity that passed that check; they reach terminals through the IPC API
// all the same.
func TestReloadErrorIsPrintable(t *testing.T) {
	now := time.Now()
	cfg := buildTestCfg(t, "https://sigil.example.test")
	withIdentity(t, cfg, newTestIdentityCA(t, now), now, now.Add(90*24*time.Hour))
	c := newTestClient(t, cfg)

	updated := *cfg
	updated.Identity.ClientCert = "-----BEGIN X\x1b]0;pwned\a-----\nAAAA\n-----END X\x1b]0;pwned\a-----\n"
	err := c.Reload(&updated)
	if err == nil || !strings.Contains(err.Error(), "load client cert") {
		t.Fatalf("Reload error = %v, want the client certificate refused", err)
	}
	assertPrintable(t, "Reload error", err.Error())
}

// The server names the certificates of the view. One whose name
// config.ValidateCertificateName rejects is not downloaded, and leaves the
// store with the material an earlier view left there; the others are
// delivered as usual.
func TestViewSkipsInvalidCertificateNames(t *testing.T) {
	good := newTestBundle(t, "api-prod")
	bad := newTestBundle(t, "api\x1b]0;pwned\a")
	fs := newFakeServer(good, bad)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod")
	seedStore(t, cfg.Client.DataDir, bad)
	c := newTestClient(t, cfg)

	err := c.Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), `invalid certificate name "api\x1b]0;pwned\a"`) {
		t.Fatalf("Fetch error = %v, want the invalid name reported", err)
	}
	assertPrintable(t, "Fetch error", err.Error())
	if got := fs.bundleRequests(); !slices.Equal(got, []string{"api-prod"}) {
		t.Fatalf("bundle requests = %q, want api-prod alone", got)
	}
	if got := readStore(t, cfg.Client.DataDir); len(got) != 1 || got["api-prod"].Fingerprint != good.Fingerprint {
		t.Fatalf("store holds %q, want api-prod alone", slices.Sorted(maps.Keys(got)))
	}
	if fileContent(outPath) != good.FullchainPEM {
		t.Fatal("api-prod was not delivered")
	}
	if got := c.Status().Certs; len(got) != 1 || got[0].Name != "api-prod" {
		t.Fatalf("status certificates = %+v, want api-prod alone", got)
	}
}

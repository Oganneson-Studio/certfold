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
// holds the DNS name dnsName, and returns its URL with the host localhost,
// which that name does not match. crypto/x509 checks the host name before it
// builds a chain, so the error of the handshake quotes the DNS names of the
// certificate. On Windows it does so only when the roots hold more than the
// system pool, as those of an enrolled client do.
func manInTheMiddle(t *testing.T, dnsName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "man in the middle"},
		DNSNames:     []string{dnsName},
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
	cfg := buildTestCfg(t, manInTheMiddle(t, "x\x1b]0;pwned\a"))
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

// A man in the middle may put a newline into a DNS name, followed by a line
// of its choosing, such as a status line that says online. Only the newlines
// errors.Join puts between errors survive in the error of Fetch and in
// LastError.
func TestErrorsKeepOnlyTheNewlinesOfJoin(t *testing.T) {
	now := time.Now()
	cfg := buildTestCfg(t, manInTheMiddle(t, "x\nServer       : https://forged.example (online)"))
	// An identity due for renewal without a saver gives the fetch a second
	// error, so that one newline must survive.
	withIdentity(t, cfg, newTestIdentityCA(t, now), now, now.Add(time.Hour))
	c := newTestClient(t, cfg)

	err := c.Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "forged.example") || !strings.Contains(err.Error(), "renew client identity") {
		t.Fatalf("Fetch error = %q, want the renewal error and the host name error of the man in the middle", err)
	}
	for what, text := range map[string]string{"Fetch error": err.Error(), "LastError": c.Status().LastError} {
		if n := strings.Count(text, "\n"); n != 1 {
			t.Errorf("%s holds %d newlines, want the one between its two errors: %q", what, n, text)
		}
	}
}

// Reload quotes the configuration it is given in one error only: an identity
// without a certificate or key block lists the types of the blocks it has.
// config.LoadClient refuses such an identity first, but the error would
// reach a terminal through the IPC API all the same.
func TestReloadErrorIsPrintable(t *testing.T) {
	now := time.Now()
	cfg := buildTestCfg(t, "https://certfold.example.test")
	withIdentity(t, cfg, newTestIdentityCA(t, now), now, now.Add(90*24*time.Hour))
	c := newTestClient(t, cfg)

	updated := *cfg
	updated.Identity.ClientCert = "-----BEGIN X\x1b]0;pwned\a-----\nAAAA\n-----END X\x1b]0;pwned\a-----\n"
	err := c.Reload(loaded(&updated))
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

// The store keeps the fingerprint of a bundle, and certfoldc status --json
// prints it: encoding/json escapes C0 there, but passes DEL and C1 through,
// and some terminals take U+009B for CSI. A bundle whose fingerprint is not
// of the form certfolds sends is refused as a bad bundle.
func TestBundleWithMalformedFingerprintIsRefused(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	bundle.Fingerprint = "sha256:\u009b2J"
	fs := newFakeServer(bundle)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	c := newTestClient(t, buildTestCfg(t, ts.URL))

	err := c.Fetch(context.Background(), "")
	for _, cert := range c.Status().Certs {
		if strings.ContainsFunc(cert.Fingerprint, unicode.IsControl) {
			t.Fatalf("status fingerprint of %s = %q, which certfoldc status --json prints as it is", cert.Name, cert.Fingerprint)
		}
	}
	if err == nil || !strings.Contains(err.Error(), `bundle "api-prod": server sent fingerprint "sha256:\u009b2J"`) {
		t.Fatalf("Fetch error = %v, want the bundle refused for its fingerprint", err)
	}
}

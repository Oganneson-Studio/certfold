package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// testCA is a throwaway certificate authority. httptest.NewTLSServer shares
// one built-in certificate across servers, so trust tests issue their own.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (authority *testCA) certPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.cert.Raw}))
}

// startEnrollServer serves successful enrollments over a certificate that
// issuer signs for the httptest listener address. reached reports whether a
// request got past the TLS handshake.
func startEnrollServer(t *testing.T, issuer *testCA) (ts *httptest.Server, reached *atomic.Bool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "sigils"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}

	reached = new(atomic.Bool)
	ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		_ = json.NewEncoder(w).Encode(proto.EnrollResponse{CACert: "ca-pem", ClientCert: "client-pem"})
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, reached
}

// withSystemRoots stands in for the operating system trust store.
func withSystemRoots(t *testing.T, roots ...*x509.Certificate) {
	t.Helper()
	original := SystemCertPool
	SystemCertPool = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		for _, root := range roots {
			pool.AddCert(root)
		}
		return pool, nil
	}
	t.Cleanup(func() { SystemCertPool = original })
}

// TestPostEnrollTrustsSystemRoots covers a server that presents a publicly
// trusted server.tls_cert_file while the token carries its mini-CA.
func TestPostEnrollTrustsSystemRoots(t *testing.T) {
	publicCA, miniCA := newTestCA(t), newTestCA(t)
	withSystemRoots(t, publicCA.cert)
	ts, _ := startEnrollServer(t, publicCA)

	token := encodeTestToken(t, Token{ServerURL: ts.URL, Name: "web-1", CACert: miniCA.certPEM()})
	kc, err := GenerateKeyAndCSR("web-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PostEnroll(ts.URL, token, kc.CSRDER); err != nil {
		t.Fatalf("PostEnroll: %v", err)
	}
}

// TestPostEnrollRejectsUntrustedServer checks that the token never reaches a
// server vouched for by neither the system roots nor the token's CA.
func TestPostEnrollRejectsUntrustedServer(t *testing.T) {
	publicCA, miniCA, unrelatedCA := newTestCA(t), newTestCA(t), newTestCA(t)
	withSystemRoots(t, publicCA.cert)
	ts, reached := startEnrollServer(t, unrelatedCA)

	token := encodeTestToken(t, Token{ServerURL: ts.URL, Name: "web-1", CACert: miniCA.certPEM()})
	kc, err := GenerateKeyAndCSR("web-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = PostEnroll(ts.URL, token, kc.CSRDER)
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("PostEnroll error = %v, want an unknown authority error", err)
	}
	if reached.Load() {
		t.Fatal("enrollment request reached an untrusted server")
	}
}

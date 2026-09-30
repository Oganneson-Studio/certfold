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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// clientCert returns, in PEM, a client certificate for name and pub that
// authority issues as the mini-CA does, after edit, unless nil, changes the
// template.
func (authority *testCA) clientCert(name string, pub any, edit func(*x509.Certificate)) (string, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if edit != nil {
		edit(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.cert, pub, authority.key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// issuedBy answers an enrollment as sigils does, with a certificate for web-1
// and the key of the request that authority issues, after edit, unless nil,
// changes it.
func issuedBy(authority *testCA, edit func(*x509.Certificate)) func(*x509.CertificateRequest) (string, error) {
	return func(csr *x509.CertificateRequest) (string, error) {
		return authority.clientCert("web-1", csr.PublicKey, edit)
	}
}

// postEnroll runs PostEnroll as sigilc enroll does, on the token that
// DecodeToken reads from tokenStr.
func postEnroll(t *testing.T, tokenStr string, csrDER []byte) (string, error) {
	t.Helper()
	token, err := DecodeToken(tokenStr)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	return PostEnroll(token, tokenStr, csrDER)
}

// startEnrollServer serves enrollments over a certificate that issuer signs
// for the httptest listener address, and answers each with the client
// certificate that issue returns for its CSR. reached reports whether a
// request got past the TLS handshake.
func startEnrollServer(t *testing.T, issuer *testCA, issue func(*x509.CertificateRequest) (string, error)) (ts *httptest.Server, reached *atomic.Bool) {
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
	ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		var req proto.EnrollRequest
		if r.Method != http.MethodPost || r.URL.Path != "/v1/enroll" || json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		if block == nil {
			http.Error(w, "no CSR", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, "bad CSR", http.StatusBadRequest)
			return
		}
		certPEM, err := issue(csr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(proto.EnrollResponse{ClientCert: certPEM})
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
	ts, _ := startEnrollServer(t, publicCA, issuedBy(miniCA, nil))

	token := encodeTestToken(t, Token{ServerURL: ts.URL, Name: "web-1", CACert: miniCA.certPEM()})
	kc, err := GenerateKeyAndCSR("web-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postEnroll(t, token, kc.CSRDER); err != nil {
		t.Fatalf("PostEnroll: %v", err)
	}
}

// TestPostEnrollChecksTheIssuedCertificate checks the certificate that the
// server answers as sigilc checks a renewed identity: it must be for the
// token's client name, chain to the token's CA for client authentication,
// and hold the key of the request. The CA of the server's TLS certificate,
// which the system roots trust, does not count.
func TestPostEnrollChecksTheIssuedCertificate(t *testing.T) {
	publicCA, miniCA := newTestCA(t), newTestCA(t)
	withSystemRoots(t, publicCA.cert)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name  string
		issue func(*x509.CertificateRequest) (string, error)
		ok    bool
	}{
		{name: "as asked", issue: issuedBy(miniCA, nil), ok: true},
		// The server has used up the token by now, so a clock behind the
		// server's must not fail the enrollment.
		{name: "with the clock behind", issue: issuedBy(miniCA, func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(time.Hour)
			c.NotAfter = time.Now().Add(90 * 24 * time.Hour)
		}), ok: true},
		{name: "for another client", issue: issuedBy(miniCA, func(c *x509.Certificate) { c.Subject.CommonName = "web-2" })},
		{name: "by the CA of the server certificate", issue: issuedBy(publicCA, nil)},
		{name: "for server authentication", issue: issuedBy(miniCA, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		})},
		{name: "for another key", issue: func(*x509.CertificateRequest) (string, error) {
			return miniCA.clientCert("web-1", &otherKey.PublicKey, nil)
		}},
		{name: "that is not one", issue: func(*x509.CertificateRequest) (string, error) { return "client-pem", nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ts, _ := startEnrollServer(t, publicCA, tt.issue)
			token := encodeTestToken(t, Token{ServerURL: ts.URL, Name: "web-1", CACert: miniCA.certPEM()})
			kc, err := GenerateKeyAndCSR("web-1")
			if err != nil {
				t.Fatal(err)
			}
			certPEM, err := postEnroll(t, token, kc.CSRDER)
			if !tt.ok {
				if err == nil {
					t.Fatal("PostEnroll accepted the certificate")
				}
				return
			}
			if err != nil {
				t.Fatalf("PostEnroll: %v", err)
			}
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				t.Fatalf("PostEnroll returned no certificate: %q", certPEM)
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil || leaf.Subject.CommonName != "web-1" {
				t.Fatalf("PostEnroll returned %v (parse error %v), want the certificate for web-1", leaf, err)
			}
		})
	}
}

// TestPostEnrollRejectsUntrustedServer checks that the token never reaches a
// server vouched for by neither the system roots nor the token's CA.
func TestPostEnrollRejectsUntrustedServer(t *testing.T) {
	publicCA, miniCA, unrelatedCA := newTestCA(t), newTestCA(t), newTestCA(t)
	withSystemRoots(t, publicCA.cert)
	ts, reached := startEnrollServer(t, unrelatedCA, issuedBy(miniCA, nil))

	token := encodeTestToken(t, Token{ServerURL: ts.URL, Name: "web-1", CACert: miniCA.certPEM()})
	kc, err := GenerateKeyAndCSR("web-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = postEnroll(t, token, kc.CSRDER)
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("PostEnroll error = %v, want an unknown authority error", err)
	}
	// The token never reached a server, which cannot have taken it.
	if errors.Is(err, ErrUnusableAnswer) {
		t.Errorf("PostEnroll error = %v, which says that the server answered", err)
	}
	if reached.Load() {
		t.Fatal("enrollment request reached an untrusted server")
	}
}

// TestPostEnrollDoesNotFollowRedirects checks that the enrollment request,
// which carries the token, goes only to the server whose TLS was verified.
// A 307 or 308 would make an HTTP client send the body again, to any host
// and over plain HTTP as well, so a front proxy that canonicalizes the host
// or the scheme would pass the token on without a word.
func TestPostEnrollDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"token"`) {
			leaked.Store(true)
		}
		http.Error(w, "gone", http.StatusGone)
	}))
	t.Cleanup(plain.Close)

	miniCA := newTestCA(t)
	withSystemRoots(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "sigils"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, miniCA.cert, &key.PublicKey, miniCA.key)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusPermanentRedirect)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	token := encodeTestToken(t, Token{ServerURL: ts.URL, Name: "web-1", CACert: miniCA.certPEM()})
	kc, err := GenerateKeyAndCSR("web-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postEnroll(t, token, kc.CSRDER); err == nil {
		t.Fatal("PostEnroll succeeded through a redirect")
	}
	if leaked.Load() {
		t.Fatal("the enrollment token followed a redirect to a plain HTTP server")
	}
}

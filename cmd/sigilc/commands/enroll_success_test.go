package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// newSigningEnrollServer enrolls every request, as sigils does a valid token:
// it signs the CSR with a CA of its own and answers the certificate. The CA
// is its TLS certificate as well, which the token method of
// refusingEnrollServer pins, so that the token carries the CA that signs the
// client, as a token of sigils does.
func newSigningEnrollServer(t *testing.T) *refusingEnrollServer {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test mini-CA"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	s := &refusingEnrollServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		var req proto.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
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
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      csr.Subject,
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(90 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.EnrollResponse{
			ClientCert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		})
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{caDER}, PrivateKey: caKey}}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// TestEnrollSuccessKeepsConfig checks that a successful enrollment leaves the
// client.yaml it wrote, with the identity the server issued: removing the
// client.yaml of a failed enrollment must not reach this path.
func TestEnrollSuccessKeepsConfig(t *testing.T) {
	srv := newSigningEnrollServer(t)
	// Enrollment refuses a directory that accounts it does not trust may
	// write to, as the temporary directory may be: securefile creates this
	// one private.
	cfgPath := filepath.Join(t.TempDir(), "etc", "client.yaml")
	if err := runEnrollCommand(cfgPath, srv.token(t, "web-1")); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		t.Fatalf("load client.yaml after a successful enrollment: %v", err)
	}
	if cfg.Client.Name != "web-1" || cfg.Client.ServerURL != srv.URL || cfg.Identity.ClientCert == "" {
		t.Fatalf("client.yaml names %q at %q, client certificate set: %t; want web-1 at %s with one",
			cfg.Client.Name, cfg.Client.ServerURL, cfg.Identity.ClientCert != "", srv.URL)
	}
}

// TestEnrollFailureLeavesTheRestOfTheDirectory checks that a failed
// enrollment removes the client.yaml it wrote and nothing beside it.
func TestEnrollFailureLeavesTheRestOfTheDirectory(t *testing.T) {
	srv := newRefusingEnrollServer(t)
	// Enrollment refuses a directory that accounts it does not trust may
	// write to, as the temporary directory may be.
	dir := filepath.Join(t.TempDir(), "etc")
	if err := securefile.EnsurePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(other, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runEnrollCommand(filepath.Join(dir, "client.yaml"), srv.token(t, "web-1")); err == nil {
		t.Fatal("enrolled with a token the server refuses")
	}
	if got, err := os.ReadFile(other); err != nil || string(got) != "kept" {
		t.Fatalf("the file beside client.yaml after a refused enrollment: %q (error %v), want it kept", got, err)
	}
}

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
)

// runMainEnv, when set, makes the test binary run main with its arguments
// instead of the tests.
const runMainEnv = "SIGILC_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) != "" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// selfSigned returns a certificate for template signed by its own new key.
func selfSigned(t *testing.T, template *x509.Certificate) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// sigilc enroll prints the error of its own TLS handshake, which quotes the
// DNS names in the certificate the server presents. A man in the middle, who
// needs no certificate the client trusts for this, must not reach the
// terminal through them.
func TestEnrollErrorIsPrintable(t *testing.T) {
	now := time.Now()
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "man in the middle"},
		DNSNames:     []string{"x\x1b]0;pwned\a"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	_, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// The host localhost does not match the DNS name, and crypto/x509
	// checks the host name before it builds a chain: on Windows as well,
	// since the roots of a token hold more than the system pool.
	ca := selfSigned(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "sigil mini-CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
	payload, err := json.Marshal(map[string]string{
		"server_url": "https://localhost:" + port,
		"name":       "web-1",
		"ca_cert":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate[0]})),
	})
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "enroll",
		"--token", base64.RawURLEncoding.EncodeToString(payload),
		"--config", filepath.Join(t.TempDir(), "client.yaml"))
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("sigilc enroll: %v, want exit status 1; stderr:\n%s", err, stderr.String())
	}
	printed := stderr.String()
	if !strings.Contains(printed, "error: enroll: ") || !strings.Contains(printed, "certificate is valid for x ]0;pwned , not localhost") {
		t.Fatalf("sigilc enroll printed %q, want the host name error with the DNS name of the certificate", printed)
	}
	if i := strings.IndexFunc(printed, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }); i >= 0 {
		t.Fatalf("sigilc enroll printed a control character: %q", printed)
	}
}

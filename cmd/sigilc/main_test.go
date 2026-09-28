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
// needs no certificate the client trusts for this, must reach the terminal
// through them neither with an escape sequence nor with a line of its own,
// such as a fake success.
func TestEnrollErrorIsPrintable(t *testing.T) {
	for _, tc := range []struct{ name, dnsName, quoted string }{
		{"escape sequence", "x\x1b]0;pwned\a", "certificate is valid for x ]0;pwned , not localhost"},
		{"newline", "x\nenrolled as \"web-1\"", `certificate is valid for x enrolled as "web-1", not localhost`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			printed := enrollThroughManInTheMiddle(t, tc.dnsName)
			if !strings.Contains(printed, "error: enroll: ") || !strings.Contains(printed, tc.quoted) {
				t.Fatalf("sigilc enroll printed %q, want the host name error with the DNS name of the certificate", printed)
			}
			if i := strings.IndexFunc(printed, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }); i >= 0 {
				t.Fatalf("sigilc enroll printed a control character: %q", printed)
			}
			if n := strings.Count(printed, "\n"); n != 1 {
				t.Fatalf("sigilc enroll printed %d lines, want the error on one: %q", n, printed)
			}
		})
	}
}

// enrollThroughManInTheMiddle runs sigilc enroll against a TLS server whose
// certificate holds the DNS name dnsName, and returns what it printed to
// stderr as it failed.
func enrollThroughManInTheMiddle(t *testing.T, dnsName string) string {
	t.Helper()
	now := time.Now()
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "man in the middle"},
		DNSNames:     []string{dnsName},
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
	token := enrollmentToken(t, map[string]string{
		"server_url": "https://localhost:" + port,
		"name":       "web-1",
		"ca_cert":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate[0]})),
	})
	return failingSigilc(t, "enroll", "--token", token, "--config", filepath.Join(t.TempDir(), "client.yaml"))
}

// main prints errors that quote local files too, such as the type error of
// a client.yaml, which quotes the value: without control characters, and
// with the newlines between the lines of the error.
func TestErrorQuotingClientYAMLIsPrintable(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "client.yaml")
	// A YAML escape: a raw control character would fail the YAML parser.
	if err := os.WriteFile(cfgPath, []byte("identity: \"\\e]0;pwned\\a\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := enrollmentToken(t, map[string]string{"server_url": "https://sigil.example.com", "name": "web-1"})
	printed := failingSigilc(t, "enroll", "--token", token, "--config", cfgPath)
	if !strings.Contains(printed, "error: load config: ") || !strings.Contains(printed, "cannot unmarshal !!str ` ]0;pwned `") {
		t.Fatalf("sigilc enroll printed %q, want the type error of client.yaml with its value", printed)
	}
	if i := strings.IndexFunc(printed, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }); i >= 0 {
		t.Fatalf("sigilc enroll printed a control character: %q", printed)
	}
}

// enrollmentToken encodes payload as the token of sigils token create.
func enrollmentToken(t *testing.T, payload map[string]string) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// failingSigilc runs main with args in a process of its own, which must exit
// with status 1, and returns what it printed to stderr.
func failingSigilc(t *testing.T, args ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("sigilc %s: %v, want exit status 1; stderr:\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stderr.String()
}

package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Oganneson-Studio/certfold/internal/agent"
	"github.com/Oganneson-Studio/certfold/internal/ipc"
	"github.com/Oganneson-Studio/certfold/internal/logging"
	"github.com/Oganneson-Studio/certfold/internal/securefile"
)

// selfSigned returns a certificate for template signed by its own new key, as
// PEM and as a tls.Certificate.
func selfSigned(t *testing.T, template *x509.Certificate) (certPEM, keyPEM string, cert tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// manInTheMiddle starts a TLS server whose certificate, which no CA signed,
// holds a DNS name with an escape sequence, and returns its URL with the
// host localhost, which that name does not match. crypto/x509 checks the
// host name before it builds a chain, so the error of the handshake quotes
// the DNS names of the certificate. On Windows it does so only when the
// roots hold more than the system pool, as those of an enrolled client do.
func manInTheMiddle(t *testing.T) string {
	t.Helper()
	now := time.Now()
	_, _, cert := selfSigned(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "man in the middle"},
		DNSNames:     []string{"x\x1b]0;pwned\a"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	ts := httptest.NewUnstartedServer(http.NotFoundHandler())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
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

// The error a man in the middle puts into a sync reaches certfoldc status as
// the last error, and certfoldc fetch over the IPC API, before main prints
// either: a terminal user interface shows the same texts.
func TestStatusAndFetchShowManInTheMiddleErrorsPrintable(t *testing.T) {
	serverURL := manInTheMiddle(t)
	socket := fmt.Sprintf(`\\.\pipe\certfoldc-terminal-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	if runtime.GOOS != "windows" {
		// Unix socket paths are length-limited; keep this one short.
		dir, err := os.MkdirTemp("", "certfold")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		socket = filepath.Join(dir, "c.sock")
	}
	// The identity of an enrolled client, which the man in the middle does
	// not ask for, and the roots it brings.
	now := time.Now()
	identityPEM, keyPEM, _ := selfSigned(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "web-1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	// The daemon refuses directories that accounts it does not trust may
	// write to, as the temporary directory may be: securefile creates these
	// two private.
	path := filepath.Join(t.TempDir(), "etc", "client.yaml")
	raw := fmt.Sprintf("client:\n  name: web-1\n  server_url: %q\n  data_dir: %q\n  ipc_socket: %q\n"+
		"identity:\n  ca_cert: %q\n  client_cert: %q\n  client_key: %q\n",
		serverURL, filepath.Join(t.TempDir(), "data"), socket, identityPEM, identityPEM, keyPEM)
	if err := securefile.WriteFile(path, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- agent.Run(ctx, path, logging.Logs{Events: logging.NewRing(), Sink: slog.NewTextHandler(io.Discard, nil)})
	}()
	t.Cleanup(func() {
		cancel()
		<-result
	})

	// The first round of the daemon fails at once.
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		c, err := ipc.NewClient(socket)
		if err == nil {
			var state *ipc.ClientState
			if state, err = c.GetClientState(ctx); err == nil && state.LastError != "" {
				break
			}
		}
		if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
			t.Skip("the certfoldc pipe admits only SYSTEM and elevated administrators")
		}
		select {
		case err := <-result:
			result <- err // for the cleanup, which waits for it
			t.Fatalf("the daemon returned early: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the daemon reported no error of its first round: %v", err)
		}
	}
	const quoted = "certificate is valid for x ]0;pwned , not localhost"

	status := runCertfoldc(t, "--ipc", socket, "status")
	if !strings.Contains(status, "Last error   : sync: ") || !strings.Contains(status, quoted) {
		t.Fatalf("status printed %q, want the last error with the DNS name of the certificate", status)
	}
	assertPrintable(t, "status", status)

	root := NewRootCmd()
	root.SetArgs([]string{"--ipc", socket, "fetch"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), quoted) {
		t.Fatalf("fetch error = %q, want the host name error with the DNS name of the certificate", err)
	}
	assertPrintable(t, "fetch error", err.Error())
}

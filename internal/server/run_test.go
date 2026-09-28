package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

func testIPCSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\sigil-server-test-%d`, time.Now().UnixNano())
	}
	// Unix socket paths are length-limited; keep this one short.
	dir, err := os.MkdirTemp("", "sigil")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// writeServerConfig writes a server.yaml without certificates, so Run never
// contacts the ACME directory.
func writeServerConfig(t *testing.T, listen, dataDir, ipcSocket string, dnsResolvers ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yaml")
	var resolvers string
	if len(dnsResolvers) > 0 {
		list, err := json.Marshal(dnsResolvers)
		if err != nil {
			t.Fatal(err)
		}
		resolvers = "\n  dns_resolvers: " + string(list)
	}
	raw := fmt.Sprintf(`server:
  listen: %q
  data_dir: %q
  ipc_socket: %q
acme:
  email: "ops@example.com"
  default_ca: "le"%s
  cas:
    le:
      directory: "https://acme.example.com/directory"
certificates: []
`, listen, dataDir, ipcSocket, resolvers)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunServesUntilCancelled(t *testing.T) {
	dataDir := t.TempDir()
	// Bootstrap the mini-CA up front so the probe can verify the listener.
	miniCA, err := ca.Bootstrap(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	path := writeServerConfig(t, fmt.Sprintf("127.0.0.1:%d", port), dataDir, testIPCSocket(t))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, path) }()
	waitServing(t, miniCA, port, result)

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// enrollClient records the client name in the store under dataDir, as
// enrollment would, and returns its mTLS identity.
func enrollClient(t *testing.T, miniCA *ca.MiniCA, dataDir, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := miniCA.Sign(csr, name)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dataDir, "sigils.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Clients.Upsert(context.Background(), &store.ClientRecord{
		Name:        name,
		Fingerprint: ca.Fingerprint(certDER),
		EnrolledAt:  time.Now().UTC(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
}

// TestRunAnswersWaitingSyncAtShutdown checks that stopping the daemon answers
// a GET /v1/sync that waits for a change, instead of letting it hold up the
// shutdown.
func TestRunAnswersWaitingSyncAtShutdown(t *testing.T) {
	dataDir := t.TempDir()
	miniCA, err := ca.Bootstrap(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	identity := enrollClient(t, miniCA, dataDir, "web-1")
	port := freeTCPPort(t)
	path := writeServerConfig(t, fmt.Sprintf("127.0.0.1:%d", port), dataDir, testIPCSocket(t))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, path) }()
	waitServing(t, miniCA, port, result)

	roots := x509.NewCertPool()
	roots.AddCert(miniCA.Cert())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{identity},
	}}}
	defer client.CloseIdleConnections()
	syncURL := fmt.Sprintf("https://127.0.0.1:%d/v1/sync", port)
	first, err := client.Get(syncURL)
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	etag := first.Header.Get("ETag")
	if first.StatusCode != http.StatusOK || etag == "" {
		t.Fatalf("first sync: status = %d, ETag = %q", first.StatusCode, etag)
	}

	req, err := http.NewRequest(http.MethodGet, syncURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("If-None-Match", etag)
	answered := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotModified {
				err = fmt.Errorf("status %d, want 304", resp.StatusCode)
			}
		}
		answered <- err
	}()
	select {
	case err := <-answered:
		t.Fatalf("sync answered before shutdown: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-answered:
		if err != nil {
			t.Fatalf("waiting sync at shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting sync was not answered within 5s of shutdown")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancellation")
	}
}

// TestRunSetsConfiguredDNSResolvers checks that acme.dns_resolvers reaches
// lego, which keeps it in a process-wide variable.
//
// Nothing can restore that variable, so the check runs in a child process.
func TestRunSetsConfiguredDNSResolvers(t *testing.T) {
	const childEnv = "SIGIL_TEST_RUN_DNS_RESOLVERS"
	if os.Getenv(childEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRunSetsConfiguredDNSResolvers$", "-test.v", "-test.timeout=1m")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		// Without the PASS line the child may have run no test at all.
		if err != nil || !strings.Contains(string(out), "--- PASS: TestRunSetsConfiguredDNSResolvers") {
			t.Fatalf("child process: %v\n%s", err, out)
		}
		return
	}

	resolver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	dataDir := t.TempDir()
	miniCA, err := ca.Bootstrap(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	path := writeServerConfig(t, fmt.Sprintf("127.0.0.1:%d", port), dataDir, testIPCSocket(t), resolver.LocalAddr().String())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, path) }()
	waitServing(t, miniCA, port, result)
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	// Run has returned, so this lookup cannot race with Run setting the
	// resolvers.
	lookup := make(chan error, 1)
	go func() {
		_, err := dns01.FindZoneByFqdn("probe.sigil.test.")
		lookup <- err
	}()
	if err := resolver.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	query := make([]byte, 512)
	n, from, err := resolver.ReadFrom(query)
	if err != nil {
		t.Fatalf("no DNS query reached the configured resolver: %v", err)
	}
	if !bytes.Contains(query[:n], []byte("\x05probe\x05sigil\x04test\x00")) {
		t.Fatalf("DNS query %x does not ask for the probe name", query[:n])
	}
	// Echo the query back as a REFUSED answer so the lookup ends at once.
	query[2] |= 0x80                // QR: response
	query[3] = query[3]&0xf0 | 0x05 // RCODE: REFUSED
	if _, err := resolver.WriteTo(query[:n], from); err != nil {
		t.Fatal(err)
	}
	select {
	case <-lookup:
	case <-time.After(10 * time.Second):
		t.Fatal("DNS lookup did not end after the REFUSED answer")
	}
}

// waitServing polls the HTTPS listener of a Run started in the background
// until it answers, failing the test if Run returns first.
func waitServing(t *testing.T, miniCA *ca.MiniCA, port int, result <-chan error) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(miniCA.Cert())
	probe := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
	}
	target := fmt.Sprintf("https://127.0.0.1:%d/install.sh", port)
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := probe.Get(target)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		select {
		case runErr := <-result:
			t.Fatalf("Run returned before serving: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTPS listener did not become ready: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRunFailsFastOnBusyHTTPSWithoutTouchingIPC(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	socket := testIPCSocket(t)
	// The management endpoint of a daemon that is already running.
	live, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	path := writeServerConfig(t, busy.Addr().String(), t.TempDir(), socket)

	start := time.Now()
	err = Run(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "https listen") {
		t.Fatalf("Run error = %v, want an https listen failure", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("busy HTTPS address took %s to fail", elapsed)
	}

	// The running daemon's endpoint must still answer. Dialing a Windows pipe
	// needs elevation, and a second listener on a pipe name fails there anyway.
	if runtime.GOOS != "windows" {
		conn, err := ipc.Dial(socket)
		if err != nil {
			t.Fatalf("running daemon's IPC endpoint was disturbed: %v", err)
		}
		conn.Close()
	}

	// Nothing left behind by the failed instance holds the endpoint.
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := ipc.Listen(socket)
	if err != nil {
		t.Fatalf("IPC endpoint is still held after the failed start: %v", err)
	}
	again.Close()
}

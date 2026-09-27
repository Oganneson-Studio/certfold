package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
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
func writeServerConfig(t *testing.T, listen, dataDir, ipcSocket string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yaml")
	raw := fmt.Sprintf(`server:
  listen: %q
  data_dir: %q
  ipc_socket: %q
acme:
  email: "ops@example.com"
  default_ca: "le"
  cas:
    le:
      directory: "https://acme.example.com/directory"
certificates: []
`, listen, dataDir, ipcSocket)
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

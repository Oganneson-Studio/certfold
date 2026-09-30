package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testIPCSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\sigil-client-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	}
	// Unix socket paths are length-limited; keep this one short.
	dir, err := os.MkdirTemp("", "sigil")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func TestRunReturnsNilWhenCancelled(t *testing.T) {
	// A listener that accepts the first sync request and never answers shows
	// the daemon reached its sync loop.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	path := filepath.Join(t.TempDir(), "client.yaml")
	raw := fmt.Sprintf("client:\n  name: web-1\n  server_url: %q\n  data_dir: %q\n  ipc_socket: %q\n",
		"https://"+upstream.Addr().String(), t.TempDir(), testIPCSocket(t))
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	logs := setupLogs(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, path, logs) }()

	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := upstream.Accept(); err == nil {
			accepted <- conn
		}
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case err := <-result:
		t.Fatalf("Run returned before pulling: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("daemon did not start pulling")
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

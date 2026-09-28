package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/version"
)

// setupLogs runs logging.Setup with a service log that is discarded, for the
// duration of t. Setup also routes the standard log package through slog,
// which restoring the default logger does not undo, so the cleanup restores
// that as well. Call it before starting a daemon, so that the daemon stops
// before the cleanup runs.
func setupLogs(t *testing.T) logging.Logs {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	return logging.Setup(slog.NewTextHandler(io.Discard, nil))
}

func TestRunServesItsEvents(t *testing.T) {
	// A server that never answers keeps the daemon in its first pull.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	serverURL := "https://" + upstream.Addr().String()
	socket := testIPCSocket(t)
	path := filepath.Join(t.TempDir(), "client.yaml")
	raw := fmt.Sprintf("client:\n  name: web-1\n  server_url: %q\n  data_dir: %q\n  ipc_socket: %q\n",
		serverURL, t.TempDir(), socket)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	logs := setupLogs(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, path, logs) }()

	var c *ipc.Client
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if c, err = ipc.NewClient(socket); err == nil {
			break
		}
		if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
			t.Skip("the sigilc pipe admits only SYSTEM and elevated administrators")
		}
		select {
		case err := <-result:
			t.Fatalf("Run returned before serving IPC: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon IPC did not become ready: %v", err)
		}
	}
	page, err := c.Events(ctx, 0)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(page.Events) == 0 {
		t.Fatal("the daemon served no events")
	}
	if e := page.Events[0]; e.Level != "INFO" || e.Message != "sigilc started" ||
		e.Attrs != fmt.Sprintf("version=%s server=%s", version.Version, serverURL) {
		t.Errorf("first event = %+v, want INFO sigilc started with the version and the server", e)
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
	events := logs.Events.Since(0)
	if e := events[len(events)-1]; e.Level != "INFO" || e.Message != "sigilc stopping" {
		t.Errorf("last event = %+v, want INFO sigilc stopping", e)
	}
}

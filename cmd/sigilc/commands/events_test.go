package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// runSigilc runs sigilc with args and returns what it printed to stdout.
func runSigilc(t *testing.T, args ...string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	printed := make(chan []byte)
	go func() {
		raw, _ := io.ReadAll(r)
		printed <- raw
	}()
	root := NewRootCmd()
	root.SetArgs(args)
	runErr := root.Execute()
	os.Stdout = stdout
	_ = w.Close()
	out := <-printed
	_ = r.Close()
	if runErr != nil {
		t.Fatalf("sigilc %s: %v", strings.Join(args, " "), runErr)
	}
	return string(out)
}

// serveEvents serves the IPC API with the events of ring alone until the
// test ends, and returns its endpoint.
func serveEvents(t *testing.T, ring *logging.Ring) string {
	t.Helper()
	socket := fmt.Sprintf(`\\.\pipe\sigilc-events-test-%d`, time.Now().UnixNano())
	if runtime.GOOS != "windows" {
		// Unix socket paths are length-limited; keep this one short.
		dir, err := os.MkdirTemp("", "sigil")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		socket = filepath.Join(dir, "c.sock")
	}
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := ipc.NewServer(ipc.ServerDeps{Events: ring})
	context.AfterFunc(ctx, func() { _ = srv.Close() })
	go func() { _ = srv.Serve(l) }()
	if _, err := ipc.NewClient(socket); err != nil {
		if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
			t.Skip("the sigilc pipe admits only SYSTEM and elevated administrators")
		}
		t.Fatal(err)
	}
	return socket
}

func TestEventsPrintsDaemonEvents(t *testing.T) {
	ring := logging.NewRing()
	logger := slog.New(logging.NewHandler(slog.NewTextHandler(io.Discard, nil), ring))
	logger.Info("sigilc started", "version", "test", "server", "https://sigil.example.com:8443")
	logger.Warn("round failed", "error", "connection refused")
	logger.Info("outputs rewritten")
	socket := serveEvents(t, ring)

	text := runSigilc(t, "--ipc", socket, "events")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	want := []string{
		"INFO   sigilc started  version=test server=https://sigil.example.com:8443",
		`WARN   round failed  error="connection refused"`,
		"INFO   outputs rewritten",
	}
	if len(lines) != len(want) {
		t.Fatalf("events printed:\n%s\nwant %d lines", text, len(want))
	}
	for i, line := range lines {
		if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}  ` + regexp.QuoteMeta(want[i]) + `$`).MatchString(line) {
			t.Errorf("line %d = %q, want the time followed by %q", i+1, line, want[i])
		}
	}

	// --json prints the events alone, as an array.
	raw := runSigilc(t, "--ipc", socket, "events", "--json")
	var events []logging.Event
	if err := json.Unmarshal([]byte(raw), &events); err != nil {
		t.Fatalf("events --json printed %q: %v", raw, err)
	}
	if len(events) != 3 || events[1].Level != "WARN" || events[1].Message != "round failed" || events[1].Attrs != `error="connection refused"` {
		t.Fatalf("events --json = %+v", events)
	}
}

func TestEventsFailsWhenDaemonIsNotRunning(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"--ipc", missingIPCSocket(t), "events"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "ipc unavailable") {
		t.Fatalf("events without a daemon: error = %v, want ipc unavailable", err)
	}
}

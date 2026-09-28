package server

import (
	"bytes"
	"io"
	"log"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// setupLogs runs logging.Setup with a service log written to sink for the
// duration of t. Setup also routes the standard log package through slog,
// which restoring the default logger does not undo, so the cleanup restores
// that as well. Call it before starting a daemon, so that the daemon stops
// before the cleanup runs.
func setupLogs(t *testing.T, sink io.Writer) logging.Logs {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	return logging.Setup(slog.NewTextHandler(sink, nil))
}

// lockedBuffer is a service log that a running daemon writes to while the
// test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitLogged waits until the service log in b contains want.
func waitLogged(t *testing.T, b *lockedBuffer, want string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(b.String(), want); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("service log does not contain %q:\n%s", want, b.String())
		}
	}
}

// findEvent returns the first event with the message msg, failing the test
// if there is none.
func findEvent(t *testing.T, events []logging.Event, msg string) logging.Event {
	t.Helper()
	for _, e := range events {
		if e.Message == msg {
			return e
		}
	}
	t.Fatalf("no event %q among %+v", msg, events)
	return logging.Event{}
}

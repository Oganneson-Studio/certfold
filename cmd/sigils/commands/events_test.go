package commands

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/logging"
)

func TestEventsPrintsDaemonEvents(t *testing.T) {
	socket, listen, _ := startDaemon(t, filepath.Join(t.TempDir(), "data"), "https://sigil.example.com")

	text := runSigils(t, "--ipc", socket, "events")
	first, _, _ := strings.Cut(text, "\n")
	pattern := `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}  INFO   sigils started  version=\S+ listen=` +
		regexp.QuoteMeta(listen) + ` public_url=https://sigil\.example\.com$`
	if !regexp.MustCompile(pattern).MatchString(first) {
		t.Fatalf("first line %q does not match %s; output:\n%s", first, pattern, text)
	}

	// --json prints the events alone, as an array.
	raw := runSigils(t, "--ipc", socket, "--json", "events")
	var events []logging.Event
	if err := json.Unmarshal([]byte(raw), &events); err != nil {
		t.Fatalf("events --json printed %q: %v", raw, err)
	}
	if len(events) == 0 || events[0].Seq != 1 || events[0].Message != "sigils started" {
		t.Fatalf("events --json = %+v, want sigils started first", events)
	}
}

func TestEventsFailsWhenDaemonIsNotRunning(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"--ipc", testIPCSocket(t), "events"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "ipc unavailable") {
		t.Fatalf("events without a daemon: error = %v, want ipc unavailable", err)
	}
}

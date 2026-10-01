package client

import (
	"errors"
	"strings"
	"testing"
)

// TestHeaderShowsWhenCertfoldcDoesNotAnswer covers a refresh that cannot read
// the state: the header stops calling the server online, since that comes
// from the state of an earlier refresh, and calls it online again once a
// refresh reads the state. A refresh that reads the state but not the events
// keeps it.
func TestHeaderShowsWhenCertfoldcDoesNotAnswer(t *testing.T) {
	f := newTestBackend()
	m := newModel(t, f)
	if view := plain(m); !strings.Contains(view, "online") {
		t.Fatalf("header of an answering certfoldc lacks online:\n%s", view)
	}

	f.stateErr = errors.New("ipc request: certfoldc stopped")
	m = press(t, m, "r")
	if view := plain(m); strings.Contains(view, "online") || !strings.Contains(view, "unknown, certfoldc is not answering") {
		t.Errorf("header of a certfoldc that does not answer:\n%s", view)
	}

	f.stateErr = nil
	f.eventsErr = errors.New("ipc GET /ipc/v1/events?after=0: server returned 404")
	m = press(t, m, "r")
	if view := plain(m); !strings.Contains(view, "online") || strings.Contains(view, "not answering") {
		t.Errorf("header after a refresh that read the state:\n%s", view)
	}
}

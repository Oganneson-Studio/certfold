package client

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// messages returns the messages of the events m holds.
func messages(m Model) []string {
	out := make([]string, 0, len(m.events))
	for _, e := range m.events {
		out = append(out, e.Message)
	}
	return out
}

// TestRefreshReadsNewEventsOnly covers the events of one daemon: each refresh
// asks for those after the newest the model holds, and adds them.
func TestRefreshReadsNewEventsOnly(t *testing.T) {
	f := newTestBackend()
	f.emit(3, "first")
	m := newModel(t, f)
	f.emit(2, "second")
	m = press(t, m, "r")
	m = press(t, m, "r")

	if want := []uint64{0, 3, 5}; !slices.Equal(f.afters, want) {
		t.Errorf("Events asked after %v, want %v", f.afters, want)
	}
	if got, want := messages(m), []string{"first 1", "first 2", "first 3", "second 1", "second 2"}; !slices.Equal(got, want) {
		t.Errorf("events = %q, want %q", got, want)
	}
	if m.lastSeq != 5 {
		t.Errorf("lastSeq = %d, want 5", m.lastSeq)
	}
}

// TestRefreshStartsOverWhenTheDaemonRestarts covers a daemon that restarted
// between two refreshes. Its events start over from Seq 1, so asking after
// the newest Seq held returns only part of them, or none: the model drops the
// events of the old daemon and reads those of the new one from the start.
func TestRefreshStartsOverWhenTheDaemonRestarts(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int // events of the new daemon; the old one had 5
	}{
		{"more events than the old daemon", 8},
		{"fewer events than the old daemon", 2},
		{"no events yet", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestBackend()
			f.emit(5, "old")
			m := newModel(t, f)
			f.restart()
			f.emit(tc.n, "new")
			f.afters = nil
			m = press(t, m, "r")

			if want := []uint64{5, 0}; !slices.Equal(f.afters, want) {
				t.Errorf("Events asked after %v, want %v", f.afters, want)
			}
			want := []string{}
			for _, e := range f.events {
				want = append(want, e.Message)
			}
			if got := messages(m); !slices.Equal(got, want) {
				t.Errorf("events = %q, want those of the new daemon %q", got, want)
			}
			if !m.started.Equal(f.started) || m.lastSeq != uint64(tc.n) {
				t.Errorf("started = %s, lastSeq = %d, want %s and %d", m.started, m.lastSeq, f.started, tc.n)
			}

			// The next refresh continues after the events of the new daemon.
			f.emit(1, "later")
			f.afters = nil
			m = press(t, m, "r")
			if want := []uint64{uint64(tc.n)}; !slices.Equal(f.afters, want) {
				t.Errorf("next refresh asked after %v, want %v", f.afters, want)
			}
			if got := messages(m); len(got) != tc.n+1 || got[tc.n] != "later 1" {
				t.Errorf("events after the next refresh = %q", got)
			}
		})
	}
}

// TestRefreshKeepsTheNewestEvents covers a TUI left open while the daemon
// logs more than a ring holds: the model keeps as many as the ring, the
// newest.
func TestRefreshKeepsTheNewestEvents(t *testing.T) {
	f := newTestBackend()
	f.emit(logging.RingSize-10, "event")
	m := newModel(t, f)
	f.emit(30, "more")
	m = press(t, m, "r")

	got := messages(m)
	if len(got) != logging.RingSize || got[len(got)-1] != "more 30" || m.events[0].Seq != 21 {
		t.Errorf("model holds %d events from Seq %d to %q, want %d up to more 30 from Seq 21",
			len(got), m.events[0].Seq, got[len(got)-1], logging.RingSize)
	}
}

// TestRefreshShowsErrors covers the errors of a refresh: the view shows them
// until a refresh succeeds, and the state read before an events error still
// shows.
func TestRefreshShowsErrors(t *testing.T) {
	f := newTestBackend()
	m := newModel(t, f)

	f.stateErr = errors.New("ipc request: sigilc stopped")
	m = press(t, m, "r")
	if view := plain(m); !strings.Contains(view, "Error: ipc request: sigilc stopped") || !strings.Contains(view, "web-1") {
		t.Errorf("view after a failed state read lacks the error or the last state:\n%s", view)
	}

	f.stateErr = nil
	f.state.Name = "web-2"
	f.eventsErr = errors.New("ipc GET /ipc/v1/events?after=0: server returned 404")
	m = press(t, m, "r")
	if view := plain(m); !strings.Contains(view, "Error: ipc GET /ipc/v1/events?after=0: server returned 404") || !strings.Contains(view, "web-2") {
		t.Errorf("view after a failed events read lacks the error or the new state:\n%s", view)
	}

	f.eventsErr = nil
	m = press(t, m, "r")
	if view := plain(m); strings.Contains(view, "Error:") {
		t.Errorf("view after a refresh that succeeded still shows an error:\n%s", view)
	}
}

// TestEventsViewFollowsNewEvents covers the events view: at the bottom it
// shows the events that arrive, and scrolled up it stays where it is.
func TestEventsViewFollowsNewEvents(t *testing.T) {
	f := newTestBackend()
	f.emit(100, "event")
	m := press(t, newModel(t, f), "e")
	if !m.eventsView.AtBottom() {
		t.Fatal("events view does not open at the bottom")
	}

	f.emit(50, "more")
	m = press(t, m, "r")
	if !m.eventsView.AtBottom() || !strings.Contains(plain(m), "more 50") {
		t.Errorf("events view at the bottom did not follow the new events:\n%s", plain(m))
	}

	m = press(t, m, "pgup")
	offset := m.eventsView.YOffset()
	f.emit(50, "later")
	m = press(t, m, "r")
	if m.eventsView.YOffset() != offset {
		t.Errorf("events view scrolled up moved from line %d to %d", offset, m.eventsView.YOffset())
	}
}

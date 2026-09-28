package client

import (
	"slices"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// TestRefreshWaitsForTheOneInFlight covers r and the end of a fetch while a
// refresh runs: they start none, so refreshes never overlap and a daemon that
// does not answer holds one request at most.
func TestRefreshWaitsForTheOneInFlight(t *testing.T) {
	m, first := step(t, newModel(t, newTestBackend()), keyMsg(t, "r"))
	if first == nil {
		t.Fatal("r returned no command")
	}
	if _, cmd := step(t, m, keyMsg(t, "r")); cmd != nil {
		t.Error("r during a refresh returned a command")
	}
	if _, cmd := step(t, m, actionMsg{name: "fetch"}); cmd != nil {
		t.Error("the end of a fetch during a refresh returned a command")
	}
}

// TestRefreshAfterTheRingIsFull covers the refresh after the model dropped its
// oldest events: it asks for those after the newest Seq held, not after the
// number of events held.
func TestRefreshAfterTheRingIsFull(t *testing.T) {
	f := newTestBackend()
	f.emit(logging.RingSize-10, "event")
	m := newModel(t, f)
	f.emit(30, "more")
	m = press(t, m, "r")
	f.emit(1, "last")
	f.afters = nil
	m = press(t, m, "r")

	if want := []uint64{logging.RingSize + 20}; !slices.Equal(f.afters, want) {
		t.Errorf("Events asked after %v, want %v", f.afters, want)
	}
	if got := messages(m); len(got) != logging.RingSize || got[len(got)-1] != "last 1" || m.events[0].Seq != 22 {
		t.Errorf("model holds %d events from Seq %d to %q", len(got), m.events[0].Seq, got[len(got)-1])
	}
}

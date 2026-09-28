package server

// Put in internal/tui/server. Both tests pass on 39c71eb.
// Mutations that must turn them red:
//   - startRefresh without the `if m.refreshing { return nil }` gate
//     -> TestRefreshWaitsForTheOneInFlight;
//   - addEvents trimming to RingSize first and then setting
//     m.lastSeq = uint64(len(m.events)) (the bug found in E2), or setting it
//     to the count at any other place -> TestRefreshAfterTheRingIsFull.

import (
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// r, the end of an action and a created token start no refresh while one is
// in flight. drive cannot show it, as it runs each command at once.
func TestRefreshWaitsForTheOneInFlight(t *testing.T) {
	m := loaded(t, newFake(3))
	next, first := m.Update(keyMsg("r"))
	if first == nil {
		t.Fatal("r started no refresh")
	}
	m = next.(Model)
	if _, cmd := m.Update(keyMsg("r")); cmd != nil {
		t.Error("r during a refresh started another")
	}
	if _, cmd := m.Update(actionMsg{}); cmd != nil {
		t.Error("the end of an action during a refresh started another")
	}
	created := createdMsg{name: "web-9", token: &ipc.CreateTokenResponse{Token: testToken, ServerURL: testServerURL}}
	if _, cmd := m.Update(created); cmd != nil {
		t.Error("a token created during a refresh started another")
	}

	m, _ = drive(t, m, first())
	if _, cmd := m.Update(keyMsg("r")); cmd == nil {
		t.Error("r after the refresh ended started none")
	}
}

// Once the model holds RingSize events, the next refresh asks for the events
// after the newest Seq it holds, not after the number of events it holds.
func TestRefreshAfterTheRingIsFull(t *testing.T) {
	t.Run("the ring fills while the TUI runs", func(t *testing.T) {
		fake := newFake(logging.RingSize - 10)
		m := loaded(t, fake)
		fake.setEvents(makeEvents(1, logging.RingSize+20, "event"))
		m = refresh(t, m)
		fake.setEvents(makeEvents(1, logging.RingSize+21, "event"))
		m = refresh(t, m)
		checkEventsAfter(t, fake, m, logging.RingSize+20, 22, logging.RingSize+21)
	})
	t.Run("the TUI starts on a full ring", func(t *testing.T) {
		// The daemon's Ring has dropped Seq 1 to 100.
		fake := newFake(0)
		fake.events = makeEvents(101, logging.RingSize+100, "event")
		m := loaded(t, fake)
		fake.setEvents(makeEvents(101, logging.RingSize+101, "event"))
		m = refresh(t, m)
		checkEventsAfter(t, fake, m, logging.RingSize+100, 102, logging.RingSize+101)
	})
}

// checkEventsAfter checks that the last refresh asked for the events after
// after, and that m holds RingSize events from Seq first to last, each once.
func checkEventsAfter(t *testing.T, fake *fakeBackend, m Model, after, first, last uint64) {
	t.Helper()
	afters := fake.eventsAfters()
	if got := afters[len(afters)-1]; got != after {
		t.Errorf("the last refresh asked for the events after %d, want %d", got, after)
	}
	n := len(m.events)
	if n != logging.RingSize || m.events[0].Seq != first || m.events[n-1].Seq != last {
		t.Errorf("model holds %d events from Seq %d to %d, want %d from %d to %d",
			n, m.events[0].Seq, m.events[n-1].Seq, logging.RingSize, first, last)
	}
	for i := 1; i < n; i++ {
		if m.events[i].Seq != m.events[i-1].Seq+1 {
			t.Fatalf("events %d and %d have Seq %d and %d", i-1, i, m.events[i-1].Seq, m.events[i].Seq)
		}
	}
}

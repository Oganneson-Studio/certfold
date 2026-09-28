package server

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/logging"
)

func TestRefreshErrorShownUntilARefreshSucceeds(t *testing.T) {
	const shown = "server returned 500: database is locked"
	fake := newFake(3)
	fake.listErr = errors.New("ipc GET /ipc/v1/certs: " + shown)
	m := loaded(t, fake)
	if !shows(m, shown) {
		t.Fatalf("the failed refresh is not shown: %q", m.View())
	}
	if m = refresh(t, m); !shows(m, shown) {
		t.Fatalf("a second failed refresh hid the error: %q", m.View())
	}

	fake.setListErr(nil)
	if m = refresh(t, m); shows(m, shown) || !shows(m, "api-prod") {
		t.Errorf("a refresh that succeeded left the error or missed the lists: %q", m.View())
	}
}

// An action that fails stays on the status line after the next refresh,
// until the next action starts.
func TestActionErrorOutlivesRefresh(t *testing.T) {
	const shown = `server returned 404: client "web-2" is not enrolled`
	fake := newFake(3)
	fake.actionErr = errors.New("ipc DELETE /ipc/v1/clients/web-2: " + shown)
	m, _ := press(t, onTab(t, fake, tabClients), "d", "y")
	if !shows(m, shown) {
		t.Fatalf("the failed removal is not shown: %q", m.View())
	}
	if m = refresh(t, m); !shows(m, shown) {
		t.Fatalf("the refresh after the failed removal hid it: %q", m.View())
	}

	fake.setActionErr(nil)
	if m, _ = press(t, m, "d", "y"); shows(m, shown) {
		t.Errorf("a removal that succeeded left the earlier error: %q", m.View())
	}
}

func TestEventsStartOverWhenTheDaemonRestarts(t *testing.T) {
	// The restarted daemon has written fewer events than the TUI has seen,
	// or more, so after=lastSeq returns none of them or only the last ones.
	for _, written := range []uint64{3, 8} {
		t.Run(fmt.Sprintf("%d events since restart", written), func(t *testing.T) {
			fake := newFake(0)
			fake.events = makeEvents(1, 5, "old")
			m := loaded(t, fake)
			if m.lastSeq != 5 {
				t.Fatalf("lastSeq after the first refresh = %d, want 5", m.lastSeq)
			}

			fake.restart(makeEvents(1, written, "new"))
			m = refresh(t, m)
			var got []string
			for _, e := range m.events {
				got = append(got, e.Message)
			}
			var want []string
			for _, e := range makeEvents(1, written, "new") {
				want = append(want, e.Message)
			}
			if !slices.Equal(got, want) {
				t.Errorf("events after the restart = %q, want %q", got, want)
			}
			if m.lastSeq != written {
				t.Errorf("lastSeq = %d, want %d", m.lastSeq, written)
			}
			if afters := fake.eventsAfters(); !slices.Equal(afters, []uint64{0, 5, 0}) {
				t.Errorf("Events asked with after %v, want [0 5 0]", afters)
			}
			m.tab = tabEvents
			if shows(m, "old-") {
				t.Error("the Events tab still shows events of the daemon before its restart")
			}
		})
	}
}

func TestEventsKeepRingSize(t *testing.T) {
	fake := newFake(300)
	m := loaded(t, fake)
	fake.setEvents(makeEvents(1, 600, "event"))
	m = refresh(t, m)
	if n := len(m.events); n != logging.RingSize || m.events[0].Seq != 101 || m.events[n-1].Seq != 600 {
		t.Errorf("kept %d events from %d to %d, want %d from 101 to 600", n, m.events[0].Seq, m.events[n-1].Seq, logging.RingSize)
	}
}

// The Events tab follows new events while it shows the newest one, and stays
// where it is once scrolled up.
func TestEventsFollowNewestOnly(t *testing.T) {
	fake := newFake(80)
	m := loaded(t, fake)
	m.tab = tabEvents
	fake.setEvents(makeEvents(1, 85, "event"))
	if m = refresh(t, m); !m.eventsView.AtBottom() || !shows(m, "event-85") {
		t.Fatalf("the Events tab did not follow event-85: %q", m.View())
	}

	m, _ = press(t, m, "k")
	offset := m.eventsView.YOffset
	fake.setEvents(makeEvents(1, 90, "event"))
	if m = refresh(t, m); m.eventsView.AtBottom() || m.eventsView.YOffset != offset {
		t.Errorf("the scrolled Events tab moved from offset %d to %d", offset, m.eventsView.YOffset)
	}
}

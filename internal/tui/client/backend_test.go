package client

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// fakeBackend is a Backend that answers from its fields and records the
// calls. Tests run the commands of the model on their own goroutine, so it
// needs no lock.
type fakeBackend struct {
	state    ipc.ClientState
	stateErr error
	// started and events are those of the daemon; events is oldest first.
	started   time.Time
	events    []logging.Event
	eventsErr error
	fetchErr  error
	reloadErr error
	// hangState and hangEvents make GetClientState and Events answer like a
	// daemon that does not.
	hangState, hangEvents bool

	stateCalls int
	afters     []uint64 // the after of each Events call
	fetches    []string // the name of each FetchClient call
	reloads    int
}

// hang returns when ctx ends, with its error, or after 5 seconds if no
// deadline ends it.
func hang(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return errors.New("no deadline ended the call")
	}
}

func (f *fakeBackend) GetClientState(ctx context.Context) (*ipc.ClientState, error) {
	f.stateCalls++
	if f.hangState {
		return nil, hang(ctx)
	}
	if f.stateErr != nil {
		return nil, f.stateErr
	}
	state := f.state
	return &state, nil
}

func (f *fakeBackend) FetchClient(_ context.Context, name string) error {
	f.fetches = append(f.fetches, name)
	return f.fetchErr
}

func (f *fakeBackend) ReloadClient(context.Context) error {
	f.reloads++
	return f.reloadErr
}

func (f *fakeBackend) Events(ctx context.Context, after uint64) (*ipc.EventsPage, error) {
	f.afters = append(f.afters, after)
	if f.hangEvents {
		return nil, hang(ctx)
	}
	if f.eventsErr != nil {
		return nil, f.eventsErr
	}
	page := &ipc.EventsPage{Started: f.started, Events: []logging.Event{}}
	for _, e := range f.events {
		if e.Seq > after {
			page.Events = append(page.Events, e)
		}
	}
	return page, nil
}

// emit adds n events to the daemon, numbered on from its newest, with
// messages prefix 1, prefix 2 and so on.
func (f *fakeBackend) emit(n int, prefix string) {
	for i := 1; i <= n; i++ {
		f.events = append(f.events, logging.Event{
			Seq:     uint64(len(f.events) + 1),
			Time:    f.started.Add(time.Duration(len(f.events)) * time.Second),
			Level:   "INFO",
			Message: fmt.Sprintf("%s %d", prefix, i),
		})
	}
}

// restart makes the daemon start over: a later Started and no events.
func (f *fakeBackend) restart() {
	f.started = f.started.Add(time.Hour)
	f.events = nil
}

// newModel returns a Model of f on a 100x30 screen that has refreshed once.
func newModel(t *testing.T, f *fakeBackend) Model {
	t.Helper()
	m, _ := step(t, New(f), tea.WindowSizeMsg{Width: 100, Height: 30})
	return press(t, m, "r")
}

// step passes msg to m and returns what Update returns.
func step(t *testing.T, m Model, msg tea.Msg) (Model, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(msg)
	return next.(Model), cmd
}

// settle runs cmd, and then the command Update returns for its message, until
// there is none, and returns the model and the messages. None of the commands
// may be a tick.
func settle(t *testing.T, m Model, cmd tea.Cmd) (Model, []tea.Msg) {
	t.Helper()
	var msgs []tea.Msg
	for cmd != nil {
		msg := cmd()
		msgs = append(msgs, msg)
		m, cmd = step(t, m, msg)
	}
	return m, msgs
}

// press sends the key k names to m and settles the command it returns.
func press(t *testing.T, m Model, k string) Model {
	t.Helper()
	m, cmd := step(t, m, keyMsg(t, k))
	m, _ = settle(t, m, cmd)
	return m
}

// keyMsg returns the message of the key k names, as key bindings name keys.
func keyMsg(t *testing.T, k string) tea.KeyMsg {
	t.Helper()
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	for _, typ := range []tea.KeyType{tea.KeyCtrlC, tea.KeyCtrlD, tea.KeyCtrlU, tea.KeyUp, tea.KeyDown, tea.KeyPgUp, tea.KeyPgDown, tea.KeySpace} {
		if typ.String() == k {
			msg = tea.KeyMsg{Type: typ}
		}
	}
	if msg.String() != k {
		t.Fatalf("no key message names %q", k)
	}
	return msg
}

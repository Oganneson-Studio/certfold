package client

import (
	"errors"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// keyCheck checks what pressing a key did: before and after are the models
// around it, msgs the messages its commands returned, and f the backend,
// whose calls are those of the key alone.
type keyCheck func(f *fakeBackend, before, after Model, msgs []tea.Msg) bool

func quits(_ *fakeBackend, _, _ Model, msgs []tea.Msg) bool {
	return slices.ContainsFunc(msgs, func(msg tea.Msg) bool { _, ok := msg.(tea.QuitMsg); return ok })
}

func scrollsUp(_ *fakeBackend, before, after Model, _ []tea.Msg) bool {
	return after.eventsView.YOffset() < before.eventsView.YOffset()
}

func scrollsDown(_ *fakeBackend, before, after Model, _ []tea.Msg) bool {
	return after.eventsView.YOffset() > before.eventsView.YOffset()
}

// TestEveryHelpKeyIsWired presses every key the full help shows and checks
// that it does what the help says. The keys of both help lines act in the main
// view and in the events view, where f still fetches rather than pages down;
// the scroll keys act in the events view.
func TestEveryHelpKeyIsWired(t *testing.T) {
	anyView := map[string]keyCheck{
		"f": func(f *fakeBackend, _, _ Model, _ []tea.Msg) bool {
			return slices.Equal(f.fetches, []string{""}) && f.reloads == 0
		},
		"R": func(f *fakeBackend, _, _ Model, _ []tea.Msg) bool { return f.reloads == 1 && len(f.fetches) == 0 },
		"r": func(f *fakeBackend, _, _ Model, _ []tea.Msg) bool {
			return f.stateCalls == 1 && len(f.afters) == 1 && len(f.fetches) == 0 && f.reloads == 0
		},
		"e": func(_ *fakeBackend, before, after Model, _ []tea.Msg) bool {
			return after.showEvents != before.showEvents
		},
		"?": func(_ *fakeBackend, before, after Model, _ []tea.Msg) bool {
			return after.help.ShowAll != before.help.ShowAll
		},
		"q":      quits,
		"ctrl+c": quits,
	}
	eventsView := map[string]keyCheck{
		"up": scrollsUp, "k": scrollsUp, "pgup": scrollsUp, "b": scrollsUp, "u": scrollsUp, "ctrl+u": scrollsUp,
		"down": scrollsDown, "j": scrollsDown, "pgdown": scrollsDown, "space": scrollsDown, "d": scrollsDown, "ctrl+d": scrollsDown,
	}

	keys := New(&fakeBackend{}).keys
	var shown []string
	for _, column := range keys.FullHelp() {
		for _, binding := range column {
			shown = append(shown, binding.Keys()...)
		}
	}
	var short []string
	for _, binding := range keys.ShortHelp() {
		short = append(short, binding.Keys()...)
	}
	for _, k := range shown {
		if anyView[k] == nil && eventsView[k] == nil {
			t.Errorf("the help shows %q, which the test does not check", k)
		}
	}
	for _, checks := range []map[string]keyCheck{anyView, eventsView} {
		for k := range checks {
			if !slices.Contains(shown, k) {
				t.Errorf("the full help does not show %q", k)
			}
		}
	}
	for k := range anyView {
		if !slices.Contains(short, k) {
			t.Errorf("the help line does not show %q", k)
		}
	}

	f := newTestBackend()
	f.emit(200, "event")
	for _, inEvents := range []bool{false, true} {
		for _, k := range shown {
			check := anyView[k]
			if check == nil {
				if !inEvents {
					continue
				}
				check = eventsView[k]
			}
			before := newModel(t, f)
			if inEvents {
				before = press(t, before, "e")
				before.eventsView.SetYOffset(50)
			}
			f.stateCalls, f.afters, f.fetches, f.reloads = 0, nil, nil, 0
			after, cmd := step(t, before, keyMsg(t, k))
			after, msgs := settle(t, after, cmd)
			if !check(f, before, after, msgs) {
				t.Errorf("key %q (events view %v) did not act: backend calls: state %d, events %v, fetches %q, reloads %d",
					k, inEvents, f.stateCalls, f.afters, f.fetches, f.reloads)
			}
		}
	}
}

// TestFetchAndReloadShowTheirOutcome covers f and R: the footer says the
// action runs, then that it is done or why it failed, and the model refreshes
// once it is done.
func TestFetchAndReloadShowTheirOutcome(t *testing.T) {
	for _, tc := range []struct {
		key, name string
		fail      func(*fakeBackend, error)
	}{
		{"f", "fetch", func(f *fakeBackend, err error) { f.fetchErr = err }},
		{"R", "reload", func(f *fakeBackend, err error) { f.reloadErr = err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestBackend()
			m := newModel(t, f)

			m, cmd := step(t, m, keyMsg(t, tc.key))
			if view := plain(m); !strings.Contains(view, tc.name+": running...") {
				t.Errorf("view while the %s runs lacks %q:\n%s", tc.name, tc.name+": running...", view)
			}
			f.state.Name = "web-2"
			m, _ = settle(t, m, cmd)
			if view := plain(m); !strings.Contains(view, tc.name+": done at ") || !strings.Contains(view, "web-2") {
				t.Errorf("view after the %s lacks %q or the state read after it:\n%s", tc.name, tc.name+": done at ", view)
			}

			tc.fail(f, errors.New("client.data_dir changed; restart certfoldc to apply it"))
			m = press(t, m, tc.key)
			want := tc.name + " failed: client.data_dir changed; restart certfoldc to apply it"
			if view := plain(m); !strings.Contains(view, want) || strings.Contains(view, tc.name+": done at ") {
				t.Errorf("view after a failed %s lacks %q:\n%s", tc.name, want, view)
			}
			if got := len(f.fetches) + f.reloads; got != 2 {
				t.Errorf("backend ran %d actions, want 2", got)
			}
		})
	}
}

// TestActionWaitsForTheOneInFlight covers f and R pressed while a fetch or
// reload runs: they start nothing.
func TestActionWaitsForTheOneInFlight(t *testing.T) {
	m, first := step(t, newModel(t, newTestBackend()), keyMsg(t, "f"))
	for _, k := range []string{"f", "R"} {
		if _, cmd := step(t, m, keyMsg(t, k)); cmd != nil {
			t.Errorf("%s during a fetch returned a command", k)
		}
	}
	if first == nil {
		t.Fatal("f returned no command")
	}
}

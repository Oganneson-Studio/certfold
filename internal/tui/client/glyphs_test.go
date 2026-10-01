package client

import (
	"errors"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Oganneson-Studio/certfold/internal/ipc"
	"github.com/Oganneson-Studio/certfold/internal/tui/shared"
)

// TestViewDrawsOnlyNarrowGlyphs checks every view of the certfoldc TUI for a
// character that some consoles draw two cells wide (see shared.WideGlyph). At
// 40 columns the help cuts its keys with an ellipsis.
func TestViewDrawsOnlyNarrowGlyphs(t *testing.T) {
	backend := func() *fakeBackend {
		f := newTestBackend()
		f.state.LastError = "sync: server returned 503"
		f.state.Certs = append(f.state.Certs, ipc.ClientCertState{
			Name: "expired", NotAfter: time.Now().Add(-time.Hour), RenewAt: time.Now().Add(-48 * time.Hour), Outputs: 1, OnChange: true, HookPending: true,
		})
		f.emit(30, "event")
		f.events[3].Level, f.events[4].Level = "WARN", "ERROR"
		return f
	}
	views := map[string]func(t *testing.T, f *fakeBackend) Model{
		"main":                 func(t *testing.T, f *fakeBackend) Model { return newModel(t, f) },
		"main with all keys":   func(t *testing.T, f *fakeBackend) Model { return press(t, newModel(t, f), "?") },
		"events":               func(t *testing.T, f *fakeBackend) Model { return press(t, newModel(t, f), "e") },
		"events with all keys": func(t *testing.T, f *fakeBackend) Model { return press(t, press(t, newModel(t, f), "e"), "?") },
		"certfoldc not answering": func(t *testing.T, f *fakeBackend) Model {
			m := newModel(t, f)
			f.stateErr = errors.New("ipc request: certfoldc stopped")
			return press(t, m, "r")
		},
		"fetch running": func(t *testing.T, f *fakeBackend) Model {
			m, _ := step(t, newModel(t, f), keyMsg(t, "f"))
			return m
		},
		"fetch failed": func(t *testing.T, f *fakeBackend) Model {
			f.fetchErr = errors.New("sync: server returned 503")
			return press(t, newModel(t, f), "f")
		},
	}
	for _, size := range []tea.WindowSizeMsg{{Width: 40, Height: 24}, {Width: 120, Height: 40}} {
		for name, open := range views {
			m, _ := step(t, open(t, backend()), size)
			if r, wide := shared.WideGlyph(m.View().Content); wide {
				t.Errorf("%s at %d columns draws %q", name, size.Width, r)
			}
		}
	}
}

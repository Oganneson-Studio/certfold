package client

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

func newTestBackend() *fakeBackend {
	return &fakeBackend{
		state: ipc.ClientState{
			Name:      "web-1",
			ServerURL: "https://sigil.example.com",
			Online:    true,
			Certs: []ipc.ClientCertState{
				{Name: "api-prod", NotAfter: time.Now().Add(60 * 24 * time.Hour), Outputs: 3},
				{Name: "corp", NotAfter: time.Now().Add(14 * 24 * time.Hour), Outputs: 1},
			},
		},
		started: time.Now().Add(-time.Hour),
	}
}

func TestClientModel_QuitKey(t *testing.T) {
	_, cmd := step(t, newModel(t, newTestBackend()), tea.KeyPressMsg{Code: 'q', Text: "q"})
	if cmd == nil {
		t.Fatal("q returned no command")
	}
	if msg := cmd(); msg != (tea.QuitMsg{}) {
		t.Errorf("the command of q returned %#v, want tea.QuitMsg", msg)
	}
}

func TestClientModel_ViewContainsClientName(t *testing.T) {
	view := plain(newModel(t, newTestBackend()))
	if !strings.Contains(view, "web-1") {
		t.Errorf("view missing client name: %q", view[:min(200, len(view))])
	}
}

func TestClientModel_ViewContainsCerts(t *testing.T) {
	view := plain(newModel(t, newTestBackend()))
	if !strings.Contains(view, "api-prod") {
		t.Errorf("view missing api-prod: %q", view)
	}
	if !strings.Contains(view, "corp") {
		t.Errorf("view missing corp: %q", view)
	}
}

func TestClientModel_WindowSize(t *testing.T) {
	m, _ := step(t, newModel(t, newTestBackend()), tea.WindowSizeMsg{Width: 120, Height: 40})
	if m.width != 120 || m.height != 40 {
		t.Errorf("size not updated: %dx%d", m.width, m.height)
	}
}

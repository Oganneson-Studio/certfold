package client

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

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
	tm := teatest.NewTestModel(t, New(newTestBackend()), teatest.WithInitialTermSize(100, 30))
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestClientModel_ViewContainsClientName(t *testing.T) {
	view := newModel(t, newTestBackend()).View()
	if !strings.Contains(view, "web-1") {
		t.Errorf("view missing client name: %q", view[:min(200, len(view))])
	}
}

func TestClientModel_ViewContainsCerts(t *testing.T) {
	view := newModel(t, newTestBackend()).View()
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

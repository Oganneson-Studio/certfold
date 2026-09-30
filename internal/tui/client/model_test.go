package client

import (
	"image/color"
	"reflect"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

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
	tm.Send(tea.KeyPressMsg{Code: 'q', Text: "q"})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

// The help takes the colors for the background the terminal reports.
func TestHelpFollowsTheBackground(t *testing.T) {
	m := newModel(t, newTestBackend())
	for _, tc := range []struct {
		name string
		bg   color.Color
		want help.Styles
	}{
		{"light", color.White, help.DefaultLightStyles()},
		{"dark", color.Black, help.DefaultDarkStyles()},
	} {
		if m, _ = step(t, m, tea.BackgroundColorMsg{Color: tc.bg}); !reflect.DeepEqual(m.help.Styles, tc.want) {
			t.Errorf("on a %s background the help does not take the styles for it", tc.name)
		}
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

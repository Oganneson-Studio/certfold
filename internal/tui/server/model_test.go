package server

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

// newTestModel returns a Model loaded from a fakeBackend (no IPC).
func newTestModel(t *testing.T) Model {
	return loaded(t, newFake(3))
}

func TestModel_InitialTabIsOverview(t *testing.T) {
	m := newTestModel(t)
	if m.tab != tabOverview {
		t.Errorf("initial tab: got %d, want %d", m.tab, tabOverview)
	}
}

func TestModel_QuitKey(t *testing.T) {
	tm := teatest.NewTestModel(t, newTestModel(t), teatest.WithInitialTermSize(100, 30))
	tm.Send(tea.KeyPressMsg{Code: 'q', Text: "q"})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

// The help takes the colors for the background the terminal reports.
func TestHelpFollowsTheBackground(t *testing.T) {
	m := newTestModel(t)
	for _, tc := range []struct {
		name string
		bg   color.Color
		want help.Styles
	}{
		{"light", color.White, help.DefaultLightStyles()},
		{"dark", color.Black, help.DefaultDarkStyles()},
	} {
		next, _ := m.Update(tea.BackgroundColorMsg{Color: tc.bg})
		if m = next.(Model); !reflect.DeepEqual(m.help.Styles, tc.want) {
			t.Errorf("on a %s background the help does not take the styles for it", tc.name)
		}
	}
}

func TestModel_TabSwitchByNumber(t *testing.T) {
	m := newTestModel(t)
	for i := 1; i <= numTabs; i++ {
		updated, _ := m.Update(tea.KeyPressMsg{Code: rune('0' + i), Text: string(rune('0' + i))})
		if got := updated.(Model).tab; got != i-1 {
			t.Errorf("tab key %d: got tab %d, want %d", i, got, i-1)
		}
	}
}

func TestModel_TabCycle(t *testing.T) {
	m := newTestModel(t)
	for i := 0; i < numTabs+1; i++ {
		updated, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
		m = updated.(Model)
	}
	// After numTabs+1 tab presses from tab 0, we should be at tab 1.
	if m.tab != 1 {
		t.Errorf("after %d tabs: got tab %d", numTabs+1, m.tab)
	}
	updated, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	updated, _ = updated.(Model).Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	if got := updated.(Model).tab; got != numTabs-1 {
		t.Errorf("shift+tab twice from tab 1: got tab %d, want %d", got, numTabs-1)
	}
}

func TestModel_OverviewView(t *testing.T) {
	m := newTestModel(t)
	for _, want := range []string{
		"Overview",
		"Certificates 3 issuing 0, backoff 1, valid 1, pending 1",
		"Clients 3",
		"Tokens 3 unused 1, used 1, expired 1",
		"event-3",
	} {
		if !shows(m, want) {
			t.Errorf("overview missing %q: %q", want, plain(m))
		}
	}
}

func TestModel_CertsTabView(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabCertificates
	view := plain(m)
	if !strings.Contains(view, "api-prod") {
		t.Errorf("certs tab missing 'api-prod': %q", view)
	}
}

func TestModel_CertsTabShowsMissingExpiryAsDash(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabCertificates
	// A configured certificate that has not been issued has no expiry.
	if got := m.certsTable.Rows()[2]; got[0] != "new-cert" || got[2] != "-" || got[3] != "-" {
		t.Errorf("row of new-cert = %q, want - for Not After and Renew At", got)
	}
	m.certsTable.SetCursor(2)
	if view := plain(m); !strings.Contains(view, "new-cert") || strings.Contains(view, "0001-01-01") {
		t.Errorf("certs tab should list new-cert without a zero date: %q", view)
	}
}

func TestModel_ClientsTabView(t *testing.T) {
	m := newTestModel(t)
	m.tab = tabClients
	// web-2 subscribes to both certificates.
	if !shows(m, "web-2") || m.clientsTable.Rows()[1][3] != "api-prod,mail" {
		t.Errorf("clients tab should list web-2 with its certificates: %q", plain(m))
	}
}

func TestModel_RefreshMsg(t *testing.T) {
	fake := newFake(3)
	m := loaded(t, fake)
	fake.mu.Lock()
	fake.certs = []*ipc.CertificateInfo{
		{Name: "new-cert", CA: "le", Domains: []string{"new.example.com"}, State: ipc.CertStatePending},
	}
	fake.mu.Unlock()
	m2 := refresh(t, m)
	if len(m2.certs) != 1 || m2.certs[0].Name != "new-cert" {
		t.Errorf("certs not updated: %v", m2.certs)
	}
}

func TestModel_WindowSizeMsg(t *testing.T) {
	m := newTestModel(t)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m2 := updated.(Model)
	if m2.width != 120 || m2.height != 40 {
		t.Errorf("size not updated: %dx%d", m2.width, m2.height)
	}
}

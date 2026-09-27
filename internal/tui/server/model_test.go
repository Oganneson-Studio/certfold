package server

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

// newTestModel returns a Model pre-loaded with sample data (no IPC).
func newTestModel() Model {
	m := New(nil)
	m.width = 100
	m.height = 30
	m.certs = []*ipc.CertificateInfo{
		{Name: "api-prod", CA: "le", Domains: []string{"api.example.com"},
			NotAfter: time.Now().Add(90 * 24 * time.Hour), UpdatedAt: time.Now()},
	}
	m.clients = []*ipc.ClientInfo{
		{Name: "web-1", Fingerprint: "sha256:AABB", EnrolledAt: time.Now()},
	}
	m.tokens = []*ipc.TokenInfo{
		{TokenID: "tok-1", Name: "web-1", ExpiresAt: time.Now().Add(time.Hour)},
	}
	m.updateTableRows()
	return m
}

func TestModel_InitialTabIsDashboard(t *testing.T) {
	m := newTestModel()
	if m.tab != 0 {
		t.Errorf("initial tab: got %d, want 0", m.tab)
	}
}

func TestModel_QuitKey(t *testing.T) {
	tm := teatest.NewTestModel(t, newTestModel(), teatest.WithInitialTermSize(100, 30))
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestModel_TabSwitchByNumber(t *testing.T) {
	m := newTestModel()
	for i := 1; i <= numTabs; i++ {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{rune('0' + i)}})
		if got := updated.(Model).tab; got != i-1 {
			t.Errorf("tab key %d: got tab %d, want %d", i, got, i-1)
		}
	}
}

func TestModel_TabCycle(t *testing.T) {
	m := newTestModel()
	for i := 0; i < numTabs+1; i++ {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = updated.(Model)
	}
	// After numTabs+1 tab presses from tab 0, we should be at tab 1.
	if m.tab != 1 {
		t.Errorf("after %d tabs: got tab %d", numTabs+1, m.tab)
	}
}

func TestModel_DashboardView(t *testing.T) {
	m := newTestModel()
	view := m.View()
	if !strings.Contains(view, "Dashboard") {
		t.Error("dashboard view missing 'Dashboard'")
	}
	if !strings.Contains(view, "Certificates") {
		t.Error("dashboard view missing 'Certificates'")
	}
}

func TestModel_CertsTabView(t *testing.T) {
	m := newTestModel()
	m.tab = 1
	view := m.View()
	if !strings.Contains(view, "api-prod") {
		t.Errorf("certs tab missing 'api-prod': %q", view)
	}
}

func TestModel_ClientsTabView(t *testing.T) {
	m := newTestModel()
	m.tab = 2
	view := m.View()
	if !strings.Contains(view, "web-1") {
		t.Errorf("clients tab missing 'web-1': %q", view)
	}
}

func TestModel_RefreshMsg(t *testing.T) {
	m := newTestModel()
	newCerts := []*ipc.CertificateInfo{
		{Name: "new-cert", CA: "le", Domains: []string{"new.example.com"}, UpdatedAt: time.Now()},
	}
	updated, _ := m.Update(refreshMsg{certs: newCerts, clients: nil, tokens: nil})
	m2 := updated.(Model)
	if len(m2.certs) != 1 || m2.certs[0].Name != "new-cert" {
		t.Errorf("certs not updated: %v", m2.certs)
	}
}

func TestModel_WindowSizeMsg(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m2 := updated.(Model)
	if m2.width != 120 || m2.height != 40 {
		t.Errorf("size not updated: %dx%d", m2.width, m2.height)
	}
}

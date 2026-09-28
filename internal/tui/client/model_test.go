package client

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

func newTestModel() Model {
	m := New("web-1", "https://sigil.example.com", nil)
	m.width = 100
	m.height = 30
	m.online = true
	m.certs = []CertStatus{
		{Name: "api-prod", NotAfter: time.Now().Add(60 * 24 * time.Hour), Outputs: 3, Healthy: true},
		{Name: "corp", NotAfter: time.Now().Add(14 * 24 * time.Hour), Outputs: 1, Healthy: true},
	}
	m.events = []Event{
		{At: time.Now().Add(-time.Hour), Message: "pull ok (no changes)"},
	}
	return m
}

func TestClientModel_QuitKey(t *testing.T) {
	tm := teatest.NewTestModel(t, newTestModel(), teatest.WithInitialTermSize(100, 30))
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestClientModel_ViewContainsClientName(t *testing.T) {
	m := newTestModel()
	view := m.View()
	if !strings.Contains(view, "web-1") {
		t.Errorf("view missing client name: %q", view[:min(200, len(view))])
	}
}

func TestClientModel_ViewContainsCerts(t *testing.T) {
	m := newTestModel()
	view := m.View()
	if !strings.Contains(view, "api-prod") {
		t.Errorf("view missing api-prod: %q", view)
	}
	if !strings.Contains(view, "corp") {
		t.Errorf("view missing corp: %q", view)
	}
}

func TestClientModel_FetchKey(t *testing.T) {
	m := newTestModel()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	m2 := updated.(Model)
	_ = m2
	// cmd must not be nil (fetch was triggered).
	if cmd == nil {
		t.Error("expected non-nil cmd after 'f' key")
	}
}

func TestClientModel_FetchMsg_Success(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(fetchMsg{err: nil})
	m2 := updated.(Model)
	if len(m2.events) == 0 {
		t.Error("expected event after successful fetch")
	}
	last := m2.events[len(m2.events)-1]
	if last.Message != "fetch ok" {
		t.Errorf("unexpected event message: %q", last.Message)
	}
}

func TestClientModel_ToggleLogs(t *testing.T) {
	m := newTestModel()
	if m.showLogs {
		t.Fatal("showLogs should start false")
	}
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	m2 := updated.(Model)
	if !m2.showLogs {
		t.Error("showLogs should be true after 'l'")
	}
	updated, _ = m2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	m3 := updated.(Model)
	if m3.showLogs {
		t.Error("showLogs should toggle back to false")
	}
}

func TestClientModel_WindowSize(t *testing.T) {
	m := newTestModel()
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m2 := updated.(Model)
	if m2.width != 120 || m2.height != 40 {
		t.Errorf("size not updated: %dx%d", m2.width, m2.height)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

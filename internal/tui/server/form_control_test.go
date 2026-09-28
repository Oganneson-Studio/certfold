package server

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// bubbletea keeps every rune of a bracketed paste, so the form drops those
// that control the terminal: it would write a pasted ESC sequence to the
// terminal, and send a name copied with its line break.
func TestFormDropsControlCharacters(t *testing.T) {
	m, _ := press(t, onTab(t, newFake(3), tabTokens), "n")
	m, _ = drive(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("web-9\x1b]0;x\x07\n"), Paste: true})
	if m.form == nil {
		t.Fatal("the paste closed the form")
	}
	if m.form.name != "web-9]0;x" {
		t.Fatalf("name after pasting web-9 ESC ]0;x BEL LF = %q, want %q", m.form.name, "web-9]0;x")
	}
	if strings.ContainsRune(m.View(), '\x1b') {
		t.Error("the form writes the pasted ESC to the terminal")
	}
}

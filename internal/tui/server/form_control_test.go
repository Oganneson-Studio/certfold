package server

import (
	"regexp"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// sgr matches the sequences with which lipgloss styles the view, the only
// escape sequences the view should hold.
var sgr = regexp.MustCompile(`\x1b\[[0-9;:]*m`)

// bubbletea keeps every rune of a bracketed paste, so the form drops those
// that control the terminal: it would write a pasted ESC sequence to the
// terminal, and send a name copied with its line break.
func TestFormDropsControlCharacters(t *testing.T) {
	m, _ := press(t, onTab(t, newFake(3), tabTokens), "n")
	m, _ = drive(t, m, tea.PasteMsg{Content: "web-9\x1b]0;x\x07\n"})
	if m.form == nil {
		t.Fatal("the paste closed the form")
	}
	if m.form.name != "web-9]0;x" {
		t.Fatalf("name after pasting web-9 ESC ]0;x BEL LF = %q, want %q", m.form.name, "web-9]0;x")
	}
	if strings.ContainsRune(sgr.ReplaceAllString(m.View().Content, ""), '\x1b') {
		t.Error("the form writes the pasted ESC to the terminal")
	}
}

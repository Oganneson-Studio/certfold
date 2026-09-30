package server

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestFormDropsC1ControlCharacters is TestFormDropsControlCharacters for the
// C1 controls: some terminals take U+009B for CSI, as they take ESC [, so a
// pasted one would start an escape sequence as a pasted ESC does. NEL
// (U+0085) would break the line of the form.
func TestFormDropsC1ControlCharacters(t *testing.T) {
	m, _ := press(t, onTab(t, newFake(3), tabTokens), "n")
	m, _ = drive(t, m, tea.PasteMsg{Content: "web-9\u009b31m\u0085x"})
	if m.form == nil {
		t.Fatal("the paste closed the form")
	}
	if m.form.name != "web-931mx" {
		t.Fatalf("name after pasting web-9 CSI 31m NEL x = %q, want %q", m.form.name, "web-931mx")
	}
	if strings.ContainsAny(m.View().Content, "\u009b\u0085") {
		t.Error("the form writes a pasted C1 control to the terminal")
	}
}

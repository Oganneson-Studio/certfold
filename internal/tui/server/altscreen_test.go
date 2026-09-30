package server

import "testing"

// The TUI draws on the alternate screen, which bubbletea v2 takes from the
// view rather than from a program option: without it, quitting leaves the
// last frame in the scrollback of the terminal.
func TestViewUsesTheAlternateScreen(t *testing.T) {
	if !newTestModel(t).View().AltScreen {
		t.Error("the view of the sigils TUI is not on the alternate screen")
	}
}

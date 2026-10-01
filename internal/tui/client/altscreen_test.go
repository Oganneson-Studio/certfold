package client

import "testing"

// See the certfolds TUI test of the same name.
func TestViewUsesTheAlternateScreen(t *testing.T) {
	if !New(newTestBackend()).View().AltScreen {
		t.Error("the view of the certfoldc TUI is not on the alternate screen")
	}
}

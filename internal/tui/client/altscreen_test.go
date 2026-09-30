package client

import "testing"

// See the sigils TUI test of the same name.
func TestViewUsesTheAlternateScreen(t *testing.T) {
	if !New(newTestBackend()).View().AltScreen {
		t.Error("the view of the sigilc TUI is not on the alternate screen")
	}
}

package client

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestRefreshGivesUpOnSilentDaemon covers a daemon that takes an IPC call of
// a refresh and never answers it: once refreshTimeout has passed the refresh
// ends with an error, whichever call it was, and the next refresh starts as
// usual.
func TestRefreshGivesUpOnSilentDaemon(t *testing.T) {
	previous := refreshTimeout
	refreshTimeout = 50 * time.Millisecond
	t.Cleanup(func() { refreshTimeout = previous })

	for _, tc := range []struct {
		name string
		hang func(f *fakeBackend, hang bool)
	}{
		{"state", func(f *fakeBackend, hang bool) { f.hangState = hang }},
		{"events", func(f *fakeBackend, hang bool) { f.hangEvents = hang }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestBackend()
			m := newModel(t, f)
			tc.hang(f, true)
			m = press(t, m, "r")
			if view := m.View(); !strings.Contains(view, "Error: "+context.DeadlineExceeded.Error()) {
				t.Fatalf("a refresh of a daemon that does not answer did not end in an error:\n%s", view)
			}
			if m.refreshing {
				t.Fatal("the refresh is still in flight after its call ended")
			}

			tc.hang(f, false)
			m = press(t, m, "r")
			if view := m.View(); strings.Contains(view, "Error:") {
				t.Errorf("the refresh after the daemon answered again still shows an error:\n%s", view)
			}
		})
	}
}

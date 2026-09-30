package server

import (
	"context"
	"testing"
	"time"
)

// A daemon that does not answer shows on the status line once
// refreshTimeout has passed, and the next refresh starts as usual.
func TestRefreshGivesUpOnSilentDaemon(t *testing.T) {
	previous := refreshTimeout
	refreshTimeout = 50 * time.Millisecond
	t.Cleanup(func() { refreshTimeout = previous })

	fake := newFake(3)
	m := loaded(t, fake)
	fake.setHang(true)
	m, _ = press(t, m, "r")
	if !shows(m, context.DeadlineExceeded.Error()) {
		t.Fatalf("a refresh of a daemon that does not answer did not end in an error: %q", plain(m))
	}
	if m.refreshing {
		t.Fatal("the refresh is still in flight after its call ended")
	}

	fake.setHang(false)
	if m, _ = press(t, m, "r"); shows(m, context.DeadlineExceeded.Error()) || !shows(m, "api-prod") {
		t.Errorf("the refresh after the daemon answered again: %q", plain(m))
	}
}

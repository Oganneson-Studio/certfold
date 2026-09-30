package client

import (
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

// TestDueFollowsRenewAt covers the yellow Not After: a certificate is due
// from its RenewAt on, however close or far its NotAfter is.
func TestDueFollowsRenewAt(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	for _, tc := range []struct {
		name              string
		notAfter, renewAt time.Time
		want              bool
	}{
		// A 6-day certificate is due with 3 days left, not with 4.
		{"6-day lifetime, 4 days left", now.Add(4 * day), now.Add(day), false},
		{"6-day lifetime, 3 days left", now.Add(3 * day), now, true},
		// A 90-day certificate is due with 30 days left, not with 31.
		{"90-day lifetime, 31 days left", now.Add(31 * day), now.Add(day), false},
		{"90-day lifetime, 25 days left", now.Add(25 * day), now.Add(-5 * day), true},
		{"RenewAt a minute ahead", now.Add(10 * day), now.Add(time.Minute), false},
		{"RenewAt a minute ago", now.Add(10 * day), now.Add(-time.Minute), true},
		{"expired", now.Add(-day), now.Add(-4 * day), true},
		{"unparsable", time.Time{}, time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ipc.ClientCertState{Name: "api-prod", NotAfter: tc.notAfter, RenewAt: tc.renewAt}
			if got := due(c, now); got != tc.want {
				t.Errorf("due = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNotAfterTextShowsDaysLeft(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.Local)
	for _, tc := range []struct {
		notAfter time.Time
		want     string
	}{
		{now.Add(60*24*time.Hour + time.Hour), "2026-11-27 (60d)"},
		{now.Add(23 * time.Hour), "2026-09-29 (0d)"},
		{now, "2026-09-28 (expired)"},
		{time.Time{}, "-"},
	} {
		if got := notAfterText(tc.notAfter, now); got != tc.want {
			t.Errorf("notAfterText(%s) = %q, want %q", tc.notAfter, got, tc.want)
		}
	}
}

// TestViewShowsState covers the header and the certificate table.
func TestViewShowsState(t *testing.T) {
	f := newTestBackend()
	f.state.LastPullAt = time.Date(2026, 9, 28, 10, 11, 12, 0, time.Local)
	f.state.LastError = "sync: server returned 503"
	f.state.Certs = []ipc.ClientCertState{
		{Name: "api-prod", NotAfter: time.Now().Add(60*24*time.Hour + time.Hour), Outputs: 3, OnChange: true, HookPending: true},
	}
	view := plain(newModel(t, f))
	for _, want := range []string{
		"web-1", "https://sigil.example.com", "online", "Last pull:  2026-09-28 10:11:12", "Last error: sync: server returned 503",
		"Name      Not After             Outputs  on_change  Pending",
		"api-prod  " + time.Now().Add(60*24*time.Hour+time.Hour).Format("2006-01-02") + " (60d)      3        yes        yes",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("view lacks %q:\n%s", want, view)
		}
	}

	f.state.Online = false
	f.state.LastPullAt = time.Time{}
	f.state.LastError = ""
	view = plain(newModel(t, f))
	for _, want := range []string{"offline", "Last pull:  never"} {
		if !strings.Contains(view, want) {
			t.Errorf("view lacks %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "Last error") {
		t.Errorf("view shows a last error the state does not have:\n%s", view)
	}
}

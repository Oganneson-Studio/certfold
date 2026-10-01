package server

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"

	"github.com/Oganneson-Studio/certfold/internal/api"
	"github.com/Oganneson-Studio/certfold/internal/ipc"
)

// A dialog gives its text and padding the width it is allowed, at most 64
// columns, and draws its rounded border, 2 columns, around them.
func TestDialogWidth(t *testing.T) {
	for _, width := range []int{30, 64, 100} {
		want := min(width, 64) + 2
		c := &confirmation{prompt: strings.Repeat("Revoke enrollment token? ", 8)}
		if got := lipgloss.Width(c.view(width)); got != want {
			t.Errorf("a confirmation allowed %d columns is %d wide, want %d", width, got, want)
		}
		if got := lipgloss.Width(newTokenForm().view(width)); got != want {
			t.Errorf("the token form allowed %d columns is %d wide, want %d", width, got, want)
		}
	}
}

func TestConfirmationActsOnlyOnY(t *testing.T) {
	tests := []struct {
		name string
		tab  int
		key  string
		want string // what y asks the backend for; the second row is selected
	}{
		{"renew certificate", tabCertificates, "R", "RenewCert mail"},
		{"delete client", tabClients, "d", "DeleteClient web-2"},
		{"revoke token", tabTokens, "d", "DeleteToken t2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"n", "esc", "enter", " ", "Y", "q", "1", "r", "tab", "R", "d", "j"} {
				fake := newFake(3)
				m, quit := press(t, onTab(t, fake, tt.tab), tt.key, k)
				if calls := fake.changes(); len(calls) != 0 || quit {
					t.Errorf("%s after %s: backend calls %q, quit %v; want none", k, tt.key, calls, quit)
				}
				if open := m.confirm != nil; open == (k == "n" || k == "esc") {
					t.Errorf("%s after %s: confirmation open = %v", k, tt.key, open)
				}
			}

			fake := newFake(3)
			m, _ := press(t, onTab(t, fake, tt.tab), tt.key, "y")
			if calls := fake.changes(); !slices.Equal(calls, []string{tt.want}) {
				t.Errorf("y: backend calls %q, want %q", calls, tt.want)
			}
			if m.confirm != nil {
				t.Error("the confirmation stayed open after y")
			}
		})
	}
}

// A token refused because a client or token newer than the lists of the TUI
// has its name: the status line says how to replace in the TUI, not with the
// flag of the CLI, and the lists are refreshed, so the next try asks.
func TestTokenRefusedForReplacementSaysHowInTheTUI(t *testing.T) {
	fake := newFake(3)
	fake.setActionErr(fmt.Errorf("client %q is already enrolled; %w", "web-9", ipc.ErrReplaceRequired))
	m, _ := press(t, onTab(t, fake, tabTokens), "n", "web-9", "enter")
	if !shows(m, "create the token again to confirm the replacement") || shows(m, "--replace") {
		t.Errorf("status after the refusal: %q", plain(m))
	}
}

// A renewal that the IPC client gave up waiting for, after five minutes, may
// still finish in the daemon, and the status line says so.
func TestRenewalNotWaitedForMayStillFinish(t *testing.T) {
	fake := newFake(3)
	fake.setActionErr(fmt.Errorf("ipc request: %w", context.DeadlineExceeded))
	m, _ := press(t, onTab(t, fake, tabCertificates), "R", "y")
	if !shows(m, "the renewal may still finish in the daemon: see `certfolds events` or `certfolds cert show mail`") {
		t.Errorf("status after a renewal that timed out: %q", plain(m))
	}
}

// A refresh that removes the selected client while the confirmation is open
// moves the cursor to another client; y still acts on the one named.
func TestConfirmationKeepsItsTarget(t *testing.T) {
	fake := newFake(3)
	m, _ := press(t, onTab(t, fake, tabClients), "d")
	fake.setClients([]*ipc.ClientInfo{fake.clients[0], fake.clients[2]})
	m = refresh(t, m)
	if row := m.clientsTable.SelectedRow(); row == nil || row[0] != "web-3" {
		t.Fatalf("selected row after web-2 left = %q, want web-3", row)
	}
	press(t, m, "y")
	if calls := fake.changes(); !slices.Equal(calls, []string{"DeleteClient web-2"}) {
		t.Errorf("backend calls %q, want the removal of web-2", calls)
	}
}

func TestTokenFormTakesTheKeysOfOtherCommands(t *testing.T) {
	fake := newFake(3)
	m, quit := press(t, onTab(t, fake, tabTokens), "n", "q", "1", "r", "d", "?", "R")
	if quit {
		t.Fatal("q in the token form quit the TUI")
	}
	if m.form == nil || m.form.name != "q1rd?R" || m.tab != tabTokens || m.help.ShowAll {
		t.Fatalf("after typing q1rd?R: form %+v, tab %d, full help %v; want the name typed and nothing else", m.form, m.tab, m.help.ShowAll)
	}

	m, _ = press(t, m, "backspace", "tab", "backspace", "x", "enter")
	if m.form == nil || !strings.Contains(m.form.err, `"1x"`) || len(fake.changes()) != 0 {
		t.Fatalf("a TTL of 1x: form %+v, calls %q; want the form open with an error", m.form, fake.changes())
	}
	m, _ = press(t, m, "backspace", "backspace", "2h", "enter")
	if calls := fake.changes(); !slices.Equal(calls, []string{"CreateToken q1rd? 2h0m0s"}) {
		t.Errorf("backend calls %q, want the token created", calls)
	}
	if m.form != nil || m.created == nil {
		t.Error("creating the token did not replace the form with the new token")
	}

	if _, quit := press(t, onTab(t, fake, tabTokens), "n", "ctrl+c"); !quit {
		t.Error("ctrl+c in the token form did not quit")
	}
}

// TestTokenForEnrolledNameAsksFirst covers a new token for the name of an
// enrolled client: the host that redeems it replaces the client, so the TUI
// asks before it creates the token, and then asks the daemon to replace.
func TestTokenForEnrolledNameAsksFirst(t *testing.T) {
	fake := newFake(3)
	m, _ := press(t, onTab(t, fake, tabTokens), "n", "web-2", "enter")
	if m.confirm == nil || !shows(m, `Client "web-2" is enrolled.`) || len(fake.changes()) != 0 {
		t.Fatalf("token for enrolled web-2: confirmation %v, calls %q; want a confirmation and no call", m.confirm, fake.changes())
	}
	m, _ = press(t, m, "n")
	if m.confirm != nil || len(fake.changes()) != 0 {
		t.Fatalf("n: confirmation %v, calls %q; want it closed and no call", m.confirm, fake.changes())
	}

	m, _ = press(t, m, "n", "web-2", "enter", "y")
	if calls := fake.changes(); !slices.Equal(calls, []string{"CreateToken web-2 1h0m0s replace"}) {
		t.Errorf("y: backend calls %q, want the token created to replace web-2", calls)
	}
	if m.confirm != nil || m.created == nil {
		t.Error("confirming did not show the new token")
	}

	// A name no client has needs no confirmation.
	fake = newFake(3)
	m, _ = press(t, onTab(t, fake, tabTokens), "n", "web-9", "enter")
	if calls := fake.changes(); m.confirm != nil || !slices.Equal(calls, []string{"CreateToken web-9 1h0m0s"}) {
		t.Errorf("token for web-9: confirmation %v, calls %q; want the token created at once", m.confirm, calls)
	}
}

// TestTokenForNameWithUnusedTokenAsksFirst covers a new token for a name
// with an unused token: of the two hosts that enroll with them, the second
// replaces the first, so the TUI asks as for an enrolled client. A token
// that was used or has expired enrolls no host.
func TestTokenForNameWithUnusedTokenAsksFirst(t *testing.T) {
	fake := newFake(3)
	m, _ := press(t, onTab(t, fake, tabTokens), "n", "web-6", "enter")
	if m.confirm == nil || !shows(m, `An enrollment token for "web-6" is unused.`) || len(fake.changes()) != 0 {
		t.Fatalf("token for web-6, whose token is unused: confirmation %v, calls %q; want a confirmation and no call", m.confirm, fake.changes())
	}
	m, _ = press(t, m, "y")
	if calls := fake.changes(); !slices.Equal(calls, []string{"CreateToken web-6 1h0m0s replace"}) {
		t.Errorf("y: backend calls %q, want the token created as a replacement", calls)
	}
	if m.created == nil || !strings.Contains(m.created.content(m.created.view.Width()), `Revoked   1 unused token(s) for "web-6"`) {
		t.Error("the box of the replacing token does not say that it revoked the unused token")
	}

	for _, name := range []string{"web-5", "web-4"} { // used, expired
		fake := newFake(3)
		m, _ := press(t, onTab(t, fake, tabTokens), "n", name, "enter")
		if calls := fake.changes(); m.confirm != nil || !slices.Equal(calls, []string{"CreateToken " + name + " 1h0m0s"}) {
			t.Errorf("token for %s: confirmation %v, calls %q; want the token created at once", name, m.confirm, calls)
		}
	}
}

func TestNewTokenShownOnlyInItsBox(t *testing.T) {
	fake := newFake(3)
	m, _ := press(t, onTab(t, fake, tabTokens), "n", "web-9", "enter")
	if m.created == nil {
		t.Fatal("the new token is not shown")
	}
	// The lines are cut to the width of the box and joined again here.
	content := strings.ReplaceAll(m.created.content(m.created.view.Width()), "\n", "")
	sh, ps1 := api.InstallCommands(testServerURL, testToken)
	// The ID names the token on the Tokens tab, as the time it expires does.
	id, expires := m.created.token.TokenID, m.created.token.ExpiresAt.Local().Format("2006-01-02 15:04:05 -07:00")
	for _, want := range []string{testToken, sh, ps1, "Token ID  " + id, "Expires   " + expires} {
		if !strings.Contains(content, want) {
			t.Errorf("the box lacks %q", want)
		}
	}
	if id == "" || strings.Contains(content, "Revoked") {
		t.Errorf("the box of a token that replaces nothing: ID %q, content %q", id, content)
	}
	if !holds(reflect.ValueOf(m), testToken, map[uintptr]bool{}) {
		t.Fatal("holds does not find the token in the open box")
	}

	m, quit := press(t, m, "q", "esc")
	if m.created != nil || quit {
		t.Fatalf("q then esc: box open %v, quit %v; want the box closed by esc", m.created != nil, quit)
	}
	if holds(reflect.ValueOf(m), testToken, map[uintptr]bool{}) {
		t.Error("the model keeps the token after its box closed")
	}
}

// holds reports whether a string reachable from v contains s.
func holds(v reflect.Value, s string, seen map[uintptr]bool) bool {
	switch v.Kind() {
	case reflect.String:
		return strings.Contains(v.String(), s)
	case reflect.Pointer:
		if v.IsNil() || seen[v.Pointer()] {
			return false
		}
		seen[v.Pointer()] = true
		return holds(v.Elem(), s, seen)
	case reflect.Interface:
		return !v.IsNil() && holds(v.Elem(), s, seen)
	case reflect.Struct:
		for i := range v.NumField() {
			if holds(v.Field(i), s, seen) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			if holds(v.Index(i), s, seen) {
				return true
			}
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			if holds(it.Key(), s, seen) || holds(it.Value(), s, seen) {
				return true
			}
		}
	}
	return false
}

// The daemon lists a new token first; the selection stays on the token it
// was on.
func TestNewTokenKeepsSelection(t *testing.T) {
	fake := newFake(3)
	m, _ := press(t, onTab(t, fake, tabTokens), "n", "web-9", "enter")
	if n := len(m.tokensTable.Rows()); n != 4 || m.tokensTable.Rows()[0][1] != "web-9" {
		t.Fatalf("tokens after creation: %q, want the new one first", m.tokensTable.Rows())
	}
	if row := m.tokensTable.SelectedRow(); row == nil || row[0] != "t2" {
		t.Errorf("selected token = %q, want t2 as before", row)
	}
}

func TestHardWrapKeepsEveryRune(t *testing.T) {
	for _, width := range []int{0, 1, 3, 7, 100} {
		lines := hardWrap("curl 'x' | sh -s -- --token 'é1'", width)
		if got := strings.Join(lines, ""); got != "curl 'x' | sh -s -- --token 'é1'" {
			t.Errorf("width %d: joined lines = %q", width, got)
		}
		for _, line := range lines {
			if width > 0 && len([]rune(line)) > width {
				t.Errorf("width %d: line %q is longer", width, line)
			}
		}
	}
}

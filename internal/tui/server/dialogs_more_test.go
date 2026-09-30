package server

// Put in internal/tui/server. All pass on 39c71eb.
// Mutations that must turn them red:
//   - handleKey handing keys to the confirmation (or the new-token box) before
//     its ctrl+c check -> TestCtrlCQuitsEveryDialog;
//   - the createdMsg error branch returning without setting actionErr
//     -> TestRefusedTokenShowsTheReason;
//   - updateForm's submit no longer clearing actionErr
//     -> TestTokenCreationClearsTheEarlierActionError;
//   - setRows without the `if t.Cursor() < 0 { t.SetCursor(0) }` step
//     -> TestSelectionAfterAnEmptyList;
//   - updateCreated's esc keeping the box's lines anywhere in the model, for
//     example m.eventsView.SetContent(m.created.view.View())
//     -> TestNewTokenLeavesNoPartOfItAfterClose. The needle of
//     TestNewTokenShownOnlyInItsBox is the whole token, which only
//     createdToken.token holds: the box holds it cut into lines of the
//     window's width, so that test misses what is left of those lines.

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// ctrl+c quits from every dialog and asks the backend for nothing.
func TestCtrlCQuitsEveryDialog(t *testing.T) {
	for _, tt := range []struct {
		name string
		tab  int
		keys []string
	}{
		{"renewal confirmation", tabCertificates, []string{"R"}},
		{"client removal confirmation", tabClients, []string{"d"}},
		{"token revocation confirmation", tabTokens, []string{"d"}},
		{"token form", tabTokens, []string{"n", "web-9"}},
		{"new token", tabTokens, []string{"n", "web-9", "enter"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFake(3)
			m, _ := press(t, onTab(t, fake, tt.tab), tt.keys...)
			if m.confirm == nil && m.form == nil && m.created == nil {
				t.Fatal("no dialog is open")
			}
			before := len(fake.changes())
			if _, quit := press(t, m, "ctrl+c"); !quit {
				t.Error("ctrl+c did not quit")
			}
			if calls := fake.changes(); len(calls) != before {
				t.Errorf("ctrl+c asked the backend for %q", calls[before:])
			}
		})
	}
}

// The daemon's reason for refusing a token shows on the status line.
func TestRefusedTokenShowsTheReason(t *testing.T) {
	const reason = `invalid client name "Web 9": must be a lowercase DNS label`
	fake := newFake(3)
	fake.actionErr = errors.New("ipc POST /ipc/v1/tokens: server returned 422: " + reason)
	m, _ := press(t, onTab(t, fake, tabTokens), "n", "Web", " ", "9", "enter")
	if calls := fake.changes(); !slices.Equal(calls, []string{"CreateToken Web 9 1h0m0s"}) {
		t.Fatalf("backend calls %q, want the creation asked for", calls)
	}
	if m.created != nil || !shows(m, reason) {
		t.Errorf("refused creation: box open %v, view %q; want the reason on the status line", m.created != nil, plain(m))
	}
}

// Creating a token is the next action, so it clears the error of the last.
func TestTokenCreationClearsTheEarlierActionError(t *testing.T) {
	const shown = `client "web-2" is not enrolled`
	fake := newFake(3)
	fake.actionErr = errors.New("ipc DELETE /ipc/v1/clients/web-2: server returned 404: " + shown)
	m, _ := press(t, onTab(t, fake, tabClients), "d", "y")
	if !shows(m, shown) {
		t.Fatalf("the failed removal is not shown: %q", plain(m))
	}
	fake.setActionErr(nil)
	// drive runs the creation after the keys pressed with it, so esc comes
	// in a press of its own.
	m, _ = press(t, m, "4", "n", "web-9", "enter")
	if m, _ = press(t, m, "esc"); shows(m, shown) {
		t.Errorf("a token created after the failed removal left its error: %q", plain(m))
	}
}

// A table that has been empty selects the first row it lists again, so the
// token created on an empty Tokens tab can be revoked at once.
func TestSelectionAfterAnEmptyList(t *testing.T) {
	fake := newFake(3)
	fake.tokens = nil
	m := loaded(t, fake)
	m.tab = tabTokens
	m, _ = press(t, m, "n", "web-9", "enter")
	if m.created == nil {
		t.Fatal("creating a token did not show it")
	}
	m, _ = press(t, m, "esc", "d")
	if m.confirm == nil || !strings.Contains(m.confirm.prompt, `"web-9"`) {
		t.Fatalf("d on the only token opened %+v, want the revocation of web-9's token", m.confirm)
	}
}

// Nothing of the token, not even a line of its box, stays in the model once
// the box has closed.
func TestNewTokenLeavesNoPartOfItAfterClose(t *testing.T) {
	m, _ := press(t, onTab(t, newFake(3), tabTokens), "n", "web-9", "enter")
	// testToken repeats 16 characters, so every line of the box that holds 47
	// or more of them holds this needle.
	needle := testToken[:32]
	if !holds(reflect.ValueOf(m.created.view), needle, map[uintptr]bool{}) {
		t.Fatal("holds does not find the needle in the lines of the open box")
	}
	m, _ = press(t, m, "esc")
	if holds(reflect.ValueOf(m), needle, map[uintptr]bool{}) {
		t.Error("the model keeps part of the token after its box closed")
	}
}

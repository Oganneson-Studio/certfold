package server

import (
	"slices"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

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

package server

import (
	"slices"
	"testing"

	"charm.land/bubbles/v2/key"
)

// TestEveryHelpKeyIsWired presses every key that the help shows, on every
// tab and in every dialog, and checks that each changes the view or returns
// a command.
func TestEveryHelpKeyIsWired(t *testing.T) {
	contexts := []struct {
		name string
		open func(t *testing.T) Model
	}{
		{"Overview", func(t *testing.T) Model { return onTab(t, newFake(80), tabOverview) }},
		{"Certificates", func(t *testing.T) Model { return onTab(t, newFake(80), tabCertificates) }},
		{"Clients", func(t *testing.T) Model { return onTab(t, newFake(80), tabClients) }},
		{"Tokens", func(t *testing.T) Model { return onTab(t, newFake(80), tabTokens) }},
		{"Events", func(t *testing.T) Model { return onTab(t, newFake(80), tabEvents) }},
		{"renewal confirmation", func(t *testing.T) Model {
			m, _ := press(t, onTab(t, newFake(80), tabCertificates), "R")
			return m
		}},
		{"client removal confirmation", func(t *testing.T) Model {
			m, _ := press(t, onTab(t, newFake(80), tabClients), "d")
			return m
		}},
		{"token revocation confirmation", func(t *testing.T) Model {
			m, _ := press(t, onTab(t, newFake(80), tabTokens), "d")
			return m
		}},
		{"token form", func(t *testing.T) Model {
			m, _ := press(t, onTab(t, newFake(80), tabTokens), "n")
			return m
		}},
		{"new token", func(t *testing.T) Model {
			m, _ := press(t, onTab(t, newFake(80), tabTokens), "n", "web-9", "enter")
			if m.created == nil {
				t.Fatal("creating a token did not show it")
			}
			v := &m.created.view
			v.SetYOffset((v.TotalLineCount() - v.Height()) / 2)
			return m
		}},
	}
	for _, c := range contexts {
		t.Run(c.name, func(t *testing.T) {
			h := c.open(t).keyHelp()
			bindings := slices.Concat(h.ShortHelp(), slices.Concat(h.FullHelp()...))
			if len(bindings) == 0 {
				t.Fatal("the help shows no keys")
			}
			for _, b := range bindings {
				for _, k := range b.Keys() {
					m := c.open(t)
					if key.Matches(keyMsg(k), m.keys.Tab) && int(k[0]-'1') == m.tab {
						continue // selects the tab shown; the other tabs press it
					}
					before := m.View().Content
					next, cmd := m.Update(keyMsg(k))
					if cmd == nil && next.(Model).View().Content == before {
						t.Errorf("%s (%s) does nothing", k, b.Help().Desc)
					}
				}
			}
		})
	}
}

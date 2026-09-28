package server

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Oganneson-Studio/sigil/internal/tui/shared"
)

// Every view holds only characters that a classic Windows console on an
// East Asian system draws one cell wide, as lipgloss counts them.
func TestViewDrawsOnlyNarrowGlyphs(t *testing.T) {
	views := map[string]func(t *testing.T) Model{
		"new token": func(t *testing.T) Model {
			m, _ := press(t, onTab(t, newFake(80), tabTokens), "n", "web-9", "enter")
			return m
		},
		"token form": func(t *testing.T) Model {
			m, _ := press(t, onTab(t, newFake(80), tabTokens), "n")
			return m
		},
		"confirmation": func(t *testing.T) Model {
			m, _ := press(t, onTab(t, newFake(80), tabClients), "d")
			return m
		},
	}
	for tab := range numTabs {
		views[tabNames[tab]] = func(t *testing.T) Model { return onTab(t, newFake(80), tab) }
		views[tabNames[tab]+" with all keys"] = func(t *testing.T) Model {
			m, _ := press(t, onTab(t, newFake(80), tab), "?")
			return m
		}
	}
	// 50 columns cut table cells and the short help.
	for _, size := range []tea.WindowSizeMsg{{Width: 50, Height: 24}, {Width: 120, Height: 40}} {
		for name, open := range views {
			m, _ := drive(t, open(t), size)
			if r, wide := shared.WideGlyph(m.View()); wide {
				t.Errorf("%s at %d columns draws %q", name, size.Width, r)
			}
		}
	}
}

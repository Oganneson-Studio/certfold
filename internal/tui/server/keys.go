package server

import (
	"slices"

	"charm.land/bubbles/v2/key"
)

// keyMap holds every key the TUI handles. The help line is built from the
// same bindings, so TestEveryHelpKeyIsWired can check that each key it shows
// does something.
type keyMap struct {
	// Everywhere but in a dialog.
	Tab     key.Binding
	NextTab key.Binding
	PrevTab key.Binding
	Refresh key.Binding
	Help    key.Binding
	Quit    key.Binding

	// Lists: the tables, the Events tab and the new-token box.
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Top      key.Binding
	Bottom   key.Binding

	// Tab actions.
	Renew    key.Binding
	Delete   key.Binding
	NewToken key.Binding
	Revoke   key.Binding

	// Dialogs.
	Confirm key.Binding
	Cancel  key.Binding
	Submit  key.Binding
	Field   key.Binding
	Close   key.Binding
}

func defaultKeys() keyMap {
	return keyMap{
		Tab:     key.NewBinding(key.WithKeys("1", "2", "3", "4", "5"), key.WithHelp("1-5", "tabs")),
		NextTab: key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next tab")),
		PrevTab: key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "previous tab")),
		Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		Help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "more keys")),
		// ctrl+c also quits while a dialog is open; q goes to the dialog.
		Quit: key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),

		// Not ↑ and ↓, which some consoles draw two cells wide; see
		// shared.WideGlyph.
		Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("k/up", "move up")),
		Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("j/down", "move down")),
		PageUp:   key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "page up")),
		PageDown: key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdn", "page down")),
		Top:      key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "oldest")),
		Bottom:   key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "newest")),

		Renew:    key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "renew")),
		Delete:   key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "delete client")),
		NewToken: key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "new token")),
		Revoke:   key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "revoke token")),

		Confirm: key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "confirm")),
		Cancel:  key.NewBinding(key.WithKeys("n", "esc"), key.WithHelp("n/esc", "cancel")),
		Submit:  key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "create")),
		Field:   key.NewBinding(key.WithKeys("tab", "shift+tab", "up", "down"), key.WithHelp("tab", "next field")),
		Close:   key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "close")),
	}
}

// keyHelp is the help.KeyMap of what the model shows.
type keyHelp struct {
	short []key.Binding
	full  [][]key.Binding
}

func (h keyHelp) ShortHelp() []key.Binding  { return h.short }
func (h keyHelp) FullHelp() [][]key.Binding { return h.full }

// keyHelp returns the keys of the open dialog, or else those of the current
// tab and the global keys. The short help leaves out the moves, so that it
// fits in 80 columns: help.Model does not cut a line that has no room left
// for its ellipsis.
func (m Model) keyHelp() keyHelp {
	k := m.keys
	switch {
	case m.confirm != nil:
		yes := k.Confirm
		yes.SetHelp("y", m.confirm.verb)
		return dialogHelp(yes, k.Cancel)
	case m.form != nil:
		cancel := k.Close
		cancel.SetHelp("esc", "cancel")
		return dialogHelp(k.Submit, k.Field, cancel)
	case m.created != nil:
		return dialogHelp(k.Up, k.Down, k.PageUp, k.PageDown, k.Close)
	}

	var moves, actions []key.Binding
	switch m.tab {
	case tabCertificates:
		moves, actions = []key.Binding{k.Up, k.Down}, []key.Binding{k.Renew}
	case tabClients:
		moves, actions = []key.Binding{k.Up, k.Down}, []key.Binding{k.Delete}
	case tabTokens:
		moves, actions = []key.Binding{k.Up, k.Down}, []key.Binding{k.NewToken, k.Revoke}
	case tabEvents:
		moves, actions = []key.Binding{k.Up, k.Down, k.PageUp, k.PageDown}, []key.Binding{k.Top, k.Bottom}
	}
	help := k.Help
	if m.help.ShowAll {
		help.SetHelp("?", "fewer keys")
	}
	return keyHelp{
		short: append(slices.Clone(actions), k.Tab, k.Refresh, help, k.Quit),
		full:  [][]key.Binding{slices.Concat(moves, actions), {k.Tab, k.NextTab, k.PrevTab, k.Refresh, help, k.Quit}},
	}
}

func dialogHelp(bindings ...key.Binding) keyHelp {
	return keyHelp{short: bindings, full: [][]key.Binding{bindings}}
}

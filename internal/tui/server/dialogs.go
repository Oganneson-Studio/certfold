package server

import (
	"context"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Oganneson-Studio/sigil/internal/tui/shared"
)

var dialogStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(shared.Purple).
	Padding(0, 1)

// confirmation asks before a renewal, a client removal or a token
// revocation. run holds the target from when the dialog opened, so a refresh
// that moves the selection cannot change what y acts on.
type confirmation struct {
	verb   string // what y does, for the help
	prompt string
	run    func(context.Context) error
}

// ask opens a confirmation of run.
func (m *Model) ask(verb, prompt string, run func(context.Context) error) {
	m.confirm = &confirmation{verb: verb, prompt: prompt, run: run}
}

func (m *Model) updateConfirm(msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, m.keys.Confirm):
		run := m.confirm.run
		m.confirm = nil
		m.actionErr = nil
		return func() tea.Msg { return actionMsg{err: run(context.Background())} }
	case key.Matches(msg, m.keys.Cancel):
		m.confirm = nil
	}
	return nil
}

func (c *confirmation) view(width int) string {
	return dialogStyle.Width(min(width, 64)).Render(c.prompt)
}

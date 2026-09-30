package server

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Oganneson-Studio/sigil/internal/api"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/tui/shared"
)

var dialogStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(shared.Purple).
	Padding(0, 1)

// confirmation asks before a renewal, a client removal, a token revocation
// or a token for the name of an enrolled client. run holds the target from
// when the dialog opened, so a refresh that moves the selection cannot change
// what y acts on.
type confirmation struct {
	verb   string // what y does, for the help
	prompt string
	run    tea.Cmd
}

// ask opens a confirmation of run.
func (m *Model) ask(verb, prompt string, run func(context.Context) error) {
	m.confirm = &confirmation{verb: verb, prompt: prompt, run: func() tea.Msg {
		return actionMsg{err: run(context.Background())}
	}}
}

func (m *Model) updateConfirm(msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, m.keys.Confirm):
		run := m.confirm.run
		m.confirm = nil
		m.actionErr = nil
		return run
	case key.Matches(msg, m.keys.Cancel):
		m.confirm = nil
	}
	return nil
}

func (c *confirmation) view(width int) string {
	return dialogStyle.Width(min(width, 64)).Render(c.prompt)
}

// tokenForm asks for the client name and the lifetime of a new enrollment
// token. Typing and backspace edit the end of the focused field; a paste
// arrives as typing, without its control characters.
type tokenForm struct {
	name  string
	ttl   string
	onTTL bool   // the TTL field has the focus
	err   string // why enter did not create the token
}

func newTokenForm() *tokenForm {
	return &tokenForm{ttl: "1h"}
}

func (m *Model) updateForm(msg tea.KeyMsg) tea.Cmd {
	f := m.form
	switch {
	case key.Matches(msg, m.keys.Close):
		m.form = nil
	case key.Matches(msg, m.keys.Field):
		f.onTTL = !f.onTTL
	case key.Matches(msg, m.keys.Submit):
		ttl, err := time.ParseDuration(f.ttl)
		if err != nil {
			f.err = fmt.Sprintf("TTL %q is not a duration such as 1h or 30m", f.ttl)
			return nil
		}
		name, b := f.name, m.backend
		m.form = nil
		m.actionErr = nil
		create := func(replace bool) tea.Cmd {
			return func() tea.Msg {
				token, err := b.CreateToken(context.Background(), ipc.CreateTokenRequest{Name: name, TTL: ttl, Replace: replace})
				return createdMsg{name: name, token: token, err: err}
			}
		}
		// The daemon refuses the name of an enrolled client, or of an unused
		// token, unless asked to replace. The lists are those of the last
		// refresh; a client or token that is newer gets the daemon's refusal.
		var taken string
		switch {
		case slices.ContainsFunc(m.clients, func(c *ipc.ClientInfo) bool { return c.Name == name }):
			taken = "Client " + strconv.Quote(name) + " is enrolled. "
		case slices.ContainsFunc(m.tokens, func(t *ipc.TokenInfo) bool { return t.Name == name && tokenStatus(t, time.Now()) == "unused" }):
			taken = "An enrollment token for " + strconv.Quote(name) + " is unused. "
		default:
			return create(false)
		}
		m.confirm = &confirmation{
			verb: "replace",
			prompt: taken + "The host that enrolls with a token for this name replaces the one before it, takes over its " +
				"certificates and locks it out. Create the token, and revoke the unused tokens for this name?",
			run: create(true),
		}
		return nil
	default:
		value := &f.name
		if f.onTTL {
			value = &f.ttl
		}
		switch msg.Type {
		case tea.KeyRunes, tea.KeySpace:
			// A paste keeps every rune, so drop those that control the
			// terminal, which the view would write to it.
			for _, r := range msg.Runes {
				if !unicode.IsControl(r) {
					*value += string(r)
				}
			}
		case tea.KeyBackspace:
			if r := []rune(*value); len(r) > 0 {
				*value = string(r[:len(r)-1])
			}
		}
	}
	return nil
}

var cursorStyle = lipgloss.NewStyle().Reverse(true)

func (f *tokenForm) view(width int) string {
	field := func(label, value string, focused bool) string {
		marker := "  "
		if focused {
			marker = "› "
			value += cursorStyle.Render(" ")
		}
		return fmt.Sprintf("%s%-6s%s", marker, label, value)
	}
	lines := []string{
		shared.TableHeader.Render("New enrollment token"),
		"",
		field("Name", f.name, !f.onTTL),
		field("TTL", f.ttl, f.onTTL),
	}
	if f.err != "" {
		lines = append(lines, "", shared.ErrorStyle.Render(f.err))
	}
	return dialogStyle.Width(min(width, 64)).Render(strings.Join(lines, "\n"))
}

// createdToken shows a new enrollment token and the commands that install
// sigilc with it. The TUI keeps the token nowhere else, so closing the box
// drops it.
type createdToken struct {
	name  string
	token *ipc.CreateTokenResponse
	view  viewport.Model
}

func newCreatedToken(name string, token *ipc.CreateTokenResponse) *createdToken {
	return &createdToken{name: name, token: token, view: viewport.New(0, 0)}
}

func (m *Model) updateCreated(msg tea.KeyMsg) {
	v := &m.created.view
	switch {
	case key.Matches(msg, m.keys.Close):
		m.created = nil
	case key.Matches(msg, m.keys.Up):
		v.LineUp(1)
	case key.Matches(msg, m.keys.Down):
		v.LineDown(1)
	case key.Matches(msg, m.keys.PageUp):
		v.PageUp()
	case key.Matches(msg, m.keys.PageDown):
		v.PageDown()
	}
}

// resize fits the box into width and height, and cuts its lines anew when
// the width changes.
func (c *createdToken) resize(width, height int) {
	if c.view.Width != width {
		c.view.Width = width
		c.view.SetContent(c.content(width))
	}
	c.view.Height = height
	c.view.SetYOffset(c.view.YOffset)
}

// copyHint explains why the commands cannot be copied as they are shown: the
// token holds the mini-CA certificate, so the commands run to more than a
// thousand characters, which no window fits in one line.
const copyHint = "The token and the commands are longer than the window, so they are cut into lines, " +
	"and copying them brings the line breaks along. To copy a command in one piece, revoke this " +
	"token and run `sigils token create`, which prints each command on one line."

func (c *createdToken) content(width int) string {
	sh, ps1 := api.InstallCommands(c.token.ServerURL, c.token.Token)
	text := lipgloss.NewStyle().Width(width)
	lines := []string{
		shared.TitleStyle.Render("New enrollment token for " + strconv.Quote(c.name)),
		"",
		"Token ID  " + c.token.TokenID,
		"Expires   " + formatTime(c.token.ExpiresAt, timeLayout, "-"),
	}
	if c.token.Revoked > 0 {
		lines = append(lines, fmt.Sprintf("Revoked   %d unused token(s) for %s", c.token.Revoked, strconv.Quote(c.name)))
	}
	lines = append(lines, "", text.Render(copyHint))
	if !c.token.PublicURLConfigured {
		warning := "server.public_url is not set, so the commands use " + c.token.ServerURL +
			", which comes from server.listen and may be unreachable for clients."
		lines = append(lines, "", text.Foreground(shared.Yellow).Render(warning))
	}
	for _, part := range []struct{ title, value string }{
		{"Token", c.token.Token},
		{"Linux or macOS, as a user who may sudo", sh},
		{"Windows, in an elevated PowerShell 5.1 or 7", ps1},
	} {
		lines = append(lines, "", shared.TableHeader.Render(part.title))
		lines = append(lines, hardWrap(part.value, width)...)
	}
	return strings.Join(lines, "\n")
}

// hardWrap cuts s into lines of width runes. It adds and drops nothing but
// the line breaks, so joining the lines gives s back.
func hardWrap(s string, width int) []string {
	r := []rune(s)
	var lines []string
	for width > 0 && len(r) > width {
		lines = append(lines, string(r[:width]))
		r = r[width:]
	}
	return append(lines, string(r))
}

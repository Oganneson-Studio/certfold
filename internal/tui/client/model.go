// Package client provides the Bubble Tea TUI for the sigilc client daemon.
package client

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/tui/shared"
)

// Backend is the part of the sigilc IPC API the TUI uses. *ipc.Client
// implements it.
type Backend interface {
	GetClientState(ctx context.Context) (*ipc.ClientState, error)
	FetchClient(ctx context.Context, name string) error
	ReloadClient(ctx context.Context) error
	Events(ctx context.Context, after uint64) (*ipc.EventsPage, error)
}

// refreshInterval is how often the TUI reads the state and the new events of
// the daemon.
const refreshInterval = 2 * time.Second

// refreshTimeout bounds each IPC call of a refresh (see shared.Within). A
// variable only so tests can shorten it.
var refreshTimeout = 10 * time.Second

var (
	// blockStyle sets the certificate table and the recent events apart.
	blockStyle = lipgloss.NewStyle().Padding(1, 1, 0)
	// lineStyle and errorStyle indent lines that may wrap, and the lines they
	// wrap to.
	lineStyle  = lipgloss.NewStyle().Padding(0, 1)
	errorStyle = shared.ErrorStyle.Padding(0, 1)
	dueStyle   = lipgloss.NewStyle().Foreground(shared.Yellow)
	// levelStyles colors the level of the events that need attention.
	levelStyles = map[string]lipgloss.Style{
		"WARN":  lipgloss.NewStyle().Foreground(shared.Yellow),
		"ERROR": lipgloss.NewStyle().Foreground(shared.Red),
	}
)

// legend explains the table under the full help.
const legend = "Not After turns yellow once the certificate is due for renewal by the ratio rule: " +
	"a third of its lifetime left, or half of a lifetime under 10 days. sigils renews later " +
	"when its CA suggests a later window (ARI), so yellow is a reminder, not an error.\n" +
	"Pending: the on_change program has yet to succeed since the certificate or one of its outputs changed."

// keyMap holds the keys of the TUI. The full help shows all of them.
type keyMap struct {
	fetch, reload, refresh, events, help, quit key.Binding
	// scroll holds the keys of the events view.
	scroll viewport.KeyMap
}

func newKeyMap() keyMap {
	scroll := viewport.DefaultKeyMap()
	// f fetches, so it does not page down.
	scroll.PageDown = key.NewBinding(key.WithKeys("pgdown", " "), key.WithHelp("pgdn", "page down"))
	return keyMap{
		fetch:   key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "fetch now")),
		reload:  key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "reload client.yaml")),
		refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		events:  key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "events")),
		help:    key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		scroll:  scroll,
	}
}

// ShortHelp returns the keys of the help line.
func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.fetch, k.reload, k.refresh, k.events, k.help, k.quit}
}

// FullHelp returns the keys ? shows: those of the help line and the keys
// that scroll the events view.
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.fetch, k.reload, k.refresh},
		{k.events, k.help, k.quit},
		{k.scroll.Up, k.scroll.Down, k.scroll.PageUp, k.scroll.PageDown, k.scroll.HalfPageUp, k.scroll.HalfPageDown},
	}
}

// Model is the root Bubble Tea model for the sigilc TUI. It reads the state
// and the events of the daemon through a Backend every refreshInterval.
type Model struct {
	backend Backend
	keys    keyMap
	help    help.Model
	width   int
	height  int

	// state is the last state the daemon returned, nil before the first.
	// stale reports that the last refresh could not read the state, so that
	// state comes from an earlier one.
	state *ipc.ClientState
	stale bool
	// events holds the newest logging.RingSize events of the daemon that
	// started at started, oldest first, and lastSeq the Seq of the newest.
	events  []logging.Event
	started time.Time
	lastSeq uint64
	// refreshing reports that a refresh is in flight. Another starts only
	// after it returns, so each refresh reads the events after those the
	// model holds.
	refreshing bool
	// err is the error of the last refresh.
	err error

	// running names the action, fetch or reload, in flight, and last is the
	// outcome of the last one to finish.
	running string
	last    actionMsg

	showEvents bool
	eventsView viewport.Model
}

// tickMsg starts a refresh.
type tickMsg struct{}

// refreshMsg carries what a refresh read: the state, and the page of events
// when the state and the events could both be read. err is the first error.
type refreshMsg struct {
	state *ipc.ClientState
	page  *ipc.EventsPage
	err   error
}

// actionMsg is the outcome of a fetch or reload.
type actionMsg struct {
	name string
	err  error
	at   time.Time
}

// New returns a Model that reads the daemon through backend.
func New(backend Backend) Model {
	keys := newKeyMap()
	events := viewport.New(0, 0)
	events.KeyMap = keys.scroll
	return Model{backend: backend, keys: keys, help: help.New(), eventsView: events}
}

// Init starts the first refresh at once.
func (m Model) Init() tea.Cmd {
	return func() tea.Msg { return tickMsg{} }
}

func tick() tea.Cmd {
	return tea.Tick(refreshInterval, func(time.Time) tea.Msg { return tickMsg{} })
}

// Update handles incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.Width = msg.Width - lineStyle.GetHorizontalPadding()
		m.setEventsContent()

	case tea.KeyMsg:
		m, cmd = m.handleKey(msg)

	case tickMsg:
		m, cmd = m.startRefresh()
		cmd = tea.Batch(cmd, tick())

	case refreshMsg:
		m.refreshing = false
		m.err = msg.err
		m.stale = msg.state == nil
		if msg.state != nil {
			m.state = msg.state
		}
		if msg.page != nil {
			m.addEvents(msg.page)
		}

	case actionMsg:
		m.running = ""
		m.last = msg
		m, cmd = m.startRefresh()
	}
	m.layout()
	return m, cmd
}

func (m Model) handleKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.quit):
		return m, tea.Quit
	case key.Matches(msg, m.keys.fetch):
		backend := m.backend
		return m.run("fetch", func(ctx context.Context) error { return backend.FetchClient(ctx, "") })
	case key.Matches(msg, m.keys.reload):
		return m.run("reload", m.backend.ReloadClient)
	case key.Matches(msg, m.keys.refresh):
		return m.startRefresh()
	case key.Matches(msg, m.keys.events):
		m.showEvents = !m.showEvents
	case key.Matches(msg, m.keys.help):
		m.help.ShowAll = !m.help.ShowAll
	case m.showEvents:
		var cmd tea.Cmd
		m.eventsView, cmd = m.eventsView.Update(msg)
		return m, cmd
	}
	return m, nil
}

// run starts action, which the status line calls name, unless an action is
// in flight.
func (m Model) run(name string, action func(context.Context) error) (Model, tea.Cmd) {
	if m.running != "" {
		return m, nil
	}
	m.running = name
	return m, func() tea.Msg {
		err := action(context.Background())
		return actionMsg{name: name, err: err, at: time.Now()}
	}
}

// startRefresh starts a refresh unless one is in flight. Each IPC call of the
// refresh ends after refreshTimeout.
func (m Model) startRefresh() (Model, tea.Cmd) {
	if m.refreshing {
		return m, nil
	}
	m.refreshing = true
	backend, after, started, timeout := m.backend, m.lastSeq, m.started, refreshTimeout
	eventsAfter := func(after uint64) func(context.Context) (*ipc.EventsPage, error) {
		return func(ctx context.Context) (*ipc.EventsPage, error) { return backend.Events(ctx, after) }
	}
	return m, func() tea.Msg {
		state, err := shared.Within(timeout, backend.GetClientState)
		if err != nil {
			return refreshMsg{err: err}
		}
		page, err := shared.Within(timeout, eventsAfter(after))
		// A daemon that started at another time numbers its events from 1
		// again, so the page lacks those up to after.
		if err == nil && after != 0 && !page.Started.Equal(started) {
			page, err = shared.Within(timeout, eventsAfter(0))
		}
		if err != nil {
			return refreshMsg{state: state, err: err}
		}
		return refreshMsg{state: state, page: page}
	}
}

// addEvents adds the events of page. When the daemon of page started at
// another time than the one of the events held, as on the first refresh and
// after the daemon restarts, they are dropped first.
func (m *Model) addEvents(page *ipc.EventsPage) {
	restarted := !page.Started.Equal(m.started)
	if !restarted && len(page.Events) == 0 {
		return
	}
	if restarted {
		m.started, m.events = page.Started, nil
	}
	m.events = append(m.events, page.Events...)
	if over := len(m.events) - logging.RingSize; over > 0 {
		m.events = m.events[over:]
	}
	m.lastSeq = 0
	if len(m.events) > 0 {
		m.lastSeq = m.events[len(m.events)-1].Seq
	}
	m.setEventsContent()
}

// setEventsContent puts the events, wrapped to the width of the screen, in
// the events view, which stays at the bottom if it was there.
func (m *Model) setEventsContent() {
	lines := make([]string, len(m.events))
	for i, e := range m.events {
		lines[i] = formatEvent(e)
	}
	atBottom := m.eventsView.AtBottom()
	m.eventsView.SetContent(lineStyle.Width(m.width).Render(strings.Join(lines, "\n")))
	if atBottom {
		m.eventsView.GotoBottom()
	}
}

// layout fits the events view to the screen below its title and above the
// footer.
func (m *Model) layout() {
	atBottom := m.eventsView.AtBottom()
	m.eventsView.Width = m.width
	m.eventsView.Height = max(0, m.height-1-lipgloss.Height(m.footer()))
	if atBottom {
		m.eventsView.GotoBottom()
	}
}

// View renders the model.
func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}
	footer := m.footer()
	if m.showEvents {
		title := shared.TitleStyle.Width(m.width).Render(fmt.Sprintf("Events (%d)", len(m.events)))
		return lipgloss.JoinVertical(lipgloss.Left, title, m.eventsView.View(), footer)
	}
	top := m.header()
	if m.state != nil {
		top = lipgloss.JoinVertical(lipgloss.Left, top, m.certTable(time.Now()))
	}
	parts := []string{top}
	if events := m.recentEvents(m.height - lipgloss.Height(top) - lipgloss.Height(footer)); events != "" {
		parts = append(parts, events)
	}
	return lipgloss.JoinVertical(lipgloss.Left, append(parts, footer)...)
}

func (m Model) header() string {
	s := m.state
	if s == nil {
		return shared.TitleStyle.Width(m.width).Render("sigilc")
	}
	online := shared.ErrorDot.String() + " offline"
	switch {
	case m.stale:
		// Whether sigils answers sigilc is not known without an answer from
		// sigilc; the error line says why there is none.
		online = shared.ErrorDot.String() + " unknown, sigilc is not answering"
	case s.Online:
		online = shared.HealthyDot.String() + " online"
	}
	lastPull := "never"
	if !s.LastPullAt.IsZero() {
		lastPull = s.LastPullAt.Local().Format("2006-01-02 15:04:05")
	}
	lines := []string{
		shared.TitleStyle.Width(m.width).Render("sigilc  " + s.Name),
		fmt.Sprintf(" Server:     %s  %s", s.ServerURL, online),
		" Last pull:  " + lastPull,
	}
	if s.LastError != "" {
		lines = append(lines, errorStyle.Width(m.width).Render("Last error: "+s.LastError))
	}
	return strings.Join(lines, "\n")
}

// certTable lists the certificates in the store of the daemon.
func (m Model) certTable(now time.Time) string {
	if len(m.state.Certs) == 0 {
		return blockStyle.Render("No certificates stored.")
	}
	width := len("Name")
	for _, c := range m.state.Certs {
		width = max(width, len(c.Name))
	}
	lines := []string{shared.TableHeader.Render(fmt.Sprintf("%-*s  %-20s  %-7s  %-9s  %s",
		width, "Name", "Not After", "Outputs", "on_change", "Pending"))}
	for _, c := range m.state.Certs {
		notAfter := fmt.Sprintf("%-20s", notAfterText(c.NotAfter, now))
		if due(c, now) {
			notAfter = dueStyle.Render(notAfter)
		}
		lines = append(lines, fmt.Sprintf("%-*s  %s  %-7d  %-9s  %s",
			width, c.Name, notAfter, c.Outputs, yesNo(c.OnChange), yesNo(c.HookPending)))
	}
	return blockStyle.Render(strings.Join(lines, "\n"))
}

// due reports whether a certificate is due for renewal by the ratio rule.
// One that sigilc cannot parse has no RenewAt and is not.
func due(c ipc.ClientCertState, now time.Time) bool {
	return !c.RenewAt.IsZero() && !now.Before(c.RenewAt)
}

// notAfterText returns the date of notAfter and the days left until it, or
// "-" when it is zero.
func notAfterText(notAfter, now time.Time) string {
	if notAfter.IsZero() {
		return "-"
	}
	date := notAfter.Local().Format("2006-01-02")
	if !now.Before(notAfter) {
		return date + " (expired)"
	}
	return fmt.Sprintf("%s (%dd)", date, int(notAfter.Sub(now)/(24*time.Hour)))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// recentEvents lists as many of the newest events as fit in rows lines, one
// line each, or returns "" when not even one fits.
func (m Model) recentEvents(rows int) string {
	n := rows - 2 // the padding line and the title
	if n < 1 {
		return ""
	}
	lines := []string{shared.TableHeader.Render("Recent events")}
	if len(m.events) == 0 {
		lines = append(lines, "No events yet.")
	}
	line := lipgloss.NewStyle().MaxWidth(m.width - 2)
	for _, e := range m.events[max(0, len(m.events)-n):] {
		lines = append(lines, line.Render(formatEvent(e)))
	}
	return blockStyle.Render(strings.Join(lines, "\n"))
}

// formatEvent returns the time, level, message and attributes of e.
func formatEvent(e logging.Event) string {
	level := fmt.Sprintf("%-5s", e.Level)
	if style, ok := levelStyles[e.Level]; ok {
		level = style.Render(level)
	}
	line := e.Time.Local().Format("2006-01-02 15:04:05") + "  " + level + "  " + e.Message
	if e.Attrs != "" {
		line += "  " + e.Attrs
	}
	return line
}

// footer renders the outcome of the last fetch or reload, the error of the
// last refresh and the help.
func (m Model) footer() string {
	var lines []string
	switch {
	case m.running != "":
		lines = append(lines, " "+m.running+": running...")
	case m.last.err != nil:
		lines = append(lines, errorStyle.Width(m.width).Render(fmt.Sprintf("%s failed: %v", m.last.name, m.last.err)))
	case m.last.name != "":
		lines = append(lines, fmt.Sprintf(" %s: done at %s", m.last.name, m.last.at.Format("15:04:05")))
	}
	if m.err != nil {
		lines = append(lines, errorStyle.Width(m.width).Render("Error: "+m.err.Error()))
	}
	lines = append(lines, lineStyle.Render(m.help.View(m.keys)))
	if m.help.ShowAll {
		lines = append(lines, shared.HelpStyle.Padding(0, 1).Width(m.width).Render(legend))
	}
	return strings.Join(lines, "\n")
}

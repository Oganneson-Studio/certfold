package server

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// Backend is the part of the sigils IPC API that the TUI uses.
type Backend interface {
	ListCerts(ctx context.Context) ([]*ipc.CertificateInfo, error)
	RenewCert(ctx context.Context, name string) error
	ListClients(ctx context.Context) ([]*ipc.ClientInfo, error)
	DeleteClient(ctx context.Context, name string) error
	ListTokens(ctx context.Context) ([]*ipc.TokenInfo, error)
	CreateToken(ctx context.Context, req ipc.CreateTokenRequest) (*ipc.CreateTokenResponse, error)
	DeleteToken(ctx context.Context, id string) error
	Events(ctx context.Context, after uint64) (*ipc.EventsPage, error)
}

var _ Backend = (*ipc.Client)(nil)

// refreshInterval is how often the TUI reloads what it shows.
const refreshInterval = 2 * time.Second

const (
	tabOverview = iota
	tabCertificates
	tabClients
	tabTokens
	tabEvents
	numTabs
)

var tabNames = [numTabs]string{
	"1 Overview",
	"2 Certificates",
	"3 Clients",
	"4 Tokens",
	"5 Events",
}

// Model is the root Bubble Tea model for the sigils TUI.
type Model struct {
	backend Backend
	keys    keyMap
	help    help.Model

	tab    int
	width  int
	height int

	// The lists of the last refresh, in the order of the table rows. The
	// first cell of a row is the name, or for tokens the ID, of what it shows.
	certs        []*ipc.CertificateInfo
	clients      []*ipc.ClientInfo
	tokens       []*ipc.TokenInfo
	certsTable   table.Model
	clientsTable table.Model
	tokensTable  table.Model

	// events holds the daemon's events, oldest first and at most
	// logging.RingSize of them. Seq starts over when the daemon restarts, so
	// the next refresh asks for the events after lastSeq only while the
	// daemon reports the same started.
	events     []logging.Event
	started    time.Time
	lastSeq    uint64
	eventsView viewport.Model

	refreshing  bool // a refresh is in flight; no other starts until it ends
	lastRefresh time.Time
	// refreshErr is the error of the last refresh; the next refresh that
	// succeeds clears it. actionErr is the error of the last renewal, client
	// removal, token revocation or token creation. It stays until the next of
	// these starts, so the refresh two seconds later does not hide it.
	refreshErr error
	actionErr  error

	// At most one dialog is open. While one is, it takes every key but
	// ctrl+c.
	confirm *confirmation
	form    *tokenForm
	created *createdToken
}

type tickMsg struct{}

// refreshMsg is the result of a refresh. events holds the events after the
// lastSeq the refresh started from, or all of them when the daemon has
// restarted since.
type refreshMsg struct {
	certs   []*ipc.CertificateInfo
	clients []*ipc.ClientInfo
	tokens  []*ipc.TokenInfo
	events  *ipc.EventsPage
	err     error
}

// actionMsg is the result of a renewal, a client removal or a token
// revocation.
type actionMsg struct{ err error }

// createdMsg is the result of a token creation.
type createdMsg struct {
	name  string
	token *ipc.CreateTokenResponse
	err   error
}

// New returns a Model that shows and changes the state of the sigils daemon
// behind backend.
func New(backend Backend) Model {
	return Model{
		backend: backend,
		keys:    defaultKeys(),
		help:    help.New(),
		certsTable: newTable(
			table.Column{Title: "Name", Width: 16},
			table.Column{Title: "State", Width: 8},
			table.Column{Title: "Not After", Width: 10},
			table.Column{Title: "Renew At", Width: 18},
			table.Column{Title: "Domains", Width: 24}, // fitted to the window
			table.Column{Title: "Subs", Width: 4},
		),
		clientsTable: newTable(
			table.Column{Title: "Name", Width: 20},
			table.Column{Title: "Last Seen", Width: 16},
			table.Column{Title: "Enrolled", Width: 16},
			table.Column{Title: "Certificates", Width: 24}, // fitted to the window
		),
		tokensTable: newTable(
			table.Column{Title: "ID", Width: 32},
			table.Column{Title: "Name", Width: 20}, // fitted to the window
			table.Column{Title: "Status", Width: 7},
			table.Column{Title: "Expires", Width: 16},
		),
		eventsView: viewport.New(0, 0),
	}
}

// newTable returns a table that marks its selected row with › besides the
// color, which a terminal without colors does not show.
func newTable(cols ...table.Column) table.Model {
	styles := table.DefaultStyles()
	styles.Selected = styles.Selected.Transform(func(row string) string {
		// The row starts with the padding of its first cell.
		if rest, ok := strings.CutPrefix(row, " "); ok {
			return "›" + rest
		}
		return row
	})
	return table.New(table.WithColumns(cols), table.WithStyles(styles))
}

// Init starts refreshing: now, and then every refreshInterval.
func (m Model) Init() tea.Cmd {
	return func() tea.Msg { return tickMsg{} }
}

// Update handles msg, then fits the tables and views to the window again:
// the status line and the help grow and shrink with what they show.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmd := m.update(msg)
	m.layout()
	return m, cmd
}

func (m *Model) update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		refresh := m.startRefresh()
		return tea.Batch(refresh, tea.Tick(refreshInterval, func(time.Time) tea.Msg { return tickMsg{} }))
	case refreshMsg:
		m.refreshing = false
		if msg.err != nil {
			m.refreshErr = msg.err
			return nil
		}
		m.refreshErr = nil
		m.lastRefresh = time.Now()
		m.setLists(msg.certs, msg.clients, msg.tokens)
		m.addEvents(msg.events)
	case actionMsg:
		if msg.err != nil {
			m.actionErr = msg.err
			return nil
		}
		return m.startRefresh()
	case createdMsg:
		if msg.err != nil {
			m.actionErr = msg.err
			return nil
		}
		// The token cannot be shown again, so it takes the place of a
		// dialog opened while it was being created.
		m.confirm, m.form = nil, nil
		m.created = newCreatedToken(msg.name, msg.token)
		return m.startRefresh()
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return nil
}

// startRefresh starts a refresh unless one is in flight.
func (m *Model) startRefresh() tea.Cmd {
	if m.refreshing {
		return nil
	}
	m.refreshing = true
	return m.load()
}

// load returns a command that reads the lists and the events after lastSeq.
func (m Model) load() tea.Cmd {
	b, started, after := m.backend, m.started, m.lastSeq
	return func() tea.Msg {
		ctx := context.Background()
		var msg refreshMsg
		var err error
		if msg.certs, err = b.ListCerts(ctx); err != nil {
			return refreshMsg{err: err}
		}
		if msg.clients, err = b.ListClients(ctx); err != nil {
			return refreshMsg{err: err}
		}
		if msg.tokens, err = b.ListTokens(ctx); err != nil {
			return refreshMsg{err: err}
		}
		if msg.events, err = b.Events(ctx, after); err != nil {
			return refreshMsg{err: err}
		}
		if after > 0 && !msg.events.Started.Equal(started) {
			// The daemon has restarted: Seq started over, and the page lacks
			// the new events up to after.
			if msg.events, err = b.Events(ctx, 0); err != nil {
				return refreshMsg{err: err}
			}
		}
		return msg
	}
}

// setLists replaces the lists, as of lastRefresh. Each table keeps its row
// selected wherever the new list puts it, so that a new token listed first
// does not move the selection to another one.
func (m *Model) setLists(certs []*ipc.CertificateInfo, clients []*ipc.ClientInfo, tokens []*ipc.TokenInfo) {
	m.certs, m.clients, m.tokens = certs, clients, tokens

	rows := make([]table.Row, len(certs))
	subscribed := make(map[string][]string)
	for i, c := range certs {
		rows[i] = table.Row{
			c.Name, c.State, formatTime(c.NotAfter, "2006-01-02", "-"), renewAt(c, "2006-01-02"),
			strings.Join(c.Domains, ","), strconv.Itoa(len(c.Subscribers)),
		}
		for _, client := range c.Subscribers {
			subscribed[client] = append(subscribed[client], c.Name)
		}
	}
	setRows(&m.certsTable, rows)

	rows = make([]table.Row, len(clients))
	for i, c := range clients {
		rows[i] = table.Row{
			c.Name, formatTime(c.LastSeen, "2006-01-02 15:04", "never"), formatTime(c.EnrolledAt, "2006-01-02 15:04", "-"),
			strings.Join(subscribed[c.Name], ","),
		}
	}
	setRows(&m.clientsTable, rows)

	rows = make([]table.Row, len(tokens))
	for i, t := range tokens {
		rows[i] = table.Row{t.TokenID, t.Name, tokenStatus(t, m.lastRefresh), formatTime(t.ExpiresAt, "2006-01-02 15:04", "-")}
	}
	setRows(&m.tokensTable, rows)
}

// setRows replaces the rows of t. The cursor stays on the row with the first
// cell of the row it was on, when the new rows have one.
func setRows(t *table.Model, rows []table.Row) {
	var selected string
	if row := t.SelectedRow(); row != nil {
		selected = row[0]
	}
	t.SetRows(rows)
	for i, row := range rows {
		if row[0] == selected {
			t.SetCursor(i)
			return
		}
	}
	// SetRows leaves the cursor at -1 once the table has been empty.
	if t.Cursor() < 0 {
		t.SetCursor(0)
	}
}

// addEvents adds the events of page, which replace those the model has when
// the daemon has restarted.
func (m *Model) addEvents(page *ipc.EventsPage) {
	if !page.Started.Equal(m.started) {
		m.events, m.started, m.lastSeq = nil, page.Started, 0
	}
	m.events = append(m.events, page.Events...)
	if n := len(page.Events); n > 0 {
		m.lastSeq = page.Events[n-1].Seq
	}
	if extra := len(m.events) - logging.RingSize; extra > 0 {
		m.events = m.events[extra:]
	}
	atBottom := m.eventsView.AtBottom()
	m.eventsView.SetContent(eventLines(m.events, m.eventsView.Width))
	follow(&m.eventsView, atBottom)
}

// follow keeps v on the newest line when it was there, so it follows new
// lines; otherwise it keeps the offset within the content.
func follow(v *viewport.Model, atBottom bool) {
	if atBottom {
		v.GotoBottom()
	} else {
		v.SetYOffset(v.YOffset)
	}
}

func (m *Model) handleKey(msg tea.KeyMsg) tea.Cmd {
	if msg.Type == tea.KeyCtrlC {
		return tea.Quit
	}
	switch {
	case m.confirm != nil:
		return m.updateConfirm(msg)
	case m.form != nil:
		return m.updateForm(msg)
	case m.created != nil:
		m.updateCreated(msg)
		return nil
	}

	k := m.keys
	switch {
	case key.Matches(msg, k.Quit):
		return tea.Quit
	case key.Matches(msg, k.Tab):
		m.tab = int(msg.Runes[0] - '1')
	case key.Matches(msg, k.NextTab):
		m.tab = (m.tab + 1) % numTabs
	case key.Matches(msg, k.PrevTab):
		m.tab = (m.tab + numTabs - 1) % numTabs
	case key.Matches(msg, k.Refresh):
		return m.startRefresh()
	case key.Matches(msg, k.Help):
		m.help.ShowAll = !m.help.ShowAll
	default:
		m.handleTabKey(msg)
	}
	return nil
}

// handleTabKey handles the keys of the current tab.
func (m *Model) handleTabKey(msg tea.KeyMsg) {
	k := m.keys
	if m.tab == tabEvents {
		v := &m.eventsView
		switch {
		case key.Matches(msg, k.Up):
			v.LineUp(1)
		case key.Matches(msg, k.Down):
			v.LineDown(1)
		case key.Matches(msg, k.PageUp):
			v.PageUp()
		case key.Matches(msg, k.PageDown):
			v.PageDown()
		case key.Matches(msg, k.Top):
			v.GotoTop()
		case key.Matches(msg, k.Bottom):
			v.GotoBottom()
		}
		return
	}

	var t *table.Model
	switch m.tab {
	case tabCertificates:
		t = &m.certsTable
	case tabClients:
		t = &m.clientsTable
	case tabTokens:
		t = &m.tokensTable
	default:
		return
	}
	switch {
	case key.Matches(msg, k.Up):
		t.MoveUp(1)
	case key.Matches(msg, k.Down):
		t.MoveDown(1)
	case m.tab == tabTokens && key.Matches(msg, k.NewToken):
		m.form = newTokenForm()
	default:
		row := t.SelectedRow()
		if row == nil {
			return
		}
		b := m.backend
		switch {
		case m.tab == tabCertificates && key.Matches(msg, k.Renew):
			name := row[0]
			m.ask("renew", "Renew certificate "+strconv.Quote(name)+" now? sigils orders a new certificate from the CA.",
				func(ctx context.Context) error { return b.RenewCert(ctx, name) })
		case m.tab == tabClients && key.Matches(msg, k.Delete):
			name := row[0]
			m.ask("delete", "Delete client "+strconv.Quote(name)+"? This revokes its access immediately.",
				func(ctx context.Context) error { return b.DeleteClient(ctx, name) })
		case m.tab == tabTokens && key.Matches(msg, k.Revoke):
			id := row[0]
			m.ask("revoke", "Revoke enrollment token "+id+" for "+strconv.Quote(row[1])+"?",
				func(ctx context.Context) error { return b.DeleteToken(ctx, id) })
		}
	}
}

// layout sizes the tables and the views to the window.
func (m *Model) layout() {
	height := m.contentHeight()
	if m.created != nil {
		// The new-token box fills the content area without padding, so its
		// lines hold as much of the commands as the window allows.
		m.created.resize(m.width, height)
	}

	// Inside the padding of shared.ContentStyle.
	w, h := max(m.width-4, 0), max(height-2, 0)
	m.help.Width = w

	fitColumn(&m.certsTable, 4, w)
	fitColumn(&m.clientsTable, 3, w)
	fitColumn(&m.tokensTable, 1, w)
	// The details of the selected certificate follow its table.
	m.certsTable.SetHeight(min(len(m.certs)+1, max(h-lipgloss.Height(m.certDetails(w))-1, 4)))
	m.clientsTable.SetHeight(h)
	m.tokensTable.SetHeight(h)

	v := &m.eventsView
	atBottom := v.AtBottom()
	if v.Width != w {
		v.Width = w
		v.SetContent(eventLines(m.events, w))
	}
	v.Height = h
	follow(v, atBottom)
}

// fitColumn gives column i of t the width that the other columns leave of
// width, and at least 8.
func fitColumn(t *table.Model, i, width int) {
	cols := slices.Clone(t.Columns())
	rest := width
	for j, c := range cols {
		rest -= 2 // the padding of each cell
		if j != i {
			rest -= c.Width
		}
	}
	if rest = max(rest, 8); cols[i].Width != rest {
		cols[i].Width = rest
		t.SetColumns(cols)
	}
}

// selectedCert returns the certificate of the selected row, or nil.
func (m Model) selectedCert() *ipc.CertificateInfo {
	if i := m.certsTable.Cursor(); i >= 0 && i < len(m.certs) {
		return m.certs[i]
	}
	return nil
}

// formatTime formats t in local time with layout, or returns none for the
// zero time.
func formatTime(t time.Time, layout, none string) string {
	if t.IsZero() {
		return none
	}
	return t.Local().Format(layout)
}

// renewAt formats when c is due for renewal with layout, or returns "-"
// without stored material.
func renewAt(c *ipc.CertificateInfo, layout string) string {
	return formatTime(c.RenewAt, layout, "-")
}

// tokenStatus reports whether t has enrolled a client, has expired unused,
// or can still be used.
func tokenStatus(t *ipc.TokenInfo, now time.Time) string {
	switch {
	case !t.UsedAt.IsZero():
		return "used"
	case !now.Before(t.ExpiresAt):
		return "expired"
	}
	return "unused"
}

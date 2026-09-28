// Package client provides the Bubble Tea TUI for the sigilc client daemon.
package client

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/tui/shared"
)

// CertStatus holds display info for one certificate.
type CertStatus struct {
	Name     string
	NotAfter time.Time
	Outputs  int
	Healthy  bool
	WarnDays int // days until expiry; show warning if < 30
}

// Event is a timestamped log line for the recent events panel.
type Event struct {
	At      time.Time
	Message string
}

// Model is the root Bubble Tea model for the sigilc TUI.
type Model struct {
	clientName   string
	serverURL    string
	online       bool
	certs        []CertStatus
	events       []Event
	showLogs     bool
	logsVP       viewport.Model
	ipc          *ipc.Client
	width        int
	height       int
	err          error
	fetchTrigger chan struct{} // closed to signal immediate fetch
}

// fetchMsg is the result of a fetch triggered via IPC.
type fetchMsg struct{ err error }
type reloadMsg struct{ err error }
type stateMsg struct {
	state *ipc.ClientState
	err   error
}

// FetchProvider is a function the model calls when 'f' is pressed.
// In production this triggers Client.Fetch over IPC; in tests it can be a stub.
type FetchProvider func(ctx context.Context) error

// New creates a new Model.
func New(clientName, serverURL string, ipcClient *ipc.Client) Model {
	return Model{
		clientName: clientName,
		serverURL:  serverURL,
		ipc:        ipcClient,
		logsVP:     viewport.New(80, 20),
	}
}

// WithCerts populates the cert list (for tests and initial state injection).
func (m Model) WithCerts(certs []CertStatus) Model {
	m.certs = certs
	return m
}

// WithEvents populates the events list.
func (m Model) WithEvents(events []Event) Model {
	m.events = events
	return m
}

// WithOnline sets the server online status.
func (m Model) WithOnline(online bool) Model {
	m.online = online
	return m
}

// Init loads the live daemon state when an IPC connection is available.
func (m Model) Init() tea.Cmd { return m.loadState() }

// Update handles incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.logsVP.Width = msg.Width - 4
		m.logsVP.Height = msg.Height - 8

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "l":
			m.showLogs = !m.showLogs
		case "f":
			return m, m.doFetch()
		case "r":
			return m, m.doReload()
		case "?":
			m = m.addEvent("Help: [f] fetch  [r] reload  [l] logs  [q] quit")
		}

	case fetchMsg:
		if msg.err != nil {
			m = m.addEvent(fmt.Sprintf("fetch error: %v", msg.err))
			m.err = msg.err
		} else {
			m = m.addEvent("fetch ok")
			m.err = nil
			return m, m.loadState()
		}

	case reloadMsg:
		if msg.err != nil {
			m = m.addEvent(fmt.Sprintf("reload error: %v", msg.err))
			m.err = msg.err
		} else {
			m = m.addEvent("reload ok")
			m.err = nil
			return m, m.loadState()
		}

	case stateMsg:
		if msg.err != nil {
			m.online = false
			m.err = msg.err
			break
		}
		m.clientName = msg.state.Name
		m.serverURL = msg.state.ServerURL
		m.online = msg.state.Online
		m.certs = make([]CertStatus, 0, len(msg.state.Certs))
		for name := range msg.state.Certs {
			m.certs = append(m.certs, CertStatus{Name: name, Healthy: msg.state.Online})
		}
		sort.Slice(m.certs, func(i, j int) bool { return m.certs[i].Name < m.certs[j].Name })
	}
	return m, nil
}

func (m Model) doFetch() tea.Cmd {
	return func() tea.Msg {
		// When no IPC client: succeed silently (tests inject state directly).
		if m.ipc == nil {
			return fetchMsg{}
		}
		return fetchMsg{err: m.ipc.FetchClient(context.Background(), "")}
	}
}

func (m Model) doReload() tea.Cmd {
	return func() tea.Msg {
		if m.ipc == nil {
			return reloadMsg{}
		}
		return reloadMsg{err: m.ipc.ReloadClient(context.Background())}
	}
}

func (m Model) loadState() tea.Cmd {
	if m.ipc == nil {
		return nil
	}
	return func() tea.Msg {
		state, err := m.ipc.GetClientState(context.Background())
		return stateMsg{state: state, err: err}
	}
}

func (m Model) addEvent(msg string) Model {
	e := Event{At: time.Now(), Message: msg}
	m.events = append(m.events, e)
	if len(m.events) > 20 {
		m.events = m.events[len(m.events)-20:]
	}
	return m
}

// View renders the model.
func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}
	if m.showLogs {
		return m.logsVP.View()
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		m.renderHeader(),
		m.renderCerts(),
		m.renderEvents(),
		m.renderHelp(),
	)
}

func (m Model) renderHeader() string {
	onlineDot := shared.StatusDot(m.online, false)
	if !m.online {
		onlineDot = shared.ErrorDot.String()
	}
	line := fmt.Sprintf(" Name: %-12s  Server: %s", m.clientName, onlineDot)
	return shared.TitleStyle.Width(m.width).Render(line)
}

func (m Model) renderCerts() string {
	if len(m.certs) == 0 {
		return shared.ContentStyle.Render("No certificates subscribed.")
	}
	header := shared.TableHeader.Render(
		fmt.Sprintf("  %-14s %-10s %-10s %-10s", "name", "not_after", "outputs", "status"))
	var rows []string
	rows = append(rows, header)
	for _, c := range m.certs {
		days := int(time.Until(c.NotAfter).Hours() / 24)
		expires := "-"
		warn := false
		if !c.NotAfter.IsZero() {
			expires = fmt.Sprintf("%dd", days)
			warn = days < 30
		}
		dot := shared.StatusDot(c.Healthy, warn)
		rows = append(rows, fmt.Sprintf("  %-14s %-10s %-10s %s",
			c.Name,
			expires,
			fmt.Sprintf("%d paths", c.Outputs),
			dot,
		))
	}
	box := strings.Join(rows, "\n")
	return shared.ContentStyle.Render(box)
}

func (m Model) renderEvents() string {
	if len(m.events) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Recent events:\n")
	start := len(m.events) - 10
	if start < 0 {
		start = 0
	}
	for _, e := range m.events[start:] {
		fmt.Fprintf(&sb, "  %s  %s\n", e.At.Format("15:04"), e.Message)
	}
	return shared.ContentStyle.Render(sb.String())
}

func (m Model) renderHelp() string {
	return shared.HelpStyle.Render("[f] fetch  [r] reload  [l] logs  [q] quit  [?] help")
}

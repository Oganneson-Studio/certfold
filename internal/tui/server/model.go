// Package server provides the Bubble Tea TUI for the sigils server daemon.
package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/tui/shared"
)

const numTabs = 6

var tabNames = [numTabs]string{
	"1 Dashboard",
	"2 Certs",
	"3 Clients",
	"4 Enroll",
	"5 Logs",
	"6 Config",
}

// Model is the root Bubble Tea model for the sigils TUI.
type Model struct {
	tab    int
	width  int
	height int
	ipc    *ipc.Client
	err    error

	// Tab-specific state.
	certsTable   table.Model
	clientsTable table.Model
	logsVP       viewport.Model
	configVP     viewport.Model

	// Data.
	certs   []*ipc.CertificateInfo
	clients []*ipc.ClientInfo
	tokens  []*ipc.TokenInfo

	// Enroll tab state.
	enrollInput string
	enrollToken string

	// Status line.
	lastRefresh time.Time
}

// refreshMsg is sent when the IPC data has been loaded.
type refreshMsg struct {
	certs   []*ipc.CertificateInfo
	clients []*ipc.ClientInfo
	tokens  []*ipc.TokenInfo
	err     error
}

// New creates a new Model.
func New(ipcClient *ipc.Client) Model {
	certsTable := table.New(
		table.WithColumns([]table.Column{
			{Title: "Name", Width: 16},
			{Title: "CA", Width: 10},
			{Title: "Not After", Width: 12},
			{Title: "Domains", Width: 24},
			{Title: "Subs", Width: 6},
		}),
		table.WithFocused(true),
	)
	clientsTable := table.New(
		table.WithColumns([]table.Column{
			{Title: "Name", Width: 16},
			{Title: "Fingerprint", Width: 20},
			{Title: "Last Seen", Width: 20},
			{Title: "Enrolled At", Width: 20},
		}),
		table.WithFocused(true),
	)
	return Model{
		ipc:          ipcClient,
		certsTable:   certsTable,
		clientsTable: clientsTable,
		logsVP:       viewport.New(80, 20),
		configVP:     viewport.New(80, 20),
	}
}

// Init triggers an initial data load.
func (m Model) Init() tea.Cmd {
	return m.refresh()
}

// refresh returns a tea.Cmd that fetches data from the IPC server.
func (m Model) refresh() tea.Cmd {
	return func() tea.Msg {
		if m.ipc == nil {
			return refreshMsg{}
		}
		ctx := context.Background()
		certs, _ := m.ipc.ListCerts(ctx)
		clients, _ := m.ipc.ListClients(ctx)
		tokens, _ := m.ipc.ListTokens(ctx)
		return refreshMsg{certs: certs, clients: clients, tokens: tokens}
	}
}

// Update handles incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.logsVP.Width = msg.Width - 4
		m.logsVP.Height = msg.Height - 6
		m.configVP.Width = msg.Width - 4
		m.configVP.Height = msg.Height - 6

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "1", "2", "3", "4", "5", "6":
			m.tab = int(msg.Runes[0] - '1')
			return m, nil
		case "tab":
			m.tab = (m.tab + 1) % numTabs
			return m, nil
		case "r":
			return m, m.refresh()
		case "j", "down":
			m.certsTable, _ = m.certsTable.Update(msg)
			m.clientsTable, _ = m.clientsTable.Update(msg)
		case "k", "up":
			m.certsTable, _ = m.certsTable.Update(msg)
			m.clientsTable, _ = m.clientsTable.Update(msg)
		case "g":
			// Go to top.
			m.logsVP.GotoTop()
		case "G":
			// Go to bottom.
			m.logsVP.GotoBottom()
		}

	case refreshMsg:
		m.err = msg.err
		m.certs = msg.certs
		m.clients = msg.clients
		m.tokens = msg.tokens
		m.lastRefresh = time.Now()
		m.updateTableRows()
	}
	return m, nil
}

// updateTableRows rebuilds the table rows from current data.
func (m *Model) updateTableRows() {
	var certRows []table.Row
	for _, c := range m.certs {
		notAfter := "-"
		if !c.NotAfter.IsZero() {
			notAfter = c.NotAfter.Format("2006-01-02")
		}
		domains := strings.Join(c.Domains, ",")
		if len(domains) > 22 {
			domains = domains[:19] + "..."
		}
		certRows = append(certRows, table.Row{c.Name, c.CA, notAfter, domains, "—"})
	}
	m.certsTable.SetRows(certRows)

	var clientRows []table.Row
	for _, cl := range m.clients {
		lastSeen := "never"
		if !cl.LastSeen.IsZero() {
			lastSeen = cl.LastSeen.Format("2006-01-02 15:04")
		}
		fp := cl.Fingerprint
		if len(fp) > 18 {
			fp = fp[:15] + "..."
		}
		clientRows = append(clientRows, table.Row{cl.Name, fp, lastSeen, cl.EnrolledAt.Format("2006-01-02")})
	}
	m.clientsTable.SetRows(clientRows)
}

// View renders the current model.
func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}
	header := m.renderTabBar()
	content := m.renderTab()
	help := shared.HelpStyle.Render("[1-6] tabs  [j/k] nav  [r] refresh  [q] quit")

	return lipgloss.JoinVertical(lipgloss.Left, header, content, help)
}

func (m Model) renderTabBar() string {
	tabs := make([]string, numTabs)
	for i, name := range tabNames {
		if i == m.tab {
			tabs[i] = shared.ActiveTab.Render(name)
		} else {
			tabs[i] = shared.InactiveTab.Render(name)
		}
	}
	bar := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
	return shared.TabBar.Width(m.width).Render(bar)
}

func (m Model) renderTab() string {
	switch m.tab {
	case 0:
		return m.renderDashboard()
	case 1:
		return m.renderCerts()
	case 2:
		return m.renderClients()
	case 3:
		return m.renderEnroll()
	case 4:
		return m.logsVP.View()
	case 5:
		return m.configVP.View()
	}
	return ""
}

func (m Model) renderDashboard() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", shared.TitleStyle.Render("Sigil Dashboard"))
	fmt.Fprintf(&b, "  Certificates : %d\n", len(m.certs))
	fmt.Fprintf(&b, "  Clients      : %d\n", len(m.clients))
	fmt.Fprintf(&b, "  Active tokens: %d\n", activeTokenCount(m.tokens))
	if !m.lastRefresh.IsZero() {
		fmt.Fprintf(&b, "\n  Last refresh : %s\n", m.lastRefresh.Format("15:04:05"))
	}
	if m.err != nil {
		fmt.Fprintf(&b, "\n%s\n", shared.ErrorStyle.Render("Error: "+m.err.Error()))
	}
	return shared.ContentStyle.Render(b.String())
}

func (m Model) renderCerts() string {
	return shared.ContentStyle.Render(m.certsTable.View())
}

func (m Model) renderClients() string {
	return shared.ContentStyle.Render(m.clientsTable.View())
}

func (m Model) renderEnroll() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", shared.TitleStyle.Render("Enrollment Tokens"))
	if len(m.tokens) == 0 {
		b.WriteString("  No active tokens. Press 'n' to create one.\n")
	}
	for _, tok := range m.tokens {
		used := "unused"
		if !tok.UsedAt.IsZero() {
			used = "used"
		}
		fmt.Fprintf(&b, "  %-20s %-10s expires %s\n",
			tok.Name, used, tok.ExpiresAt.Format("2006-01-02"))
	}
	if m.enrollToken != "" {
		fmt.Fprintf(&b, "\nToken: %s\n", m.enrollToken)
	}
	return shared.ContentStyle.Render(b.String())
}

func activeTokenCount(tokens []*ipc.TokenInfo) int {
	n := 0
	now := time.Now()
	for _, t := range tokens {
		if t.UsedAt.IsZero() && now.Before(t.ExpiresAt) {
			n++
		}
	}
	return n
}

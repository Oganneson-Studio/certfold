package server

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/tui/shared"
)

// View renders the current model.
func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}
	return shared.Narrow(lipgloss.JoinVertical(lipgloss.Left, m.renderTabBar(), m.renderContent(), m.renderStatus(), m.renderHelp()))
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

// contentHeight is the height the tab bar above and the status line and
// help below leave for the content.
func (m Model) contentHeight() int {
	return max(m.height-lipgloss.Height(m.renderTabBar())-lipgloss.Height(m.renderStatus())-lipgloss.Height(m.renderHelp()), 0)
}

// renderContent renders the open dialog, or else the current tab, in
// exactly contentHeight lines.
func (m Model) renderContent() string {
	if m.created != nil {
		return m.created.view.View()
	}
	h, w := m.contentHeight(), max(m.width-4, 0)
	var body string
	switch {
	case m.confirm != nil:
		body = m.confirm.view(w)
	case m.form != nil:
		body = m.form.view(w)
	case m.tab == tabOverview:
		body = m.renderOverview(w)
	case m.tab == tabCertificates:
		body = m.renderCertificates(w)
	case m.tab == tabClients:
		body = orHint(m.clients, m.clientsTable.View(), "No clients are enrolled. Create an enrollment token on the Tokens tab.")
	case m.tab == tabTokens:
		body = orHint(m.tokens, m.tokensTable.View(), "No enrollment tokens. Press n to create one.")
	case m.tab == tabEvents:
		body = orHint(m.events, m.eventsView.View(), "No events yet.")
	}
	return shared.ContentStyle.Height(h).MaxHeight(h).Render(body)
}

// orHint returns view, or hint when list is empty.
func orHint[T any](list []T, view, hint string) string {
	if len(list) == 0 {
		return hint
	}
	return view
}

func (m Model) renderOverview(w int) string {
	var b strings.Builder
	states := make(map[string]int)
	for _, c := range m.certs {
		states[c.State]++
	}
	fmt.Fprintf(&b, "Certificates  %-4d issuing %d, backoff %d, valid %d, pending %d\n", len(m.certs),
		states[ipc.CertStateIssuing], states[ipc.CertStateBackoff], states[ipc.CertStateValid], states[ipc.CertStatePending])
	fmt.Fprintf(&b, "Clients       %d\n", len(m.clients))
	statuses := make(map[string]int)
	for _, t := range m.tokens {
		statuses[tokenStatus(t, m.lastRefresh)]++
	}
	fmt.Fprintf(&b, "Tokens        %-4d unused %d, used %d, expired %d\n", len(m.tokens),
		statuses["unused"], statuses["used"], statuses["expired"])

	fmt.Fprintf(&b, "\n%s\n\n", shared.TitleStyle.Render("Recent events"))
	recent := m.events[max(len(m.events)-10, 0):]
	if len(recent) == 0 {
		b.WriteString("No events yet.\n")
	}
	line := lipgloss.NewStyle().MaxWidth(w)
	for _, e := range recent {
		b.WriteString(line.Render(formatEvent(e)) + "\n")
	}
	return b.String()
}

func (m Model) renderCertificates(w int) string {
	if len(m.certs) == 0 {
		return "No certificates are configured. Add one with `sigils cert add`."
	}
	return m.certsTable.View() + "\n\n" + m.certDetails(w)
}

// certDetails describes the selected certificate in lines of at most w
// columns, or returns "" when none is selected.
func (m Model) certDetails(w int) string {
	c := m.selectedCert()
	if c == nil {
		return ""
	}
	const layout = "2006-01-02 15:04 MST"
	fields := [][2]string{
		{"CA", c.CA},
		{"Domains", strings.Join(c.Domains, ", ")},
		{"Subscribers", strings.Join(c.Subscribers, ", ")},
		{"Fingerprint", c.Fingerprint},
		{"Issued At", formatTime(c.IssuedAt, layout, "")},
		{"Not After", formatTime(c.NotAfter, layout, "")},
		{"Renew At", renewAt(c, layout)},
		{"Failures", strconv.Itoa(c.Failures)},
		{"Last Attempt", formatTime(c.LastAttemptAt, layout, "")},
		{"Next Attempt", formatTime(c.NextAttemptAt, layout, "")},
		{"Last Error", c.LastError},
	}
	value := lipgloss.NewStyle().Width(max(w-14, 10))
	lines := []string{shared.TableHeader.Render(c.Name)}
	for _, f := range fields {
		if f[1] == "" {
			f[1] = "-"
		}
		lines = append(lines, lipgloss.JoinHorizontal(lipgloss.Top, fmt.Sprintf("%-14s", f[0]), value.Render(f[1])))
	}
	return strings.Join(lines, "\n")
}

// renderStatus shows the errors of the last action and of the last refresh,
// or else when the last refresh ended.
func (m Model) renderStatus() string {
	w := max(m.width-4, 1)
	var lines []string
	for _, err := range []error{m.actionErr, m.refreshErr} {
		if err != nil {
			lines = append(lines, shared.ErrorStyle.Width(w).Render("Error: "+err.Error()))
		}
	}
	if len(lines) == 0 {
		status := "loading"
		if !m.lastRefresh.IsZero() {
			status = "updated " + m.lastRefresh.Format("15:04:05")
		}
		lines = append(lines, shared.HelpStyle.Render(status))
	}
	return lipgloss.NewStyle().PaddingLeft(2).Render(strings.Join(lines, "\n"))
}

func (m Model) renderHelp() string {
	return lipgloss.NewStyle().PaddingLeft(2).Render(m.help.View(m.keyHelp()))
}

// eventLines renders events one per line, wrapped at width when it is set.
func eventLines(events []logging.Event, width int) string {
	style := lipgloss.NewStyle().Width(width)
	lines := make([]string, len(events))
	for i, e := range events {
		lines[i] = style.Render(formatEvent(e))
	}
	return strings.Join(lines, "\n")
}

// formatEvent formats e as "2006-01-02 15:04:05  INFO   message  attrs" in
// local time, as `sigils events` prints it.
func formatEvent(e logging.Event) string {
	line := fmt.Sprintf("%s  %-5s  %s", e.Time.Local().Format("2006-01-02 15:04:05"), e.Level, e.Message)
	if e.Attrs != "" {
		line += "  " + e.Attrs
	}
	return line
}

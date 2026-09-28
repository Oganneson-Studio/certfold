// Package shared provides common lipgloss styles for all Sigil TUI components.
package shared

import "github.com/charmbracelet/lipgloss"

var (
	// Primary purple accent.
	Purple = lipgloss.Color("#7B2FBE")
	// Blue highlight.
	Blue = lipgloss.Color("#3B82F6")
	// Neutral gray.
	Gray = lipgloss.Color("#6B7280")
	// Status colors.
	Green  = lipgloss.Color("#22C55E")
	Yellow = lipgloss.Color("#F59E0B")
	Red    = lipgloss.Color("#EF4444")
	White  = lipgloss.Color("#F9FAFB")

	// Tab bar styles.
	ActiveTab = lipgloss.NewStyle().
			Foreground(White).
			Background(Purple).
			Padding(0, 1).
			Bold(true)

	InactiveTab = lipgloss.NewStyle().
			Foreground(Gray).
			Padding(0, 1)

	TabBar = lipgloss.NewStyle().
		BorderBottom(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(Purple)

	// Content area.
	ContentStyle = lipgloss.NewStyle().Padding(1, 2)

	// Status indicators: • rather than ●, which some consoles draw two
	// cells wide (see narrowGlyphs).
	HealthyDot = lipgloss.NewStyle().Foreground(Green).SetString("•")
	ErrorDot   = lipgloss.NewStyle().Foreground(Red).SetString("•")

	// Header / title bar.
	TitleStyle = lipgloss.NewStyle().
			Foreground(White).
			Background(Purple).
			Padding(0, 1).
			Bold(true).
			Width(40)

	// Error style.
	ErrorStyle = lipgloss.NewStyle().Foreground(Red).Bold(true)

	// Help bar.
	HelpStyle = lipgloss.NewStyle().Foreground(Gray).Italic(true)

	// Table header.
	TableHeader = lipgloss.NewStyle().Foreground(Blue).Bold(true)
)

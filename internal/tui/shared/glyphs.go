package shared

import (
	"strings"
	"unicode"
)

// narrowGlyphs are the characters beyond ASCII that the TUIs may draw. A
// classic Windows console on an East Asian system (conhost, code page 936)
// was seen on 2026-09-28 to draw these one cell wide, but · … ↑ ↓ ● — × two
// cells wide. lipgloss counts those as one cell, so a line that holds one
// spills into the next row and drags the rest of the view down.
const narrowGlyphs = "─│╭╮╰╯•›"

// Narrow replaces the … with which bubbles tables and help cut text. The
// TUIs apply it to what their View returns.
func Narrow(view string) string {
	return strings.ReplaceAll(view, "…", "~")
}

// WideGlyph returns the first character of view beyond ASCII that is not
// known to be one cell wide in such a console. Tests of the TUIs check their
// views with it.
func WideGlyph(view string) (rune, bool) {
	for _, r := range view {
		if r > unicode.MaxASCII && !strings.ContainsRune(narrowGlyphs, r) {
			return r, true
		}
	}
	return 0, false
}

package shared

import "testing"

func TestNarrowReplacesEllipsis(t *testing.T) {
	if got := Narrow("api.exa… • ?"); got != "api.exa~ • ?" {
		t.Errorf("Narrow = %q", got)
	}
}

func TestWideGlyph(t *testing.T) {
	if r, wide := WideGlyph("plain text ─│╭╮╰╯•›"); wide {
		t.Errorf("WideGlyph of narrow glyphs = %q", r)
	}
	for _, s := range []string{"·", "…", "↑", "↓", "●", "—", "×"} {
		if r, wide := WideGlyph("a " + s + " b"); !wide || string(r) != s {
			t.Errorf("WideGlyph(%q) = %q, %v", s, r, wide)
		}
	}
}

func TestStatusDotsAreNarrow(t *testing.T) {
	for _, dot := range []string{HealthyDot.String(), ErrorDot.String()} {
		if r, wide := WideGlyph(dot); wide {
			t.Errorf("status dot %q draws %q", dot, r)
		}
	}
}

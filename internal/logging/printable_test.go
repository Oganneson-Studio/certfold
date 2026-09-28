package logging

import (
	"errors"
	"testing"
)

// Printable replaces everything a terminal may take for a command: C0 but
// "\n", DEL, C1 and invalid UTF-8.
func TestPrintable(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"OSC", "x\x1b]0;pwned\a", "x ]0;pwned "},
		{"carriage return and tab", "a\rb\tc", "a b c"},
		{"DEL", "a\x7fb", "a b"},
		{"C1 CSI", "a\u009b31mb", "a 31mb"},
		{"first and last C1", "\u0080\u009f", "  "},
		{"invalid UTF-8", "a\xffb\x9b[2Jc\xc2", "a\uFFFDb\uFFFD[2Jc\uFFFD"},
		{"newline", "a\nb", "a\nb"},
		{"printable", "déjà vu – 证书", "déjà vu – 证书"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Printable(tc.in); got != tc.want {
				t.Fatalf("Printable(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The errors that errors.Join joins stay on lines of their own.
func TestPrintableKeepsJoinedErrorsApart(t *testing.T) {
	err := errors.Join(errors.New("sync: x\x1b[2J"), errors.New(`bundle "api": server returned 500`))
	if got, want := Printable(err.Error()), "sync: x [2J\nbundle \"api\": server returned 500"; got != want {
		t.Fatalf("Printable = %q, want %q", got, want)
	}
}

func TestOneLine(t *testing.T) {
	if got, want := OneLine("a\nb\x1b[2J\r\n\u009b"), "a b [2J   "; got != want {
		t.Fatalf("OneLine = %q, want %q", got, want)
	}
}

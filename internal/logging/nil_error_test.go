package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// pointerError is an error whose Error method reads its receiver, as the
// errors of many packages do: its Error panics for a nil *pointerError.
type pointerError struct{ text string }

func (e *pointerError) Error() string { return e.text }

// TestTypedNilErrorRendersAsNil logs a nil *pointerError held in an error, as
// a function that returns a typed nil leaves it. The service log, events and
// the lines of NewLineHandler all show <nil>, as fmt does, instead of
// panicking in the goroutine that logs.
func TestTypedNilErrorRendersAsNil(t *testing.T) {
	var err error = (*pointerError)(nil)
	var sink bytes.Buffer
	ring := NewRing()
	line := logToAll(&sink, ring, func(logger *slog.Logger) { logger.Warn("round failed", "error", err) })

	if e := onlyEvent(t, ring); e.Attrs != "error=<nil>" {
		t.Errorf("event attrs = %q, want error=<nil>", e.Attrs)
	}
	if want := "round failed error=<nil>"; line != want {
		t.Errorf("line = %q, want %q", line, want)
	}
	if !strings.Contains(sink.String(), "error=<nil>") {
		t.Errorf("service log = %q, want error=<nil>", sink.String())
	}
}

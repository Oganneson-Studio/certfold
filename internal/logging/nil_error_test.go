package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// pointerError is an error whose Error method panics for a nil receiver, as
// the errors of many packages do. It panics itself instead of reading through
// nil: on windows/amd64, recovering from a hardware nil read can corrupt the
// heap (golang/go#81238), which crashed CI.
type pointerError struct{ text string }

func (e *pointerError) Error() string {
	if e == nil {
		panic("nil *pointerError")
	}
	return e.text
}

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

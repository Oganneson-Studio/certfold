package logging

import (
	"bytes"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// newTestLogger returns a logger that writes to sink through a TextHandler
// and to the returned Ring.
func newTestLogger(sink *bytes.Buffer) (*slog.Logger, *Ring) {
	ring := NewRing()
	return slog.New(NewHandler(slog.NewTextHandler(sink, nil), ring)), ring
}

// onlyEvent returns the one event in ring.
func onlyEvent(t *testing.T, ring *Ring) Event {
	t.Helper()
	events := ring.Since(0)
	if len(events) != 1 {
		t.Fatalf("ring holds %d events, want 1: %+v", len(events), events)
	}
	return events[0]
}

func TestHandlerPassesRecordsToSinkAndRing(t *testing.T) {
	var sink bytes.Buffer
	logger, ring := newTestLogger(&sink)
	before := time.Now()
	logger.Warn("certificate issuance failed", "cert", "api-prod", "failures", 2)

	e := onlyEvent(t, ring)
	if e.Seq != 1 || e.Level != "WARN" || e.Message != "certificate issuance failed" || e.Attrs != "cert=api-prod failures=2" {
		t.Fatalf("event = %+v", e)
	}
	if e.Time.Before(before) || e.Time.After(time.Now()) {
		t.Fatalf("event time %s is not the time of the record", e.Time)
	}
	if !strings.Contains(sink.String(), `level=WARN msg="certificate issuance failed" cert=api-prod failures=2`) {
		t.Fatalf("service log = %q", sink.String())
	}
}

func TestHandlerDropsRecordsBelowInfo(t *testing.T) {
	var sink bytes.Buffer
	ring := NewRing()
	// The sink would take the record.
	debugSink := slog.NewTextHandler(&sink, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.New(NewHandler(debugSink, ring)).Debug("verbose")

	if events := ring.Since(0); len(events) != 0 {
		t.Fatalf("ring holds %+v", events)
	}
	if sink.Len() != 0 {
		t.Fatalf("service log = %q", sink.String())
	}
}

// TestHandlerKeepsRecordsTheSinkDoesNotTake covers a sink with a higher level
// than Info: it gets only the records it is enabled for, and the ring still
// gets all of them.
func TestHandlerKeepsRecordsTheSinkDoesNotTake(t *testing.T) {
	var sink bytes.Buffer
	ring := NewRing()
	warnSink := slog.NewTextHandler(&sink, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.New(NewHandler(warnSink, ring)).Info("client enrolled", "client", "web-1")

	if e := onlyEvent(t, ring); e.Message != "client enrolled" {
		t.Fatalf("event = %+v", e)
	}
	if sink.Len() != 0 {
		t.Fatalf("service log = %q", sink.String())
	}
}

// TestPrivateValuesStayInServiceLog covers Private values given with the
// record, inside a group and through WithAttrs, outside and inside a group.
func TestPrivateValuesStayInServiceLog(t *testing.T) {
	var sink bytes.Buffer
	logger, ring := newTestLogger(&sink)
	logger.With("bound", Private("secret-bound")).
		WithGroup("hook").
		With("argv0", "/usr/sbin/reload", "env", Private("secret-grouped")).
		Warn("on_change failed",
			"cert", "api-prod",
			"output", Private("secret-output\nline 2"),
			slog.Group("run", "stderr", Private("secret-nested")))

	e := onlyEvent(t, ring)
	for _, secret := range []string{"secret-bound", "secret-grouped", "secret-output", "secret-nested"} {
		if strings.Contains(e.Attrs, secret) || strings.Contains(e.Message, secret) {
			t.Errorf("event holds %q: %+v", secret, e)
		}
		if !strings.Contains(sink.String(), secret) {
			t.Errorf("service log lacks %q: %s", secret, sink.String())
		}
	}
	want := `bound="(in service log)" hook.argv0=/usr/sbin/reload hook.env="(in service log)" ` +
		`hook.cert=api-prod hook.output="(in service log)" hook.run.stderr="(in service log)"`
	if e.Attrs != want {
		t.Fatalf("event attrs:\n got %s\nwant %s", e.Attrs, want)
	}
}

// TestEventAttrsFollowTextHandler checks the attributes of events against
// what slog.TextHandler writes for the same records, which also checks that
// WithAttrs and WithGroup nest as slog defines.
func TestEventAttrsFollowTextHandler(t *testing.T) {
	var sink bytes.Buffer
	// The sink writes only the attributes: no time, level or message.
	attrsOnly := &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey || a.Key == slog.MessageKey) {
			return slog.Attr{}
		}
		return a
	}}
	ring := NewRing()
	logger := slog.New(NewHandler(slog.NewTextHandler(&sink, attrsOnly), ring))

	notAfter := time.Date(2026, 12, 27, 10, 0, 0, 0, time.UTC)
	nested := logger.With("component", "lego").WithGroup("acme").With("ca", "le").WithGroup("order")
	nested.Info("certificate issued",
		"cert", "api prod",
		"not_after", notAfter,
		"error", errors.New(`say "hi"`+"\n"),
		"lifetime", 90*24*time.Hour,
		slog.Group("result", "id", 7, "ok", true),
		slog.Group("empty"))
	// A group without attributes is left out.
	nested.Info("no attributes")
	logger.WithGroup("unused").Info("no attributes either")

	lines := strings.Split(strings.TrimSuffix(sink.String(), "\n"), "\n")
	events := ring.Since(0)
	if len(events) != len(lines) {
		t.Fatalf("%d events for %d lines of the service log:\n%s", len(events), len(lines), sink.String())
	}
	for i, e := range events {
		if e.Attrs != lines[i] {
			t.Errorf("event %d attrs:\n got %s\nwant %s", i, e.Attrs, lines[i])
		}
	}
	if want := `component=lego acme.ca=le`; events[1].Attrs != want {
		t.Errorf("attrs = %q, want %q", events[1].Attrs, want)
	}
}

func TestEventMessageReplacesControlCharacters(t *testing.T) {
	var sink bytes.Buffer
	logger, ring := newTestLogger(&sink)
	logger.Info("lego: \x1b[31mretry\x1b[0m\r\nnext\x00\xff line")

	if got, want := onlyEvent(t, ring).Message, "lego:  [31mretry [0m  next \uFFFD line"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}

func TestEventAttrsAreCutAtRuneBoundary(t *testing.T) {
	t.Run("long", func(t *testing.T) {
		var sink bytes.Buffer
		logger, ring := newTestLogger(&sink)
		// The runes start at bytes 3, 6, ... of k=a中中..., so byte 2048 is
		// inside one.
		value := "a" + strings.Repeat("中", 1000)
		logger.Info("long", "k", value)

		attrs := onlyEvent(t, ring).Attrs
		kept, cut := strings.CutSuffix(attrs, "...")
		if !cut || !utf8.ValidString(attrs) || len(kept) > maxAttrsBytes || len(kept) < maxAttrsBytes-2 {
			t.Fatalf("attrs of %d bytes, valid UTF-8 %t: %q", len(attrs), utf8.ValidString(attrs), attrs)
		}
		if !strings.HasPrefix("k="+value, kept) {
			t.Fatalf("attrs %q are not the start of the attributes", attrs)
		}
	})
	t.Run("at the limit", func(t *testing.T) {
		var sink bytes.Buffer
		logger, ring := newTestLogger(&sink)
		value := strings.Repeat("a", maxAttrsBytes-2)
		logger.Info("long", "k", value)

		if got := onlyEvent(t, ring).Attrs; got != "k="+value {
			t.Fatalf("attrs of %d bytes were cut to %d", maxAttrsBytes, len(got))
		}
	})
}

func TestLineHandlerWritesOneLinePerRecord(t *testing.T) {
	type line struct {
		level slog.Level
		text  string
	}
	var lines []line
	logger := slog.New(NewLineHandler(func(level slog.Level, text string) error {
		lines = append(lines, line{level, text})
		return nil
	})).With("component", "lego").WithGroup("hook")

	logger.Warn("on_change failed", "cert", "api-prod", "output", Private("line 1\nline 2"))
	logger.Error("daemon\nfailed")

	want := []line{
		// The line shows the text of Private values.
		{slog.LevelWarn, `on_change failed component=lego hook.cert=api-prod hook.output="line 1\nline 2"`},
		{slog.LevelError, "daemon failed component=lego"},
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("lines:\n got %+v\nwant %+v", lines, want)
	}
}

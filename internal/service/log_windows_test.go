//go:build windows

package service

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Oganneson-Studio/certfold/internal/logging"
)

// fakeEventLog records the events written to it as "<type> <id> <text>".
type fakeEventLog struct{ events []string }

func (l *fakeEventLog) record(kind string, eid uint32, msg string) error {
	l.events = append(l.events, fmt.Sprintf("%s %d %s", kind, eid, msg))
	return nil
}

func (l *fakeEventLog) Info(eid uint32, msg string) error    { return l.record("info", eid, msg) }
func (l *fakeEventLog) Warning(eid uint32, msg string) error { return l.record("warning", eid, msg) }
func (l *fakeEventLog) Error(eid uint32, msg string) error   { return l.record("error", eid, msg) }

func TestWriteEventMapsLevelsToEventTypesAndIDs(t *testing.T) {
	var log fakeEventLog
	logger := slog.New(logging.NewLineHandler(writeEvent(&log)))
	logger.Info("certfolds started", "version", "test")
	logger.Warn("configuration reload rejected", "error", "bad")
	logger.Error("daemon failed", "error", "bad")

	want := []string{
		"info 1 certfolds started version=test",
		"warning 2 configuration reload rejected error=bad",
		"error 3 daemon failed error=bad",
	}
	if strings.Join(log.events, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(log.events, "\n"), strings.Join(want, "\n"))
	}
}

// TestWriteEventWithholdsPrivateValues covers the output of an on_change or
// exec DNS program: any interactive user can read the Application log.
func TestWriteEventWithholdsPrivateValues(t *testing.T) {
	var log fakeEventLog
	slog.New(logging.NewLineHandler(writeEvent(&log))).Warn("on_change failed",
		"cert", "api-prod", "output", logging.Private("secret-output-5c1e"))

	if len(log.events) != 1 || !strings.Contains(log.events[0], "(withheld)") || strings.Contains(log.events[0], "secret-output-5c1e") {
		t.Fatalf("events = %q, want the output withheld", log.events)
	}
}

func TestWriteEventCutsLongLinesAtRuneBoundary(t *testing.T) {
	// "é" takes two bytes and starts at odd offsets, so byte maxEventBytes
	// falls inside one.
	long := "a" + strings.Repeat("é", maxEventBytes)
	exact := strings.Repeat("b", maxEventBytes)
	var log fakeEventLog
	write := writeEvent(&log)
	for _, line := range []string{long, exact} {
		if err := write(slog.LevelInfo, line); err != nil {
			t.Fatal(err)
		}
	}

	got := strings.TrimPrefix(log.events[0], "info 1 ")
	if len(got) > maxEventBytes || len(got) < maxEventBytes-utf8.UTFMax || !utf8.ValidString(got) || !strings.HasPrefix(long, got) {
		t.Fatalf("long line was cut to %d bytes (valid UTF-8: %t), want a prefix of at most %d bytes ending at a rune boundary",
			len(got), utf8.ValidString(got), maxEventBytes)
	}
	if got := strings.TrimPrefix(log.events[1], "info 1 "); got != exact {
		t.Fatalf("line of exactly %d bytes was changed to %d bytes", maxEventBytes, len(got))
	}
}

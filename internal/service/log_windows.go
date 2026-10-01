//go:build windows

package service

import (
	"log/slog"
	"os"
	"unicode/utf8"

	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/Oganneson-Studio/certfold/internal/logging"
)

// maxEventBytes bounds the text of an event: ReportEvent rejects a string of
// more than 31,839 characters.
const maxEventBytes = 31000

// daemonLog returns the service log of a daemon and a function that closes
// it. A daemon started by the service manager has no stderr anyone reads, so
// it writes to the Application event log, under the event source that
// installing its service registered with its name. A daemon run from a
// terminal, or one that cannot open the event log, writes to stderr.
func daemonLog(role Role, interactive bool) (slog.Handler, func()) {
	stderr := slog.NewTextHandler(os.Stderr, nil)
	if interactive {
		return stderr, func() {}
	}
	name, _, _, _ := roleAttrs(role)
	log, err := eventlog.Open(name)
	if err != nil {
		return stderr, func() {}
	}
	return logging.NewLineHandler(writeEvent(log)), func() { _ = log.Close() }
}

// eventWriter is the part of *eventlog.Log that writeEvent uses.
type eventWriter interface {
	Info(eid uint32, msg string) error
	Warning(eid uint32, msg string) error
	Error(eid uint32, msg string) error
}

// writeEvent returns the write function of a logging.NewLineHandler that
// writes each line to log as an event of the level of its record, with event
// ID 1 for INFO, 2 for WARN and 3 for ERROR. A line longer than maxEventBytes
// is cut at a rune boundary.
func writeEvent(log eventWriter) func(slog.Level, string) error {
	return func(level slog.Level, line string) error {
		if len(line) > maxEventBytes {
			cut := maxEventBytes
			for !utf8.RuneStart(line[cut]) {
				cut--
			}
			line = line[:cut]
		}
		switch {
		case level >= slog.LevelError:
			return log.Error(3, line)
		case level >= slog.LevelWarn:
			return log.Warning(2, line)
		default:
			return log.Info(1, line)
		}
	}
}

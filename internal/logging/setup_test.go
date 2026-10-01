package logging

import (
	"bytes"
	"log"
	"log/slog"
	"strings"
	"testing"
)

// setupForTest runs Setup for one test. Restoring the default slog logger
// does not undo what Setup did to the standard log package, so the cleanup
// restores that as well.
func setupForTest(t *testing.T, sink slog.Handler) Logs {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	return Setup(sink)
}

func TestSetupRoutesDefaultAndStandardLoggers(t *testing.T) {
	var buf bytes.Buffer
	sink := slog.NewTextHandler(&buf, nil)
	logs := setupForTest(t, sink)
	if logs.Events == nil || logs.Sink != sink {
		t.Fatalf("Setup returned %+v", logs)
	}

	slog.Info("certfolds started", "version", "test")
	log.Printf("http: TLS handshake error from %s", "192.0.2.1:1234")

	events := logs.Events.Since(0)
	if len(events) != 2 {
		t.Fatalf("ring holds %d events, want 2: %+v", len(events), events)
	}
	if e := events[0]; e.Level != "INFO" || e.Message != "certfolds started" || e.Attrs != "version=test" {
		t.Errorf("event 1 = %+v", e)
	}
	if e := events[1]; e.Level != "INFO" || e.Message != "http: TLS handshake error from 192.0.2.1:1234" || e.Attrs != "" {
		t.Errorf("event 2 = %+v", e)
	}
	for _, want := range []string{`msg="certfolds started" version=test`, `msg="http: TLS handshake error from 192.0.2.1:1234"`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("service log lacks %s: %s", want, buf.String())
		}
	}
}

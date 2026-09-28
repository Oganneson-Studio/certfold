package server

import (
	"log"
	"strings"
	"testing"

	legolog "github.com/go-acme/lego/v4/log"
)

// TestLegoLinesAreRedactedAndCutInEvents covers the error text of a failed
// request of a DNS provider, which lego logs whole: its URL may carry
// credentials in the query, and the body of the answer may be long.
func TestLegoLinesAreRedactedAndCutInEvents(t *testing.T) {
	sink := &lockedBuffer{}
	logs := setupLogs(t, sink)
	previous := legolog.Logger
	legolog.Logger = log.New(legoLog{}, "", 0)
	t.Cleanup(func() { legolog.Logger = previous })

	body := strings.Repeat("b", 5000)
	legolog.Warnf("[api.example.com] acme: cleaning up failed: Get %q: %s", "https://x.example/p?token=x", body)

	events := logs.Events.Since(0)
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one", events)
	}
	e := events[0]
	if e.Level != "WARN" || !strings.HasPrefix(e.Message, `[api.example.com] acme: cleaning up failed: Get "https://x.example/p?REDACTED": bbb`) {
		t.Errorf("event %s %.200s, want the WARN line with the query withheld", e.Level, e.Message)
	}
	if strings.Contains(e.Message, "token=x") || len(e.Message) > 1<<10 {
		t.Errorf("event message holds %d bytes (query withheld: %t), want at most 1 KiB without the query",
			len(e.Message), !strings.Contains(e.Message, "token=x"))
	}
	// The service log keeps the whole line.
	if log := sink.String(); !strings.Contains(log, `https://x.example/p?token=x`) || !strings.Contains(log, body) {
		t.Errorf("service log does not hold the whole line: %.300s", log)
	}
}

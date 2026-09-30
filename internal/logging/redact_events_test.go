package logging

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
)

// logToAll logs one record through a handler with sink and ring, and through
// a NewLineHandler, and returns the line.
func logToAll(sink *bytes.Buffer, ring *Ring, log func(*slog.Logger)) string {
	var line string
	log(slog.New(NewHandler(slog.NewTextHandler(sink, nil), ring)))
	log(slog.New(NewLineHandler(func(_ slog.Level, text string) error {
		line = text
		return nil
	})))
	return line
}

func TestEventsAndLinesWithholdURLQueries(t *testing.T) {
	var sink bytes.Buffer
	ring := NewRing()
	line := logToAll(&sink, ring, func(logger *slog.Logger) {
		logger.Warn(`Get "https://a.example/m?token=m-secret": timeout`,
			"url", "https://a.example/s?token=s-secret",
			"error", errors.New(`Get "https://a.example/e?token=e-secret": timeout`),
			slog.Group("dns", "url", "https://a.example/g?token=g-secret"))
	})

	e := onlyEvent(t, ring)
	wantMessage := `Get "https://a.example/m?REDACTED": timeout`
	wantAttrs := `url=https://a.example/s?REDACTED error="Get \"https://a.example/e?REDACTED\": timeout" dns.url=https://a.example/g?REDACTED`
	if e.Message != wantMessage || e.Attrs != wantAttrs {
		t.Errorf("event = %+v, want message %q and attrs %q", e, wantMessage, wantAttrs)
	}
	if want := wantMessage + " " + wantAttrs; line != want {
		t.Errorf("line = %q, want %q", line, want)
	}
	// The service log keeps the text.
	for _, secret := range []string{"m-secret", "s-secret", "e-secret", "g-secret"} {
		if !strings.Contains(sink.String(), secret) {
			t.Errorf("service log lacks %s: %s", secret, sink.String())
		}
	}
}

// "?REDACTED" is longer than a short query, so the query is withheld before
// the message is cut: the other way round, a message of maxMessageBytes that
// ends with a URL would come out longer.
func TestEventMessagesAreRedactedBeforeTheyAreCut(t *testing.T) {
	url := "https://a.example/x?k"
	msg := strings.Repeat("a", maxMessageBytes-len(url)) + url
	var sink bytes.Buffer
	ring := NewRing()
	line := logToAll(&sink, ring, func(logger *slog.Logger) { logger.Info(msg) })

	// The URL keeps its length, len("https://a.example/x?k"), of which
	// "?REDACTED" fills the last two bytes.
	want := strings.Repeat("a", maxMessageBytes-len(url)) + "https://a.example/x?R"
	for _, got := range []string{onlyEvent(t, ring).Message, line} {
		if got != want {
			t.Errorf("message of %d bytes ends with %q, want %d bytes ending with %q",
				len(got), got[max(0, len(got)-30):], len(want), want[len(want)-30:])
		}
	}
}

func TestEventMessagesAreCutAtRuneBoundary(t *testing.T) {
	// "é" takes two bytes and starts at odd offsets, so byte maxMessageBytes
	// falls inside one.
	long := "a" + strings.Repeat("é", maxMessageBytes)
	var sink bytes.Buffer
	ring := NewRing()
	line := logToAll(&sink, ring, func(logger *slog.Logger) { logger.Info(long) })

	for _, got := range []string{onlyEvent(t, ring).Message, line} {
		if len(got) > maxMessageBytes || len(got) < maxMessageBytes-utf8.UTFMax || !utf8.ValidString(got) || !strings.HasPrefix(long, got) {
			t.Errorf("message was cut to %d bytes (valid UTF-8: %t), want a prefix of at most %d bytes ending at a rune boundary",
				len(got), utf8.ValidString(got), maxMessageBytes)
		}
	}
	if !strings.Contains(sink.String(), long) {
		t.Error("service log cut the message")
	}

	exact := strings.Repeat("b", maxMessageBytes)
	ring = NewRing()
	logToAll(&sink, ring, func(logger *slog.Logger) { logger.Info(exact) })
	if got := onlyEvent(t, ring).Message; got != exact {
		t.Errorf("message of exactly %d bytes was changed to %d bytes", maxMessageBytes, len(got))
	}
}

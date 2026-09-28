package server

import (
	"bytes"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLimitedWriterPassesTenLinesAMinute(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	logger := log.New(&limitedWriter{w: &out, clock: func() time.Time { return now }}, "", 0)
	for i := range 1000 {
		logger.Printf("http: TLS handshake error %d", i)
	}
	if got := strings.Count(out.String(), "\n"); got != maxErrorLinesPerMinute {
		t.Fatalf("passed %d lines, want %d:\n%s", got, maxErrorLinesPerMinute, out.String())
	}

	now = now.Add(time.Minute)
	logger.Printf("http: TLS handshake error %d", 1000)
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if got, want := lines[len(lines)-1], "http: TLS handshake error 1000 (990 earlier lines dropped)"; got != want {
		t.Fatalf("first line of the next minute = %q, want %q", got, want)
	}

	// Reporting the dropped lines resets their count: the next line passed
	// does not repeat it.
	logger.Printf("http: TLS handshake error %d", 1001)
	lines = strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if got, want := lines[len(lines)-1], "http: TLS handshake error 1001"; got != want {
		t.Fatalf("second line of the next minute = %q, want %q", got, want)
	}
}

func TestRunLimitsTheErrorLogOfHTTPS(t *testing.T) {
	sink := &lockedBuffer{}
	logs := setupLogs(t, sink)
	_, listen, _, stop := startRun(t, logs)

	// The server logs the failed handshake before it closes the connection.
	for range maxErrorLinesPerMinute + 5 {
		conn, err := net.Dial("tcp", listen)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("not a TLS handshake\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
		conn.Close()
	}
	stop()

	if got := strings.Count(sink.String(), "http: TLS handshake error"); got != maxErrorLinesPerMinute {
		t.Fatalf("service log holds %d handshake errors, want %d:\n%s", got, maxErrorLinesPerMinute, sink.String())
	}
}

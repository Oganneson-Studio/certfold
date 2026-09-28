package logging

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecovererLogsPanicWithoutStack(t *testing.T) {
	var buf bytes.Buffer
	logs := setupForTest(t, slog.NewTextHandler(&buf, nil))
	h := Recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/install.ps1?token=secret-token", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	e := onlyEvent(t, logs.Events)
	want := `method=GET path=/install.ps1 panic=boom stack=(withheld)`
	if e.Level != "ERROR" || e.Message != "panic serving request" || e.Attrs != want {
		t.Fatalf("event = %+v, want attrs %s", e, want)
	}
	// The stack names the function that panicked.
	if !strings.Contains(buf.String(), "goroutine ") || !strings.Contains(buf.String(), "TestRecovererLogsPanicWithoutStack") {
		t.Fatalf("service log lacks the stack: %s", buf.String())
	}
	if strings.Contains(buf.String(), "secret-token") {
		t.Fatalf("service log holds the query: %s", buf.String())
	}
}

func TestRecovererRepanicsErrAbortHandler(t *testing.T) {
	logs := setupForTest(t, slog.NewTextHandler(io.Discard, nil))
	h := Recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/sync", nil))
	}()
	if recovered != http.ErrAbortHandler {
		t.Fatalf("recovered %v, want http.ErrAbortHandler", recovered)
	}
	if events := logs.Events.Since(0); len(events) != 0 {
		t.Fatalf("ring holds %+v", events)
	}
}

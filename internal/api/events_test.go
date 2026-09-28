package api

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// setupLogs runs logging.Setup with a service log that is discarded, for the
// duration of t. Setup also routes the standard log package through slog,
// which restoring the default logger does not undo, so the cleanup restores
// that as well.
func setupLogs(t *testing.T) logging.Logs {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	return logging.Setup(slog.NewTextHandler(io.Discard, nil))
}

// eventLines returns the events of logs as "LEVEL message attrs".
func eventLines(logs logging.Logs) []string {
	var lines []string
	for _, e := range logs.Events.Since(0) {
		lines = append(lines, strings.TrimSpace(e.Level+" "+e.Message+" "+e.Attrs))
	}
	return lines
}

func TestRouterLogsPanicsAsEvents(t *testing.T) {
	logs := setupLogs(t)
	router := buildRouter(newHandlers(buildDeps(t))).(*chi.Mux)
	router.Get("/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	want := "ERROR panic serving request method=GET path=/panic panic=boom stack=(withheld)"
	if got := eventLines(logs); len(got) != 1 || got[0] != want {
		t.Fatalf("events = %q, want %q", got, want)
	}
}

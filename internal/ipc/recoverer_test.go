package ipc

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Oganneson-Studio/sigil/internal/logging"
)

func TestRouterLogsPanicsAsEvents(t *testing.T) {
	// Setup also routes the standard log package through slog, which
	// restoring the default logger does not undo.
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	logs := logging.Setup(slog.NewTextHandler(io.Discard, nil))

	router := buildIPCRouter(&ipcHandlers{}).(*chi.Mux)
	router.Get("/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	events := logs.Events.Since(0)
	if len(events) != 1 || events[0].Level != "ERROR" || events[0].Message != "panic serving request" ||
		events[0].Attrs != "method=GET path=/panic panic=boom stack=(withheld)" {
		t.Fatalf("events = %+v, want the panic as one ERROR event with the stack withheld", events)
	}
}

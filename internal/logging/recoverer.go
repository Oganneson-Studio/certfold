package logging

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recoverer replaces chi's middleware.Recoverer, which prints the panic and
// its stack to os.Stderr, where a Windows service has none. It logs a panic
// of next as the ERROR event "panic serving request" and answers 500. The
// stack is Private: journald keeps it, the events and the Windows event log
// do not. The path is r.URL.Path, never RequestURI, whose query may hold an
// enrollment token.
//
// A panic with http.ErrAbortHandler is not recovered: net/http aborts the
// response without logging it.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			slog.Error("panic serving request",
				"method", r.Method,
				"path", r.URL.Path,
				"panic", fmt.Sprint(v),
				"stack", Private(debug.Stack()))
			w.WriteHeader(http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

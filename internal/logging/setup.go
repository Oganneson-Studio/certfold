package logging

import "log/slog"

// Logs is the logging of a daemon, as Setup made it.
type Logs struct {
	// Events is the source of GET /ipc/v1/events; nil means the route is
	// not served.
	Events *Ring
	// Sink is the service log alone, for records that must not become
	// events, such as the errors of net/http servers; nil means none is set.
	Sink slog.Handler
}

// Setup makes a logger that writes to sink and to a new Ring the default slog
// logger, and returns both. From then on the standard log package writes
// through it too, at Info.
func Setup(sink slog.Handler) Logs {
	ring := NewRing()
	slog.SetDefault(slog.New(NewHandler(sink, ring)))
	return Logs{Events: ring, Sink: sink}
}

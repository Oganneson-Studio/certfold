package logging

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Private marks a value that goes only to the service log: the sink of
// NewHandler and NewLineHandler show its text, while events show
// "(in service log)" in its place. Use it for the output of on_change and exec
// DNS programs, which may repeat credentials, and for panic stacks.
type Private string

// LogValue returns the text of p.
func (p Private) LogValue() slog.Value { return slog.StringValue(string(p)) }

// withheld stands for a Private value in events.
const withheld = "(in service log)"

// maxAttrsBytes bounds Event.Attrs.
const maxAttrsBytes = 2 << 10

// NewHandler returns a handler that passes every record at Info and above to
// sink unchanged, unless sink is not enabled for its level, and adds it to
// ring with the Private values withheld. Records below Info are dropped.
// Attributes and groups given through WithAttrs and WithGroup reach both.
//
// A Private value is recognized in the attribute as the caller gave it,
// before slog resolves it: the built-in handlers resolve a value before they
// call ReplaceAttr, so a ReplaceAttr function only ever sees its text.
func NewHandler(sink slog.Handler, ring *Ring) slog.Handler {
	return &handler{sink: sink, ring: ring}
}

type handler struct {
	sink slog.Handler
	ring *Ring
	// scope holds the attributes and groups given to this handler, with the
	// Private values already withheld; sink has them as given.
	scope scope
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.sink.Enabled(ctx, r.Level) {
		err = h.sink.Handle(ctx, r)
	}
	h.ring.add(Event{
		Time:    r.Time,
		Level:   r.Level.String(),
		Message: clean(r.Message),
		Attrs:   truncate(render(h.scope.nest(withhold(recordAttrs(r))))),
	})
	return err
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return &handler{
		sink:  h.sink.WithAttrs(attrs),
		ring:  h.ring,
		scope: h.scope.with(groupOrAttrs{attrs: withhold(attrs)}),
	}
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &handler{
		sink:  h.sink.WithGroup(name),
		ring:  h.ring,
		scope: h.scope.with(groupOrAttrs{group: name}),
	}
}

// NewLineHandler returns a handler that renders every record as one line,
// "message key=value ...", without the time and the level and with the text
// of Private values, and passes it to write together with the record's level.
// It serves the Windows event log, which keeps both. The line is rendered as
// events are, except that Private values are shown and it is not cut.
func NewLineHandler(write func(slog.Level, string) error) slog.Handler {
	return &lineHandler{write: write}
}

type lineHandler struct {
	write func(slog.Level, string) error
	scope scope
}

func (h *lineHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *lineHandler) Handle(_ context.Context, r slog.Record) error {
	line := clean(r.Message)
	if attrs := render(h.scope.nest(recordAttrs(r))); attrs != "" {
		line += " " + attrs
	}
	return h.write(r.Level, line)
}

func (h *lineHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return &lineHandler{write: h.write, scope: h.scope.with(groupOrAttrs{attrs: attrs})}
}

func (h *lineHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &lineHandler{write: h.write, scope: h.scope.with(groupOrAttrs{group: name})}
}

// groupOrAttrs is what one call of WithGroup or WithAttrs gave a handler: a
// group name, or attributes.
type groupOrAttrs struct {
	group string
	attrs []slog.Attr
}

// scope lists what WithGroup and WithAttrs gave a handler, oldest first.
type scope []groupOrAttrs

// with returns s followed by goa, without sharing its array with s, which
// other handlers derived from the same one may extend.
func (s scope) with(goa groupOrAttrs) scope {
	return append(slices.Clip(s), goa)
}

// nest returns attrs, the attributes of a record, as a handler without a
// scope must see them: after the attributes of s, and inside its groups.
func (s scope) nest(attrs []slog.Attr) []slog.Attr {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i].group != "" {
			// slog leaves out a group without attributes, and so does
			// the handler render uses.
			attrs = []slog.Attr{{Key: s[i].group, Value: slog.GroupValue(attrs...)}}
		} else {
			attrs = slices.Concat(s[i].attrs, attrs)
		}
	}
	return attrs
}

func recordAttrs(r slog.Record) []slog.Attr {
	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	return attrs
}

// withhold returns attrs with every Private value, in groups too, replaced
// by the withheld placeholder. It must look at the attributes as the caller
// gave them: once slog resolves a Private value, only its text is left.
func withhold(attrs []slog.Attr) []slog.Attr {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		switch a.Value.Kind() {
		case slog.KindLogValuer:
			if _, ok := a.Value.Any().(Private); ok {
				a.Value = slog.StringValue(withheld)
			}
		case slog.KindGroup:
			a.Value = slog.GroupValue(withhold(a.Value.Group())...)
		}
		out[i] = a
	}
	return out
}

// renderOptions make a slog.TextHandler write only the attributes of a record
// without a time: they drop the level and the message it writes for every
// record. Attributes named level or msg outside any group are dropped with
// them, so these two keys are reserved.
var renderOptions = &slog.HandlerOptions{
	ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && (a.Key == slog.LevelKey || a.Key == slog.MessageKey) {
			return slog.Attr{}
		}
		return a
	},
}

// render writes attrs as slog.TextHandler does: key=value separated by
// spaces, a value quoted when it holds spaces, quotes, control characters or
// invalid UTF-8, and the keys in a group written g.k.
func render(attrs []slog.Attr) string {
	var buf bytes.Buffer
	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "", 0)
	r.AddAttrs(attrs...)
	// Writing to a bytes.Buffer does not fail.
	_ = slog.NewTextHandler(&buf, renderOptions).Handle(context.Background(), r)
	return strings.TrimSuffix(buf.String(), "\n")
}

// clean replaces control characters with spaces, so that a message stays on
// one line of a terminal. strings.Map also turns invalid UTF-8 into U+FFFD.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// truncate cuts s to maxAttrsBytes at a rune boundary, and marks the cut with
// "...".
func truncate(s string) string {
	if len(s) <= maxAttrsBytes {
		return s
	}
	cut := maxAttrsBytes
	for !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

package logging

import (
	"sync"
	"time"
)

// Event is one record in a Ring, and the DTO of GET /ipc/v1/events.
type Event struct {
	// Seq increases by one per event from 1, and starts over when the daemon
	// restarts.
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`
	// Level is slog.Level.String(): INFO, WARN or ERROR.
	Level string `json:"level"`
	// Message is the message of the record, with control characters replaced
	// by spaces and invalid UTF-8 replaced by U+FFFD.
	Message string `json:"message"`
	// Attrs holds the attributes as key=value, quoted as slog.TextHandler
	// quotes them, with the keys in a group written g.k. Longer attributes
	// are cut at a rune boundary to at most 2 KiB, followed by "...".
	Attrs string `json:"attrs,omitempty"`
}

// RingSize is the number of events a Ring keeps.
const RingSize = 500

// Ring keeps the last RingSize events of a daemon. It is safe for concurrent
// use.
type Ring struct {
	started time.Time

	mu sync.Mutex
	// events holds the event with Seq s at index (s-1)%RingSize.
	events [RingSize]Event
	seq    uint64 // Seq of the newest event, 0 before the first
}

// NewRing returns an empty Ring created now.
func NewRing() *Ring {
	return &Ring{started: time.Now()}
}

// Started returns when the Ring was created, that is when the daemon started.
// Seq starts over from 1 when the daemon restarts, so a caller that keeps the
// last Seq it has seen must also keep Started: when it changes, the events
// start over, and a Seq the caller has already seen may be a new event.
func (r *Ring) Started() time.Time { return r.started }

// Since returns the events with a Seq greater than after, oldest first. It
// returns an empty slice, not nil, when there are none.
func (r *Ring) Since(after uint64) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Event{}
	kept := min(r.seq, RingSize)
	for i := r.seq - kept; i < r.seq; i++ {
		if e := r.events[i%RingSize]; e.Seq > after {
			out = append(out, e)
		}
	}
	return out
}

// add gives e the next Seq and keeps it. Once the Ring is full, e replaces
// the oldest event.
func (r *Ring) add(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	e.Seq = r.seq
	r.events[(r.seq-1)%RingSize] = e
}

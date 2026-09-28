package logging

import (
	"io"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

// addEvents adds n events to r whose messages are their Seq.
func addEvents(r *Ring, n int) {
	for range n {
		r.add(Event{Message: strconv.FormatUint(r.seq+1, 10)})
	}
}

func seqs(events []Event) []uint64 {
	out := []uint64{}
	for _, e := range events {
		out = append(out, e.Seq)
	}
	return out
}

func TestRingSinceReturnsEventsAfterSeq(t *testing.T) {
	r := NewRing()
	if got := r.Since(0); got == nil || len(got) != 0 {
		t.Fatalf("Since(0) of an empty ring = %#v, want an empty slice", got)
	}
	addEvents(r, 3)
	for _, tc := range []struct {
		after uint64
		want  []uint64
	}{
		{0, []uint64{1, 2, 3}},
		// The event whose Seq equals after has been seen.
		{1, []uint64{2, 3}},
		{2, []uint64{3}},
		{3, []uint64{}},
		{10, []uint64{}},
	} {
		got := r.Since(tc.after)
		if got == nil || !slices.Equal(seqs(got), tc.want) {
			t.Errorf("Since(%d) returned Seq %v, want %v", tc.after, seqs(got), tc.want)
		}
		for _, e := range got {
			if e.Message != strconv.FormatUint(e.Seq, 10) {
				t.Errorf("Since(%d) returned the event %+v under the wrong Seq", tc.after, e)
			}
		}
	}
}

func TestRingReplacesOldestEventsWhenFull(t *testing.T) {
	r := NewRing()
	addEvents(r, RingSize+10)
	got := r.Since(0)
	if len(got) != RingSize {
		t.Fatalf("ring holds %d events, want %d", len(got), RingSize)
	}
	for i, e := range got {
		if want := uint64(11 + i); e.Seq != want || e.Message != strconv.FormatUint(want, 10) {
			t.Fatalf("event %d = %+v, want Seq %d", i, e, want)
		}
	}
	want := []uint64{RingSize + 6, RingSize + 7, RingSize + 8, RingSize + 9, RingSize + 10}
	if got := seqs(r.Since(RingSize + 5)); !slices.Equal(got, want) {
		t.Fatalf("Since(%d) returned Seq %v, want %v", RingSize+5, got, want)
	}
}

func TestRingStartedStaysTheSame(t *testing.T) {
	before := time.Now()
	r := NewRing()
	started := r.Started()
	if started.Before(before) || started.After(time.Now()) {
		t.Fatalf("Started() = %s, want the time NewRing ran", started)
	}
	addEvents(r, RingSize+1)
	if got := r.Started(); !got.Equal(started) {
		t.Fatalf("Started() changed from %s to %s", started, got)
	}
}

// TestRingConcurrentUse logs and reads events at the same time; run it with
// -race.
func TestRingConcurrentUse(t *testing.T) {
	ring := NewRing()
	logger := slog.New(NewHandler(slog.NewTextHandler(io.Discard, nil), ring))
	const writers, perWriter = 4, 200

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 2 {
		readers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				events := ring.Since(0)
				for i := 1; i < len(events); i++ {
					if events[i].Seq != events[i-1].Seq+1 {
						t.Errorf("Since(0) returned Seq %d after %d", events[i].Seq, events[i-1].Seq)
						return
					}
				}
			}
		})
	}
	var logged sync.WaitGroup
	for w := range writers {
		logged.Go(func() {
			for i := range perWriter {
				logger.With("writer", w).Info("event", "i", i)
			}
		})
	}
	logged.Wait()
	close(stop)
	readers.Wait()

	events := ring.Since(0)
	if len(events) != RingSize {
		t.Fatalf("ring holds %d events, want %d", len(events), RingSize)
	}
	if last := events[len(events)-1].Seq; last != writers*perWriter {
		t.Fatalf("the newest event has Seq %d, want %d", last, writers*perWriter)
	}
}

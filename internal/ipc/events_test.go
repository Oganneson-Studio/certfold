package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/Oganneson-Studio/certfold/internal/logging"
)

// logEvents returns a Ring holding the events "event 1" ... "event n".
func logEvents(n int) *logging.Ring {
	ring := logging.NewRing()
	logger := slog.New(logging.NewHandler(slog.NewTextHandler(io.Discard, nil), ring))
	for i := range n {
		logger.Info(fmt.Sprintf("event %d", i+1))
	}
	return ring
}

func eventsServer(t *testing.T, ring *logging.Ring) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(buildIPCRouter(&ipcHandlers{deps: ServerDeps{Events: ring}}))
	t.Cleanup(ts.Close)
	return ts
}

// getEvents sends GET /ipc/v1/events with query and returns the status and
// the body.
func getEvents(t *testing.T, ts *httptest.Server, query string) (int, []byte) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + "/ipc/v1/events" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func messages(events []logging.Event) []string {
	out := []string{}
	for _, e := range events {
		out = append(out, e.Message)
	}
	return out
}

func TestEventsReturnsEventsAfterSeq(t *testing.T) {
	ring := logEvents(3)
	c := newTestClient(eventsServer(t, ring))

	page, err := c.Events(context.Background(), 1)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if got, want := messages(page.Events), []string{"event 2", "event 3"}; !slices.Equal(got, want) {
		t.Fatalf("events = %q, want %q", got, want)
	}
	if page.Events[0].Seq != 2 || page.Events[1].Seq != 3 {
		t.Fatalf("events = %+v, want Seq 2 and 3", page.Events)
	}
	if !page.Started.Equal(ring.Started()) {
		t.Fatalf("started = %s, want %s", page.Started, ring.Started())
	}
}

func TestEventsAfterDefaultsToZero(t *testing.T) {
	ts := eventsServer(t, logEvents(2))
	status, body := getEvents(t, ts, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	var page EventsPage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if got, want := messages(page.Events), []string{"event 1", "event 2"}; !slices.Equal(got, want) {
		t.Fatalf("events = %q, want %q", got, want)
	}
}

func TestEventsRejectsUnparsableAfter(t *testing.T) {
	ts := eventsServer(t, logEvents(1))
	for _, query := range []string{"?after=x", "?after=-1", "?after=1.5", "?after=18446744073709551616"} {
		if status, body := getEvents(t, ts, query); status != http.StatusBadRequest {
			t.Errorf("GET %s: status = %d, want %d; body = %s", query, status, http.StatusBadRequest, body)
		}
	}
}

// TestEventsAnswersEmptyArray covers a daemon without events, and one without
// events after the Seq asked for: both answer [], not null, with started.
func TestEventsAnswersEmptyArray(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ring  *logging.Ring
		query string
	}{
		{"no events", logEvents(0), ""},
		{"none after", logEvents(2), "?after=2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := getEvents(t, eventsServer(t, tc.ring), tc.query)
			if status != http.StatusOK {
				t.Fatalf("status = %d, body = %s", status, body)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["events"]) != "[]" {
				t.Fatalf("events = %s, want []; body = %s", fields["events"], body)
			}
			var started string
			if err := json.Unmarshal(fields["started"], &started); err != nil || started == "" {
				t.Fatalf("body lacks started: %s", body)
			}
		})
	}
}

// TestEventsStartedStaysTheSame covers what callers detect a restart by: two
// answers of the same daemon carry the same started.
func TestEventsStartedStaysTheSame(t *testing.T) {
	ring := logEvents(1)
	c := newTestClient(eventsServer(t, ring))
	first, err := c.Events(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	slog.New(logging.NewHandler(slog.NewTextHandler(io.Discard, nil), ring)).Info("event 2")
	second, err := c.Events(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.Started.IsZero() || !first.Started.Equal(second.Started) || !second.Started.Equal(ring.Started()) {
		t.Fatalf("started = %s, then %s; want %s both times", first.Started, second.Started, ring.Started())
	}
	if got := messages(second.Events); !slices.Equal(got, []string{"event 2"}) {
		t.Fatalf("second answer = %q, want the new event", got)
	}
}

// TestEventsRouteFollowsDeps covers the routers of both daemons: each serves
// the events when it has a Ring, and neither does without one.
func TestEventsRouteFollowsDeps(t *testing.T) {
	daemons := []struct {
		name string
		deps ServerDeps
	}{
		{"certfolds", ServerDeps{
			DB:           mustOpenDB(t),
			Server:       &ServerControlDeps{},
			Certificates: certDeps(testCertConfig()),
			Tokens:       &TokenControlDeps{},
		}},
		{"certfoldc", ServerDeps{Client: &ClientControlDeps{}}},
	}
	for _, daemon := range daemons {
		for _, ring := range []*logging.Ring{logEvents(1), nil} {
			t.Run(fmt.Sprintf("%s with ring %t", daemon.name, ring != nil), func(t *testing.T) {
				deps := daemon.deps
				deps.Events = ring
				ts := httptest.NewServer(buildIPCRouter(&ipcHandlers{deps: deps}))
				defer ts.Close()

				status, body := getEvents(t, ts, "")
				want := http.StatusOK
				if ring == nil {
					want = http.StatusNotFound
				}
				if status != want {
					t.Fatalf("status = %d, want %d; body = %s", status, want, body)
				}
			})
		}
	}
}

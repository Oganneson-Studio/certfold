package ipc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// captureEvents makes the default logger add every record to the returned
// Ring, as the events of the daemon, for the duration of t.
func captureEvents(t *testing.T) *logging.Ring {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		// slog.SetDefault redirected the standard log package as well.
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	ring := logging.NewRing()
	slog.SetDefault(slog.New(logging.NewHandler(slog.NewTextHandler(io.Discard, nil), ring)))
	return ring
}

// TestDeleteMissingClientOrTokenIsNotFound covers removing a client or
// revoking an enrollment token that does not exist, such as a mistyped name:
// the daemon answers 404 with the reason, and logs no removal.
func TestDeleteMissingClientOrTokenIsNotFound(t *testing.T) {
	ts := httptest.NewServer(buildIPCRouter(&ipcHandlers{deps: ServerDeps{DB: mustOpenDB(t)}}))
	defer ts.Close()
	c := newTestClient(ts)
	ring := captureEvents(t)
	missingToken := strings.Repeat("0", 32)

	err := c.DeleteClient(context.Background(), "web-9")
	if want := `server returned 404: client "web-9" is not enrolled`; err == nil || !strings.HasSuffix(err.Error(), want) {
		t.Errorf("DeleteClient error = %v, want it to end in %s", err, want)
	}
	err = c.DeleteToken(context.Background(), missingToken)
	if want := `server returned 404: enrollment token "` + missingToken + `" does not exist`; err == nil || !strings.HasSuffix(err.Error(), want) {
		t.Errorf("DeleteToken error = %v, want it to end in %s", err, want)
	}
	if events := ring.Since(0); len(events) != 0 {
		t.Errorf("events = %+v, want none: nothing was removed", events)
	}
}

// TestDeleteLooksUpWhatWasTyped covers a mistyped name or ID with a '?' or
// '#', which would cut the path short: the daemon looks up exactly what was
// typed and answers 404, and the client or token the cut path would name
// stays.
func TestDeleteLooksUpWhatWasTyped(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	now := time.Now()
	if err := db.Clients.Upsert(ctx, &store.ClientRecord{Name: "web-1", Fingerprint: "sha256:AA", EnrolledAt: now}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Tokens.Upsert(ctx, &store.TokenRecord{
		TokenID:   "tok-1",
		Name:      "web-2",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(buildIPCRouter(&ipcHandlers{deps: ServerDeps{DB: db}}))
	defer ts.Close()
	c := newTestClient(ts)

	for _, typed := range []string{"web-1?", "web-1#", "web-1?x=1"} {
		err := c.DeleteClient(ctx, typed)
		if want := fmt.Sprintf("server returned 404: client %q is not enrolled", typed); err == nil || !strings.HasSuffix(err.Error(), want) {
			t.Errorf("DeleteClient(%q) error = %v, want it to end in %s", typed, err, want)
		}
	}
	for _, typed := range []string{"tok-1?", "tok-1#", "tok-1?x=1"} {
		err := c.DeleteToken(ctx, typed)
		if want := fmt.Sprintf("server returned 404: enrollment token %q does not exist", typed); err == nil || !strings.HasSuffix(err.Error(), want) {
			t.Errorf("DeleteToken(%q) error = %v, want it to end in %s", typed, err, want)
		}
	}
	if _, err := db.Clients.Get(ctx, "web-1", nil); err != nil {
		t.Errorf("web-1 is gone: %v", err)
	}
	if _, err := db.Tokens.Get(ctx, "tok-1", nil); err != nil {
		t.Errorf("tok-1 is gone: %v", err)
	}
}

// TestDeleteClientAndTokenAreLogged covers a removal and a revocation that
// succeed: each is an event, which names the client, or the token by its ID.
func TestDeleteClientAndTokenAreLogged(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	now := time.Now()
	if err := db.Clients.Upsert(ctx, &store.ClientRecord{Name: "web-1", Fingerprint: "sha256:AA", EnrolledAt: now}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Tokens.Upsert(ctx, &store.TokenRecord{
		TokenID:   "tok-1",
		Name:      "web-2",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(buildIPCRouter(&ipcHandlers{deps: ServerDeps{DB: db}}))
	defer ts.Close()
	c := newTestClient(ts)
	ring := captureEvents(t)

	if err := c.DeleteClient(ctx, "web-1"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if err := c.DeleteToken(ctx, "tok-1"); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	if _, err := db.Clients.Get(ctx, "web-1", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Get of the removed client: error = %v, want sql.ErrNoRows", err)
	}
	if _, err := db.Tokens.Get(ctx, "tok-1", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Get of the revoked token: error = %v, want sql.ErrNoRows", err)
	}
	var got []string
	for _, e := range ring.Since(0) {
		got = append(got, e.Level+" "+e.Message+" "+e.Attrs)
	}
	if want := []string{"INFO client removed client=web-1", "INFO enrollment token revoked token=tok-1"}; !slices.Equal(got, want) {
		t.Fatalf("events = %q, want %q", got, want)
	}
}

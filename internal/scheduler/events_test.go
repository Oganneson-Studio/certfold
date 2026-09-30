package scheduler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// captureEvents makes the default logger keep the records of the rest of the
// test in a new Ring, and returns it. slog.SetDefault redirects the standard
// log package as well, so the cleanup restores that too.
func captureEvents(t *testing.T) *logging.Ring {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	return logging.Setup(slog.NewTextHandler(io.Discard, nil)).Events
}

// eventLines renders the events in ring as "LEVEL message attrs", oldest
// first.
func eventLines(ring *logging.Ring) []string {
	var lines []string
	for _, e := range ring.Since(0) {
		lines = append(lines, strings.TrimSpace(e.Level+" "+e.Message+" "+e.Attrs))
	}
	return lines
}

func assertEvents(t *testing.T, ring *logging.Ring, want ...string) {
	t.Helper()
	if got := eventLines(ring); !slices.Equal(got, want) {
		t.Fatalf("events:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// issuedEvent is the event of storing result for api-prod, due for renewal
// at renewAt.
func issuedEvent(result *acme.Result, renewAt time.Time) string {
	return fmt.Sprintf("INFO certificate issued cert=api-prod not_after=%s renew_at=%s fingerprint=%s",
		result.NotAfter.Format("2006-01-02T15:04:05.000Z07:00"), renewAt.Format("2006-01-02T15:04:05.000Z07:00"),
		certificateFingerprint(result.Certificate))
}

// Each issuance is reported when it starts, with the reason, and when it
// ends, with the stored certificate or the failure and its backoff.
func TestIssuanceIsReportedAsEvents(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := start
	r := New(&mockIssuer{}, db, nil, func() time.Time { return clock })
	cfg := minimalCfg("api-prod", nil)
	events := captureEvents(t)

	first := successResult(t, start.Add(90*24*time.Hour))
	r.issuer = &mockIssuer{result: first}
	if err := tickAndWait(ctx, r, cfg); err != nil {
		t.Fatal(err)
	}
	// At its renewal time, 60 days on.
	clock = start.Add(60 * 24 * time.Hour)
	second := successResult(t, clock.Add(90*24*time.Hour))
	r.issuer = &mockIssuer{result: second}
	if err := tickAndWait(ctx, r, cfg); err != nil {
		t.Fatal(err)
	}
	third := successResult(t, clock.Add(91*24*time.Hour))
	r.issuer = &mockIssuer{result: third}
	if err := r.RenewNamed(ctx, static(cfg), "api-prod"); err != nil {
		t.Fatal(err)
	}
	r.issuer = &mockIssuer{err: errors.New("acme failed\x1b[2J")}
	if err := r.RenewNamed(ctx, static(cfg), "api-prod"); err == nil {
		t.Fatal("RenewNamed succeeded although the issuance failed")
	}

	assertEvents(t, events,
		"INFO certificate issuance started cert=api-prod reason=new",
		issuedEvent(first, start.Add(60*24*time.Hour)),
		// Renewals name the certificate they replace in the order.
		"INFO certificate issuance started cert=api-prod reason=ratio",
		issuedEvent(second, clock.Add(60*24*time.Hour))+" replacing=true",
		"INFO certificate issuance started cert=api-prod reason=manual",
		issuedEvent(third, clock.Add(61*24*time.Hour))+" replacing=true",
		"INFO certificate issuance started cert=api-prod reason=manual",
		// The error is sanitized as for last_error.
		`ERROR certificate issuance failed cert=api-prod error="acme failed [2J" failures=1 next_attempt=2025-03-02T00:05:00.000Z`,
	)
}

// A certificate that is due as it arrives is reported as issued, then as a
// failure with its backoff.
func TestCertificateDueOnArrivalIsReportedAsFailure(t *testing.T) {
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	// 90 days long, 10 left: due 20 days ago.
	result := &acme.Result{
		Certificate: certificatePEM(t, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour)),
		PrivateKey:  []byte("---key---"),
		NotAfter:    now.Add(10 * 24 * time.Hour),
	}
	r := New(&mockIssuer{result: result}, db, nil, func() time.Time { return now })
	events := captureEvents(t)

	if err := tickAndWait(context.Background(), r, minimalCfg("api-prod", nil)); err != nil {
		t.Fatal(err)
	}
	assertEvents(t, events,
		"INFO certificate issuance started cert=api-prod reason=new",
		issuedEvent(result, now.Add(-20*24*time.Hour)),
		`ERROR certificate issuance failed cert=api-prod error="issued certificate was stored, but is already due for renewal `+
			`(lifetime 2160h0m0s, renewal due 2024-12-12T00:00:00Z)" failures=1 next_attempt=2025-01-01T00:05:00.000Z`,
	)
}

// A certificate discarded because a reload changed it during issuance is
// reported, and so is a failure whose backoff cannot be stored.
func TestUnstoredOutcomesAreReportedAsEvents(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	t.Run("discarded", func(t *testing.T) {
		ctx := context.Background()
		iss := newGatedIssuer(t, now.Add(90*24*time.Hour))
		r := New(iss, mustOpenDB(t), nil, clock)
		var current atomic.Pointer[config.ServerConfig]
		current.Store(minimalCfg("api-prod", nil))
		events := captureEvents(t)

		renewed := renewAsync(ctx, r, current.Load, "api-prod")
		call := iss.next(t)
		if err := r.PublishConfig(ctx, func() { current.Store(&config.ServerConfig{}) }); err != nil {
			t.Fatal(err)
		}
		call.succeed()
		if err := receive(t, renewed, "RenewNamed"); err == nil {
			t.Fatal("RenewNamed stored a certificate that is no longer configured")
		}
		assertEvents(t, events,
			"INFO certificate issuance started cert=api-prod reason=manual",
			"WARN issued certificate discarded cert=api-prod",
		)
	})

	t.Run("backoff not stored", func(t *testing.T) {
		db := mustOpenDB(t)
		r := New(&mockIssuer{err: errors.New("CA down")}, db, nil, clock)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		events := captureEvents(t)

		if err := r.RenewNamed(context.Background(), static(minimalCfg("api-prod", nil)), "api-prod"); err == nil {
			t.Fatal("RenewNamed succeeded although the issuance failed")
		}
		assertEvents(t, events,
			"INFO certificate issuance started cert=api-prod reason=manual",
			`ERROR certificate issuance failed cert=api-prod error="CA down"`,
			`ERROR record issuance failure failed cert=api-prod error="sql: database is closed"`,
		)
	})
}

// A tick that cannot read the store is reported.
func TestFailedTickIsReportedAsEvent(t *testing.T) {
	db := mustOpenDB(t)
	r := New(&mockIssuer{}, db, nil, nil)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	events := captureEvents(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, static(minimalCfg("api-prod", nil))) }()

	waitFor(t, "the tick is reported", func() bool { return len(events.Since(0)) > 0 })
	cancel()
	if err := receive(t, done, "RunDynamic"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
	assertEvents(t, events, `ERROR renewal tick failed error="list certs: sql: database is closed"`)
}

// A tick that shutdown interrupts is not reported: its store reads fail only
// because shutdown cancelled them.
func TestTickInterruptedByShutdownIsNotReported(t *testing.T) {
	r := New(&mockIssuer{}, mustOpenDB(t), nil, nil)
	events := captureEvents(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := minimalCfg("api-prod", nil)
	// Shutdown starts as the tick reads the configuration, before it reads
	// the store.
	current := func() *config.ServerConfig {
		cancel()
		return cfg
	}
	if err := r.RunDynamic(ctx, current); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
	assertEvents(t, events)
}

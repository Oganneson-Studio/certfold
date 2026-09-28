package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// A stored certificate is renewed when a third of its lifetime is left, or
// half of it for a lifetime under 10 days, and not before.
func TestRenewalFollowsCertificateLifetime(t *testing.T) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		left     time.Duration // NotAfter - renewal time
	}{
		{"6 days", 6 * 24 * time.Hour, 72 * time.Hour},
		{"90 days", 90 * 24 * time.Hour, 30 * 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := mustOpenDB(t)
			notAfter := start.Add(tc.lifetime)
			mi := &mockIssuer{result: &acme.Result{
				Certificate: certificatePEM(t, start, notAfter),
				PrivateKey:  []byte("---key---"),
				NotAfter:    notAfter,
			}}
			clock := start
			r := New(mi, db, nil, func() time.Time { return clock })
			cfg := minimalCfg("api-prod", nil)

			for _, step := range []struct {
				at    time.Time
				calls int
			}{
				{start, 1}, // nothing stored yet
				{start.Add(time.Hour), 1},
				{notAfter.Add(-tc.left - time.Second), 1},
				{notAfter.Add(-tc.left), 2},
			} {
				clock = step.at
				if err := tickAndWait(ctx, r, cfg); err != nil {
					t.Fatal(err)
				}
				if mi.calls != step.calls {
					t.Fatalf("Issue calls at NotAfter-%s = %d, want %d", notAfter.Sub(step.at), mi.calls, step.calls)
				}
			}
		})
	}
}

// The loop wakes at the renewal time of a stored certificate: one that lives
// for 2 seconds is issued again 1 second after it starts.
func TestShortLivedCertificateIsRenewedOnTime(t *testing.T) {
	db := mustOpenDB(t)
	// x509 keeps whole seconds. Starting at the next one keeps the renewal
	// time ahead of the issuance, which would otherwise find the certificate
	// due as it arrives.
	notBefore := time.Now().Truncate(time.Second).Add(time.Second)
	renewAt := notBefore.Add(time.Second)
	called := make(chan struct{}, 1)
	mi := &mockIssuer{
		result: &acme.Result{
			Certificate: certificatePEM(t, notBefore, notBefore.Add(2*time.Second)),
			PrivateKey:  []byte("---key---"),
			NotAfter:    notBefore.Add(2 * time.Second),
		},
		called: called,
	}
	r := New(mi, db, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, static(minimalCfg("api-prod", nil))) }()

	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("no issuance started")
	}
	first := time.Now()
	select {
	case <-called:
		if time.Now().Before(renewAt) {
			t.Fatalf("renewed %s before the renewal time", renewAt.Sub(time.Now()))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("the certificate was not renewed within 3s of its issuance at %s; renewal time %s", first, renewAt)
	}
	cancel()
	if err := receive(t, done, "RunDynamic"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
}

// tickWithin is tickAndWait that fails the test when the issuances the tick
// starts do not end within 5 seconds, as when a call inside the save
// transaction waits for the store's only connection.
func tickWithin(t *testing.T, r *Renewer, cfg *config.ServerConfig) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- tickAndWait(context.Background(), r, cfg) }()
	if err := receive(t, done, "tick"); err != nil {
		t.Fatal(err)
	}
}

// A certificate that is due for renewal as it arrives is stored and handed to
// the clients, but the attempt counts as failed: the next one waits out a
// backoff that doubles while the CA keeps issuing such certificates.
func TestCertificateDueOnArrivalBacksOff(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name        string
		certificate []byte
		wantErr     string
	}{
		// 90 days long, 10 left: due 20 days ago.
		{"due", certificatePEM(t, now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour)),
			"issued certificate was stored, but is already due for renewal (lifetime 2160h0m0s, renewal due 2024-12-12T00:00:00Z)"},
		{"unreadable", []byte("---cert---"),
			"issued certificate was stored, but is already due for renewal: no certificate PEM block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := mustOpenDB(t)
			mi := &mockIssuer{result: &acme.Result{
				Certificate: tc.certificate,
				PrivateKey:  []byte("---key---"),
				NotAfter:    now.Add(10 * 24 * time.Hour),
			}}
			clock := now
			var stored atomic.Int32
			r := New(mi, db, func() { stored.Add(1) }, func() time.Time { return clock })
			cfg := minimalCfg("api-prod", nil)

			for i, delay := range []time.Duration{baseBackoff, 2 * baseBackoff} {
				tickWithin(t, r, cfg)
				if mi.calls != i+1 {
					t.Fatalf("Issue calls = %d, want %d", mi.calls, i+1)
				}
				rec, err := db.Certs.Get(ctx, "api-prod", nil)
				if err != nil {
					t.Fatalf("the certificate was not stored: %v", err)
				}
				if rec.FullchainPEM != string(tc.certificate) || !rec.IssuedAt.Equal(clock) {
					t.Fatalf("stored record = %+v", rec)
				}
				if got := stored.Load(); got != int32(i+1) {
					t.Fatalf("stored calls = %d, want %d", got, i+1)
				}
				assertStatus(t, db, store.IssuanceStatus{
					Name: "api-prod", Failures: i + 1, LastError: tc.wantErr,
					LastAttemptAt: clock, NextAttemptAt: clock.Add(delay),
				})

				// Not issued again until the retry time.
				tickWithin(t, r, cfg)
				if mi.calls != i+1 {
					t.Fatalf("issued again during the backoff; Issue calls = %d", mi.calls)
				}
				clock = clock.Add(delay)
			}
		})
	}
}

// RenewalPlan applies renewal.RenewAt, and has a certificate it cannot read
// renewed at once.
func TestRenewalPlanUsesLifetimeRatio(t *testing.T) {
	r := New(&mockIssuer{}, mustOpenDB(t), nil, nil)
	notBefore := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	for _, tc := range []struct {
		name      string
		fullchain string
		want      time.Time
	}{
		{"readable", string(certificatePEM(t, notBefore, notAfter)), notAfter.Add(-30 * 24 * time.Hour)},
		{"unreadable", "---cert---", time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at, source := r.RenewalPlan(&store.CertRecord{Name: "api-prod", FullchainPEM: tc.fullchain, NotAfter: notAfter})
			if !at.Equal(tc.want) || source != "ratio" {
				t.Fatalf("RenewalPlan = %s, %q; want %s, ratio", at, source, tc.want)
			}
		})
	}
}

// tick asks to be woken at the earliest retry time or renewal time still
// ahead, and never for a certificate it starts or skips as being issued:
// their past renewal times would wake the loop at once, over and over.
func TestTickWakesAtEarliestRenewalOrRetry(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(t, now.Add(90*24*time.Hour))}
	r := New(mi, db, nil, func() time.Time { return now })
	cfg := multiCfg("backoff", "renewing", "due", "issuing")
	stored := func(name string, renewAt time.Time) {
		t.Helper()
		spec, _ := specNamed(cfg, name)
		notAfter := renewAt.Add(30 * 24 * time.Hour)
		if err := db.Certs.Upsert(ctx, &store.CertRecord{
			Name: name, CA: spec.CA, Domains: spec.Domains,
			SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
			FullchainPEM:    string(certificatePEM(t, notAfter.Add(-90*24*time.Hour), notAfter)),
			NotAfter:        notAfter, UpdatedAt: now,
		}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Issuance.Upsert(ctx, &store.IssuanceStatus{
		Name: "backoff", Failures: 1, LastAttemptAt: now.Add(-time.Minute), NextAttemptAt: now.Add(2 * time.Hour),
	}, nil); err != nil {
		t.Fatal(err)
	}
	stored("renewing", now.Add(time.Hour))
	stored("due", now.Add(-time.Hour))
	stored("issuing", now.Add(-2*time.Hour))
	lock := r.lock("issuing")
	lock <- struct{}{}

	wakeAt, err := r.tick(ctx, static(cfg))
	r.wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(time.Hour); !wakeAt.Equal(want) {
		t.Fatalf("wakeAt = %s, want the renewal time %s", wakeAt, want)
	}
	if mi.calls != 1 || mi.cfg != cfg {
		t.Fatalf("Issue calls = %d, want 1 for the due certificate", mi.calls)
	}

	// With only a certificate being issued left, there is nothing to wake for.
	wakeAt, err = r.tick(ctx, static(multiCfg("issuing")))
	r.wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if !wakeAt.IsZero() {
		t.Fatalf("wakeAt = %s, want none", wakeAt)
	}
}

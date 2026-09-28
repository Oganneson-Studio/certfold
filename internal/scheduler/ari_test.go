package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// testClock is a clock that tests set while the renewal info goroutine reads
// it.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(now time.Time) *testClock { return &testClock{now: now} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// ariIssuer issues a new certificate on every Issue call, valid for 90 days
// from the time of its clock, and answers RenewalInfo as its answer function
// does. It records the replacing argument of every Issue call and the
// certificate of every RenewalInfo call.
type ariIssuer struct {
	t     *testing.T
	clock func() time.Time

	mu        sync.Mutex
	answer    func(certPEM []byte) (*acme.RenewalInfo, error)
	replacing [][]byte
	asked     []string
}

func newARIIssuer(t *testing.T, clock func() time.Time) *ariIssuer {
	a := &ariIssuer{t: t, clock: clock}
	a.answerWith(nil, acme.ErrNoRenewalInfo)
	return a
}

func (a *ariIssuer) Issue(_ context.Context, _ *config.ServerConfig, _ config.CertificateSpec, replacing []byte) (*acme.Result, error) {
	a.mu.Lock()
	a.replacing = append(a.replacing, replacing)
	a.mu.Unlock()
	return successResult(a.t, a.clock().Add(90*24*time.Hour)), nil
}

func (a *ariIssuer) RenewalInfo(_ *config.ServerConfig, _ config.CertificateSpec, certPEM []byte) (*acme.RenewalInfo, error) {
	a.mu.Lock()
	a.asked = append(a.asked, string(certPEM))
	answer := a.answer
	a.mu.Unlock()
	return answer(certPEM)
}

func (a *ariIssuer) setAnswer(answer func(certPEM []byte) (*acme.RenewalInfo, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.answer = answer
}

// answerWith has RenewalInfo return a copy of info, or err.
func (a *ariIssuer) answerWith(info *acme.RenewalInfo, err error) {
	a.setAnswer(func([]byte) (*acme.RenewalInfo, error) {
		if err != nil {
			return nil, err
		}
		answer := *info
		return &answer, nil
	})
}

// issued returns the replacing argument of every Issue call so far.
func (a *ariIssuer) issued() [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.replacing)
}

// queries returns the certificate of every RenewalInfo call so far.
func (a *ariIssuer) queries() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.asked)
}

const day = 24 * time.Hour

var ariStart = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func window(start, end time.Time, retryAfter time.Duration) *acme.RenewalInfo {
	return &acme.RenewalInfo{Start: start, End: end, RetryAfter: retryAfter}
}

// storeCert stores a certificate for the named certificate of cfg, issued at
// issuedAt for 90 days: the lifetime ratio has it renewed 60 days after.
func storeCert(t *testing.T, db *store.DB, cfg *config.ServerConfig, name string, issuedAt time.Time) *store.CertRecord {
	t.Helper()
	spec, ok := specNamed(cfg, name)
	if !ok {
		t.Fatalf("no certificate %s", name)
	}
	notAfter := issuedAt.Add(90 * day)
	fullchain := certificatePEM(t, issuedAt, notAfter)
	rec := &store.CertRecord{
		Name: name, CA: spec.CA, Domains: spec.Domains,
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
		FullchainPEM:    string(fullchain), KeyPEM: "---key---",
		NotAfter: notAfter, Fingerprint: certificateFingerprint(fullchain),
		IssuedAt: issuedAt, UpdatedAt: issuedAt,
	}
	if err := db.Certs.Upsert(context.Background(), rec, nil); err != nil {
		t.Fatal(err)
	}
	return rec
}

func mustCert(t *testing.T, db *store.DB, name string) *store.CertRecord {
	t.Helper()
	rec, err := db.Certs.Get(context.Background(), name, nil)
	if err != nil {
		t.Fatalf("certificate %s: %v", name, err)
	}
	return rec
}

// waitForChecks waits until no renewal info query runs.
func waitForChecks(t *testing.T, r *Renewer) {
	t.Helper()
	waitFor(t, "the renewal info queries end", func() bool {
		r.ariMu.Lock()
		defer r.ariMu.Unlock()
		return !r.ariChecking
	})
}

// tickAndCheck runs one tick and waits for the issuances and the renewal info
// queries it starts. It returns when the tick asked to be woken.
func tickAndCheck(t *testing.T, r *Renewer, cfg *config.ServerConfig) time.Time {
	t.Helper()
	wakeAt, err := r.tick(context.Background(), static(cfg))
	if err != nil {
		t.Fatal(err)
	}
	r.wg.Wait()
	waitForChecks(t, r)
	return wakeAt
}

// ariStateOf returns a copy of what r knows of the renewal window of the named
// certificate.
func ariStateOf(t *testing.T, r *Renewer, name string) ariState {
	t.Helper()
	r.ariMu.Lock()
	defer r.ariMu.Unlock()
	st := r.ari[name]
	if st == nil {
		t.Fatalf("no renewal info state for %s", name)
	}
	return *st
}

func assertPlan(t *testing.T, r *Renewer, rec *store.CertRecord, w *acme.RenewalInfo) time.Time {
	t.Helper()
	at, source := r.RenewalPlan(rec)
	if source != "ari" || at.Before(w.Start) || !at.Before(w.End) {
		t.Fatalf("RenewalPlan = %s, %q; want a time in [%s, %s), ari", at, source, w.Start, w.End)
	}
	return at
}

// A stored certificate is asked about as soon as it is stored, and renewed at
// a time within the window the CA sends.
func TestRenewalInfoIsAskedForOnceStored(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	w := window(ariStart.Add(58*day), ariStart.Add(60*day), 6*time.Hour)
	iss.answerWith(w, nil)
	r := New(iss, db, nil, clock.Now)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, static(minimalCfg("api-prod", nil))) }()

	waitFor(t, "the stored certificate is asked about", func() bool { return len(iss.queries()) > 0 })
	waitForChecks(t, r)
	// Before shutdown: cancelling a query of the tick in flight can close the
	// connection, and with it the in-memory database.
	rec := mustCert(t, db, "api-prod")
	if queries := iss.queries(); len(queries) != 1 || queries[0] != rec.FullchainPEM {
		t.Fatalf("asked about %d certificates, want the stored one once", len(queries))
	}
	assertPlan(t, r, rec, w)
	cancel()
	if err := receive(t, done, "RunDynamic"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
}

// A window that has passed has the certificate renewed at once, naming the
// stored certificate as the one it replaces. The guard against passed windows
// spares a certificate stored before the scheduler started, as on a restart.
func TestPassedWindowRenewsAtOnce(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	old := storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
	iss.answerWith(window(ariStart.Add(-2*time.Hour), ariStart.Add(-time.Hour), 0), nil)
	events := captureEvents(t)

	tickAndCheck(t, r, cfg) // asks
	if n := len(iss.issued()); n != 0 {
		t.Fatalf("issued %d times before the CA was asked", n)
	}
	tickAndCheck(t, r, cfg) // renews
	issued := iss.issued()
	if len(issued) != 1 || string(issued[0]) != old.FullchainPEM {
		t.Fatalf("Issue calls replacing %q, want one replacing the stored certificate", issued)
	}
	assertStatus(t, db, store.IssuanceStatus{Name: "api-prod", LastAttemptAt: ariStart})
	lines := eventLines(events)
	if !slices.Contains(lines, "INFO certificate issuance started cert=api-prod reason=ari") {
		t.Fatalf("no issuance with reason ari in the events:\n  %s", strings.Join(lines, "\n  "))
	}
	if !slices.ContainsFunc(lines, func(line string) bool {
		return strings.HasPrefix(line, "INFO certificate issued cert=api-prod") && strings.HasSuffix(line, " replacing=true")
	}) {
		t.Fatalf("no issued certificate replacing another in the events:\n  %s", strings.Join(lines, "\n  "))
	}
}

// The CA is asked again when its Retry-After says, within bounds, and later
// after an error. A CA without renewal info leaves the plan to the lifetime
// ratio.
func TestRenewalInfoIsAskedAgainAsTheCASays(t *testing.T) {
	timeout := &url.Error{Op: "Get", URL: "https://ca.example/renewal-info/x", Err: os.ErrDeadlineExceeded}
	refused := &url.Error{Op: "Get", URL: "https://ca.example/renewal-info/x", Err: errors.New("connection refused")}
	for _, tc := range []struct {
		name       string
		retryAfter time.Duration
		err        error
		want       time.Duration
		wantSource string
	}{
		{"Retry-After 6h", 6 * time.Hour, nil, 6 * time.Hour, "ari"},
		{"Retry-After 30s", 30 * time.Second, nil, time.Minute, "ari"},
		{"Retry-After 3 days", 3 * day, nil, 24 * time.Hour, "ari"},
		{"no Retry-After", 0, nil, 6 * time.Hour, "ari"},
		{"timeout", 0, timeout, time.Hour, "ratio"},
		{"other error", 0, refused, 6 * time.Hour, "ratio"},
		{"no renewal info", 0, fmt.Errorf("renewal info: %w", acme.ErrNoRenewalInfo), 24 * time.Hour, "ratio"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mustOpenDB(t)
			clock := newTestClock(ariStart)
			iss := newARIIssuer(t, clock.Now)
			r := New(iss, db, nil, clock.Now)
			cfg := minimalCfg("api-prod", nil)
			rec := storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
			iss.answerWith(window(ariStart.Add(58*day), ariStart.Add(60*day), tc.retryAfter), tc.err)

			tickAndCheck(t, r, cfg)
			if got := ariStateOf(t, r, "api-prod").nextCheck; !got.Equal(ariStart.Add(tc.want)) {
				t.Fatalf("next query at %s, want %s", got, ariStart.Add(tc.want))
			}
			if _, source := r.RenewalPlan(rec); source != tc.wantSource {
				t.Fatalf("RenewalPlan source = %q, want %q", source, tc.wantSource)
			}
		})
	}
}

// A failed query keeps the window the CA sent last, including a window that
// acme found invalid; a CA that stops offering renewal info leaves the plan to
// the lifetime ratio again.
func TestFailedQueryKeepsTheWindow(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	rec := storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
	w := window(ariStart.Add(58*day), ariStart.Add(60*day), 0)
	iss.answerWith(w, nil)
	tickAndCheck(t, r, cfg)
	pick := assertPlan(t, r, rec, w)

	for _, err := range []error{
		errors.New("invalid renewal window [0001-01-01T00:00:00Z, 0001-01-01T00:00:00Z)"),
		&url.Error{Op: "Get", URL: "https://ca.example/renewal-info/x", Err: os.ErrDeadlineExceeded},
	} {
		clock.Set(clock.Now().Add(ariMaxInterval))
		iss.answerWith(nil, err)
		tickAndCheck(t, r, cfg)
		if at, source := r.RenewalPlan(rec); source != "ari" || !at.Equal(pick) {
			t.Fatalf("after %q: RenewalPlan = %s, %q; want %s, ari", err, at, source, pick)
		}
	}
	clock.Set(clock.Now().Add(ariMaxInterval))
	iss.answerWith(nil, acme.ErrNoRenewalInfo)
	tickAndCheck(t, r, cfg)
	if _, source := r.RenewalPlan(rec); source != "ratio" {
		t.Fatalf("RenewalPlan source = %q without renewal info, want ratio", source)
	}
	if n := len(iss.queries()); n != 4 {
		t.Fatalf("asked %d times, want 4", n)
	}
}

// The renewal time drawn from a window stays while the CA sends the same
// window, and is drawn again when the window changes.
func TestRenewalTimeIsDrawnOncePerWindow(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	rec := storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
	w := window(ariStart.Add(30*day), ariStart.Add(60*day), 0)
	iss.answerWith(w, nil)
	tickAndCheck(t, r, cfg)
	pick := assertPlan(t, r, rec, w)

	for range 3 {
		clock.Set(clock.Now().Add(ariDefaultInterval))
		tickAndCheck(t, r, cfg)
		if at := assertPlan(t, r, rec, w); !at.Equal(pick) {
			t.Fatalf("renewal time %s drawn again for the same window; was %s", at, pick)
		}
	}
	moved := window(ariStart.Add(40*day), ariStart.Add(41*day), 0)
	iss.answerWith(moved, nil)
	clock.Set(clock.Now().Add(ariDefaultInterval))
	tickAndCheck(t, r, cfg)
	assertPlan(t, r, rec, moved)
	if n := len(iss.queries()); n != 5 {
		t.Fatalf("asked %d times, want 5", n)
	}
}

// An expired certificate is not asked about (RFC 9773, section 4.3); a
// certificate waiting out a backoff is.
func TestExpiredCertificateIsNotAsked(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	iss.answerWith(window(ariStart.Add(58*day), ariStart.Add(60*day), 0), nil)
	r := New(iss, db, nil, clock.Now)
	cfg := multiCfg("expired", "valid")
	storeCert(t, db, cfg, "expired", ariStart.Add(-91*day))
	valid := storeCert(t, db, cfg, "valid", ariStart.Add(-10*day))
	// Both wait out a backoff, which keeps the expired one from being renewed.
	for _, name := range []string{"expired", "valid"} {
		if err := db.Issuance.Upsert(ctx, &store.IssuanceStatus{
			Name: name, Failures: 1, LastError: "CA down",
			LastAttemptAt: ariStart.Add(-time.Minute), NextAttemptAt: ariStart.Add(time.Hour),
		}, nil); err != nil {
			t.Fatal(err)
		}
	}

	tickAndCheck(t, r, cfg)
	if queries := iss.queries(); len(queries) != 1 || queries[0] != valid.FullchainPEM {
		t.Fatalf("asked about %d certificates, want only the valid one", len(queries))
	}
	if n := len(iss.issued()); n != 0 {
		t.Fatalf("issued %d times during the backoff", n)
	}
}

// A newly stored certificate is asked about afresh, and a late answer about
// the certificate it replaced is dropped.
func TestNewCertificateIsAskedAboutAfresh(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	old := storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
	asked, release := make(chan struct{}, 1), make(chan struct{})
	iss.setAnswer(func([]byte) (*acme.RenewalInfo, error) {
		asked <- struct{}{}
		<-release
		// It would have the certificate renewed at once.
		return window(ariStart.Add(-2*time.Hour), ariStart.Add(-time.Hour), 0), nil
	})
	if _, err := r.tick(ctx, static(cfg)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("the stored certificate was not asked about")
	}

	// A manual renewal stores a new certificate meanwhile, which the next
	// tick follows.
	if err := r.RenewNamed(ctx, static(cfg), "api-prod"); err != nil {
		t.Fatal(err)
	}
	renewed := mustCert(t, db, "api-prod")
	if _, err := r.tick(ctx, static(cfg)); err != nil {
		t.Fatal(err)
	}
	fresh := window(ariStart.Add(58*day), ariStart.Add(60*day), 0)
	iss.answerWith(fresh, nil)
	close(release)
	waitForChecks(t, r)
	if at, source := r.RenewalPlan(renewed); source != "ratio" {
		t.Fatalf("RenewalPlan = %s, %q: the answer about the replaced certificate was applied to the new one", at, source)
	}

	tickAndCheck(t, r, cfg)
	assertPlan(t, r, renewed, fresh)
	if queries := iss.queries(); len(queries) != 2 || queries[0] != old.FullchainPEM || queries[1] != renewed.FullchainPEM {
		t.Fatalf("asked about %d certificates, want the old one, then the new one", len(queries))
	}
	if n := len(iss.issued()); n != 1 {
		t.Fatalf("issued %d times, want only the manual renewal", n)
	}
}

// A query holds no lock: while the CA is slow to answer, renewal plans, the
// IPC listing of certificates, reloads and issuances all go on.
func TestRenewalInfoQueryHoldsNoLock(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	var current atomic.Pointer[config.ServerConfig]
	current.Store(minimalCfg("api-prod", nil))
	rec := storeCert(t, db, current.Load(), "api-prod", ariStart.Add(-10*day))
	asked, release := make(chan struct{}, 1), make(chan struct{})
	iss.setAnswer(func([]byte) (*acme.RenewalInfo, error) {
		asked <- struct{}{}
		<-release
		return nil, errors.New("CA too slow")
	})
	if _, err := r.tick(ctx, current.Load); err != nil {
		t.Fatal(err)
	}
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("the stored certificate was not asked about")
	}
	t.Cleanup(func() {
		close(release)
		waitForChecks(t, r)
	})

	promptly := func(what string, f func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- f() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s waited for the renewal info query", what)
		}
	}
	promptly("RenewalPlan", func() error {
		r.RenewalPlan(rec)
		return nil
	})
	srv := ipc.NewServer(ipc.ServerDeps{DB: db, Certificates: &ipc.CertificateControlDeps{
		Current: current.Load, Issuing: r.Issuing, RenewalPlan: r.RenewalPlan,
	}})
	promptly("listing certificates over IPC", func() error {
		resp := httptest.NewRecorder()
		srv.Handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/ipc/v1/certs", nil))
		if resp.Code != http.StatusOK {
			return fmt.Errorf("status %d: %s", resp.Code, resp.Body)
		}
		return nil
	})
	promptly("PublishConfig", func() error {
		return r.PublishConfig(ctx, func() { current.Store(minimalCfg("api-prod", []string{"web-1"})) })
	})
	promptly("RenewNamed", func() error { return r.RenewNamed(ctx, current.Load, "api-prod") })
}

// The IPC listing of certificates shows the renewal time drawn from the
// window, with "ari" as its source.
func TestIPCListsTheRenewalTimeOfTheWindow(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	rec := storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
	w := window(ariStart.Add(58*day), ariStart.Add(60*day), 0)
	iss.answerWith(w, nil)
	tickAndCheck(t, r, cfg)
	pick := assertPlan(t, r, rec, w)

	srv := ipc.NewServer(ipc.ServerDeps{DB: db, Certificates: &ipc.CertificateControlDeps{
		Current: static(cfg), Issuing: r.Issuing, RenewalPlan: r.RenewalPlan,
	}})
	resp := httptest.NewRecorder()
	srv.Handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/ipc/v1/certs", nil))
	var infos []ipc.CertificateInfo
	if err := json.Unmarshal(resp.Body.Bytes(), &infos); err != nil {
		t.Fatalf("status %d, body %s: %v", resp.Code, resp.Body, err)
	}
	if len(infos) != 1 || infos[0].RenewSource != "ari" || !infos[0].RenewAt.Equal(pick) {
		t.Fatalf("listed %+v, want renew_at %s from ari", infos, pick)
	}
}

// One goroutine asks about the certificates, one after the other: a tick
// while it runs starts no other.
func TestRenewalInfoIsAskedOneCertificateAtATime(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := multiCfg("first", "second")
	first := storeCert(t, db, cfg, "first", ariStart.Add(-10*day))
	second := storeCert(t, db, cfg, "second", ariStart.Add(-10*day))
	entered, proceed := make(chan string, 2), make(chan struct{})
	var mu sync.Mutex
	active, peak := 0, 0
	iss.setAnswer(func(certPEM []byte) (*acme.RenewalInfo, error) {
		mu.Lock()
		active++
		peak = max(peak, active)
		mu.Unlock()
		entered <- string(certPEM)
		<-proceed
		mu.Lock()
		active--
		mu.Unlock()
		return window(ariStart.Add(58*day), ariStart.Add(60*day), 0), nil
	})
	next := func() string {
		t.Helper()
		select {
		case certPEM := <-entered:
			return certPEM
		case <-time.After(5 * time.Second):
			t.Fatal("no certificate was asked about")
			return ""
		}
	}

	if _, err := r.tick(ctx, static(cfg)); err != nil {
		t.Fatal(err)
	}
	if next() != first.FullchainPEM {
		t.Fatal("the first certificate was not asked about first")
	}
	if _, err := r.tick(ctx, static(cfg)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
		t.Fatal("two certificates were asked about at once")
	case <-time.After(100 * time.Millisecond):
	}
	proceed <- struct{}{}
	if next() != second.FullchainPEM {
		t.Fatal("the second certificate was not asked about next")
	}
	proceed <- struct{}{}
	waitForChecks(t, r)
	mu.Lock()
	defer mu.Unlock()
	if peak != 1 || len(iss.queries()) != 2 {
		t.Fatalf("%d queries, up to %d at once; want 2, one at a time", len(iss.queries()), peak)
	}
}

// A reload has every certificate asked about again at once.
func TestReloadAsksForRenewalInfoAgain(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
	iss.answerWith(window(ariStart.Add(58*day), ariStart.Add(60*day), 6*time.Hour), nil)

	tickAndCheck(t, r, cfg)
	tickAndCheck(t, r, cfg)
	if n := len(iss.queries()); n != 1 {
		t.Fatalf("asked %d times before the Retry-After, want 1", n)
	}
	if err := r.PublishConfig(context.Background(), func() {}); err != nil {
		t.Fatal(err)
	}
	tickAndCheck(t, r, cfg)
	if n := len(iss.queries()); n != 2 {
		t.Fatalf("asked %d times after the reload, want 2", n)
	}
}

// Only the renewal of a certificate whose latest attempt did not fail names
// the certificate it replaces; issuing for a changed specification does not.
func TestRenewalNamesTheReplacedCertificate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failures int  // of the latest attempt; -1 for none stored
		changed  bool // the domains changed since the certificate was stored
		manual   bool
		want     bool
	}{
		{"renewal", -1, false, false, true},
		{"renewal after a success", 0, false, false, true},
		{"renewal after a failure", 1, false, false, false},
		{"changed specification", -1, true, false, false},
		{"manual renewal", 0, false, true, true},
		{"manual renewal after a failure", 1, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := mustOpenDB(t)
			clock := newTestClock(ariStart)
			iss := newARIIssuer(t, clock.Now)
			r := New(iss, db, nil, clock.Now)
			cfg := minimalCfg("api-prod", nil)
			// Due by the lifetime ratio.
			old := storeCert(t, db, cfg, "api-prod", ariStart.Add(-70*day))
			if tc.failures >= 0 {
				if err := db.Issuance.Upsert(ctx, &store.IssuanceStatus{
					Name: "api-prod", Failures: tc.failures, LastAttemptAt: ariStart.Add(-time.Hour),
					NextAttemptAt: ariStart.Add(-time.Minute),
				}, nil); err != nil {
					t.Fatal(err)
				}
			}
			if tc.changed {
				cfg = minimalCfg("api-prod", nil)
				cfg.Certificates[0].Domains = []string{"new.example.com"}
			}

			if tc.manual {
				if err := r.RenewNamed(ctx, static(cfg), "api-prod"); err != nil {
					t.Fatal(err)
				}
			} else {
				tickAndCheck(t, r, cfg)
			}
			issued := iss.issued()
			if len(issued) != 1 {
				t.Fatalf("issued %d times, want once", len(issued))
			}
			if replaces := string(issued[0]) == old.FullchainPEM; replaces != tc.want || !replaces && issued[0] != nil {
				t.Fatalf("Issue replacing %q, want the stored certificate: %v", issued[0], tc.want)
			}
		})
	}
}

// The loop wakes at the renewal time drawn from the window, or earlier when
// the CA is to be asked again first.
func TestTickWakesForRenewalInfo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		retryAfter time.Duration
		want       time.Duration
	}{
		{"renewal time first", 6 * time.Hour, 2 * time.Hour},
		{"next query first", time.Hour, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mustOpenDB(t)
			clock := newTestClock(ariStart)
			iss := newARIIssuer(t, clock.Now)
			r := New(iss, db, nil, clock.Now)
			cfg := minimalCfg("api-prod", nil)
			storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
			// One nanosecond long: its renewal time is its start.
			iss.answerWith(window(ariStart.Add(2*time.Hour), ariStart.Add(2*time.Hour+1), tc.retryAfter), nil)

			tickAndCheck(t, r, cfg)
			if wakeAt := tickAndCheck(t, r, cfg); !wakeAt.Equal(ariStart.Add(tc.want)) {
				t.Fatalf("wakeAt = %s, want %s", wakeAt, ariStart.Add(tc.want))
			}
		})
	}
}

// Each window, each distinct error and a CA without renewal info are
// reported once, however often the CA is asked. Errors are reported as
// last_error would store them.
func TestRenewalInfoEventsAreNotRepeated(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
	events := captureEvents(t)
	w := window(ariStart.Add(58*day), ariStart.Add(60*day), 0)
	w.ExplanationURL = "https://ca.example/incident"
	down := errors.New("GET https://ca.example/renewal-info/x?token=secret: 503\x1b[2J")
	for _, answer := range []struct {
		info *acme.RenewalInfo
		err  error
	}{
		{w, nil}, {w, nil},
		{nil, down}, {nil, down},
		{nil, errors.New("CA answered 500")},
		{nil, acme.ErrNoRenewalInfo}, {nil, acme.ErrNoRenewalInfo},
		{w, nil},
	} {
		iss.answerWith(answer.info, answer.err)
		tickAndCheck(t, r, cfg)
		clock.Set(clock.Now().Add(ariMaxInterval))
	}

	var got []string
	for _, e := range events.Since(0) {
		got = append(got, e.Level+" "+e.Message)
		// The events withhold URL queries themselves, and would show the
		// control character escaped.
		if e.Message == "renewal info query failed" && strings.Contains(e.Attrs, "503") &&
			!strings.Contains(e.Attrs, `error="GET https://ca.example/renewal-info/x?REDACTED 503 [2J"`) {
			t.Errorf("error not sanitized as last_error: %s", e.Attrs)
		}
		if e.Message == "renewal window updated" && !strings.Contains(e.Attrs, "explanation_url=https://ca.example/incident") {
			t.Errorf("window event without its explanation: %s", e.Attrs)
		}
	}
	want := []string{
		"INFO renewal window updated",
		"WARN renewal info query failed",
		"WARN renewal info query failed",
		"INFO CA offers no renewal info",
		"INFO renewal window updated",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("events:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// The first window of a certificate this process issued that has already
// passed fails the issuance: the certificate is renewed after a backoff, not
// at once, and without naming the certificate it replaces.
func TestPassedWindowOfNewCertificateBacksOff(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	iss.answerWith(window(ariStart.Add(-2*time.Hour), ariStart.Add(-time.Hour), 0), nil)
	events := captureEvents(t)

	tickAndCheck(t, r, cfg) // issues
	tickAndCheck(t, r, cfg) // asks
	tickAndCheck(t, r, cfg)
	if n := len(iss.issued()); n != 1 {
		t.Fatalf("issued %d times, want once", n)
	}
	assertStatus(t, db, store.IssuanceStatus{
		Name: "api-prod", Failures: 1, LastError: errWindowPassed.Error(),
		LastAttemptAt: ariStart, NextAttemptAt: ariStart.Add(baseBackoff),
	})
	if at, source := r.RenewalPlan(mustCert(t, db, "api-prod")); source != "ari" || !at.Equal(ariStart.Add(baseBackoff)) {
		t.Fatalf("RenewalPlan = %s, %q; want the retry time, ari", at, source)
	}
	if !slices.Contains(eventLines(events), fmt.Sprintf(`WARN renewal info query failed cert=api-prod error="%s" next_check=%s`,
		errWindowPassed, ariStart.Add(ariDefaultInterval).Format("2006-01-02T15:04:05.000Z07:00"))) {
		t.Fatalf("the guard is not in the events:\n  %s", strings.Join(eventLines(events), "\n  "))
	}

	clock.Set(ariStart.Add(baseBackoff))
	tickAndCheck(t, r, cfg)
	if issued := iss.issued(); len(issued) != 2 || issued[1] != nil {
		t.Fatalf("Issue calls replacing %q, want a second one replacing nothing", issued)
	}
}

// The backoff doubles while the CA keeps sending passed windows for the
// certificates it issues, though storing each one clears the stored failures;
// a window ahead resets it.
func TestPassedWindowBackoffDoubles(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	iss.answerWith(window(ariStart.Add(-2*time.Hour), ariStart.Add(-time.Hour), 0), nil)

	tickAndCheck(t, r, cfg) // issues
	for failures := 1; failures <= 2; failures++ {
		issuedAt := clock.Now()
		tickAndCheck(t, r, cfg) // asks
		next := issuedAt.Add(retryDelay(failures))
		assertStatus(t, db, store.IssuanceStatus{
			Name: "api-prod", Failures: failures, LastError: errWindowPassed.Error(),
			LastAttemptAt: issuedAt, NextAttemptAt: next,
		})
		clock.Set(next)
		tickAndCheck(t, r, cfg) // renews
		if n := len(iss.issued()); n != failures+1 {
			t.Fatalf("issued %d times, want %d", n, failures+1)
		}
	}

	ahead := window(ariStart.Add(58*day), ariStart.Add(60*day), 0)
	iss.answerWith(ahead, nil)
	tickAndCheck(t, r, cfg)
	assertPlan(t, r, mustCert(t, db, "api-prod"), ahead)
	r.ariMu.Lock()
	trips := r.ariTrips["api-prod"]
	r.ariMu.Unlock()
	if trips != 0 {
		t.Fatalf("%d passed windows still counted after a window ahead", trips)
	}
}

// A certificate issued other than as the CA directed, here by a manual
// renewal, starts the count of passed windows afresh.
func TestManualRenewalResetsPassedWindowCount(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	iss.answerWith(window(ariStart.Add(-2*time.Hour), ariStart.Add(-time.Hour), 0), nil)

	tickAndCheck(t, r, cfg) // issues
	tickAndCheck(t, r, cfg) // asks
	if st := mustStatus(t, db, "api-prod"); st.Failures != 1 {
		t.Fatalf("issuance status = %+v, want one failure", st)
	}
	if err := r.RenewNamed(context.Background(), static(cfg), "api-prod"); err != nil {
		t.Fatal(err)
	}
	tickAndCheck(t, r, cfg) // asks about the new certificate
	if st := mustStatus(t, db, "api-prod"); st.Failures != 1 || !st.NextAttemptAt.Equal(ariStart.Add(baseBackoff)) {
		t.Fatalf("issuance status = %+v, want one failure backing off %s", st, baseBackoff)
	}
}

// The end of the queries wakes the loop, which renews a certificate whose
// window has passed at once, rather than at its next hourly tick.
func TestAnswerWakesTheLoop(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	storeCert(t, db, cfg, "api-prod", ariStart.Add(-10*day))
	iss.answerWith(window(ariStart.Add(-2*time.Hour), ariStart.Add(-time.Hour), 0), nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, static(cfg)) }()

	waitFor(t, "the certificate is renewed", func() bool { return len(iss.issued()) > 0 })
	cancel()
	if err := receive(t, done, "RunDynamic"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
}

// A certificate issued within the second the scheduler started counts as
// issued by it, although the store keeps whole seconds.
func TestGuardCoversCertificatesIssuedAsTheSchedulerStarts(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart.Add(500 * time.Millisecond))
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	iss.answerWith(window(ariStart.Add(-2*time.Hour), ariStart.Add(-time.Hour), 0), nil)

	tickAndCheck(t, r, cfg) // issues
	tickAndCheck(t, r, cfg) // asks
	tickAndCheck(t, r, cfg)
	if n := len(iss.issued()); n != 1 {
		t.Fatalf("issued %d times, want once", n)
	}
	if st := mustStatus(t, db, "api-prod"); st.Failures != 1 {
		t.Fatalf("issuance status = %+v, want one failure", st)
	}
}

// Between recording a passed window and storing its backoff, a tick reads no
// backoff yet: the renewal time recorded with the window holds the renewal
// back all the same.
func TestPassedWindowHoldsRenewalBeforeTheBackoffIsStored(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := minimalCfg("api-prod", nil)
	tickAndCheck(t, r, cfg) // issues
	rec := mustCert(t, db, "api-prod")
	iss.answerWith(window(ariStart.Add(-2*time.Hour), ariStart.Add(-time.Hour), 0), nil)

	// Storing the backoff waits for genMu.
	r.genMu.Lock()
	locked := true
	t.Cleanup(func() {
		if locked {
			r.genMu.Unlock()
		}
		r.wg.Wait()
	})
	if _, err := r.tick(ctx, static(cfg)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the window is recorded", func() bool {
		_, source := r.RenewalPlan(rec)
		return source == "ari"
	})
	if _, err := r.tick(ctx, static(cfg)); err != nil {
		t.Fatal(err)
	}
	if r.Issuing("api-prod") {
		t.Fatal("renewed at once, before the backoff was stored")
	}
	r.genMu.Unlock()
	locked = false
	waitForChecks(t, r)
	assertStatus(t, db, store.IssuanceStatus{
		Name: "api-prod", Failures: 1, LastError: errWindowPassed.Error(),
		LastAttemptAt: ariStart, NextAttemptAt: ariStart.Add(baseBackoff),
	})
}

// A reload between the tick and storing the backoff of a passed window
// cleared the backoffs of that generation: the backoff is not stored under
// the new one, where it would delay an issuance the reload calls for.
func TestPassedWindowBackoffIsNotStoredAcrossAReload(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	var current atomic.Pointer[config.ServerConfig]
	current.Store(minimalCfg("api-prod", nil))
	if _, err := r.tick(ctx, current.Load); err != nil { // issues
		t.Fatal(err)
	}
	r.wg.Wait()
	rec := mustCert(t, db, "api-prod")
	iss.answerWith(window(ariStart.Add(-2*time.Hour), ariStart.Add(-time.Hour), 0), nil)

	// Hold the guard before it stores the backoff, and publish meanwhile as
	// PublishConfig does.
	r.genMu.Lock()
	locked := true
	t.Cleanup(func() {
		if locked {
			r.genMu.Unlock()
		}
	})
	if _, err := r.tick(ctx, current.Load); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the window is recorded", func() bool {
		_, source := r.RenewalPlan(rec)
		return source == "ari"
	})
	current.Store(minimalCfg("api-prod", []string{"web-1"}))
	r.genMu.Unlock()
	locked = false
	waitForChecks(t, r)
	assertStatus(t, db, store.IssuanceStatus{Name: "api-prod", LastAttemptAt: ariStart})
}

// Shutdown does not wait for a query, which lego cannot interrupt, and no
// other certificate is asked about afterwards.
func TestShutdownDoesNotWaitForRenewalInfo(t *testing.T) {
	db := mustOpenDB(t)
	clock := newTestClock(ariStart)
	iss := newARIIssuer(t, clock.Now)
	r := New(iss, db, nil, clock.Now)
	cfg := multiCfg("first", "second")
	storeCert(t, db, cfg, "first", ariStart.Add(-10*day))
	storeCert(t, db, cfg, "second", ariStart.Add(-10*day))
	asked, release := make(chan struct{}, 2), make(chan struct{})
	iss.setAnswer(func([]byte) (*acme.RenewalInfo, error) {
		asked <- struct{}{}
		<-release
		return nil, errors.New("CA too slow")
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, static(cfg)) }()
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("no certificate was asked about")
	}

	cancel()
	err := receive(t, done, "RunDynamic")
	close(release)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
	waitForChecks(t, r)
	if n := len(iss.queries()); n != 1 {
		t.Fatalf("asked %d times, want no query after shutdown", n)
	}
}

package client

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// captureEvents makes the default logger, for the duration of t, add every
// record to the returned Ring, as the events of sigilc, and write it to the
// returned buffer through a slog.TextHandler, as the service log on Linux.
// The buffer is not safe for concurrent use: read it only once nothing logs.
func captureEvents(t *testing.T) (*logging.Ring, *bytes.Buffer) {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		// slog.SetDefault redirected the standard log package as well.
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	var sink bytes.Buffer
	ring := logging.NewRing()
	slog.SetDefault(slog.New(logging.NewHandler(slog.NewTextHandler(&sink, nil), ring)))
	return ring, &sink
}

// eventLines returns the events in ring, each as "LEVEL message attrs".
func eventLines(ring *logging.Ring) []string {
	lines := []string{}
	for _, e := range ring.Since(0) {
		lines = append(lines, strings.TrimSpace(e.Level+" "+e.Message+" "+e.Attrs))
	}
	return lines
}

// updatedEvent returns the event line of bundle stored with a new
// fingerprint. slog.TextHandler writes times as RFC 3339 with milliseconds.
func updatedEvent(t *testing.T, bundle *proto.CertBundle) string {
	t.Helper()
	return fmt.Sprintf("INFO certificate updated cert=%s fingerprint=%s not_after=%s",
		bundle.Name, bundle.Fingerprint, bundleNotAfter(t, bundle).Format("2006-01-02T15:04:05.000Z07:00"))
}

// TestRunHookWithholdsOutputFromEvents covers a failed run of an on_change
// program: its event names the certificate and the exit status, and holds
// only a placeholder for the output, which the service log holds in full.
func TestRunHookWithholdsOutputFromEvents(t *testing.T) {
	ring, logs := captureEvents(t)

	if err := runHook(context.Background(), "api-prod", hookArgv(t, "fail", "--token="+argvSecret)); err == nil {
		t.Fatal("runHook succeeded, want the program's failure")
	}
	events := ring.Since(0)
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one", events)
	}
	e := events[0]
	if e.Level != "WARN" || e.Message != "on_change failed" || !strings.HasPrefix(e.Attrs, `cert=api-prod error="exit status 3" `) {
		t.Fatalf("event = %+v, want the failure of the program of api-prod", e)
	}
	if !strings.Contains(e.Attrs, "(withheld)") {
		t.Errorf("event attrs %q do not withhold the output", e.Attrs)
	}
	for _, secret := range []string{outputSecret, argvSecret} {
		if strings.Contains(e.Attrs, secret) {
			t.Errorf("event attrs %q hold %q", e.Attrs, secret)
		}
	}
	if !strings.Contains(logs.String(), outputSecret) {
		t.Errorf("service log does not hold the output: %q", logs.String())
	}
}

// TestFetchLogsCertificateChanges covers the events of fetches: the
// certificates stored with a new fingerprint, the outputs rewritten for them
// and the on_change programs that succeed, then a certificate that leaves
// the view. A fetch that changes nothing logs nothing.
func TestFetchLogsCertificateChanges(t *testing.T) {
	a, b := newTestBundle(t, "a"), newTestBundle(t, "b")
	fs := newFakeServer(a, b)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	// b has neither outputs nor an on_change program.
	fullchainOutput(cfg, t.TempDir(), "a", "/usr/sbin/reload")
	c := newTestClient(t, cfg)
	c.hook = (&fakeHook{}).run
	ring, _ := captureEvents(t)
	fetch := func() {
		t.Helper()
		if err := c.Fetch(context.Background(), ""); err != nil {
			t.Fatalf("Fetch: %v", err)
		}
	}

	fetch()
	want := []string{
		updatedEvent(t, a),
		updatedEvent(t, b),
		"INFO outputs rewritten cert=a",
		"INFO on_change succeeded cert=a",
	}
	if got := eventLines(ring); !slices.Equal(got, want) {
		t.Fatalf("events of the first fetch:\n got %q\nwant %q", got, want)
	}

	fetch()
	if got := eventLines(ring); !slices.Equal(got, want) {
		t.Fatalf("a fetch without changes logged %q", got[len(want):])
	}

	renewed := newTestBundle(t, "a")
	fs.setView(renewed)
	fetch()
	want = append(want,
		updatedEvent(t, renewed),
		"INFO certificate no longer delivered cert=b",
		"INFO outputs rewritten cert=a",
		"INFO on_change succeeded cert=a",
	)
	if got := eventLines(ring); !slices.Equal(got, want) {
		t.Fatalf("events after a was renewed and b left the view:\n got %q\nwant %q", got, want)
	}
}

// TestFetchLogsOnlyChangedCertificates covers a view in which one
// certificate is renewed and another stays as it was: only the renewed one is
// logged.
func TestFetchLogsOnlyChangedCertificates(t *testing.T) {
	a, b := newTestBundle(t, "a"), newTestBundle(t, "b")
	fs := newFakeServer(a, b)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	c := newTestClient(t, buildTestCfg(t, ts.URL))
	ring, _ := captureEvents(t)
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	before := len(eventLines(ring))

	renewed := newTestBundle(t, "a")
	fs.setView(renewed, b)
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got, want := eventLines(ring)[before:], []string{updatedEvent(t, renewed)}; !slices.Equal(got, want) {
		t.Fatalf("events after a was renewed:\n got %q\nwant %q", got, want)
	}
}

// TestStoreChangesAreLoggedOnceWritten covers a renewal the store cannot be
// written for: nothing is logged, since the store keeps the old certificate,
// and the renewal is logged once, by the fetch that writes it.
func TestStoreChangesAreLoggedOnceWritten(t *testing.T) {
	a := newTestBundle(t, "a")
	fs := newFakeServer(a)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	c := newTestClient(t, cfg)
	ring, _ := captureEvents(t)
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// A directory where certs.json belongs fails every write of the store.
	storePath := filepath.Join(cfg.Client.DataDir, storeFileName)
	if err := os.Remove(storePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(storePath, 0o700); err != nil {
		t.Fatal(err)
	}
	updatedEvents := func(lines []string) []string {
		var out []string
		for _, line := range lines {
			if strings.Contains(line, " certificate updated ") {
				out = append(out, line)
			}
		}
		return out
	}
	before := len(eventLines(ring))

	renewed := newTestBundle(t, "a")
	fs.setView(renewed)
	if err := c.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "save store") {
		t.Fatalf("Fetch error = %v, want the failed write of the store", err)
	}
	if got := updatedEvents(eventLines(ring)[before:]); len(got) != 0 {
		t.Fatalf("logged %q although the store was not written", got)
	}

	if err := os.Remove(storePath); err != nil {
		t.Fatal(err)
	}
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch after the repair: %v", err)
	}
	if got, want := updatedEvents(eventLines(ring)[before:]), []string{updatedEvent(t, renewed)}; !slices.Equal(got, want) {
		t.Fatalf("updates logged:\n got %q\nwant %q", got, want)
	}
}

// TestFailedProgramIsNotLoggedAsSucceeded covers an on_change program that
// fails: the reconcile logs no "on_change succeeded" for it.
func TestFailedProgramIsNotLoggedAsSucceeded(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	cfg := buildTestCfg(t, "https://sigil.example.test")
	fullchainOutput(cfg, t.TempDir(), "api-prod", "/usr/sbin/reload")
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)
	c.hook = func(_ context.Context, certName string, _ []string) error {
		return fmt.Errorf("on_change of certificate %s: exit status 1", certName)
	}
	ring, _ := captureEvents(t)

	c.pullMu.Lock()
	err := c.reconcileLocked()
	c.pullMu.Unlock()
	if err == nil {
		t.Fatal("reconcile succeeded, want the failure of the program")
	}
	if got, want := eventLines(ring), []string{"INFO outputs rewritten cert=api-prod"}; !slices.Equal(got, want) {
		t.Fatalf("events:\n got %q\nwant %q", got, want)
	}
}

// TestRejectedReloadIsNotLogged covers a reload that changes a setting only a
// restart applies: Reload fails, and logs nothing.
func TestRejectedReloadIsNotLogged(t *testing.T) {
	cfg := buildTestCfg(t, "https://sigil.example.test")
	c := newTestClient(t, cfg)
	ring, _ := captureEvents(t)

	updated := *cfg
	updated.Client.IPCSocket = filepath.Join(t.TempDir(), "other.sock")
	if err := c.Reload(loaded(&updated)); err == nil || !strings.Contains(err.Error(), "client.ipc_socket") {
		t.Fatalf("Reload error = %v, want client.ipc_socket to require a restart", err)
	}
	if got := eventLines(ring); len(got) != 0 {
		t.Fatalf("events = %q, want none for a rejected reload", got)
	}
}

// TestMetadataRepairIsNotLoggedAsRewrite covers an output whose content
// matches but whose mode was changed. A reconcile restores the mode in place
// on Unix, and does not compare modes on Windows; either way it rewrites no
// output, so it logs no "outputs rewritten" and runs no on_change program.
func TestMetadataRepairIsNotLoggedAsRewrite(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	cfg := buildTestCfg(t, "https://sigil.example.test")
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod", "/usr/sbin/reload")
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)
	c.hook = (&fakeHook{}).run
	ring, _ := captureEvents(t)
	reconcile := func() {
		t.Helper()
		c.pullMu.Lock()
		err := c.reconcileLocked()
		c.pullMu.Unlock()
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}

	// The output is missing, so the first reconcile writes it.
	reconcile()
	want := []string{"INFO outputs rewritten cert=api-prod", "INFO on_change succeeded cert=api-prod"}
	if got := eventLines(ring); !slices.Equal(got, want) {
		t.Fatalf("events of the first reconcile:\n got %q\nwant %q", got, want)
	}
	if err := os.Chmod(outPath, 0o444); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if got := eventLines(ring); !slices.Equal(got, want) {
		t.Fatalf("the reconcile after the mode changed logged %q", got[len(want):])
	}
}

// TestLastErrorIsLoggedWhenItChanges covers the events of the last error,
// which reloads, IPC fetches and the rounds of the loop all set: an error is
// logged once for as long as it repeats, another error again, and the
// recovery once.
func TestLastErrorIsLoggedWhenItChanges(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	fs := newFakeServer(bundle)
	var unavailable atomic.Bool
	fs.syncStatus = func(string) int {
		if unavailable.Load() {
			return http.StatusServiceUnavailable
		}
		return 0
	}
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)
	ring, _ := captureEvents(t)
	roundEvents := func() []string {
		var out []string
		for _, line := range eventLines(ring) {
			if strings.Contains(line, " round ") {
				out = append(out, line)
			}
		}
		return out
	}

	// A file where the key's directory belongs fails that output, in the
	// reconcile of the reload and in those of the fetches after it.
	blocker := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	updated := *cfg
	updated.Certificates = map[string]config.CertificateOutputs{"api-prod": {
		Outputs: []config.OutputSpec{{Format: "pem-key", Path: filepath.Join(blocker, "api.key")}},
	}}
	if err := c.Reload(loaded(&updated)); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	failure := c.Status().LastError
	if !strings.Contains(failure, "outputs of certificate api-prod") {
		t.Fatalf("last error = %q, want the failed output", failure)
	}
	for range 2 {
		if err := c.Fetch(context.Background(), ""); err == nil || err.Error() != failure {
			t.Fatalf("Fetch error = %v, want %q again", err, failure)
		}
	}
	if got := roundEvents(); len(got) != 1 || !strings.HasPrefix(got[0], "WARN round failed error=") ||
		!strings.Contains(got[0], "outputs of certificate api-prod") {
		t.Fatalf("round events = %q, want one failure for the reload and the fetches that repeat it", got)
	}

	unavailable.Store(true)
	if err := c.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("Fetch error = %v, want the 503 as well", err)
	}
	if got := roundEvents(); len(got) != 2 || !strings.HasPrefix(got[1], "WARN round failed error=") ||
		!strings.Contains(got[1], "503") {
		t.Fatalf("round events = %q, want another failure for the other error", got)
	}

	unavailable.Store(false)
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.Fetch(context.Background(), ""); err != nil {
			t.Fatalf("Fetch after the repair: %v", err)
		}
	}
	if got := roundEvents(); len(got) != 3 || got[2] != "INFO round succeeded again" {
		t.Fatalf("round events = %q, want one recovery after the failures", got)
	}
}

// TestReloadDuringOutageKeepsLastError covers a reload while the server is
// unreachable. Its reconcile succeeds, but does not reach the server, so the
// last error of the fetch before it stays, and the reload logs no recovery.
// The fetch that reaches the server again logs it, once.
func TestReloadDuringOutageKeepsLastError(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	fs := newFakeServer(bundle)
	var down atomic.Bool
	down.Store(true)
	fs.syncStatus = func(string) int {
		if down.Load() {
			return http.StatusServiceUnavailable
		}
		return 0
	}
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)
	ring, _ := captureEvents(t)

	failure := "sync: server returned 503"
	if err := c.Fetch(context.Background(), ""); err == nil || err.Error() != failure {
		t.Fatalf("Fetch error = %v, want %q", err, failure)
	}
	updated := *cfg
	if err := c.Reload(loaded(&updated)); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := c.Status().LastError; got != failure {
		t.Fatalf("last error after the reload = %q, want %q, which the reload cannot tell is gone", got, failure)
	}
	if err := c.Fetch(context.Background(), ""); err == nil || err.Error() != failure {
		t.Fatalf("Fetch error = %v, want %q again", err, failure)
	}
	down.Store(false)
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch once the server is back: %v", err)
	}
	want := []string{
		`WARN round failed error="` + failure + `"`,
		"INFO configuration reloaded",
		"INFO round succeeded again",
	}
	if got := eventLines(ring); !slices.Equal(got, want) {
		t.Fatalf("events:\n got %q\nwant %q", got, want)
	}
}

// TestReloadIsLogged covers the events of a reload that configures an output
// with an on_change program: the reload, then the output its reconcile
// writes and the program it runs.
func TestReloadIsLogged(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	cfg := buildTestCfg(t, "https://sigil.example.test")
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)
	c.hook = (&fakeHook{}).run
	ring, _ := captureEvents(t)

	updated := *cfg
	updated.Certificates = map[string]config.CertificateOutputs{}
	fullchainOutput(&updated, t.TempDir(), "api-prod", "/usr/sbin/reload")
	if err := c.Reload(loaded(&updated)); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	want := []string{
		"INFO configuration reloaded",
		"INFO outputs rewritten cert=api-prod",
		"INFO on_change succeeded cert=api-prod",
	}
	if got := eventLines(ring); !slices.Equal(got, want) {
		t.Fatalf("events:\n got %q\nwant %q", got, want)
	}
}

// TestCorruptStoreIsLogged covers a certs.json that is not valid JSON: New
// starts with an empty store, and logs the path and the error.
func TestCorruptStoreIsLogged(t *testing.T) {
	cfg := buildTestCfg(t, "https://sigil.example.test")
	if err := os.WriteFile(filepath.Join(cfg.Client.DataDir, storeFileName), []byte(`{"certs":`), 0o600); err != nil {
		t.Fatal(err)
	}
	ring, _ := captureEvents(t)

	newTestClient(t, cfg)
	events := ring.Since(0)
	if len(events) != 1 || events[0].Level != "WARN" || events[0].Message != "certificate store is not valid; starting empty" {
		t.Fatalf("events = %+v, want the invalid store", events)
	}
	if attrs := events[0].Attrs; !strings.HasPrefix(attrs, "path=") || !strings.Contains(attrs, storeFileName) ||
		!strings.Contains(attrs, " error=") {
		t.Fatalf("event attrs = %q, want the path and the error", attrs)
	}
}

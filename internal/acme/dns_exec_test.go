package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/logging"
)

// The test binary doubles as the program of an exec provider: when
// testHookEnv names a mode, TestMain runs that hook instead of the tests.
const (
	testHookEnv    = "CERTFOLD_TEST_DNS_HOOK"
	testHookDirEnv = "CERTFOLD_TEST_DNS_HOOK_DIR"

	// Sentinels that an exec provider error must never contain.
	argvSecret   = "argv-secret-7f3a"
	outputSecret = "output-secret-91c2"

	// floodBytes is how much the "flood" mode prints.
	floodBytes = 128 << 20
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(testHookEnv); mode != "" {
		os.Exit(runTestHook(mode))
	}
	os.Exit(m.Run())
}

// runTestHook acts as the program of an exec provider and returns its exit
// code.
func runTestHook(mode string) int {
	switch mode {
	case "record":
		// One file per run, so concurrent runs cannot interleave.
		f, err := os.CreateTemp(os.Getenv(testHookDirEnv), "run-*.json")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := json.NewEncoder(f).Encode(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := f.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "fail":
		fmt.Println(outputSecret)
		fmt.Fprintln(os.Stderr, outputSecret)
		return 3
	case "sleep":
		time.Sleep(20 * time.Second)
		return 0
	case "flood":
		// Print floodBytes, far more than is logged, then fail.
		chunk := []byte(strings.Repeat("x", 1<<20))
		for written := 0; written < floodBytes; written += len(chunk) {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return 2
			}
		}
		return 1
	case "spawn":
		// Start a child, whose output is not this program's, then sleep.
		exe, err := os.Executable()
		if err != nil {
			return 1
		}
		child := exec.Command(exe)
		child.Env = append(os.Environ(), testHookEnv+"=child")
		if err := child.Start(); err != nil {
			return 1
		}
		time.Sleep(20 * time.Second)
		return 0
	case "child":
		// Write the time to the heartbeat file until the stop file appears,
		// for at most 20 seconds.
		dir := os.Getenv(testHookDirEnv)
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
				break
			}
			_ = os.WriteFile(filepath.Join(dir, "heartbeat"), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600)
		}
		return 0
	case "orphan":
		// Exit at once, leaving a process that holds this one's output open.
		exe, err := os.Executable()
		if err != nil {
			return 1
		}
		child := exec.Command(exe)
		child.Env = append(os.Environ(), testHookEnv+"=hold")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			return 1
		}
		return 0
	case "hold":
		// Keep the inherited output open until its reader closes it, which
		// makes the next write fail, or for at most 20 seconds.
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if _, err := os.Stdout.Write([]byte(".")); err != nil {
				return 0
			}
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown hook mode %q\n", mode)
	return 2
}

// hookProvider returns an exec provider that runs the test binary in hook
// mode with args.
func hookProvider(t *testing.T, mode string, args ...string) *execProvider {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(testHookEnv, mode)
	// Otherwise lego resolves CNAMEs of the challenge record with real DNS
	// queries before every run.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	// Spare capacity makes a run that appends to argv in place overwrite
	// what a concurrent run appended.
	argv := make([]string, 0, 16)
	argv = append(argv, exe)
	return &execProvider{ctx: context.Background(), argv: append(argv, args...)}
}

// setHookBounds overrides the bounds on one run for the duration of t.
func setHookBounds(t *testing.T, timeout, waitDelay time.Duration) {
	t.Helper()
	oldTimeout, oldWaitDelay := dnsHookTimeout, dnsHookWaitDelay
	dnsHookTimeout, dnsHookWaitDelay = timeout, waitDelay
	t.Cleanup(func() { dnsHookTimeout, dnsHookWaitDelay = oldTimeout, oldWaitDelay })
}

// captureLog runs logging.Setup with a service log in the returned buffer for
// the duration of t, and returns the events too. Setup also routes the
// standard log package through slog, which restoring the default logger does
// not undo, so the cleanup restores that as well.
func captureLog(t *testing.T) (*bytes.Buffer, *logging.Ring) {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	var buf bytes.Buffer
	return &buf, logging.Setup(slog.NewTextHandler(&buf, nil)).Events
}

// txtValue is the TXT record content for keyAuth, computed independently of
// lego: base64url(sha256(keyAuth)) without padding.
func txtValue(keyAuth string) string {
	sum := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// recordedRuns returns the arguments of every "record" run in dir, each
// formatted with %q, sorted.
func recordedRuns(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "run-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	runs := make([]string, 0, len(files))
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var args []string
		if err := json.Unmarshal(raw, &args); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		runs = append(runs, fmt.Sprintf("%q", args))
	}
	slices.Sort(runs)
	return runs
}

func TestBuildDNSProviderExec(t *testing.T) {
	provider, err := buildDNSProvider(context.Background(), config.DNSProvider{
		Type:    "exec",
		Command: []string{"/usr/local/bin/dns-hook", "--zone", "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := provider.(*execProvider)
	if !ok {
		t.Fatalf("provider = %T, want *execProvider", provider)
	}
	if !slices.Equal(p.argv, []string{"/usr/local/bin/dns-hook", "--zone", "example.com"}) {
		t.Fatalf("argv = %q", p.argv)
	}
	if _, ok := provider.(interface{ Sequential() time.Duration }); ok {
		t.Fatal("exec provider is sequential: lego would wait between the domains of a certificate")
	}
}

func TestExecProviderPassesActionRecordAndValue(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(testHookDirEnv, dir)
	p := hookProvider(t, "record", "--zone", "two words")
	const keyAuth = "token.thumbprint"

	if err := p.Present("www.example.com", "token", keyAuth); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := p.CleanUp("www.example.com", "token", keyAuth); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	record := "_acme-challenge.www.example.com."
	want := []string{
		fmt.Sprintf("%q", []string{"--zone", "two words", "present", record, txtValue(keyAuth)}),
		fmt.Sprintf("%q", []string{"--zone", "two words", "cleanup", record, txtValue(keyAuth)}),
	}
	slices.Sort(want)
	if got := recordedRuns(t, dir); !slices.Equal(got, want) {
		t.Fatalf("runs:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestExecProviderErrorOmitsArgumentsAndOutput(t *testing.T) {
	logs, events := captureLog(t)
	p := hookProvider(t, "fail", "--token="+argvSecret)

	err := p.Present("example.com", "token", "token.thumbprint")
	if err == nil {
		t.Fatal("Present succeeded, want the program's failure")
	}
	msg := err.Error()
	for _, want := range []string{"present", "_acme-challenge.example.com.", "exit status 3"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
	for _, secret := range []string{argvSecret, outputSecret} {
		if strings.Contains(msg, secret) {
			t.Errorf("error %q leaks %q", msg, secret)
		}
	}
	// The output goes to the service log instead, where the operator can see
	// why the program failed; the arguments do not.
	if !strings.Contains(logs.String(), outputSecret) {
		t.Errorf("service log does not contain the program output: %q", logs.String())
	}
	if strings.Contains(logs.String(), argvSecret) {
		t.Errorf("service log leaks the arguments: %q", logs.String())
	}
	// The event says the program failed but withholds its output.
	got := events.Since(0)
	if len(got) != 1 || got[0].Level != "WARN" || got[0].Message != "exec DNS provider failed" ||
		!strings.Contains(got[0].Attrs, "action=present record=_acme-challenge.example.com.") ||
		!strings.Contains(got[0].Attrs, "output=(withheld)") {
		t.Fatalf("events = %+v, want one WARN exec DNS provider failed with the output withheld", got)
	}
	for _, secret := range []string{argvSecret, outputSecret} {
		if strings.Contains(got[0].Message+got[0].Attrs, secret) {
			t.Errorf("event %+v leaks %q", got[0], secret)
		}
	}
}

func TestExecProviderKillsProgramAfterTimeout(t *testing.T) {
	setHookBounds(t, 100*time.Millisecond, dnsHookWaitDelay)
	captureLog(t)
	p := hookProvider(t, "sleep")

	start := time.Now()
	err := p.Present("example.com", "token", "token.thumbprint")
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Present returned after %v, want about the 100ms timeout", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "timed out after 100ms") {
		t.Fatalf("Present error = %v, want a timeout", err)
	}
}

// TestExecProviderKillsTheProcessesItsProgramStarted covers certfolds giving up
// on an issuance at shutdown: the ctx the provider was built with ends, and
// its running program is killed, not waited for, along with the processes it
// started. Programs are often interpreters, such as /bin/sh or
// powershell.exe, whose children, such as a curl without --max-time, do the
// work; one left running could set the record after lego has cleaned it up.
// A timeout reaches the same kill.
func TestExecProviderKillsTheProcessesItsProgramStarted(t *testing.T) {
	captureLog(t)
	dir := t.TempDir()
	t.Setenv(testHookDirEnv, dir)
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600)
		time.Sleep(200 * time.Millisecond) // let a surviving child see it and exit
	})
	heartbeat := func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "heartbeat"))
		return string(data)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider, err := buildDNSProvider(ctx, config.DNSProvider{Type: "exec", Command: hookProvider(t, "spawn").argv})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		// Once the program's child runs, or after 10 seconds.
		for deadline := time.Now().Add(10 * time.Second); heartbeat() == "" && time.Now().Before(deadline); {
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
	}()

	start := time.Now()
	err = provider.Present("example.com", "token", "token.thumbprint")
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("Present returned after %v, want it soon after ctx ended", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("Present error = %v, want the cancellation", err)
	}
	if heartbeat() == "" {
		t.Fatal("the program's child never ran")
	}
	time.Sleep(300 * time.Millisecond)
	before := heartbeat()
	time.Sleep(300 * time.Millisecond)
	if heartbeat() != before {
		t.Fatal("a process the exec program started is still running after the program was killed")
	}
}

// TestExecProviderFailsWhenOutputIsHeldOpen covers a program that exits 0 but
// leaves a process holding its output: Present returns soon after, and,
// unlike on_change, fails, since that process may yet change the record.
func TestExecProviderFailsWhenOutputIsHeldOpen(t *testing.T) {
	setHookBounds(t, dnsHookTimeout, 100*time.Millisecond)
	captureLog(t)
	p := hookProvider(t, "orphan", "--token="+argvSecret)

	start := time.Now()
	err := p.Present("example.com", "token", "token.thumbprint")
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Present returned after %v, want it soon after the program exited", elapsed)
	}
	if err == nil {
		t.Fatal("Present succeeded, want a failure: a process the program started held its output open")
	}
	want := "exec: present _acme-challenge.example.com.: exit status 0, but a process it started still holds its output"
	if msg := err.Error(); msg != want {
		t.Fatalf("Present error = %q, want %q", msg, want)
	}
}

// TestExecProviderBoundsOutputMemory covers a program that prints without
// end: only the end of its output is logged, so only that may be kept. Up to
// four issuances run at once, each for up to the 2-minute timeout.
func TestExecProviderBoundsOutputMemory(t *testing.T) {
	logs, _ := captureLog(t)
	p := hookProvider(t, "flood")

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := p.Present("example.com", "token", "token.thumbprint")
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("Present error = %v, want the program's exit status 1", err)
	}
	// Holding the whole output allocates at least floodBytes; keeping its
	// end, little more than the buffers that copy it.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > floodBytes/4 {
		t.Fatalf("Present allocated %d MiB for %d MiB of output, want the output bounded",
			allocated>>20, floodBytes>>20)
	}
	if !strings.Contains(logs.String(), "xxxx") {
		t.Errorf("service log does not hold the end of the output: %.200q", logs.String())
	}
}

func TestExecProviderRunsConcurrently(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(testHookDirEnv, dir)
	p := hookProvider(t, "record", "--zone", "example.com")

	const n = 8
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, n)
		want  = make([]string, 0, n)
	)
	for i := range n {
		domain := fmt.Sprintf("host%d.example.com", i)
		keyAuth := fmt.Sprintf("token%d.thumbprint", i)
		want = append(want, fmt.Sprintf("%q", []string{
			"--zone", "example.com", "present", "_acme-challenge." + domain + ".", txtValue(keyAuth),
		}))
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = p.Present(domain, "token", keyAuth)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Present %d: %v", i, err)
		}
	}
	slices.Sort(want)
	if got := recordedRuns(t, dir); !slices.Equal(got, want) {
		t.Fatalf("runs:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

package acme

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// The test binary doubles as the program of an exec provider: when
// testHookEnv names a mode, TestMain runs that hook instead of the tests.
const (
	testHookEnv    = "SIGIL_TEST_DNS_HOOK"
	testHookDirEnv = "SIGIL_TEST_DNS_HOOK_DIR"

	// Sentinels that an exec provider error must never contain.
	argvSecret   = "argv-secret-7f3a"
	outputSecret = "output-secret-91c2"
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
	return &execProvider{argv: append(argv, args...)}
}

// setHookBounds overrides the bounds on one run for the duration of t.
func setHookBounds(t *testing.T, timeout, waitDelay time.Duration) {
	t.Helper()
	oldTimeout, oldWaitDelay := dnsHookTimeout, dnsHookWaitDelay
	dnsHookTimeout, dnsHookWaitDelay = timeout, waitDelay
	t.Cleanup(func() { dnsHookTimeout, dnsHookWaitDelay = oldTimeout, oldWaitDelay })
}

// captureLog redirects the standard logger for the duration of t.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return &buf
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
	provider, err := buildDNSProvider(config.DNSProvider{
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
	logs := captureLog(t)
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
	// The output goes to the log instead, where the operator can see why the
	// program failed; the arguments do not.
	if !strings.Contains(logs.String(), outputSecret) {
		t.Errorf("log does not contain the program output: %q", logs.String())
	}
	if strings.Contains(logs.String(), argvSecret) {
		t.Errorf("log leaks the arguments: %q", logs.String())
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

func TestExecProviderDoesNotWaitForOutputHeldByOrphans(t *testing.T) {
	setHookBounds(t, dnsHookTimeout, 100*time.Millisecond)
	captureLog(t)
	p := hookProvider(t, "orphan")

	// The program exits at once but leaves a process holding its output.
	// Whether that counts as a failure does not matter here; returning soon
	// after the program exits does.
	start := time.Now()
	_ = p.Present("example.com", "token", "token.thumbprint")
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Present returned after %v, want it soon after the program exited", elapsed)
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

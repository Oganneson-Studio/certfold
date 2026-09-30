package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as an on_change program: when testHookEnv names a
// mode, TestMain runs that program instead of the tests. This is the only
// TestMain of the package.
const (
	testHookEnv    = "SIGIL_TEST_ON_CHANGE"
	testHookDirEnv = "SIGIL_TEST_ON_CHANGE_DIR"

	// Sentinels that a runHook error must never contain.
	argvSecret   = "argv-secret-5d1e"
	outputSecret = "output-secret-c83b"

	// Markers at the start and the end of the output of the "flood" mode.
	floodHead = "flood-head-2a9f"
	floodTail = "flood-tail-6b07"
)

// hookRecord is what the "record" mode writes about how it was run.
type hookRecord struct {
	Args []string
	// Dir is its working directory.
	Dir string
	// StdinEOF reports whether its first read from stdin returned EOF.
	StdinEOF bool
}

func TestMain(m *testing.M) {
	if mode := os.Getenv(testHookEnv); mode != "" {
		os.Exit(runTestHook(mode))
	}
	os.Exit(m.Run())
}

// runTestHook acts as an on_change program and returns its exit code.
func runTestHook(mode string) int {
	switch mode {
	case "record":
		// Record how the program was run, and print output that a successful
		// run must not log.
		dir, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		n, readErr := os.Stdin.Read(make([]byte, 1))
		data, err := json.Marshal(hookRecord{Args: os.Args[1:], Dir: dir, StdinEOF: n == 0 && readErr == io.EOF})
		if err == nil {
			err = os.WriteFile(filepath.Join(os.Getenv(testHookDirEnv), "record.json"), data, 0o600)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(outputSecret)
		return 0
	case "fail":
		fmt.Println(outputSecret)
		fmt.Fprintln(os.Stderr, outputSecret)
		return 3
	case "flood":
		// Far more output than runHook keeps.
		fmt.Print(floodHead + strings.Repeat("x", 64<<10) + floodTail)
		return 1
	case "sleep":
		time.Sleep(20 * time.Second)
		return 0
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
		// Exit 0 at once, leaving a process that holds this one's output open.
		fmt.Println(outputSecret)
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

// hookArgv returns the argv of an on_change program that runs the test
// binary in mode with args.
func hookArgv(t *testing.T, mode string, args ...string) []string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(testHookEnv, mode)
	return append([]string{exe}, args...)
}

// setHookBounds overrides the bounds on one run for the duration of t.
func setHookBounds(t *testing.T, timeout, waitDelay time.Duration) {
	t.Helper()
	oldTimeout, oldWaitDelay := hookTimeout, hookWaitDelay
	hookTimeout, hookWaitDelay = timeout, waitDelay
	t.Cleanup(func() { hookTimeout, hookWaitDelay = oldTimeout, oldWaitDelay })
}

// TestRunHookRunsArgvAsGiven covers how the program runs: its arguments reach
// it unchanged, with no shell in between, its stdin is empty, and it works in
// the working directory of sigilc.
func TestRunHookRunsArgvAsGiven(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(testHookDirEnv, dir)
	_, logs := captureEvents(t)
	// Give this process a stdin with data waiting, so that a program that
	// inherited it would not read EOF.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("stdin")); err != nil {
		t.Fatal(err)
	}
	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = stdin
		_ = r.Close()
		_ = w.Close()
	})
	// A shell would split, expand, unquote or glob these.
	args := []string{"two words", `quote"d`, `back\slash\`, "$HOME", "%PATH%", "semi;colon", "*"}

	if err := runHook(context.Background(), "api-prod", hookArgv(t, "record", args...)); err != nil {
		t.Fatalf("runHook: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got hookRecord
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Args, args) {
		t.Errorf("arguments = %q, want %q", got.Args, args)
	}
	if !got.StdinEOF {
		t.Error("the program's stdin was not empty")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got.Dir != wd {
		t.Errorf("working directory = %q, want %q", got.Dir, wd)
	}
	// The output of a successful run is not logged.
	if logs.Len() != 0 {
		t.Errorf("successful run logged %q", logs.String())
	}
}

func TestRunHookErrorOmitsArgumentsAndOutput(t *testing.T) {
	_, logs := captureEvents(t)

	err := runHook(context.Background(), "api-prod", hookArgv(t, "fail", "--token="+argvSecret))
	if err == nil {
		t.Fatal("runHook succeeded, want the program's failure")
	}
	msg := err.Error()
	for _, want := range []string{"api-prod", "exit status 3"} {
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
		t.Errorf("log does not contain the program output: %q", logs.String())
	}
	if strings.Contains(logs.String(), argvSecret) {
		t.Errorf("log leaks the arguments: %q", logs.String())
	}
}

// TestRunHookLogsTheEndOfTheOutput covers a failed run with more output than
// runHook keeps: the end of the output is logged, and the start dropped.
func TestRunHookLogsTheEndOfTheOutput(t *testing.T) {
	_, logs := captureEvents(t)

	if err := runHook(context.Background(), "api-prod", hookArgv(t, "flood")); err == nil {
		t.Fatal("runHook succeeded, want the program's failure")
	}
	got := logs.String()
	if !strings.Contains(got, floodTail) || strings.Contains(got, floodHead) {
		t.Errorf("log does not hold just the end of the output: %.200q", got)
	}
	// proc.Run keeps the last 4 KiB.
	if len(got) > 4<<10+256 {
		t.Errorf("log is %d bytes, want about 4 KiB", len(got))
	}
}

func TestRunHookErrorNamesProgramThatCannotStart(t *testing.T) {
	captureEvents(t)
	missing := filepath.Join(t.TempDir(), "no-such-program")

	err := runHook(context.Background(), "api-prod", []string{missing, "--token=" + argvSecret})
	if err == nil {
		t.Fatal("runHook succeeded, want a start failure")
	}
	msg := err.Error()
	// The name may be quoted, which doubles the backslashes of a Windows path.
	if !strings.Contains(msg, missing) && !strings.Contains(msg, strconv.Quote(missing)) {
		t.Errorf("error %q does not name the program %q", msg, missing)
	}
	if !strings.Contains(msg, "api-prod") {
		t.Errorf("error %q does not name the certificate", msg)
	}
	if strings.Contains(msg, argvSecret) {
		t.Errorf("error %q leaks the arguments", msg)
	}
}

func TestRunHookKillsProgramAfterTimeout(t *testing.T) {
	setHookBounds(t, 100*time.Millisecond, hookWaitDelay)
	captureEvents(t)

	start := time.Now()
	err := runHook(context.Background(), "api-prod", hookArgv(t, "sleep"))
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("runHook returned after %v, want about the 100ms timeout", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "timed out after 100ms") {
		t.Fatalf("runHook error = %v, want a timeout", err)
	}
}

// TestRunHookKillsProgramWhenContextEnds covers the daemon stopping while a
// program runs: ctx ends, and the program is killed, not waited for, along
// with the processes it started. Programs are often interpreters, such as
// /bin/sh or powershell.exe, whose children do the work.
func TestRunHookKillsProgramWhenContextEnds(t *testing.T) {
	captureEvents(t)
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
	go func() {
		// Once the program's child runs, or after 10 seconds.
		for deadline := time.Now().Add(10 * time.Second); heartbeat() == "" && time.Now().Before(deadline); {
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
	}()

	start := time.Now()
	err := runHook(ctx, "api-prod", hookArgv(t, "spawn"))
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("runHook returned after %v, want it soon after ctx ended", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("runHook error = %v, want the cancellation", err)
	}
	if heartbeat() == "" {
		t.Fatal("the program's child never ran")
	}
	time.Sleep(300 * time.Millisecond)
	before := heartbeat()
	time.Sleep(300 * time.Millisecond)
	if heartbeat() != before {
		t.Fatal("a process the on_change program started is still running after runHook killed the program")
	}
}

// TestRunHookDoesNotWaitForOutputHeldByOrphans covers a program that exits 0
// but leaves a process holding its output: runHook returns once WaitDelay
// expires, and the run succeeds, since the program exited 0.
func TestRunHookDoesNotWaitForOutputHeldByOrphans(t *testing.T) {
	setHookBounds(t, hookTimeout, 100*time.Millisecond)
	ring, logs := captureEvents(t)

	start := time.Now()
	err := runHook(context.Background(), "api-prod", hookArgv(t, "orphan", "--token="+argvSecret))
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("runHook returned after %v, want it soon after the program exited", elapsed)
	}
	if err != nil {
		t.Fatalf("runHook error = %v, want success: the program exited 0", err)
	}
	// Closing the output may end the orphan, so the run is logged, naming the
	// certificate, with neither the arguments nor the output.
	if got, want := eventLines(ring), []string{"WARN on_change output held open cert=api-prod"}; !slices.Equal(got, want) {
		t.Errorf("events = %q, want %q", got, want)
	}
	got := logs.String()
	for _, secret := range []string{argvSecret, outputSecret} {
		if strings.Contains(got, secret) {
			t.Errorf("log leaks %q: %q", secret, got)
		}
	}
}

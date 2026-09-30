package proc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The test binary doubles as the program that Run runs: when testModeEnv
// names a mode, TestMain runs that program instead of the tests.
const (
	testModeEnv = "SIGIL_TEST_PROC"
	// testDirEnv is the directory of the heartbeat and stop files of the
	// "child" mode.
	testDirEnv = "SIGIL_TEST_PROC_DIR"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(testModeEnv); mode != "" {
		os.Exit(runTestProgram(mode))
	}
	os.Exit(m.Run())
}

// runTestProgram acts as the program Run runs, and returns its exit code.
func runTestProgram(mode string) int {
	switch mode {
	case "spawn", "spawn-exit":
		// Start a child that outlives this program unless it is killed; its
		// output is not this program's. Then sleep, or exit 0 once the child
		// runs.
		if err := startTestProgram("child", nil); err != nil {
			return 1
		}
		if mode == "spawn" {
			time.Sleep(20 * time.Second)
			return 0
		}
		if !heartbeat(os.Getenv(testDirEnv)).started() {
			return 1
		}
		return 0
	case "exit-during-run":
		// Run the "spawn" program, and exit without ending the run once the
		// program's child runs.
		exe, err := os.Executable()
		if err != nil {
			return 1
		}
		if err := os.Setenv(testModeEnv, "spawn"); err != nil {
			return 1
		}
		go func() { _, _ = Run(context.Background(), []string{exe}, time.Minute, time.Second) }()
		if !heartbeat(os.Getenv(testDirEnv)).started() {
			return 1
		}
		return 0
	case "child":
		// Write the time to the heartbeat file until the stop file appears,
		// for at most 20 seconds.
		dir := os.Getenv(testDirEnv)
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
				break
			}
			_ = os.WriteFile(filepath.Join(dir, "heartbeat"), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600)
		}
		return 0
	case "orphan":
		// Exit 0 at once, leaving a process that holds this one's output open.
		if err := startTestProgram("hold", os.Stdout); err != nil {
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
	return 2
}

// startTestProgram starts the test binary in mode, with out as its output,
// and does not wait for it.
func startTestProgram(mode string, out *os.File) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), testModeEnv+"="+mode)
	if out != nil {
		cmd.Stdout, cmd.Stderr = out, out
	}
	return cmd.Start()
}

// testArgv returns the argv that runs the test binary in mode.
func testArgv(t *testing.T, mode string) []string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(testModeEnv, mode)
	return []string{exe}
}

// heartbeat is the child of the "spawn" modes, seen through its files.
type heartbeat string

// newHeartbeat points the "child" mode at a new directory for the duration of
// t, and stops a child still running when t ends.
func newHeartbeat(t *testing.T) heartbeat {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(testDirEnv, dir)
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600)
		// Let a child still running see it and exit before TempDir's cleanup
		// removes the directory.
		time.Sleep(200 * time.Millisecond)
	})
	return heartbeat(dir)
}

func (h heartbeat) last() string {
	data, _ := os.ReadFile(filepath.Join(string(h), "heartbeat"))
	return string(data)
}

// started reports whether the child has written a heartbeat, waiting for it
// for up to 10 seconds.
func (h heartbeat) started() bool {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if h.last() != "" {
			return true
		}
	}
	return false
}

// alive reports whether the child still writes heartbeats.
func (h heartbeat) alive() bool {
	before := h.last()
	time.Sleep(300 * time.Millisecond)
	return h.last() != before
}

// TestRunKillsTheProcessesItsProgramStarted covers a run killed while its
// program has a child: a program is often an interpreter such as /bin/sh or
// powershell.exe whose children do the work, and a child left running when
// its program is killed could still act after the run failed.
func TestRunKillsTheProcessesItsProgramStarted(t *testing.T) {
	child := newHeartbeat(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		child.started()
		cancel()
	}()

	_, err := Run(ctx, testArgv(t, "spawn"), time.Minute, 100*time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want the cancellation", err)
	}
	if child.last() == "" {
		t.Fatal("the program's child never ran")
	}
	time.Sleep(300 * time.Millisecond)
	if child.alive() {
		t.Fatal("a process the program started is still running after Run killed the program")
	}
}

// TestRunLeavesTheProcessesOfAProgramThatExited covers a program that exits
// by itself and leaves a process behind, such as a service it starts: Run
// does not kill it.
func TestRunLeavesTheProcessesOfAProgramThatExited(t *testing.T) {
	child := newHeartbeat(t)

	// The program exits once its child runs.
	if _, err := Run(context.Background(), testArgv(t, "spawn-exit"), time.Minute, 100*time.Millisecond); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !child.alive() {
		t.Fatal("Run killed a process that its program left behind when it exited 0")
	}
}

// TestRunDoesNotWaitForOutputHeldOpen covers a program that exits 0 but
// leaves a process holding its output: Run returns once waitDelay has passed,
// with exec.ErrWaitDelay.
func TestRunDoesNotWaitForOutputHeldOpen(t *testing.T) {
	start := time.Now()
	_, err := Run(context.Background(), testArgv(t, "orphan"), time.Minute, 100*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Run returned after %v, want it soon after the program exited", elapsed)
	}
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("Run error = %v, want exec.ErrWaitDelay", err)
	}
}

func TestRunReportsTheTimeout(t *testing.T) {
	newHeartbeat(t)

	_, err := Run(context.Background(), testArgv(t, "spawn"), 100*time.Millisecond, 100*time.Millisecond)
	if err == nil || err.Error() != "timed out after 100ms" {
		t.Fatalf("Run error = %v, want the timeout", err)
	}
}

func TestTailWriterKeepsTheEnd(t *testing.T) {
	head := bytes.Repeat([]byte("h"), 1000)
	body := bytes.Repeat([]byte("b"), outputLimit-1000)
	w := &tailWriter{}
	for _, p := range [][]byte{head, body} {
		if n, err := w.Write(p); n != len(p) || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if w.truncated || !bytes.Equal(w.tail, append(head, body...)) {
		t.Fatalf("after exactly %d bytes: truncated=%v, %d bytes kept", outputLimit, w.truncated, len(w.tail))
	}
	end := []byte("end")
	_, _ = w.Write(end)
	if want := append(append(head[len(end):], body...), end...); !w.truncated || !bytes.Equal(w.tail, want) {
		t.Fatalf("after %d more bytes: truncated=%v, tail does not hold the last %d bytes", len(end), w.truncated, outputLimit)
	}
}

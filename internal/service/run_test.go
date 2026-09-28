package service

import (
	"bytes"
	"context"
	"errors"
	"log"
	"log/slog"
	"testing"
	"time"
)

// captureLog makes the default logger write to the returned buffer for the
// duration of t. Setting the default logger also routes the standard log
// package through it, which restoring the default does not undo, so the
// cleanup restores that as well. Read the buffer only once the daemon has
// returned.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	return &buf
}

// managedBy returns a fake service manager that starts the daemon and stops
// it once stop is closed, as the OS does on a stop request.
func managedBy(stop <-chan struct{}) func(Daemon) error {
	return func(d Daemon) error {
		if err := d.Start(nil); err != nil {
			return err
		}
		<-stop
		return d.Stop(nil)
	}
}

func TestRunDaemonInteractiveRunsDirectly(t *testing.T) {
	want := errors.New("daemon finished")
	err := runDaemon(true, func(Daemon) error {
		t.Error("interactive run went through the service manager")
		return nil
	}, func(ctx context.Context) error {
		if ctx.Err() != nil {
			t.Error("daemon context was cancelled before any stop request")
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestRunDaemonReturnsEarlyFailureWithoutStopRequest(t *testing.T) {
	logged := captureLog(t)
	stop := make(chan struct{})
	defer close(stop)
	want := errors.New("invalid configuration")
	result := make(chan error, 1)
	go func() {
		result <- runDaemon(false, managedBy(stop), func(context.Context) error { return want })
	}()

	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service run kept waiting for a stop request after the daemon failed")
	}
	if got := bytes.Count(logged.Bytes(), []byte("\n")); got != 1 {
		t.Fatalf("service log holds %d records, want 1:\n%s", got, logged)
	}
	if want := `level=ERROR msg="daemon failed" error="invalid configuration"`; !bytes.Contains(logged.Bytes(), []byte(want)) {
		t.Fatalf("service log lacks %s:\n%s", want, logged)
	}
}

func TestRunDaemonStopCancelsAndWaitsForDaemon(t *testing.T) {
	logged := captureLog(t)
	stop := make(chan struct{})
	cancelled := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runDaemon(false, managedBy(stop), func(ctx context.Context) error {
			<-ctx.Done()
			close(cancelled)
			<-release
			return nil
		})
	}()

	close(stop)
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("stop request did not cancel the daemon context")
	}
	select {
	case err := <-result:
		t.Fatalf("service run returned before the daemon function did: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("clean stop returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service run did not return after the daemon function finished")
	}
	if logged.Len() != 0 {
		t.Fatalf("clean stop wrote to the service log:\n%s", logged)
	}
}

func TestRunDaemonWaitsForManagerToAcknowledgeStop(t *testing.T) {
	stop := make(chan struct{})
	ack := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runDaemon(false, func(d Daemon) error {
			if err := d.Start(nil); err != nil {
				return err
			}
			<-stop
			if err := d.Stop(nil); err != nil {
				return err
			}
			<-ack // still reporting the stop to the OS
			return nil
		}, func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		})
	}()

	close(stop)
	select {
	case err := <-result:
		t.Fatalf("service run returned before the manager acknowledged the stop: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(ack)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("clean stop returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service run did not return after the manager acknowledged the stop")
	}
}

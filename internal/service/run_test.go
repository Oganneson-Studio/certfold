package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	ksvc "github.com/kardianos/service"
)

// fakeService is the handle a fake manager passes to the daemon callbacks.
// It records what the daemon writes to the system log.
type fakeService struct {
	ksvc.Service
	logged []string // read only after runDaemon returns
}

func (s *fakeService) SystemLogger(chan<- error) (ksvc.Logger, error) {
	return fakeLogger{svc: s}, nil
}

type fakeLogger struct {
	ksvc.Logger
	svc *fakeService
}

func (l fakeLogger) Error(v ...interface{}) error {
	l.svc.logged = append(l.svc.logged, fmt.Sprint(v...))
	return nil
}

// managedBy returns a fake service manager that starts the daemon and stops
// it once stop is closed, as the OS does on a stop request.
func managedBy(s *fakeService, stop <-chan struct{}) func(Daemon) error {
	return func(d Daemon) error {
		if err := d.Start(s); err != nil {
			return err
		}
		<-stop
		return d.Stop(s)
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
	s := &fakeService{}
	stop := make(chan struct{})
	defer close(stop)
	want := errors.New("invalid configuration")
	result := make(chan error, 1)
	go func() {
		result <- runDaemon(false, managedBy(s, stop), func(context.Context) error { return want })
	}()

	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service run kept waiting for a stop request after the daemon failed")
	}
	if len(s.logged) != 1 || s.logged[0] != want.Error() {
		t.Fatalf("system log = %q, want the failure %q", s.logged, want)
	}
}

func TestRunDaemonStopCancelsAndWaitsForDaemon(t *testing.T) {
	s := &fakeService{}
	stop := make(chan struct{})
	cancelled := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runDaemon(false, managedBy(s, stop), func(ctx context.Context) error {
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
	if len(s.logged) != 0 {
		t.Fatalf("clean stop wrote to the system log: %q", s.logged)
	}
}

func TestRunDaemonWaitsForManagerToAcknowledgeStop(t *testing.T) {
	s := &fakeService{}
	stop := make(chan struct{})
	ack := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runDaemon(false, func(d Daemon) error {
			if err := d.Start(s); err != nil {
				return err
			}
			<-stop
			if err := d.Stop(s); err != nil {
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

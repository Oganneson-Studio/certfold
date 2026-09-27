package service

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	ksvc "github.com/kardianos/service"
)

// Run executes fn as the daemon body until the process is asked to stop. fn
// should block until its context is cancelled and then return promptly.
//
// When a service manager (Windows SCM, systemd, launchd) started the process,
// fn runs inside the kardianos service loop so start and stop requests are
// acknowledged, and a stop request cancels fn's context. Otherwise the first
// SIGINT or SIGTERM cancels it and a second one terminates the process. If fn
// fails before any stop request, the error is written to the system log and
// Run returns it at once, so the process exits and the manager sees the failure.
func Run(cfg Config, fn func(context.Context) error) error {
	return runDaemon(ksvc.Interactive(), func(d Daemon) error {
		s, err := New(d, cfg)
		if err != nil {
			return err
		}
		return s.Run()
	}, fn)
}

// runDaemon is Run with the service manager detection and loop injected.
func runDaemon(interactive bool, manage func(Daemon) error, fn func(context.Context) error) error {
	if interactive {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		// Restore default signal handling once shutdown starts, so a second
		// Ctrl+C can end a shutdown that hangs.
		context.AfterFunc(ctx, stop)
		return fn(ctx)
	}

	d := newContextDaemon(fn)
	managed := make(chan error, 1)
	go func() { managed <- manage(d) }()
	select {
	case err := <-managed:
		return err
	case <-d.done:
		if d.ctx.Err() != nil {
			// Stop cancelled fn; let the manager finish acknowledging the stop.
			return <-managed
		}
		return d.err
	}
}

// contextDaemon adapts a blocking function to the kardianos callbacks: Start
// runs it in a goroutine, Stop cancels its context and waits for it to return.
type contextDaemon struct {
	run    func(ctx context.Context) error
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{} // closed when run returns
	err    error         // run's result, read only after done is closed
}

func newContextDaemon(run func(ctx context.Context) error) *contextDaemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &contextDaemon{run: run, ctx: ctx, cancel: cancel, done: make(chan struct{})}
}

func (d *contextDaemon) Start(s ksvc.Service) error {
	go func() {
		defer close(d.done)
		d.err = d.run(d.ctx)
		if d.err != nil && d.ctx.Err() == nil {
			// stderr may be invisible under the manager (Windows SCM), so keep
			// the reason in the system log. Logging errors are ignored; they
			// must not change how the daemon exits.
			if logger, err := s.SystemLogger(nil); err == nil {
				_ = logger.Error(d.err)
			}
		}
	}()
	return nil
}

func (d *contextDaemon) Stop(_ ksvc.Service) error {
	d.cancel()
	<-d.done
	return d.err
}

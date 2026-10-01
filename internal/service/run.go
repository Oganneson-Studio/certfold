package service

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	ksvc "github.com/kardianos/service"

	"github.com/Oganneson-Studio/certfold/internal/logging"
)

// Run executes fn as the daemon body until the process is asked to stop. fn
// should block until its context is cancelled and then return promptly.
//
// Run first sets up the logging of the daemon with logging.Setup and passes
// it to fn. The service log is stderr, except in a Windows service, which
// writes to the Application event log.
//
// When a service manager (Windows SCM, systemd, launchd) started the process,
// fn runs inside the kardianos service loop so start and stop requests are
// acknowledged, and a stop request cancels fn's context. Otherwise the first
// SIGINT or SIGTERM cancels it and a second one terminates the process. If fn
// fails before any stop request, the error is logged as "daemon failed" and
// Run returns it at once, so the process exits and the manager sees the
// failure.
func Run(cfg Config, fn func(context.Context, logging.Logs) error) error {
	interactive := ksvc.Interactive()
	sink, closeSink := daemonLog(cfg.Role, interactive)
	defer closeSink()
	logs := logging.Setup(sink)
	return runDaemon(interactive, func(d Daemon) error {
		s, err := New(d, cfg)
		if err != nil {
			return err
		}
		return s.Run()
	}, func(ctx context.Context) error { return fn(ctx, logs) })
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

func (d *contextDaemon) Start(ksvc.Service) error {
	go func() {
		defer close(d.done)
		d.err = d.run(d.ctx)
		if d.err != nil && d.ctx.Err() == nil {
			// The error Run returns reaches only stderr, which nobody reads
			// under the Windows SCM; the service log keeps the reason.
			slog.Error("daemon failed", "error", d.err)
		}
	}()
	return nil
}

func (d *contextDaemon) Stop(_ ksvc.Service) error {
	d.cancel()
	<-d.done
	return d.err
}

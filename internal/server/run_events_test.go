package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	legolog "github.com/go-acme/lego/v4/log"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// startRun runs the daemon on a loopback port with logs until the test ends,
// and returns once its HTTPS listener answers. stop cancels it and waits for
// Run to return nil.
func startRun(t *testing.T, logs logging.Logs) (miniCA *ca.MiniCA, listen, socket string, stop func()) {
	t.Helper()
	dataDir := t.TempDir()
	miniCA, err := ca.Bootstrap(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	listen = fmt.Sprintf("127.0.0.1:%d", port)
	socket = testIPCSocket(t)
	path := writeServerConfig(t, listen, dataDir, socket)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- Run(ctx, path, logs) }()
	stopped := false
	stop = func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("Run returned %v after cancellation, want nil", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("Run did not return after cancellation")
		}
	}
	t.Cleanup(stop)
	waitServing(t, miniCA, port, result)
	return miniCA, listen, socket, stop
}

func TestRunLogsEventsAndKeepsServerErrorsOutOfThem(t *testing.T) {
	sink := &lockedBuffer{}
	logs := setupLogs(t, sink)
	_, listen, _, stop := startRun(t, logs)

	// A client that does not speak TLS, as scanners on the internet do.
	conn, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("not a TLS handshake\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.Copy(io.Discard, conn)
	conn.Close()
	waitLogged(t, sink, "http: TLS handshake error")

	legolog.Infof("[%s] acme: Obtaining bundled SAN certificate", "api.example.com")
	legolog.Warnf("[%s] acme: cleaning up failed: %v", "api.example.com", "exit status 3")
	stop()

	events := logs.Events.Since(0)
	if len(events) == 0 {
		t.Fatal("no events")
	}
	if e := events[0]; e.Level != "INFO" || e.Message != "sigils started" ||
		!strings.Contains(e.Attrs, "version=") || !strings.Contains(e.Attrs, "listen="+listen+` public_url=""`) {
		t.Errorf("first event = %+v, want INFO sigils started with the version, listen and public_url", e)
	}
	if e := events[len(events)-1]; e.Level != "INFO" || e.Message != "sigils stopping" {
		t.Errorf("last event = %+v, want INFO sigils stopping", e)
	}
	// lego marks its lines, and the marks become levels.
	if e := findEvent(t, events, "[api.example.com] acme: Obtaining bundled SAN certificate"); e.Level != "INFO" || e.Attrs != "component=lego" {
		t.Errorf("lego info line became %+v", e)
	}
	if e := findEvent(t, events, "[api.example.com] acme: cleaning up failed: exit status 3"); e.Level != "WARN" || e.Attrs != "component=lego" {
		t.Errorf("lego warning became %+v", e)
	}
	// The handshake error reached the service log only.
	for _, e := range events {
		if strings.Contains(e.Message+e.Attrs, "TLS handshake error") {
			t.Errorf("handshake error became the event %+v", e)
		}
	}
}

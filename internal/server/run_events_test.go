package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	legolog "github.com/go-acme/lego/v4/log"

	"github.com/Oganneson-Studio/certfold/internal/ca"
	"github.com/Oganneson-Studio/certfold/internal/enroll"
	"github.com/Oganneson-Studio/certfold/internal/ipc"
	"github.com/Oganneson-Studio/certfold/internal/logging"
	"github.com/Oganneson-Studio/certfold/pkg/proto"
)

// startRun runs the daemon on a loopback port with logs until the test ends,
// and returns once its HTTPS listener answers. stop cancels it and waits for
// Run to return nil.
func startRun(t *testing.T, logs logging.Logs) (miniCA *ca.MiniCA, listen, socket string, stop func()) {
	t.Helper()
	dataDir := privateDir(t)
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
	if e := events[0]; e.Level != "INFO" || e.Message != "certfolds started" ||
		!strings.Contains(e.Attrs, "version=") || !strings.Contains(e.Attrs, "listen="+listen+` public_url=""`) {
		t.Errorf("first event = %+v, want INFO certfolds started with the version, listen and public_url", e)
	}
	if e := events[len(events)-1]; e.Level != "INFO" || e.Message != "certfolds stopping" {
		t.Errorf("last event = %+v, want INFO certfolds stopping", e)
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

// skipWithoutPipeAccess skips the test when err shows that this process may
// not open the certfolds pipe, which admits only SYSTEM and elevated
// administrators.
func skipWithoutPipeAccess(t *testing.T, err error) {
	t.Helper()
	if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
		t.Skip("the certfolds pipe admits only SYSTEM and elevated administrators")
	}
}

func TestRunKeepsEnrollmentTokensOutOfEvents(t *testing.T) {
	sink := &lockedBuffer{}
	logs := setupLogs(t, sink)
	miniCA, listen, socket, stop := startRun(t, logs)

	c, err := ipc.NewClient(socket)
	if err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}
	// Without public_url the token is bound to the listen address.
	created, err := c.CreateToken(context.Background(), ipc.CreateTokenRequest{Name: "web-1", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := enroll.DecodeToken(created.Token)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "web-1"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(proto.EnrollRequest{
		Token: created.Token,
		CSR:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(miniCA.Cert())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	defer client.CloseIdleConnections()
	resp, err := client.Post("https://"+listen+"/v1/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d", resp.StatusCode)
	}
	stop()

	events := logs.Events.Since(0)
	if e := findEvent(t, events, "enrollment token created"); !strings.HasPrefix(e.Attrs, "token="+payload.TokenID+" client=web-1 expires_at=") {
		t.Errorf("token creation event = %+v, want the token ID, the client and the expiry", e)
	}
	if e := findEvent(t, events, "client enrolled"); e.Attrs != "client=web-1 token="+payload.TokenID {
		t.Errorf("enrollment event = %+v, want the client and the token ID", e)
	}
	// Only the ID: the token itself enrolls a client, and so does its secret
	// with the rest of the payload. The start of the token is enough to find
	// it in attributes cut to 2 KiB.
	for what, leak := range map[string]string{"token": created.Token[:64], "secret": payload.Secret} {
		for _, e := range events {
			if strings.Contains(e.Message+e.Attrs, leak) {
				t.Errorf("event %+v holds the %s", e, what)
			}
		}
		if strings.Contains(sink.String(), leak) {
			t.Errorf("service log holds the %s:\n%s", what, sink.String())
		}
	}
}

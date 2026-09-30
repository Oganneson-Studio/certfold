package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
	"github.com/Oganneson-Studio/sigil/internal/server"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

func testIPCSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\sigils-cli-test-%d`, time.Now().UnixNano())
	}
	// Unix socket paths are length-limited; keep this one short.
	dir, err := os.MkdirTemp("", "sigil")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// skipWithoutPipeAccess skips the test when err shows that this process may
// not open the sigils pipe, which admits only SYSTEM and elevated
// administrators.
func skipWithoutPipeAccess(t *testing.T, err error) {
	t.Helper()
	if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
		t.Skip("the sigils pipe admits only SYSTEM and elevated administrators")
	}
}

// startDaemon runs the sigils daemon on a loopback port with a configuration
// without certificates, so it never contacts an ACME directory. It returns
// once the daemon answers on its IPC endpoint; stop may be called repeatedly.
// The daemon logs as `sigils serve` does, to a service log that is discarded.
func startDaemon(t *testing.T, dataDir, publicURL string) (socket, listen string, stop func() error) {
	t.Helper()
	// Setup also routes the standard log package through slog, which
	// restoring the default logger does not undo. Registered first, the
	// cleanup runs after the daemon has stopped.
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	logs := logging.Setup(slog.NewTextHandler(io.Discard, nil))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen = l.Addr().String()
	l.Close()
	socket = testIPCSocket(t)

	var publicURLLine string
	if publicURL != "" {
		publicURLLine = fmt.Sprintf("  public_url: %q\n", publicURL)
	}
	// The daemon refuses a directory of server.yaml that accounts it does
	// not trust may write to, as the temporary directory may be:
	// securefile creates this one private.
	cfgPath := filepath.Join(t.TempDir(), "etc", "server.yaml")
	raw := fmt.Sprintf(`server:
  listen: %q
  data_dir: %q
  ipc_socket: %q
%sacme:
  email: "ops@example.com"
  default_ca: "le"
  cas:
    le:
      directory: "https://acme.example.com/directory"
certificates: []
`, listen, dataDir, socket, publicURLLine)
	if err := securefile.WriteFile(cfgPath, []byte(raw)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan struct{})
	var runErr error
	go func() {
		runErr = server.Run(ctx, cfgPath, logs)
		close(exited)
	}()
	stop = func() error {
		cancel()
		<-exited
		return runErr
	}
	t.Cleanup(func() { _ = stop() })

	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := ipc.NewClient(socket)
		if err == nil {
			return socket, listen, stop
		}
		skipWithoutPipeAccess(t, err)
		select {
		case <-exited:
			t.Fatalf("daemon exited before serving IPC: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon IPC did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// tokenCreate runs `sigils --ipc socket token create` with args and returns
// what the command printed.
func tokenCreate(socket string, args ...string) (stdout, stderr string, err error) {
	root := NewRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"--ipc", socket, "token", "create"}, args...))
	err = root.Execute()
	return out.String(), errOut.String(), err
}

func TestTokenCreateIssuesTokenThroughDaemon(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
		wantWarn  bool
	}{
		{name: "public URL", publicURL: "https://sigil.example.com:8443"},
		{name: "derived from listen", wantWarn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "data")
			socket, listen, stop := startDaemon(t, dataDir, tt.publicURL)
			wantURL := tt.publicURL
			if wantURL == "" {
				wantURL = "https://" + listen
			}

			stdout, stderr, err := tokenCreate(socket, "--name", "web-1", "--expires", "10m")
			if err != nil {
				t.Fatalf("token create: %v", err)
			}

			// E2E reads the token from this line.
			var token string
			for _, line := range strings.Split(stdout, "\n") {
				if strings.HasPrefix(line, "Token: ") {
					token = strings.TrimPrefix(line, "Token: ")
				}
			}
			if token == "" {
				t.Fatalf("no Token line in output:\n%s", stdout)
			}
			for _, want := range []string{
				"Install (Linux/macOS):\n" +
					"  curl -fsSL '" + wantURL + "/install.sh' | sudo sh -s -- --token '" + token + "'\n",
				// The Windows command passes the token as an argument of the
				// script, which the server no longer writes into it.
				"Install (Windows, elevated PowerShell):\n" +
					"  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; " +
					"& ([scriptblock]::Create((irm '" + wantURL + "/install.ps1'))) -Token '" + token + "'\n",
			} {
				if !strings.Contains(stdout, want) {
					t.Errorf("output lacks %q:\n%s", want, stdout)
				}
			}
			if warned := strings.Contains(stderr, "server.public_url is not set"); warned != tt.wantWarn {
				t.Errorf("public_url warning = %t, want %t; stderr:\n%s", warned, tt.wantWarn, stderr)
			}

			// A lifetime that is not positive fails instead of printing an
			// already expired token.
			stdout, _, err = tokenCreate(socket, "--name", "web-2", "--expires", "-5m")
			if err == nil || !strings.Contains(err.Error(), "must be positive") {
				t.Errorf("token create --expires -5m: error = %v, want a positive lifetime error", err)
			}
			if strings.Contains(stdout, "Token:") {
				t.Errorf("token create --expires -5m printed a token:\n%s", stdout)
			}

			// The token must redeem against the daemon's own store.
			if err := stop(); err != nil {
				t.Fatalf("daemon: %v", err)
			}
			db, err := store.Open(filepath.Join(dataDir, "sigils.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			miniCA, err := ca.Bootstrap(dataDir)
			if err != nil {
				t.Fatal(err)
			}
			name, _, err := enroll.NewServer(db, miniCA).Verify(context.Background(), token)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if name != "web-1" {
				t.Fatalf("token name = %q, want web-1", name)
			}
			payload, err := enroll.DecodeToken(token)
			if err != nil {
				t.Fatal(err)
			}
			if payload.ServerURL != wantURL {
				t.Fatalf("token is bound to %q, want %q", payload.ServerURL, wantURL)
			}
		})
	}
}

func TestTokenCreateRefusesAnswerOfOutdatedDaemon(t *testing.T) {
	socket := testIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	// A daemon started before the upgrade still answers with a bare token ID.
	outdated := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"token":"0123456789abcdef"}`)
	})}
	go func() { _ = outdated.Serve(l) }()
	t.Cleanup(func() { _ = outdated.Close() })
	if _, err := ipc.NewClient(socket); err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}

	stdout, _, err := tokenCreate(socket, "--name", "web-1")
	if err == nil || !strings.Contains(err.Error(), "restart the sigils service") {
		t.Fatalf("token create error = %v, want a request to restart the daemon", err)
	}
	if strings.Contains(stdout, "Token:") {
		t.Fatalf("printed the answer of an outdated daemon as a token:\n%s", stdout)
	}
}

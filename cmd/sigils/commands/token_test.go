package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/api"
	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
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
	cfgPath := filepath.Join(t.TempDir(), "server.yaml")
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
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
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
			dataDir := t.TempDir()
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
			// The ID names the token in token list and token revoke.
			payload, err := enroll.DecodeToken(token)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"Token ID: " + payload.TokenID + "\n",
				"Expires:  " + payload.ExpiresAt.Local().Format("2006-01-02 15:04:05 -07:00") + "\n",
			} {
				if !strings.Contains(stdout, want) {
					t.Errorf("output lacks %q:\n%s", want, stdout)
				}
			}

			// A lifetime that is not positive fails instead of printing an
			// already expired token, and one longer than a week fails too.
			for _, tc := range []struct{ expires, want string }{
				{"-5m", "must be positive"},
				{"169h", "must be at most 168h0m0s"},
			} {
				stdout, _, err = tokenCreate(socket, "--name", "web-2", "--expires", tc.expires)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("token create --expires %s: error = %v, want %q", tc.expires, err, tc.want)
				}
				if strings.Contains(stdout, "Token:") {
					t.Errorf("token create --expires %s printed a token:\n%s", tc.expires, stdout)
				}
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
			if payload.ServerURL != wantURL {
				t.Fatalf("token is bound to %q, want %q", payload.ServerURL, wantURL)
			}
		})
	}
}

// serveTokens serves the token creation of the IPC API with create until the
// test ends, and returns its endpoint.
func serveTokens(t *testing.T, create func(context.Context, ipc.CreateTokenRequest) (ipc.CreateTokenResponse, error)) string {
	t.Helper()
	socket := testIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := ipc.NewServer(ipc.ServerDeps{Tokens: &ipc.TokenControlDeps{Create: create}})
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Serve(l) }()
	if _, err := ipc.NewClient(socket); err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}
	return socket
}

// TestTokenCreatePassesReplace covers --replace, which the daemon requires to
// create a token for the name of an enrolled client.
func TestTokenCreatePassesReplace(t *testing.T) {
	requests := make(chan ipc.CreateTokenRequest, 2)
	socket := serveTokens(t, func(_ context.Context, req ipc.CreateTokenRequest) (ipc.CreateTokenResponse, error) {
		requests <- req
		return ipc.CreateTokenResponse{Token: "token", TokenID: "0123456789abcdef0123456789abcdef", ExpiresAt: time.Now().Add(req.TTL),
			ServerURL: "https://sigil.example.com", PublicURLConfigured: true}, nil
	})
	for _, replace := range []bool{false, true} {
		args := []string{"--name", "web-1"}
		if replace {
			args = append(args, "--replace")
		}
		if _, _, err := tokenCreate(socket, args...); err != nil {
			t.Fatalf("token create %v: %v", args, err)
		}
		if req := <-requests; req.Name != "web-1" || req.Replace != replace {
			t.Errorf("token create %v sent %+v, want replace %t", args, req, replace)
		}
	}
}

// TestTokenCreateSaysHowToReplace covers the daemon's refusal of a name that
// an enrolled client or an unused token has: the error says to add
// --replace, and a replacement says how many unused tokens it revoked.
func TestTokenCreateSaysHowToReplace(t *testing.T) {
	socket := serveTokens(t, func(_ context.Context, req ipc.CreateTokenRequest) (ipc.CreateTokenResponse, error) {
		if !req.Replace {
			return ipc.CreateTokenResponse{}, fmt.Errorf("enrollment token t1 for %q is unused; %w", req.Name, ipc.ErrReplaceRequired)
		}
		return ipc.CreateTokenResponse{Token: "token", TokenID: "0123456789abcdef0123456789abcdef", ExpiresAt: time.Now().Add(req.TTL),
			Revoked: 2, ServerURL: "https://sigil.example.com", PublicURLConfigured: true}, nil
	})
	_, _, err := tokenCreate(socket, "--name", "web-1")
	if !errors.Is(err, ipc.ErrReplaceRequired) || !strings.Contains(err.Error(), `add --replace, which also revokes the unused tokens of "web-1"`) {
		t.Errorf("token create for a name that needs a replacement: error = %v, want one that says to add --replace", err)
	}
	stdout, _, err := tokenCreate(socket, "--name", "web-1", "--replace")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Revoked:  2 unused token(s) for \"web-1\"\n") {
		t.Errorf("token create --replace printed:\n%s\nwant the number of tokens it revoked", stdout)
	}
}

// TestTokenCreatePrintsJSON covers token create --json, which prints what a
// script needs: the token, its ID and expiry, and the install commands.
func TestTokenCreatePrintsJSON(t *testing.T) {
	expires := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	socket := serveTokens(t, func(_ context.Context, req ipc.CreateTokenRequest) (ipc.CreateTokenResponse, error) {
		return ipc.CreateTokenResponse{Token: "token", TokenID: "0123456789abcdef0123456789abcdef", ExpiresAt: expires,
			ServerURL: "https://sigil.example.com", PublicURLConfigured: true}, nil
	})
	stdout, _, err := tokenCreate(socket, "--name", "web-1", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("token create --json printed %q: %v", stdout, err)
	}
	sh, ps1 := api.InstallCommands("https://sigil.example.com", "token")
	want := map[string]any{
		"token":       "token",
		"token_id":    "0123456789abcdef0123456789abcdef",
		"expires_at":  "2026-09-29T12:00:00Z",
		"install_sh":  sh,
		"install_ps1": ps1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("token create --json = %v, want %v", got, want)
	}
}

func TestTokenCreateRefusesAnswerOfOutdatedDaemon(t *testing.T) {
	socket := testIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	// A daemon started before an upgrade answers with a bare token ID, or,
	// before --replace, without the token ID; that one creates a token for
	// the name of an enrolled client without asking.
	answers := make(chan string, 2)
	answers <- `{"token":"0123456789abcdef"}`
	answers <- `{"token":"token","server_url":"https://sigil.example.com","public_url_configured":true}`
	outdated := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, <-answers)
	})}
	go func() { _ = outdated.Serve(l) }()
	t.Cleanup(func() { _ = outdated.Close() })
	if _, err := ipc.NewClient(socket); err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}

	for range 2 {
		stdout, _, err := tokenCreate(socket, "--name", "web-1")
		if err == nil || !strings.Contains(err.Error(), "restart the sigils service") {
			t.Fatalf("token create error = %v, want a request to restart the daemon", err)
		}
		if strings.Contains(stdout, "Token:") {
			t.Fatalf("printed the answer of an outdated daemon as a token:\n%s", stdout)
		}
	}
}

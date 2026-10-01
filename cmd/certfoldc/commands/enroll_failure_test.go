package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/securefile"
)

// refusingEnrollServer refuses every enrollment, as certfolds does a token that
// was already used, and counts the requests that reach it.
type refusingEnrollServer struct {
	*httptest.Server
	requests atomic.Int32
	// signed, when set, runs in the server of newSigningEnrollServer once it
	// has signed the certificate, before it answers.
	signed func()
}

func newRefusingEnrollServer(t *testing.T) *refusingEnrollServer {
	t.Helper()
	s := &refusingEnrollServer{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.requests.Add(1)
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
	}))
	t.Cleanup(s.Close)
	return s
}

// token returns a token for the client name that pins the certificate of s,
// as certfolds token create does its own.
func (s *refusingEnrollServer) token(t *testing.T, name string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"server_url": s.URL,
		"name":       name,
		"token_id":   "id",
		"secret":     "secret",
		"ca_cert":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})),
		"expires_at": time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func runEnrollCommand(cfgPath, token string) error {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "enroll", "--token", token})
	return cmd.Execute()
}

// TestEnrollFailureLeavesNoConfig checks that an enrollment the server
// refuses leaves no client.yaml behind. One without an identity would bind
// the next attempt to the client name and server URL of the refused token,
// though the usual fix for a first enrollment that fails is a new token with
// a corrected server.public_url.
func TestEnrollFailureLeavesNoConfig(t *testing.T) {
	first := newRefusingEnrollServer(t)
	// Enrollment refuses a directory that accounts it does not trust may
	// write to, as the temporary directory may be: securefile creates this
	// one private.
	cfgPath := filepath.Join(t.TempDir(), "etc", "client.yaml")
	if err := runEnrollCommand(cfgPath, first.token(t, "web-1")); err == nil {
		t.Fatal("enrolled with a token the server refuses")
	}
	if n := first.requests.Load(); n != 1 {
		t.Fatalf("server got %d requests, want 1", n)
	}
	if _, err := os.Stat(cfgPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat client.yaml after a refused enrollment: %v, want it absent", err)
	}

	// A token for another client name and server URL gets to its server.
	second := newRefusingEnrollServer(t)
	err := runEnrollCommand(cfgPath, second.token(t, "web-2"))
	if n := second.requests.Load(); n != 1 {
		t.Fatalf("the next token did not reach its server: %v", err)
	}
}

// TestEnrollFailureKeepsExistingConfig checks that a refused enrollment
// leaves a client.yaml that was there before as it was.
func TestEnrollFailureKeepsExistingConfig(t *testing.T) {
	srv := newRefusingEnrollServer(t)
	// Enrollment refuses a directory that accounts it does not trust may
	// write to, as the temporary directory may be: securefile creates this
	// one private.
	cfgPath := filepath.Join(t.TempDir(), "etc", "client.yaml")
	existing := fmt.Appendf(nil, "client:\n  name: web-1\n  server_url: %q\n  data_dir: %q\n", srv.URL, t.TempDir())
	if err := securefile.WriteFile(cfgPath, existing); err != nil {
		t.Fatal(err)
	}
	if err := runEnrollCommand(cfgPath, srv.token(t, "web-1")); err == nil {
		t.Fatal("enrolled with a token the server refuses")
	}
	if n := srv.requests.Load(); n != 1 {
		t.Fatalf("server got %d requests, want 1", n)
	}
	if got, err := os.ReadFile(cfgPath); err != nil || !bytes.Equal(got, existing) {
		t.Fatalf("client.yaml after a refused enrollment = %q (error %v), want it unchanged:\n%s", got, err, existing)
	}
}

// TestEnrollKeepsTokenWhenConfigCannotBeWritten checks that certfoldc finds out
// it cannot write client.yaml before it sends the token, which the server
// spends on the first request. Something stands where the directory of
// client.yaml should be, so that reading client.yaml finds nothing, as
// before any enrollment, and writing it fails: on Windows a file, and on
// Unix, which reports a path through a file as ENOTDIR rather than as
// missing, a dangling symbolic link.
func TestEnrollKeepsTokenWhenConfigCannotBeWritten(t *testing.T) {
	srv := newRefusingEnrollServer(t)
	// In a private directory, so that enrollment goes on to write client.yaml.
	dir := filepath.Join(t.TempDir(), "etc")
	if err := securefile.EnsurePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(dir, "certfold")
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), blocker); err != nil {
		t.Fatal(err)
	}
	err := runEnrollCommand(filepath.Join(blocker, "client.yaml"), srv.token(t, "web-1"))
	if err == nil {
		t.Fatal("enrolled without a writable client.yaml")
	}
	if n := srv.requests.Load(); n != 0 {
		t.Fatalf("sent the token %d times before finding out that client.yaml cannot be written (%v)", n, err)
	}
}

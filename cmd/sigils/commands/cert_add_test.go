package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

// cert add no longer takes --renew-days-before: when a certificate is renewed
// is not configured.
func TestCertAddRejectsRenewDaysBefore(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--ipc", testIPCSocket(t), "cert", "add", "api-prod",
		"--domains", "api.example.com", "--dns", "route", "--renew-days-before", "30",
	})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag: --renew-days-before") {
		t.Fatalf("cert add error = %v, want an unknown flag", err)
	}
}

// configEdits stands in for the daemon's side of cert add and cert remove: it
// records what it is asked, and answers with err.
type configEdits struct {
	mu      sync.Mutex
	added   []config.CertificateSpec
	removed []string
	err     error
}

// serveConfigEdits serves edits on a new IPC endpoint, as a daemon running
// /etc/sigil/server.yaml, and returns the endpoint.
func serveConfigEdits(t *testing.T, edits *configEdits) string {
	t.Helper()
	socket := testIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := ipc.NewServer(ipc.ServerDeps{Server: &ipc.ServerControlDeps{
		ConfigPath: "/etc/sigil/server.yaml",
		AddCertificate: func(_ context.Context, spec config.CertificateSpec) error {
			edits.mu.Lock()
			defer edits.mu.Unlock()
			edits.added = append(edits.added, spec)
			return edits.err
		},
		RemoveCertificate: func(_ context.Context, name string) error {
			edits.mu.Lock()
			defer edits.mu.Unlock()
			edits.removed = append(edits.removed, name)
			return edits.err
		},
	}})
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	if _, err := ipc.NewClient(socket); err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}
	return socket
}

// cert add and cert remove leave server.yaml to the running daemon, which
// edits the file it runs and applies the result.
func TestCertAddAndRemoveGoThroughTheDaemon(t *testing.T) {
	edits := &configEdits{}
	socket := serveConfigEdits(t, edits)

	out := runSigils(t, "--ipc", socket, "cert", "add", " api-prod ",
		"--domains", "api.example.com, www.example.com", "--dns", "route", "--subscribers", "web-1,,web-2")
	if want := "certificate \"api-prod\" added to /etc/sigil/server.yaml\nrunning sigils configuration reloaded\n"; out != want {
		t.Errorf("cert add printed %q, want %q", out, want)
	}
	out = runSigils(t, "--ipc", socket, "--json", "cert", "remove", "api-prod")
	if want := `{"name":"api-prod","config_path":"/etc/sigil/server.yaml","stored_material_retained":true}`; compactJSON(t, out) != want {
		t.Errorf("cert remove --json printed %s, want %s", out, want)
	}

	edits.mu.Lock()
	defer edits.mu.Unlock()
	want := config.CertificateSpec{
		Name:        "api-prod",
		Domains:     []string{"api.example.com", "www.example.com"},
		DNSProvider: "route",
		KeyType:     "ec256",
		Subscribers: []string{"web-1", "web-2"},
	}
	if len(edits.added) != 1 || !reflect.DeepEqual(edits.added[0], want) {
		t.Errorf("the daemon was asked to add %+v, want %+v", edits.added, want)
	}
	if len(edits.removed) != 1 || edits.removed[0] != "api-prod" {
		t.Errorf("the daemon was asked to remove %q, want api-prod", edits.removed)
	}
}

// The daemon's reason for refusing a change is the command's error, which
// main prints before it exits 1.
func TestCertAddAndRemoveReportTheDaemonsRefusal(t *testing.T) {
	for _, tc := range []struct {
		args []string
		err  error
		want string
	}{
		{
			args: []string{"cert", "add", "api-prod", "--domains", "api.example.com", "--dns", "route"},
			err:  errors.New("cannot hot reload changes to server.listen; restart sigils to apply them"),
			want: "server returned 422: cannot hot reload changes to server.listen; restart sigils to apply them",
		},
		{
			args: []string{"cert", "remove", "api-prod"},
			err:  fmt.Errorf("cert %q %w", "api-prod", config.ErrCertificateNotFound),
			want: `server returned 404: cert "api-prod" not found`,
		},
	} {
		socket := serveConfigEdits(t, &configEdits{err: tc.err})
		root := NewRootCmd()
		root.SetArgs(append([]string{"--ipc", socket}, tc.args...))
		if err := root.Execute(); err == nil || !strings.HasSuffix(err.Error(), tc.want) {
			t.Errorf("sigils %s: error = %v, want it to end in %s", strings.Join(tc.args, " "), err, tc.want)
		}
	}
}

// Without a running daemon, cert add fails like token create, and changes
// nothing: the command does not edit server.yaml itself.
func TestCertAddFailsWhenDaemonIsNotRunning(t *testing.T) {
	path := writeManagementTestConfig(t, "  []\n")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--config", path, "--ipc", testIPCSocket(t), "cert", "add", "api-prod",
		"--domains", "api.example.com", "--dns", "route",
	})
	if err := cmd.Execute(); err == nil || !strings.HasPrefix(err.Error(), "ipc unavailable: ") {
		t.Fatalf("cert add error = %v, want the daemon to be unavailable", err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("cert add changed server.yaml without a daemon (read error %v):\n%s", err, after)
	}
}

func compactJSON(t *testing.T, raw string) string {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, []byte(raw)); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, raw)
	}
	return out.String()
}

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The test binary doubles as the program of an exec DNS provider: when
// testProgramEnv names a mode, TestMain runs that program instead of the
// tests. This is the only TestMain of the package.
const (
	testProgramEnv = "SIGIL_TEST_SERVER_DNS_PROGRAM"
	// testProgramDirEnv is the directory of the heartbeat and stop files of
	// the "child" mode.
	testProgramDirEnv = "SIGIL_TEST_SERVER_DNS_PROGRAM_DIR"
)

func TestMain(m *testing.M) {
	switch os.Getenv(testProgramEnv) {
	case "":
		os.Exit(m.Run())
	case "spawn":
		// Start a child, whose output is not this program's, then sleep.
		exe, err := os.Executable()
		if err != nil {
			os.Exit(1)
		}
		child := exec.Command(exe)
		child.Env = append(os.Environ(), testProgramEnv+"=child")
		if err := child.Start(); err != nil {
			os.Exit(1)
		}
		time.Sleep(20 * time.Second)
		os.Exit(0)
	case "child":
		// Write the time to the heartbeat file until the stop file appears,
		// for at most 20 seconds.
		dir := os.Getenv(testProgramDirEnv)
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
				break
			}
			_ = os.WriteFile(filepath.Join(dir, "heartbeat"), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600)
		}
		os.Exit(0)
	}
	os.Exit(2)
}

// newChallengeCA starts an ACME server that takes any account and any order,
// and holds the order at a pending dns-01 challenge for domain: lego gets as
// far as running the DNS provider's present. It returns the directory URL. It
// checks no signatures.
func newChallengeCA(t *testing.T, domain string) string {
	t.Helper()
	var url string
	answer := func(w http.ResponseWriter, status int, location string, body any) {
		w.Header().Set("Replay-Nonce", "nonce")
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dir", func(w http.ResponseWriter, r *http.Request) {
		answer(w, http.StatusOK, "", map[string]string{
			"newNonce":   url + "/nonce",
			"newAccount": url + "/new-acct",
			"newOrder":   url + "/new-order",
			"revokeCert": url + "/revoke-cert",
			"keyChange":  url + "/key-change",
		})
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce")
	})
	mux.HandleFunc("POST /new-acct", func(w http.ResponseWriter, r *http.Request) {
		answer(w, http.StatusCreated, url+"/acct/1", map[string]string{"status": "valid"})
	})
	mux.HandleFunc("POST /new-order", func(w http.ResponseWriter, r *http.Request) {
		answer(w, http.StatusCreated, url+"/order/1", map[string]any{
			"status":         "pending",
			"identifiers":    []map[string]string{{"type": "dns", "value": domain}},
			"authorizations": []string{url + "/authz/1"},
			"finalize":       url + "/finalize/1",
		})
	})
	mux.HandleFunc("POST /authz/1", func(w http.ResponseWriter, r *http.Request) {
		answer(w, http.StatusOK, "", map[string]any{
			"status":     "pending",
			"identifier": map[string]string{"type": "dns", "value": domain},
			"challenges": []map[string]string{{"type": "dns-01", "url": url + "/chall/1", "token": "token", "status": "pending"}},
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	url = srv.URL
	// lego's HTTP client trusts exactly the certificates in this file.
	caFile := filepath.Join(t.TempDir(), "acme-server.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caFile)
	return url + "/dir"
}

// TestRunKillsExecDNSProgramsWhenItAbandonsIssuance covers the program of an
// exec DNS provider during shutdown: it keeps running while shutdown waits for
// the issuance that runs it, which may still clean up its records, and is
// killed along with the processes it started when shutdown gives up on that
// issuance.
func TestRunKillsExecDNSProgramsWhenItAbandonsIssuance(t *testing.T) {
	previous := issuanceStopTimeout
	issuanceStopTimeout = 2 * time.Second
	t.Cleanup(func() { issuanceStopTimeout = previous })
	directory := newChallengeCA(t, "api.example.com")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv(testProgramEnv, "spawn")
	t.Setenv(testProgramDirEnv, dir)
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600)
		time.Sleep(200 * time.Millisecond) // let a surviving child see it and exit
	})
	// Otherwise lego looks up CNAMEs of the challenge record in real DNS.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	heartbeat := func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "heartbeat"))
		return string(data)
	}
	alive := func() bool {
		before := heartbeat()
		time.Sleep(300 * time.Millisecond)
		return heartbeat() != before
	}

	path := filepath.Join(privateDir(t), "server.yaml")
	raw := fmt.Sprintf(`server:
  listen: "127.0.0.1:%d"
  data_dir: %q
  ipc_socket: %q
acme:
  email: "ops@example.com"
  default_ca: "fake"
  cas:
    fake:
      directory: %q
dns_providers:
  hook:
    type: "exec"
    command: [%q]
certificates:
  - name: "api-prod"
    domains: ["api.example.com"]
    ca: "fake"
    dns_provider: "hook"
`, freeTCPPort(t), privateDir(t), testIPCSocket(t), directory, exe)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	sink := &lockedBuffer{}
	logs := setupLogs(t, sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, path, logs) }()
	for deadline := time.Now().Add(30 * time.Second); heartbeat() == ""; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the exec DNS program did not run:\n%s", sink.String())
		}
	}

	cancel()
	if !alive() {
		t.Fatal("the exec DNS program was killed as shutdown started, before shutdown gave up on its issuance")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation, want nil", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run waited for the issuance past issuanceStopTimeout")
	}
	time.Sleep(300 * time.Millisecond)
	if alive() {
		t.Fatal("a process the exec DNS program started is still running after Run returned")
	}

	// The abandoned issuance fails once its program is killed, and reports it
	// last. That must happen before the next test captures events.
	waitLogged(t, sink, "certificate issuance failed")
}

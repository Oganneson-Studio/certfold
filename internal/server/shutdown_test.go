package server

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Shutdown waits for a running issuance for issuanceStopTimeout at most, then
// abandons it: lego cannot be interrupted, and a stalled CA or DNS provider
// would otherwise hold a service stop for as long as it stalls.
func TestRunAbandonsIssuanceAfterStopTimeout(t *testing.T) {
	arrived, release := make(chan struct{}), make(chan struct{})
	var arrivedOnce sync.Once
	stalled := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivedOnce.Do(func() { close(arrived) })
		<-release
		http.Error(w, "stalled", http.StatusServiceUnavailable)
	}))
	// Cleanups run last first: the handler returns before Close waits for it.
	t.Cleanup(stalled.Close)
	t.Cleanup(func() { close(release) })
	// lego's HTTP client trusts exactly the certificates in this file.
	caFile := filepath.Join(t.TempDir(), "acme-server.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stalled.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caFile)
	previous := issuanceStopTimeout
	issuanceStopTimeout = time.Second
	t.Cleanup(func() { issuanceStopTimeout = previous })

	path := filepath.Join(t.TempDir(), "server.yaml")
	raw := fmt.Sprintf(`server:
  listen: "127.0.0.1:%d"
  data_dir: %q
  ipc_socket: %q
acme:
  email: "ops@example.com"
  default_ca: "stalled"
  cas:
    stalled:
      directory: %q
dns_providers:
  cf:
    type: "cloudflare"
    api_token: "never-used"
certificates:
  - name: "api-prod"
    domains: ["api.example.com"]
    ca: "stalled"
    dns_provider: "cf"
`, freeTCPPort(t), t.TempDir(), testIPCSocket(t), stalled.URL+"/dir")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := setupLogs(t, io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, path, logs) }()
	select {
	case <-arrived:
		// The scheduler's first issuance now waits for the CA's directory.
	case err := <-result:
		t.Fatalf("Run returned before issuing: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the scheduler did not start issuing")
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run waited for the stalled issuance")
	}
	if e := findEvent(t, logs.Events.Since(0), "certificate issuance abandoned at shutdown"); e.Level != "WARN" || e.Attrs != "certs=api-prod" {
		t.Errorf("abandonment event = %+v, want WARN naming api-prod", e)
	}
}

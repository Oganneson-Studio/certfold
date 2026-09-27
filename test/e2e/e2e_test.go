//go:build e2e

// Package e2e exercises the complete Sigil enrollment and certificate
// distribution path. On Windows it uses WSLC directly; no Compose service or
// fixed container IP addresses are required.
package e2e

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	certPollTimeout  = 60 * time.Second
	certPollInterval = time.Second
)

func TestMain(m *testing.M) {
	rt, err := detectContainerRuntime()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: %v\n", err)
		if runtime.GOOS == "windows" || os.Getenv("SIGIL_E2E_REQUIRED") == "1" {
			os.Exit(1)
		}
		os.Exit(0)
	}

	stack, err = newE2EStack(rt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create e2e stack: %v\n", err)
		os.Exit(1)
	}
	if err := stack.start(); err != nil {
		fmt.Fprintf(os.Stderr, "start e2e stack: %v\n", err)
		stack.cleanup()
		os.Exit(1)
	}

	code := m.Run()
	stack.cleanup()
	os.Exit(code)
}

func TestEnrollFetchAndRevoke(t *testing.T) {
	token := createToken(t, "web-1", "10m")
	out := mustExec(t, stack.clientName, "sigilc", "enroll", "--token", token)
	if !strings.Contains(out, `enrolled as "web-1"`) {
		t.Fatalf("unexpected enroll output:\n%s", out)
	}

	if err := stack.startClientDaemon(); err != nil {
		t.Fatal(err)
	}
	waitForClientDaemon(t)
	mustExec(t, stack.clientName, "sigilc", "fetch", "--cert", "test-cert")

	certPath := stack.certPath("test-cert", "fullchain.pem")
	waitForFile(t, certPath, certPollTimeout)
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("output is not PEM: %q", raw)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse output certificate: %v", err)
	}
	if err := cert.VerifyHostname("test.example.com"); err != nil {
		t.Fatalf("certificate SAN verification: %v", err)
	}

	status := mustExec(t, stack.clientName, "sigilc", "status")
	if !strings.Contains(status, "Certificates : 1") {
		t.Fatalf("client status did not report fetched certificate:\n%s", status)
	}

	mustExec(t, stack.serverName, "sigils", "client", "remove", "web-1")
	out, err = stack.exec(stack.clientName, "sigilc", "fetch", "--cert", "test-cert")
	if err == nil {
		t.Fatalf("revoked client still fetched certificates:\n%s", out)
	}
	if !strings.Contains(out, "401") && !strings.Contains(out, "403") {
		t.Fatalf("revoked client failed for an unexpected reason:\n%s", out)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	token := createToken(t, "expiry-test", "1s")
	time.Sleep(2 * time.Second)
	assertEnrollmentRejected(t, token, "/e2e/client-data/expiry.yaml")
}

func TestRevokedTokenIsRejected(t *testing.T) {
	token := createToken(t, "revoke-test", "10m")
	list := mustExec(t, stack.serverName, "sigils", "token", "list")
	var tokenID string
	for _, line := range strings.Split(list, "\n") {
		if strings.Contains(line, "revoke-test") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				tokenID = fields[0]
			}
			break
		}
	}
	if tokenID == "" {
		t.Fatalf("revoke-test token not found:\n%s", list)
	}
	mustExec(t, stack.serverName, "sigils", "token", "revoke", tokenID)
	assertEnrollmentRejected(t, token, "/e2e/client-data/revoked.yaml")
}

func TestInstallScriptUsesNetworkAlias(t *testing.T) {
	resp, err := insecureHTTPGet(stack.hostServerURL() + "/install.sh")
	if err != nil {
		t.Fatalf("GET /install.sh: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `SERVER_URL="https://sigils:18443"`) {
		t.Fatalf("install script does not use configured public URL:\n%s", body)
	}
	if strings.Contains(string(body), "172.30.0.") {
		t.Fatal("install script still contains a fixed container IP")
	}
}

func createToken(t *testing.T, name, ttl string) string {
	t.Helper()
	out := mustExec(t, stack.serverName,
		"sigils", "token", "create", "--name", name, "--expires", ttl,
	)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Token: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Token: "))
		}
	}
	t.Fatalf("token not found in output:\n%s", out)
	return ""
}

func assertEnrollmentRejected(t *testing.T, token, configPath string) {
	t.Helper()
	out, err := stack.exec(stack.clientName,
		"sigilc", "--config", configPath, "enroll", "--token", token,
	)
	if err == nil {
		t.Fatalf("expected enrollment rejection, got success:\n%s", out)
	}
	if !strings.Contains(out, "401") {
		t.Fatalf("enrollment failed for an unexpected reason:\n%s", out)
	}
}

func mustExec(t *testing.T, container string, args ...string) string {
	t.Helper()
	out, err := stack.exec(container, args...)
	if err != nil {
		t.Fatalf("exec %s %v: %v\n%s", container, args, err, out)
	}
	return out
}

func waitForClientDaemon(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastOutput string
	for time.Now().Before(deadline) {
		out, err := stack.exec(stack.clientName, "sigilc", "status")
		lastOutput = out
		if err == nil && strings.Contains(out, "Client       : web-1") {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("sigilc daemon did not become ready:\n%s\ncontainer logs:\n%s",
		lastOutput, stack.logs(stack.clientName))
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return
		}
		time.Sleep(certPollInterval)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func (s *e2eStack) certPath(parts ...string) string {
	all := append([]string{s.certOutputDir}, parts...)
	return filepath.Join(all...)
}

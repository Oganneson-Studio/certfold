//go:build e2e

// Package e2e exercises the complete Sigil enrollment and certificate
// distribution path. On Windows it uses WSLC directly; no Compose service or
// fixed container IP addresses are required.
package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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

// TestEnrollFetchRenewAndRevoke follows the client of the mini-CA server
// through its life. Each step checks how many times in all test-cert's
// on_change program has run, not whether its own command replaced an output:
// the sync loop reconciles after every answer to GET /v1/sync, so it may
// restore an output before a fetch does.
func TestEnrollFetchRenewAndRevoke(t *testing.T) {
	d := stack.miniCA
	fullchain := testCertOutputs + "/fullchain.pem"
	// step stops the test at the first step that fails: each step builds on
	// the state, and the on_change count, that the steps before it left.
	step := func(name string, f func(t *testing.T)) {
		if !t.Run(name, f) {
			t.FailNow()
		}
	}

	var issued *x509.Certificate
	step("enroll and fetch", func(t *testing.T) {
		issued = enrollAndFetch(t, d)
		status := mustExec(t, d.clientContainer, "sigilc", "status")
		if !strings.Contains(status, "Certificates : 1") {
			t.Fatalf("client status did not report fetched certificate:\n%s", status)
		}
		// The program hashed the fullchain.pem in place, so it ran after the
		// outputs were written.
		runs := hookRuns(t, d)
		if len(runs) != 1 {
			t.Fatalf("on_change ran %d times, want 1", len(runs))
		}
		if sum := strings.Fields(mustExec(t, d.clientContainer, "sha256sum", fullchain))[0]; runs[0] != sum {
			t.Fatalf("on_change logged sha256 %s, but fullchain.pem has %s", runs[0], sum)
		}
	})

	step("last seen", func(t *testing.T) {
		// The mTLS client check records it for the client's requests.
		out := mustExec(t, d.serverContainer, "sigils", "--json", "client", "show", d.clientName)
		var client struct {
			LastSeen *time.Time `json:"last_seen"`
		}
		if err := json.Unmarshal([]byte(out), &client); err != nil {
			t.Fatalf("parse client show: %v\n%s", err, out)
		}
		if client.LastSeen == nil {
			t.Fatalf("server recorded no last_seen for %s:\n%s", d.clientName, out)
		}
	})

	step("fetch again", func(t *testing.T) {
		before := mustExec(t, d.clientContainer, "cat", fullchain)
		mustExec(t, d.clientContainer, "sigilc", "fetch")
		if after := mustExec(t, d.clientContainer, "cat", fullchain); after != before {
			t.Fatal("fetch changed fullchain.pem although the certificate did not change")
		}
		if runs := hookRuns(t, d); len(runs) != 1 {
			t.Fatalf("on_change ran %d times, want still 1", len(runs))
		}
	})

	step("fetch restores deleted output", func(t *testing.T) {
		mustExec(t, d.clientContainer, "rm", fullchain)
		mustExec(t, d.clientContainer, "sigilc", "fetch")
		if leaf := verifyOutput(t, d); leaf.SerialNumber.Cmp(issued.SerialNumber) != 0 {
			t.Fatalf("restored fullchain.pem holds serial %s, want %s", leaf.SerialNumber, issued.SerialNumber)
		}
		if runs := hookRuns(t, d); len(runs) != 2 {
			t.Fatalf("on_change ran %d times, want 2", len(runs))
		}
	})

	step("fetch restores changed output", func(t *testing.T) {
		mustExec(t, d.clientContainer, "sh", "-c", `printf garbage > "$1"`, "sh", testCertOutputs+"/key.pem")
		mustExec(t, d.clientContainer, "sigilc", "fetch")
		verifyOutput(t, d)
		if runs := hookRuns(t, d); len(runs) != 3 {
			t.Fatalf("on_change ran %d times, want 3", len(runs))
		}
	})

	// Before the revocation: the loop backs off once its requests fail, and
	// would restore the output later.
	step("sync loop restores deleted output", func(t *testing.T) {
		mustExec(t, d.clientContainer, "rm", fullchain)
		start := time.Now()
		// No fetch: the loop reconciles after each answer to GET /v1/sync,
		// which an idle client gets at least every 55 seconds. on_change
		// runs once the outputs are in place, so its count shows the round
		// is over.
		runs := hookRuns(t, d)
		for ; len(runs) < 4; runs = hookRuns(t, d) {
			if time.Since(start) > 70*time.Second {
				_, err := stack.exec(d.clientContainer, "test", "-e", fullchain)
				status, _ := stack.exec(d.clientContainer, "sigilc", "status")
				t.Fatalf("on_change ran %d times within 70s of deleting fullchain.pem, want 4; fullchain.pem restored: %t\nclient status:\n%s\nclient logs:\n%s",
					len(runs), err == nil, status, stack.logs(d.clientContainer))
			}
			time.Sleep(time.Second)
		}
		t.Logf("the sync loop restored fullchain.pem %s after it was deleted", time.Since(start).Round(100*time.Millisecond))
		if len(runs) != 4 {
			t.Fatalf("on_change ran %d times, want 4", len(runs))
		}
		verifyOutput(t, d)
	})

	step("reload adds output", func(t *testing.T) {
		der := testCertOutputs + "/cert.der"
		editClientConfig(t, d, func(doc map[string]any) {
			cert := doc["certificates"].(map[string]any)["test-cert"].(map[string]any)
			cert["outputs"] = append(cert["outputs"].([]any), map[string]any{"format": "der", "path": der})
		})
		mustExec(t, d.clientContainer, "sigilc", "reload")
		// Reload reconciles the outputs before it returns.
		if _, err := stack.exec(d.clientContainer, "test", "-s", der); err != nil {
			t.Fatalf("reload returned before it wrote %s", der)
		}
		if runs := hookRuns(t, d); len(runs) != 5 {
			t.Fatalf("on_change ran %d times, want 5", len(runs))
		}
	})

	// This step must directly follow the reload, which has just restarted the
	// loop's GET /v1/sync. Only the scheduler's stored callback wakes that
	// request when the renewed certificate is stored. No unit test covers the
	// callback: without it the request, and this step, would wait the full 55
	// seconds.
	step("sync delivers renewal", func(t *testing.T) {
		fingerprint := certFingerprint(t, d)
		mustExec(t, d.serverContainer, "sigils", "cert", "renew", "test-cert")
		start := time.Now()
		// The client has no periodic pull and this step runs no fetch, so
		// only GET /v1/sync can deliver the renewal. on_change runs once all
		// outputs are replaced.
		runs := hookRuns(t, d)
		for ; len(runs) < 6; runs = hookRuns(t, d) {
			if time.Since(start) > 15*time.Second {
				status, _ := stack.exec(d.clientContainer, "sigilc", "status", "--json")
				t.Fatalf("on_change ran %d times within 15s of the renewal, want 6; the server lists fingerprint %s\nclient status:\n%s\nclient logs:\n%s",
					len(runs), certFingerprint(t, d), status, stack.logs(d.clientContainer))
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Logf("sync delivered the renewal %s after sigils cert renew returned", time.Since(start).Round(100*time.Millisecond))
		if len(runs) != 6 {
			t.Fatalf("on_change ran %d times, want 6", len(runs))
		}
		if renewed := certFingerprint(t, d); renewed == fingerprint {
			t.Fatalf("cert list still shows fingerprint %s after renewal", fingerprint)
		}
		if leaf := verifyOutput(t, d); leaf.SerialNumber.Cmp(issued.SerialNumber) == 0 {
			t.Fatalf("fullchain.pem still holds serial %s after renewal", issued.SerialNumber)
		}
		if sum := strings.Fields(mustExec(t, d.clientContainer, "sha256sum", fullchain))[0]; runs[5] != sum {
			t.Fatalf("on_change last logged sha256 %s, but the renewed fullchain.pem has %s", runs[5], sum)
		}
	})

	step("server reload wakes sync", func(t *testing.T) {
		// Subscribe the client to test-cert-2. Subscribers are not part of
		// the spec fingerprint, so the server keeps the certificate it has.
		path := d.hostPath("server.yaml")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("parse server.yaml: %v", err)
		}
		for _, cert := range cfg["certificates"].([]any) {
			if cert := cert.(map[string]any); cert["name"] == "test-cert-2" {
				cert["subscribers"] = []string{d.clientName}
			}
		}
		if raw, err = yaml.Marshal(cfg); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		mustExec(t, d.serverContainer, "sigils", "reload")
		start := time.Now()
		for {
			out := mustExec(t, d.clientContainer, "sigilc", "status", "--json")
			var status struct {
				Certs []struct {
					Name string `json:"name"`
				} `json:"certs"`
			}
			if err := json.Unmarshal([]byte(out), &status); err != nil {
				t.Fatalf("parse client status: %v\n%s", err, out)
			}
			delivered := false
			for _, cert := range status.Certs {
				delivered = delivered || cert.Name == "test-cert-2"
			}
			if delivered {
				break
			}
			if time.Since(start) > 15*time.Second {
				t.Fatalf("client did not get test-cert-2 within 15s of the server reload; client status:\n%s", out)
			}
			time.Sleep(500 * time.Millisecond)
		}
		// client.yaml has no outputs and no on_change for test-cert-2.
		if runs := hookRuns(t, d); len(runs) != 6 {
			t.Fatalf("on_change ran %d times, want still 6", len(runs))
		}
	})

	step("revoke", func(t *testing.T) {
		mustExec(t, d.serverContainer, "sigils", "client", "remove", d.clientName)
		out, err := stack.exec(d.clientContainer, "sigilc", "fetch", "--cert", "test-cert")
		if err == nil {
			t.Fatalf("revoked client still fetched certificates:\n%s", out)
		}
		if !strings.Contains(out, "401") && !strings.Contains(out, "403") {
			t.Fatalf("revoked client failed for an unexpected reason:\n%s", out)
		}
	})
}

// TestPublicTLSEnrollAndFetch covers a server that presents a publicly trusted
// server.tls_cert_file: the client trusts it through the system roots, both
// to enroll and for every pull after enrollment.
func TestPublicTLSEnrollAndFetch(t *testing.T) {
	enrollAndFetch(t, stack.publicTLS)
}

// TestIssuanceUsesDNSResolvers checks that the servers looked up every
// challenge name through acme.dns_resolvers. Only lego sends CNAME queries,
// which follow CNAMEs of the name; pebble queries TXT records alone. The first
// issuance always solves a challenge, while a later one may reuse the
// authorization.
func TestIssuanceUsesDNSResolvers(t *testing.T) {
	const typeCNAME = 5
	for _, d := range stack.deployments() {
		for _, cert := range d.certs {
			name := "_acme-challenge." + cert.domain
			types, err := stack.dnsQueryTypes(name)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(types, typeCNAME) {
				t.Errorf("%s: challtestsrv received no CNAME query for %s, only query types %v", d.alias, name, types)
			}
		}
	}
}

// enrollAndFetch enrolls the client of d, starts its daemon, and checks that a
// fetch writes test-cert as pebble issued it. It returns the certificate.
func enrollAndFetch(t *testing.T, d *deployment) *x509.Certificate {
	t.Helper()
	token := createToken(t, d, d.clientName, "10m")
	out := mustExec(t, d.clientContainer, "sigilc", "enroll", "--token", token)
	if !strings.Contains(out, fmt.Sprintf("enrolled as %q", d.clientName)) {
		t.Fatalf("unexpected enroll output:\n%s", out)
	}

	if err := stack.startClientDaemon(d); err != nil {
		t.Fatal(err)
	}
	waitForClientDaemon(t, d)
	// The fetch returns once the outputs are written.
	mustExec(t, d.clientContainer, "sigilc", "fetch", "--cert", "test-cert")
	return verifyOutput(t, d)
}

// verifyOutput checks the test-cert output of the client of d: a chain from
// the root pebble issues from to a certificate for test-cert's domain, and
// the key of that certificate. It returns the certificate. The outputs are
// in the client container, so they are read there.
func verifyOutput(t *testing.T, d *deployment) *x509.Certificate {
	t.Helper()
	chainPEM := []byte(mustExec(t, d.clientContainer, "cat", testCertOutputs+"/fullchain.pem"))
	var chain []*x509.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse output certificate: %v", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		t.Fatalf("output is not PEM: %q", chainPEM)
	}
	roots, err := stack.pebbleIssuingRoots()
	if err != nil {
		t.Fatal(err)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	leaf, domain := chain[0], d.certs[0].domain
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       domain,
		Roots:         roots,
		Intermediates: intermediates,
		// pebble does not backdate certificates, and the host clock may lag
		// the clock of the containers.
		CurrentTime: leaf.NotBefore,
	}); err != nil {
		t.Fatalf("output is not a certificate pebble issued for %s: %v", domain, err)
	}
	keyPEM := mustExec(t, d.clientContainer, "cat", testCertOutputs+"/key.pem")
	if _, err := tls.X509KeyPair(chainPEM, []byte(keyPEM)); err != nil {
		t.Fatalf("key output does not belong to the certificate output: %v", err)
	}
	return leaf
}

// certFingerprint returns the fingerprint of test-cert that the server of d
// lists.
func certFingerprint(t *testing.T, d *deployment) string {
	t.Helper()
	out := mustExec(t, d.serverContainer, "sigils", "--json", "cert", "list")
	var certs []certState
	if err := json.Unmarshal([]byte(out), &certs); err != nil {
		t.Fatalf("parse cert list: %v\n%s", err, out)
	}
	for _, cert := range certs {
		if cert.Name == "test-cert" && cert.Fingerprint != "" {
			return cert.Fingerprint
		}
	}
	t.Fatalf("cert list has no fingerprint for test-cert:\n%s", out)
	return ""
}

// hookRuns returns the sha256 that each run of test-cert's on_change program
// logged to hook.log of d, oldest first. The program runs as the container's
// root, so the log is read in the client container.
func hookRuns(t *testing.T, d *deployment) []string {
	t.Helper()
	// sha256sum ends each line with a newline, so the last element is empty
	// or a line still being written.
	lines := strings.Split(mustExec(t, d.clientContainer, "cat", d.containerPath("hook.log")), "\n")
	runs := make([]string, 0, len(lines)-1)
	for _, line := range lines[:len(lines)-1] {
		sum, _, _ := strings.Cut(line, " ")
		runs = append(runs, sum)
	}
	return runs
}

// editClientConfig applies edit to the client.yaml of d. Enrollment rewrote
// that file as the container's root with mode 0600, so it is read and written
// in the client container; the shell's > keeps its owner and mode.
func editClientConfig(t *testing.T, d *deployment, edit func(doc map[string]any)) {
	t.Helper()
	path := d.containerPath("client-data", "client.yaml")
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(mustExec(t, d.clientContainer, "cat", path)), &doc); err != nil {
		t.Fatalf("parse client.yaml: %v", err)
	}
	edit(doc)
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, d.clientContainer, "sh", "-c", `printf %s "$1" | base64 -d > "$2"`, "sh",
		base64.StdEncoding.EncodeToString(data), path)
}

func TestExpiredTokenIsRejected(t *testing.T) {
	token := createToken(t, stack.miniCA, "expiry-test", "1s")
	time.Sleep(2 * time.Second)
	assertEnrollmentRejected(t, stack.miniCA, token, "expiry.yaml")
}

func TestRevokedTokenIsRejected(t *testing.T) {
	d := stack.miniCA
	token := createToken(t, d, "revoke-test", "10m")
	list := mustExec(t, d.serverContainer, "sigils", "token", "list")
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
	mustExec(t, d.serverContainer, "sigils", "token", "revoke", tokenID)
	assertEnrollmentRejected(t, d, token, "revoked.yaml")
}

func TestInstallScriptUsesNetworkAlias(t *testing.T) {
	resp, err := insecureHTTPGet(stack.miniCA.hostURL() + "/install.sh")
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

func createToken(t *testing.T, d *deployment, name, ttl string) string {
	t.Helper()
	out := mustExec(t, d.serverContainer,
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

// assertEnrollmentRejected enrolls in the client container of d with a fresh
// client-data/<configName>, so the running daemon's identity is untouched.
func assertEnrollmentRejected(t *testing.T, d *deployment, token, configName string) {
	t.Helper()
	out, err := stack.exec(d.clientContainer,
		"sigilc", "--config", d.containerPath("client-data", configName), "enroll", "--token", token,
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

func waitForClientDaemon(t *testing.T, d *deployment) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastOutput string
	for time.Now().Before(deadline) {
		out, err := stack.exec(d.clientContainer, "sigilc", "status")
		lastOutput = out
		if err == nil && strings.Contains(out, "Client       : "+d.clientName) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("sigilc daemon did not become ready:\n%s\ncontainer logs:\n%s",
		lastOutput, stack.logs(d.clientContainer))
}

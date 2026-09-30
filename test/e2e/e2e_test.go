//go:build e2e

// Package e2e exercises the complete Sigil enrollment and certificate
// distribution path. On Windows it uses WSLC directly; no Compose service or
// fixed container IP addresses are required.
package e2e

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
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

	step("events of the renewal", func(t *testing.T) {
		// The server issued test-cert when it started and again for the
		// renewal.
		events := serverEvents(t, d)
		if n := certEvents(events, "certificate issued", "test-cert"); n < 2 {
			t.Errorf("the server has %d certificate issued events for test-cert, want at least 2:\n%s", n, formatEvents(events))
		}
		if certEvents(events, "manual renewal requested", "test-cert") == 0 {
			t.Errorf("the server has no manual renewal requested event for test-cert:\n%s", formatEvents(events))
		}
		events = clientEvents(t, d)
		for _, message := range []string{"outputs rewritten", "on_change succeeded"} {
			if certEvents(events, message, "test-cert") == 0 {
				t.Errorf("the client has no %s event for test-cert:\n%s", message, formatEvents(events))
			}
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

// TestRenewalTimeFollowsTheCAWindow checks that both servers asked pebble for
// the renewal window of test-cert (RFC 9773) and renew it within the window.
func TestRenewalTimeFollowsTheCAWindow(t *testing.T) {
	for _, d := range stack.deployments() {
		t.Run(d.alias, func(t *testing.T) { waitForCAWindow(t, d) })
	}
}

// TestARIDirectedRenewal has pebble answer that test-cert of the public TLS
// server is due now, as a CA does when it revokes certificates. After a reload
// the server asks again, renews at once naming the certificate it replaces,
// and the client, whose daemon TestPublicTLSEnrollAndFetch started, gets the
// new one.
func TestARIDirectedRenewal(t *testing.T) {
	d := stack.publicTLS
	// The server must have the usual window of the certificate first: a first
	// window that has passed would count as a CA error, to be retried after a
	// backoff.
	before := waitForCAWindow(t, d)
	block, _ := pem.Decode([]byte(mustExec(t, d.clientContainer, "cat", testCertOutputs+"/fullchain.pem")))
	if block == nil {
		t.Fatal("fullchain.pem of the client holds no PEM block")
	}
	// Pebble returns the response as is, with a Retry-After of 6 hours. The
	// times must be RFC 3339 with a zone, and end after start: RenewalInfo
	// rejects any other window, and the plan would stay with pebble's usual
	// one.
	now := time.Now().UTC().Truncate(time.Second)
	windowStart, windowEnd := now.Add(-2*time.Hour), now.Add(-time.Hour)
	body, err := json.Marshal(map[string]string{
		"Certificate": string(pem.EncodeToMemory(block)),
		"ARIResponse": fmt.Sprintf(`{"suggestedWindow":{"start":%q,"end":%q}}`,
			windowStart.Format(time.RFC3339), windowEnd.Format(time.RFC3339)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The manual renewal of TestEnrollFetchRenewAndRevoke replaced a
	// certificate as well.
	replacements := strings.Count(stack.logs(stack.pebbleContainer), "is a replacement of")
	client := &http.Client{Timeout: 10 * time.Second, Transport: stack.pebbleTransport()}
	resp, err := client.Post(fmt.Sprintf("https://127.0.0.1:%d/set-renewal-info/", stack.pebbleAdminPort),
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("set pebble's renewal info: %v", err)
	}
	answer, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set pebble's renewal info: status %d: %s", resp.StatusCode, answer)
	}

	// A reload has the server ask again at once.
	mustExec(t, d.serverContainer, "sigils", "reload")
	start := time.Now()
	renewed := testCertState(t, d)
	for ; renewed.Fingerprint == before.Fingerprint || renewed.Fingerprint == ""; renewed = testCertState(t, d) {
		if time.Since(start) > 30*time.Second {
			t.Fatalf("test-cert was not renewed within 30s of the reload; cert list shows %+v\nserver logs:\n%s",
				renewed, stack.logs(d.serverContainer))
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("the server renewed test-cert %s after the reload", time.Since(start).Round(100*time.Millisecond))
	if n := strings.Count(stack.logs(stack.pebbleContainer), "is a replacement of"); n <= replacements {
		t.Fatalf("pebble logged no new replacement order: the renewal did not name the certificate it replaces")
	}

	events := serverEvents(t, d)
	for _, want := range []struct{ message, attrs string }{
		{"renewal window updated", "cert=test-cert window_start=" + eventTime(windowStart) + " window_end=" + eventTime(windowEnd) + " "},
		{"certificate issuance started", "cert=test-cert reason=ari"},
		{"certificate issued", "cert=test-cert "},
	} {
		if !slices.ContainsFunc(events, func(e daemonEvent) bool {
			return e.Message == want.message && strings.HasPrefix(e.Attrs+" ", want.attrs) &&
				(want.message != "certificate issued" || strings.HasSuffix(e.Attrs, " replacing=true"))
		}) {
			t.Errorf("no event %q with %q among the events of %s:\n%s", want.message, want.attrs, d.alias, formatEvents(events))
		}
	}

	start = time.Now()
	for {
		out := mustExec(t, d.clientContainer, "sigilc", "status", "--json")
		var status struct {
			Certs []struct{ Name, Fingerprint string } `json:"certs"`
		}
		if err := json.Unmarshal([]byte(out), &status); err != nil {
			t.Fatalf("parse client status: %v\n%s", err, out)
		}
		if slices.ContainsFunc(status.Certs, func(c struct{ Name, Fingerprint string }) bool {
			return c.Name == "test-cert" && c.Fingerprint == renewed.Fingerprint
		}) {
			break
		}
		if time.Since(start) > 15*time.Second {
			t.Fatalf("client did not get the renewed test-cert within 15s; client status:\n%s", out)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Pebble answers with the usual window for the new certificate.
	if after := waitForCAWindow(t, d); after.Fingerprint != renewed.Fingerprint {
		t.Fatalf("cert list shows fingerprint %s, want the renewed %s", after.Fingerprint, renewed.Fingerprint)
	}
}

// testCertState returns what the server of d lists for test-cert.
func testCertState(t *testing.T, d *deployment) certState {
	t.Helper()
	out := mustExec(t, d.serverContainer, "sigils", "--json", "cert", "list")
	var certs []certState
	if err := json.Unmarshal([]byte(out), &certs); err != nil {
		t.Fatalf("parse cert list: %v\n%s", err, out)
	}
	for _, cert := range certs {
		if cert.Name == "test-cert" {
			return cert
		}
	}
	t.Fatalf("cert list has no test-cert:\n%s", out)
	return certState{}
}

// waitForCAWindow waits until the server of d renews test-cert at a time from
// the renewal window pebble suggests, and returns what it lists for test-cert.
// The server asks for the window once it has stored the certificate. Pebble's
// window spans the 24 hours around the point a third of the lifetime before
// expiry: 30 days for its 90-day certificates.
func waitForCAWindow(t *testing.T, d *deployment) certState {
	t.Helper()
	start := time.Now()
	cert := testCertState(t, d)
	for ; cert.RenewSource != "ari"; cert = testCertState(t, d) {
		if time.Since(start) > 15*time.Second {
			t.Fatalf("%s does not renew test-cert as its CA suggests within 15s; cert list shows %+v\nserver logs:\n%s",
				d.alias, cert, stack.logs(d.serverContainer))
		}
		time.Sleep(500 * time.Millisecond)
	}
	day := 24 * time.Hour
	if left := cert.NotAfter.Sub(cert.RenewAt); left < 29*day-time.Minute || left > 31*day+time.Minute {
		t.Fatalf("%s renews test-cert at %s, %s before it expires at %s; want 29 to 31 days", d.alias, cert.RenewAt, left, cert.NotAfter)
	}
	if !cert.RenewAt.After(cert.IssuedAt) {
		t.Fatalf("%s renews test-cert at %s, not after it was issued at %s", d.alias, cert.RenewAt, cert.IssuedAt)
	}
	return cert
}

func formatEvents(events []daemonEvent) string {
	var b strings.Builder
	for _, e := range events {
		fmt.Fprintf(&b, "  %s %s %s\n", e.Level, e.Message, e.Attrs)
	}
	return b.String()
}

// certEvents returns how many of events have message and are about the
// certificate named cert, which every such event names first.
func certEvents(events []daemonEvent, message, cert string) int {
	n := 0
	for _, e := range events {
		if e.Message == message && strings.HasPrefix(e.Attrs+" ", "cert="+cert+" ") {
			n++
		}
	}
	return n
}

// eventTime formats t as events show a time.
func eventTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// TestPublicTLSCertificateReload replaces the server.tls_cert_file and key of
// the public TLS server from the host, and checks that new connections get
// the new certificate without a restart. It needs the client daemon that
// TestPublicTLSEnrollAndFetch started.
func TestPublicTLSCertificateReload(t *testing.T) {
	d := stack.publicTLS
	serial := big.NewInt(3)
	// Both files are written, and closed, before the first new connection.
	if err := writeServerTLS(d.hostPath("tls"), d.alias, serial, d.publicRoot, d.publicRootKey); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for {
		got, err := servedSerial(d)
		if err == nil && got.Cmp(serial) == 0 {
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatalf("server presents serial %v (error %v) 10s after its files were replaced, want %s\nserver logs:\n%s",
				got, err, serial, stack.logs(d.serverContainer))
		}
		time.Sleep(200 * time.Millisecond)
	}
	// The server reloaded once: the harness connects only after both files
	// are written, and the client daemon keeps its connection alive, so no
	// handshake came while they were being written.
	var reloads []daemonEvent
	for _, e := range serverEvents(t, d) {
		if e.Message == "server TLS certificate reloaded" {
			reloads = append(reloads, e)
		}
	}
	if len(reloads) != 1 || reloads[0].Level != "INFO" || !strings.HasPrefix(reloads[0].Attrs, "not_after=") {
		t.Fatalf("server TLS certificate reloaded events: %+v, want one at INFO with not_after", reloads)
	}
	// The client trusts the new certificate through the same root.
	mustExec(t, d.clientContainer, "sigilc", "fetch")
}

// daemonEvent is an entry of `sigils --json events` or `sigilc events --json`.
type daemonEvent struct {
	Level   string `json:"level"`
	Message string `json:"message"`
	Attrs   string `json:"attrs"`
}

// serverEvents returns the events that the server of d keeps, oldest first.
func serverEvents(t *testing.T, d *deployment) []daemonEvent {
	t.Helper()
	return daemonEvents(t, d.serverContainer, "sigils", "--json", "events")
}

// clientEvents returns the events that the client daemon of d keeps, oldest
// first.
func clientEvents(t *testing.T, d *deployment) []daemonEvent {
	t.Helper()
	return daemonEvents(t, d.clientContainer, "sigilc", "events", "--json")
}

// daemonEvents runs command, the events command of a daemon, in container and
// returns the events it prints.
func daemonEvents(t *testing.T, container string, command ...string) []daemonEvent {
	t.Helper()
	out := mustExec(t, container, command...)
	var events []daemonEvent
	if err := json.Unmarshal([]byte(out), &events); err != nil {
		t.Fatalf("parse events: %v\n%s", err, out)
	}
	return events
}

// servedSerial returns the serial of the certificate that the server of d
// presents to a new connection.
func servedSerial(d *deployment) (*big.Int, error) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: d.readinessTransport()}
	defer client.CloseIdleConnections()
	resp, err := client.Get(d.hostURL() + "/install.sh")
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return resp.TLS.PeerCertificates[0].SerialNumber, nil
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
// user, so the log is read in the client container.
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
// that file as the container's user with mode 0600, so it is read and written
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

// TestRemovingMissingClientOrTokenFails checks that sigils fails with the
// reason of the daemon for a client name or token ID that does not exist,
// such as a mistyped one, instead of reporting a removal that did not happen.
func TestRemovingMissingClientOrTokenFails(t *testing.T) {
	missingToken := strings.Repeat("0", 32)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"client", "remove", "no-such-client"}, `server returned 404: client "no-such-client" is not enrolled`},
		{[]string{"token", "revoke", missingToken}, `server returned 404: enrollment token "` + missingToken + `" does not exist`},
	} {
		out, err := stack.exec(stack.miniCA.serverContainer, append([]string{"sigils"}, tc.args...)...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("sigils %s: error %v, output:\n%s\nwant it to fail with %s", strings.Join(tc.args, " "), err, out, tc.want)
		}
	}
}

func TestInstallScriptUsesNetworkAlias(t *testing.T) {
	sh := getInstallScript(t, "/install.sh")
	if !strings.Contains(sh, `SERVER_URL="https://sigils:18443"`) {
		t.Fatalf("install.sh does not use configured public URL:\n%s", sh)
	}
	if strings.Contains(sh, "172.30.0.") {
		t.Fatal("install.sh still contains a fixed container IP")
	}

	// install.ps1 is the same for every request: the token is the -Token
	// argument of the command that runs it, or PowerShell asks for it.
	ps1 := getInstallScript(t, "/install.ps1")
	for _, want := range []string{
		`$ServerURL = 'https://sigils:18443'`,
		`[Parameter(Mandatory = $true, ParameterSetName = 'Install')][string]$Token,`,
	} {
		if !strings.Contains(ps1, want) {
			t.Errorf("install.ps1 lacks %s:\n%s", want, ps1)
		}
	}
	if withToken := getInstallScript(t, "/install.ps1?token=zzz"); withToken != ps1 {
		t.Errorf("install.ps1?token=zzz differs from install.ps1:\n%s", withToken)
	}
}

// getInstallScript returns the body of GET path from the mini-CA server.
func getInstallScript(t *testing.T, path string) string {
	t.Helper()
	resp, err := insecureHTTPGet(stack.miniCA.hostURL() + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, resp.StatusCode, body)
	}
	return string(body)
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

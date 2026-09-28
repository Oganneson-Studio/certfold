//go:build e2e

// Package e2e exercises the complete Sigil enrollment and certificate
// distribution path. On Windows it uses WSLC directly; no Compose service or
// fixed container IP addresses are required.
package e2e

import (
	"crypto/tls"
	"crypto/x509"
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

func TestEnrollFetchRenewAndRevoke(t *testing.T) {
	d := stack.miniCA
	issued := enrollAndFetch(t, d)

	status := mustExec(t, d.clientContainer, "sigilc", "status")
	if !strings.Contains(status, "Certificates : 1") {
		t.Fatalf("client status did not report fetched certificate:\n%s", status)
	}

	// A manual renewal issues a new certificate, which the next fetch writes.
	fingerprint := certFingerprint(t, d)
	mustExec(t, d.serverContainer, "sigils", "cert", "renew", "test-cert")
	if renewed := certFingerprint(t, d); renewed == fingerprint {
		t.Fatalf("cert list still shows fingerprint %s after renewal", fingerprint)
	}
	mustExec(t, d.clientContainer, "sigilc", "fetch", "--cert", "test-cert")
	if renewed := verifyOutput(t, d); renewed.SerialNumber.Cmp(issued.SerialNumber) == 0 {
		t.Fatalf("client output still holds serial %s after renewal and fetch", issued.SerialNumber)
	}

	mustExec(t, d.serverContainer, "sigils", "client", "remove", d.clientName)
	out, err := stack.exec(d.clientContainer, "sigilc", "fetch", "--cert", "test-cert")
	if err == nil {
		t.Fatalf("revoked client still fetched certificates:\n%s", out)
	}
	if !strings.Contains(out, "401") && !strings.Contains(out, "403") {
		t.Fatalf("revoked client failed for an unexpected reason:\n%s", out)
	}
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

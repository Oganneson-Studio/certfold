//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const startupTimeout = 2 * time.Minute

type containerRuntime struct {
	path string
	name string
}

type e2eStack struct {
	runtime     containerRuntime
	rootDir     string
	network     string
	serverImage string
	clientImage string
	pebbleImage string
	// mountDir is the host directory every container mounts at /e2e. It is
	// the same in every run, because a WSLC session can mount only 15
	// distinct host paths; each run keeps its files in its own runDir in it.
	mountDir string
	runDir   string
	// Both servers issue their certificates from pebble, an ACME test CA.
	// Their exec DNS provider sets the challenge records in challtestsrv,
	// which answers the DNS lookups of pebble and of the servers. The host
	// reaches both through ports published on 127.0.0.1.
	pebbleContainer       string
	challtestsrvContainer string
	pebblePort            int // ACME API
	pebbleAdminPort       int // management API, which serves pebble's issuing root
	challtestsrvPort      int // management API
	// pebbleTLSRoot signs the certificate pebble serves. The certificates
	// pebble issues chain to another root, which it generates at startup.
	pebbleTLSRoot *x509.Certificate
	// miniCA's server presents its default mini-CA certificate. publicTLS's
	// server presents server.tls_cert_file, signed by a test root that its
	// client trusts through the system roots, as it would a public CA.
	miniCA    *deployment
	publicTLS *deployment
}

// deployment is one sigils server and the sigilc client enrolled with it.
// Its files live in hostDir, which its containers see as containerDir, except
// the client's outputs, which stay in the client container.
type deployment struct {
	hostDir         string
	containerDir    string
	alias           string // server network alias and public_url host
	clientName      string
	serverContainer string
	clientContainer string
	serverPort      int
	// publicRoot signs the server's tls_cert_file; nil for a mini-CA server.
	publicRoot *x509.Certificate
	// certs are the certificates the server issues; the client subscribes to
	// the first, test-cert. Each has a domain of its own: challtestsrv's
	// clear-txt removes every value of a name, so issuances for one domain
	// running at once would remove each other's challenge record.
	certs []certificate
}

// certificate is a certificate in a server's configuration.
type certificate struct {
	name   string
	domain string
}

// testCertOutputs is the directory of test-cert's outputs in a client
// container. It is not in the bind mount: WSLC reports every file there as
// mode 0777 whatever chmod sets, so the client would find the modes of its
// outputs wrong in every reconcile and set them again, in vain.
const testCertOutputs = "/cert-output/test-cert"

var stack *e2eStack

func detectContainerRuntime() (containerRuntime, error) {
	if configured := strings.TrimSpace(os.Getenv("SIGIL_CONTAINER_CLI")); configured != "" {
		path, err := exec.LookPath(configured)
		if err != nil {
			return containerRuntime{}, fmt.Errorf("find %s: %w", configured, err)
		}
		name := runtimeName(path)
		if runtime.GOOS == "windows" && name != "wslc" {
			return containerRuntime{}, fmt.Errorf("Windows e2e requires WSLC, got %s", name)
		}
		return containerRuntime{path: path, name: name}, nil
	}
	if path, err := exec.LookPath("wslc"); err == nil {
		return containerRuntime{path: path, name: "wslc"}, nil
	}
	if runtime.GOOS == "windows" {
		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		path := filepath.Join(programFiles, "WSL", "wslc.exe")
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return containerRuntime{path: path, name: "wslc"}, nil
		}
	}
	if runtime.GOOS != "windows" {
		if path, err := exec.LookPath("docker"); err == nil {
			return containerRuntime{path: path, name: "docker"}, nil
		}
	}
	return containerRuntime{}, fmt.Errorf("WSLC is required on Windows; set SIGIL_CONTAINER_CLI explicitly on other platforms")
}

func runtimeName(path string) string {
	name := strings.TrimSuffix(strings.ToLower(filepath.Base(path)), filepath.Ext(path))
	if strings.Contains(name, "wslc") {
		return "wslc"
	}
	return name
}

func newE2EStack(rt containerRuntime) (*e2eStack, error) {
	rootDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return nil, err
	}
	mountDir := filepath.Join(os.TempDir(), "sigil-wslc-e2e")
	if err := os.MkdirAll(mountDir, 0o700); err != nil {
		return nil, err
	}
	runDir, err := os.MkdirTemp(mountDir, "run-")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*e2eStack, error) {
		_ = os.RemoveAll(runDir)
		return nil, err
	}
	suffix := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().Unix())
	s := &e2eStack{
		runtime:               rt,
		rootDir:               rootDir,
		mountDir:              mountDir,
		runDir:                runDir,
		network:               "sigil-e2e-" + suffix,
		serverImage:           "sigil-e2e-sigils:" + suffix,
		clientImage:           "sigil-e2e-sigilc:" + suffix,
		pebbleImage:           "sigil-e2e-pebble:" + suffix,
		pebbleContainer:       "sigil-e2e-pebble-" + suffix,
		challtestsrvContainer: "sigil-e2e-challtestsrv-" + suffix,
	}
	ports, err := availablePorts(5)
	if err != nil {
		return fail(err)
	}
	s.pebblePort, s.pebbleAdminPort, s.challtestsrvPort = ports[2], ports[3], ports[4]
	if s.miniCA, err = s.newDeployment("minica", "sigils", "web-1", suffix, ports[0]); err != nil {
		return fail(err)
	}
	// No client subscribes to test-cert-2. It makes the first tick of the
	// mini-CA server issue two certificates at once for a new ACME account.
	s.miniCA.certs = append(s.miniCA.certs, certificate{name: "test-cert-2", domain: "second.sigils.example.com"})
	if s.publicTLS, err = s.newDeployment("public", "sigils-public", "web-public", suffix, ports[1]); err != nil {
		return fail(err)
	}
	if err := s.writeFixtures(); err != nil {
		return fail(err)
	}
	return s, nil
}

func (s *e2eStack) newDeployment(dir, alias, clientName, suffix string, port int) (*deployment, error) {
	d := &deployment{
		hostDir:         filepath.Join(s.runDir, dir),
		containerDir:    s.containerPath(dir),
		alias:           alias,
		clientName:      clientName,
		serverContainer: "sigil-e2e-" + alias + "-" + suffix,
		clientContainer: "sigil-e2e-" + clientName + "-" + suffix,
		serverPort:      port,
		certs:           []certificate{{name: "test-cert", domain: alias + ".example.com"}},
	}
	for _, sub := range []string{"server-data", "client-data"} {
		if err := os.MkdirAll(d.hostPath(sub), 0o700); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (s *e2eStack) deployments() []*deployment {
	return []*deployment{s.miniCA, s.publicTLS}
}

func (s *e2eStack) start() error {
	if out, err := s.run("network", "create", s.network); err != nil {
		return fmt.Errorf("create network: %w\n%s", err, out)
	}
	fmt.Printf("E2E: building sigils with %s\n", s.runtime.name)
	if out, err := s.runInRoot("build", "-f", "test/e2e/Dockerfile.sigils", "-t", s.serverImage, "."); err != nil {
		return fmt.Errorf("build sigils: %w\n%s", err, out)
	}
	fmt.Printf("E2E: building sigilc with %s\n", s.runtime.name)
	if out, err := s.runInRoot("build", "-f", "test/e2e/Dockerfile.sigilc", "-t", s.clientImage, "."); err != nil {
		return fmt.Errorf("build sigilc: %w\n%s", err, out)
	}
	fmt.Printf("E2E: building pebble with %s\n", s.runtime.name)
	if out, err := s.runInRoot("build", "-f", "test/e2e/Dockerfile.pebble", "-t", s.pebbleImage, "."); err != nil {
		return fmt.Errorf("build pebble: %w\n%s", err, out)
	}
	if err := s.startACME(); err != nil {
		return err
	}
	for _, d := range s.deployments() {
		if err := s.startServer(d); err != nil {
			return err
		}
		if err := s.runClient(d, true); err != nil {
			return err
		}
	}
	return nil
}

// startACME starts challtestsrv and pebble and waits until the host reaches
// both. A server started before them would fail its first issuance and wait
// out the retry backoff.
func (s *e2eStack) startACME() error {
	// challtestsrv serves only DNS on port 8053 and its management API.
	args := []string{
		"run", "-d",
		"--name", s.challtestsrvContainer,
		"--network", s.network,
		"--network-alias", "challtestsrv",
		"-p", fmt.Sprintf("127.0.0.1:%d:8055", s.challtestsrvPort),
		"--entrypoint", "pebble-challtestsrv",
		s.pebbleImage,
		"-http01=", "-https01=", "-tlsalpn01=", "-doh=", "-defaultIPv6=",
	}
	if out, err := s.run(args...); err != nil {
		return fmt.Errorf("start challtestsrv: %w\n%s", err, out)
	}
	args = []string{
		"run", "-d",
		"--name", s.pebbleContainer,
		"--network", s.network,
		"--network-alias", "pebble",
		"-p", fmt.Sprintf("127.0.0.1:%d:14000", s.pebblePort),
		"-p", fmt.Sprintf("127.0.0.1:%d:15000", s.pebbleAdminPort),
		// Validate challenges without a random delay, and accept every
		// valid nonce, so issuance takes seconds.
		"-e", "PEBBLE_VA_NOSLEEP=1",
		"-e", "PEBBLE_WFE_NONCEREJECT=0",
		"-v", bindMount(s.mountDir, "/e2e", false),
		s.pebbleImage,
		"-config", s.containerPath("pebble", "pebble-config.json"),
		"-dnsserver", "challtestsrv:8053",
	}
	if out, err := s.run(args...); err != nil {
		return fmt.Errorf("start pebble: %w\n%s", err, out)
	}
	// Any response, such as 404 for "/", means the management API is up.
	challtestsrv := fmt.Sprintf("http://127.0.0.1:%d/", s.challtestsrvPort)
	if err := waitForHTTP(challtestsrv, &http.Transport{}, startupTimeout); err != nil {
		return fmt.Errorf("wait for challtestsrv: %w\n%s", err, s.logs(s.challtestsrvContainer))
	}
	pebble := fmt.Sprintf("https://127.0.0.1:%d/dir", s.pebblePort)
	if err := waitForHTTP(pebble, s.pebbleTransport(), startupTimeout); err != nil {
		return fmt.Errorf("wait for pebble: %w\n%s", err, s.logs(s.pebbleContainer))
	}
	return nil
}

func (s *e2eStack) startServer(d *deployment) error {
	args := []string{
		"run", "-d",
		"--name", d.serverContainer,
		"--network", s.network,
		"--network-alias", d.alias,
		"-p", fmt.Sprintf("127.0.0.1:%d:18443", d.serverPort),
		"-e", "SIGILS_CONFIG=" + d.containerPath("server.yaml"),
		// lego trusts pebble's certificate through this root, the way a
		// server trusts any private ACME CA.
		"-e", "LEGO_CA_CERTIFICATES=" + s.containerPath("pebble", "root.pem"),
		"-v", bindMount(s.mountDir, "/e2e", false),
		s.serverImage,
	}
	if out, err := s.run(args...); err != nil {
		return fmt.Errorf("start %s: %w\n%s", d.alias, err, out)
	}
	if err := waitForHTTP(d.hostURL()+"/install.sh", d.readinessTransport(), startupTimeout); err != nil {
		return fmt.Errorf("wait for %s: %w\n%s", d.alias, err, s.logs(d.serverContainer))
	}
	return s.waitForIssuance(d)
}

// certState is the part of an entry of `sigils --json cert list` that the
// tests read.
type certState struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
	LastError   string `json:"last_error"`
}

// waitForIssuance waits until the server of d has issued all its
// certificates. A certificate in retry backoff fails at once: its next
// attempt is minutes away.
func (s *e2eStack) waitForIssuance(d *deployment) error {
	deadline := time.Now().Add(startupTimeout)
	var last string
	for time.Now().Before(deadline) {
		// The command fails until the server's IPC endpoint is up.
		out, err := s.exec(d.serverContainer, "sigils", "--json", "cert", "list")
		last = out
		if err == nil {
			var certs []certState
			if err := json.Unmarshal([]byte(out), &certs); err != nil {
				return fmt.Errorf("parse cert list of %s: %w\n%s", d.alias, err, out)
			}
			valid := 0
			for _, cert := range certs {
				switch cert.State {
				case "backoff":
					return fmt.Errorf("%s: certificate %s is in retry backoff: %s\nserver logs:\n%s",
						d.alias, cert.Name, cert.LastError, s.logs(d.serverContainer))
				case "valid":
					valid++
				}
			}
			if len(certs) == len(d.certs) && valid == len(certs) {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("%s did not issue its certificates within %s; last cert list:\n%s\nserver logs:\n%s",
		d.alias, startupTimeout, last, s.logs(d.serverContainer))
}

// runClient starts the client container of d. A bootstrap container idles so
// tests can run sigilc enroll in it; otherwise the container runs the daemon.
func (s *e2eStack) runClient(d *deployment, bootstrap bool) error {
	args := []string{
		"run", "-d",
		"--name", d.clientContainer,
		"--network", s.network,
		"-e", "SIGILC_CONFIG=" + d.containerPath("client-data", "client.yaml"),
		"-v", bindMount(s.mountDir, "/e2e", false),
	}
	if d.publicRoot != nil {
		// On Linux, Go loads SSL_CERT_FILE into the system roots.
		args = append(args, "-e", "SSL_CERT_FILE="+d.containerPath("tls", "root.pem"))
	}
	if bootstrap {
		args = append(args, "--entrypoint", "/bin/sh", s.clientImage, "-c", "while :; do sleep 3600; done")
	} else {
		args = append(args, s.clientImage)
	}
	if out, err := s.run(args...); err != nil {
		return fmt.Errorf("start %s: %w\n%s", d.clientContainer, err, out)
	}
	return nil
}

// dnsHook is the program of the servers' exec DNS provider, run as
// /bin/sh dns-hook.sh present|cleanup <fqdn> <value>. It sets and clears
// the challenge record in challtestsrv.
const dnsHook = `set -eu
case "$1" in
present) body="{\"host\":\"$2\",\"value\":\"$3\"}"; url=http://challtestsrv:8055/set-txt ;;
cleanup) body="{\"host\":\"$2\"}"; url=http://challtestsrv:8055/clear-txt ;;
*) exit 2 ;;
esac
exec curl -fsS --max-time 10 -X POST --data-binary "$body" "$url"
`

func (s *e2eStack) writeFixtures() error {
	pebbleDir := filepath.Join(s.runDir, "pebble")
	var err error
	if s.pebbleTLSRoot, err = writePublicTLS(pebbleDir, "pebble"); err != nil {
		return err
	}
	// A Retry-After of one second keeps lego's polling short. pebble's VA
	// builds addresses from httpPort and tlsPort even though DNS-01 uses
	// neither; the values are those of pebble's own test configuration.
	pebbleConfig := fmt.Sprintf(`{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": %q,
    "privateKey": %q,
    "httpPort": 5002,
    "tlsPort": 5001,
    "retryAfter": {"authz": 1, "order": 1}
  }
}
`, s.containerPath("pebble", "server.pem"), s.containerPath("pebble", "server-key.pem"))
	if err := os.WriteFile(filepath.Join(pebbleDir, "pebble-config.json"), []byte(pebbleConfig), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.runDir, "dns-hook.sh"), []byte(dnsHook), 0o600); err != nil {
		return err
	}
	if s.publicTLS.publicRoot, err = writePublicTLS(s.publicTLS.hostPath("tls"), s.publicTLS.alias); err != nil {
		return err
	}
	for _, d := range s.deployments() {
		if err := d.writeConfigs(s.containerPath("dns-hook.sh")); err != nil {
			return err
		}
	}
	return nil
}

func (d *deployment) writeConfigs(dnsHookPath string) error {
	tlsFiles := ""
	if d.publicRoot != nil {
		tlsFiles = fmt.Sprintf("  tls_cert_file: %q\n  tls_key_file: %q\n",
			d.containerPath("tls", "server.pem"), d.containerPath("tls", "server-key.pem"))
	}
	var certs strings.Builder
	for i, cert := range d.certs {
		fmt.Fprintf(&certs, `  - name: %s
    domains: [%q]
    ca: pebble
    dns_provider: challtestsrv
    key_type: ec256
`, cert.name, cert.domain)
		if i == 0 {
			fmt.Fprintf(&certs, "    subscribers: [%q]\n", d.clientName)
		}
	}
	serverConfig := fmt.Sprintf(`server:
  listen: ":18443"
  data_dir: %q
  public_url: "https://%s:18443"
%s
acme:
  email: "test@example.com"
  default_ca: pebble
  dns_resolvers: ["challtestsrv:8053"]
  cas:
    pebble:
      directory: "https://pebble:14000/dir"

dns_providers:
  challtestsrv:
    type: exec
    command: ["/bin/sh", %q]
    # challtestsrv answers SOA queries with NOTIMP, which fails the check.
    skip_propagation_check: true

certificates:
%s`, d.containerPath("server-data"), d.alias, tlsFiles, dnsHookPath, certs.String())
	// test-cert's on_change program appends the sha256 of fullchain.pem to
	// hook.log, one line per run. client.yaml expands ${VAR} in every value,
	// so the program has no $ in it.
	hook := fmt.Sprintf("sha256sum %s/fullchain.pem >> %s", testCertOutputs, d.containerPath("hook.log"))
	clientConfig := fmt.Sprintf(`client:
  name: %s
  server_url: "https://%s:18443"
  data_dir: %q

certificates:
  test-cert:
    outputs:
      - format: pem-fullchain
        path: %s
      - format: pem-key
        path: %s
    on_change: ["/bin/sh", "-c", %q]
`, d.clientName, d.alias, d.containerPath("client-data"),
		testCertOutputs+"/fullchain.pem", testCertOutputs+"/key.pem", hook)
	if err := os.WriteFile(d.hostPath("server.yaml"), []byte(serverConfig), 0o600); err != nil {
		return err
	}
	return os.WriteFile(d.hostPath("client-data", "client.yaml"), []byte(clientConfig), 0o600)
}

// writePublicTLS writes a test root to dir/root.pem and a certificate for host
// signed by it to dir/server.pem and dir/server-key.pem. The root stands in
// for a CA the connecting side trusts: a public CA, or the private CA of an
// ACME server.
func writePublicTLS(dir, host string) (*x509.Certificate, error) {
	now := time.Now().UTC()
	root, rootKey, err := issueCertificate(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Sigil E2E Public Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	if err != nil {
		return nil, err
	}
	server, serverKey, err := issueCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, root, rootKey)
	if err != nil {
		return nil, err
	}
	keyPEM, err := privateKeyPEM(serverKey)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for name, data := range map[string][]byte{
		"root.pem":       certificatePEM(root),
		"server.pem":     certificatePEM(server),
		"server-key.pem": keyPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return nil, err
		}
	}
	return root, nil
}

// issueCertificate creates a certificate from template for a new P-256 key,
// signed by parentKey, or self-signed when parent is nil.
func issueCertificate(template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func certificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func privateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// availablePorts returns n free loopback ports. Every listener stays open until
// all ports are chosen, so the same port is never returned twice.
func availablePorts(n int) ([]int, error) {
	ports := make([]int, 0, n)
	for range n {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		defer listener.Close()
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

func bindMount(source, destination string, readOnly bool) string {
	mount := filepath.Clean(source) + ":" + destination
	if readOnly {
		mount += ":ro"
	}
	return mount
}

func waitForHTTP(target string, transport *http.Transport, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(target)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				return nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("%s did not become ready: %w", target, lastErr)
}

// readinessTransport verifies a public TLS server against its test root, which
// proves it serves tls_cert_file. A mini-CA server is only probed.
func (d *deployment) readinessTransport() *http.Transport {
	if d.publicRoot == nil {
		return insecureTransport()
	}
	return verifyingTransport(d.publicRoot, d.alias)
}

// pebbleTransport verifies pebble's certificate against the test root that
// signs it. pebble serves its ACME and management APIs with it.
func (s *e2eStack) pebbleTransport() *http.Transport {
	return verifyingTransport(s.pebbleTLSRoot, "pebble")
}

// verifyingTransport verifies the certificate of a server for serverName
// against root alone.
func verifyingTransport(root *x509.Certificate, serverName string) *http.Transport {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName}}
}

// pebbleIssuingRoots returns the root pebble generated at startup, to which
// every certificate it issues chains.
func (s *e2eStack) pebbleIssuingRoots() (*x509.CertPool, error) {
	client := &http.Client{Timeout: 10 * time.Second, Transport: s.pebbleTransport()}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/roots/0", s.pebbleAdminPort))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if resp.StatusCode != http.StatusOK || !roots.AppendCertsFromPEM(body) {
		return nil, fmt.Errorf("get pebble root: status %d: %q", resp.StatusCode, body)
	}
	return roots, nil
}

// dnsQueryTypes returns the type of every DNS query challtestsrv received for
// name, which is written without the trailing dot.
func (s *e2eStack) dnsQueryTypes(name string) ([]uint16, error) {
	body, err := json.Marshal(map[string]string{"host": name})
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	target := fmt.Sprintf("http://127.0.0.1:%d/dns-request-history", s.challtestsrvPort)
	resp, err := client.Post(target, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get DNS request history of %s: status %d", name, resp.StatusCode)
	}
	var history []struct {
		Question struct{ Qtype uint16 }
	}
	if err := json.NewDecoder(resp.Body).Decode(&history); err != nil {
		return nil, fmt.Errorf("parse DNS request history of %s: %w", name, err)
	}
	types := make([]uint16, 0, len(history))
	for _, event := range history {
		types = append(types, event.Question.Qtype)
	}
	return types, nil
}

func (d *deployment) hostURL() string {
	return fmt.Sprintf("https://127.0.0.1:%d", d.serverPort)
}

func (d *deployment) hostPath(parts ...string) string {
	return filepath.Join(append([]string{d.hostDir}, parts...)...)
}

func (d *deployment) containerPath(parts ...string) string {
	return strings.Join(append([]string{d.containerDir}, parts...), "/")
}

func (s *e2eStack) containerPath(parts ...string) string {
	return strings.Join(append([]string{"/e2e", filepath.Base(s.runDir)}, parts...), "/")
}

func (s *e2eStack) run(args ...string) (string, error) {
	return s.runtime.run(s.rootDir, args...)
}

func (s *e2eStack) runInRoot(args ...string) (string, error) {
	return s.runtime.run(s.rootDir, args...)
}

func (r containerRuntime) run(dir string, args ...string) (string, error) {
	cmd := exec.Command(r.path, args...)
	cmd.Dir = dir
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}

func (s *e2eStack) exec(container string, args ...string) (string, error) {
	command := append([]string{"exec", container}, args...)
	return s.run(command...)
}

// startClientDaemon replaces the bootstrap client container of d with one
// that runs sigilc serve against the enrolled identity.
func (s *e2eStack) startClientDaemon(d *deployment) error {
	if out, err := s.removeContainer(d.clientContainer); err != nil {
		return fmt.Errorf("remove bootstrap client: %w\n%s", err, out)
	}
	return s.runClient(d, false)
}

func (s *e2eStack) removeContainer(name string) (string, error) {
	if s.runtime.name == "wslc" {
		return s.run("remove", "-f", name)
	}
	return s.run("rm", "-f", name)
}

func (s *e2eStack) removeNetwork() {
	for attempt := 0; attempt < 20; attempt++ {
		var err error
		if s.runtime.name == "wslc" {
			_, err = s.run("network", "remove", "-f", s.network)
		} else {
			_, err = s.run("network", "rm", s.network)
		}
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *e2eStack) logs(container string) string {
	out, _ := s.run("logs", container)
	return out
}

func (s *e2eStack) cleanup() {
	if s == nil {
		return
	}
	for _, d := range s.deployments() {
		_, _ = s.removeContainer(d.clientContainer)
		_, _ = s.removeContainer(d.serverContainer)
	}
	_, _ = s.removeContainer(s.pebbleContainer)
	_, _ = s.removeContainer(s.challtestsrvContainer)
	s.removeNetwork()
	_, _ = s.run("rmi", "-f", s.clientImage)
	_, _ = s.run("rmi", "-f", s.serverImage)
	_, _ = s.run("rmi", "-f", s.pebbleImage)
	_ = os.RemoveAll(s.runDir)
}

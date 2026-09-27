//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

const startupTimeout = 2 * time.Minute

type containerRuntime struct {
	path string
	name string
}

type e2eStack struct {
	runtime     containerRuntime
	rootDir     string
	tempDir     string
	network     string
	serverImage string
	clientImage string
	// miniCA's server presents its default mini-CA certificate. publicTLS's
	// server presents server.tls_cert_file, signed by a test root that its
	// client trusts through the system roots, as it would a public CA.
	miniCA    *deployment
	publicTLS *deployment
}

// deployment is one sigils server and the sigilc client enrolled with it.
// Its files live in hostDir, which its containers see as /e2e/<dir>.
type deployment struct {
	dir             string
	hostDir         string
	alias           string // server network alias and public_url host
	clientName      string
	serverContainer string
	clientContainer string
	serverPort      int
	// publicRoot signs the server's tls_cert_file; nil for a mini-CA server.
	publicRoot *x509.Certificate
}

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
	tempDir, err := os.MkdirTemp("", "sigil-wslc-e2e-")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*e2eStack, error) {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	suffix := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().Unix())
	s := &e2eStack{
		runtime:     rt,
		rootDir:     rootDir,
		tempDir:     tempDir,
		network:     "sigil-e2e-" + suffix,
		serverImage: "sigil-e2e-sigils:" + suffix,
		clientImage: "sigil-e2e-sigilc:" + suffix,
	}
	if s.miniCA, err = s.newDeployment("minica", "sigils", "web-1", suffix); err != nil {
		return fail(err)
	}
	if s.publicTLS, err = s.newDeployment("public", "sigils-public", "web-public", suffix); err != nil {
		return fail(err)
	}
	if err := s.writeFixtures(); err != nil {
		return fail(err)
	}
	return s, nil
}

func (s *e2eStack) newDeployment(dir, alias, clientName, suffix string) (*deployment, error) {
	port, err := availablePort()
	if err != nil {
		return nil, err
	}
	d := &deployment{
		dir:             dir,
		hostDir:         filepath.Join(s.tempDir, dir),
		alias:           alias,
		clientName:      clientName,
		serverContainer: "sigil-e2e-" + alias + "-" + suffix,
		clientContainer: "sigil-e2e-" + clientName + "-" + suffix,
		serverPort:      port,
	}
	for _, sub := range []string{"server-data", "client-data", "cert-output"} {
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

func (s *e2eStack) startServer(d *deployment) error {
	args := []string{
		"run", "-d",
		"--name", d.serverContainer,
		"--network", s.network,
		"--network-alias", d.alias,
		"-p", fmt.Sprintf("127.0.0.1:%d:18443", d.serverPort),
		"-e", "SIGILS_CONFIG=" + d.containerPath("server.yaml"),
		"-v", bindMount(s.tempDir, "/e2e", false),
		s.serverImage,
	}
	if out, err := s.run(args...); err != nil {
		return fmt.Errorf("start %s: %w\n%s", d.alias, err, out)
	}
	if err := waitForHTTP(d.hostURL()+"/install.sh", d.readinessTransport(), startupTimeout); err != nil {
		return fmt.Errorf("wait for %s: %w\n%s", d.alias, err, s.logs(d.serverContainer))
	}
	if out, err := s.exec(d.serverContainer,
		"curl", "--fail", "--silent", "--show-error",
		"--unix-socket", "/var/run/sigil/sigils.sock",
		"-H", "Content-Type: application/json",
		"--data-binary", "@/e2e/seed-cert.json",
		"http://localhost/ipc/v1/certs",
	); err != nil {
		return fmt.Errorf("seed certificate on %s: %w\n%s", d.alias, err, out)
	}
	return nil
}

// runClient starts the client container of d. A bootstrap container idles so
// tests can run sigilc enroll in it; otherwise the container runs the daemon.
func (s *e2eStack) runClient(d *deployment, bootstrap bool) error {
	args := []string{
		"run", "-d",
		"--name", d.clientContainer,
		"--network", s.network,
		"-e", "SIGILC_CONFIG=" + d.containerPath("client-data", "client.yaml"),
		"-v", bindMount(s.tempDir, "/e2e", false),
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

func (s *e2eStack) writeFixtures() error {
	record, err := seededCertificate()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.tempDir, "seed-cert.json"), raw, 0o600); err != nil {
		return err
	}
	if s.publicTLS.publicRoot, err = writePublicTLS(s.publicTLS.hostPath("tls"), s.publicTLS.alias); err != nil {
		return err
	}
	for _, d := range s.deployments() {
		if err := d.writeConfigs(); err != nil {
			return err
		}
	}
	return nil
}

func (d *deployment) writeConfigs() error {
	tlsFiles := ""
	if d.publicRoot != nil {
		tlsFiles = fmt.Sprintf("  tls_cert_file: %q\n  tls_key_file: %q\n",
			d.containerPath("tls", "server.pem"), d.containerPath("tls", "server-key.pem"))
	}
	serverConfig := fmt.Sprintf(`server:
  listen: ":18443"
  data_dir: %q
  public_url: "https://%s:18443"
%s
acme:
  email: "test@example.com"
  default_ca: test
  cas:
    test:
      directory: "https://127.0.0.1:18443/directory"

dns_providers:
  test:
    type: route53

certificates:
  - name: test-cert
    domains: ["test.example.com"]
    ca: test
    dns_provider: test
    key_type: ec256
    renew_days_before: 30
    subscribers: [%q]
`, d.containerPath("server-data"), d.alias, tlsFiles, d.clientName)
	clientConfig := fmt.Sprintf(`client:
  name: %s
  server_url: "https://%s:18443"
  pull_interval: 30s
  data_dir: %q

outputs:
  test-cert:
    - format: pem-fullchain
      path: %s
    - format: pem-key
      path: %s
`, d.clientName, d.alias, d.containerPath("client-data"),
		d.containerPath("cert-output", "test-cert", "fullchain.pem"),
		d.containerPath("cert-output", "test-cert", "key.pem"))
	if err := os.WriteFile(d.hostPath("server.yaml"), []byte(serverConfig), 0o600); err != nil {
		return err
	}
	return os.WriteFile(d.hostPath("client-data", "client.yaml"), []byte(clientConfig), 0o600)
}

// writePublicTLS writes a test root to dir/root.pem and a certificate for host
// signed by it to dir/server.pem and dir/server-key.pem. The root stands in
// for a publicly trusted CA.
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

func seededCertificate() (*store.CertRecord, error) {
	now := time.Now().UTC()
	cert, key, err := issueCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, nil, nil)
	if err != nil {
		return nil, err
	}
	certPEM := certificatePEM(cert)
	keyPEM, err := privateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(certPEM)
	cfg := &config.ServerConfig{ACME: config.ACMESection{CAs: map[string]config.CAEntry{
		"test": {Directory: "https://127.0.0.1:18443/directory"},
	}}}
	spec := config.CertificateSpec{
		Name: "test-cert", CA: "test", Domains: []string{"test.example.com"}, KeyType: "ec256",
	}
	return &store.CertRecord{
		Name:            "test-cert",
		CA:              "test",
		Domains:         []string{"test.example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
		FullchainPEM:    string(certPEM),
		KeyPEM:          string(keyPEM),
		NotAfter:        cert.NotAfter,
		Fingerprint:     "sha256:" + hex.EncodeToString(sum[:]),
		IssuedAt:        now,
		UpdatedAt:       now,
	}, nil
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

func availablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
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
	roots := x509.NewCertPool()
	roots.AddCert(d.publicRoot)
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: d.alias}}
}

func (d *deployment) hostURL() string {
	return fmt.Sprintf("https://127.0.0.1:%d", d.serverPort)
}

func (d *deployment) hostPath(parts ...string) string {
	return filepath.Join(append([]string{d.hostDir}, parts...)...)
}

func (d *deployment) containerPath(parts ...string) string {
	return strings.Join(append([]string{"/e2e", d.dir}, parts...), "/")
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
	s.removeNetwork()
	_, _ = s.run("rmi", "-f", s.clientImage)
	_, _ = s.run("rmi", "-f", s.serverImage)
	if strings.HasPrefix(filepath.Base(s.tempDir), "sigil-wslc-e2e-") {
		_ = os.RemoveAll(s.tempDir)
	}
}

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	runtime       containerRuntime
	rootDir       string
	tempDir       string
	network       string
	serverName    string
	clientName    string
	serverImage   string
	clientImage   string
	serverPort    int
	serverDataDir string
	clientDataDir string
	certOutputDir string
	sharedDir     string
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
	port, err := availablePort()
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	suffix := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().Unix())
	s := &e2eStack{
		runtime:       rt,
		rootDir:       rootDir,
		tempDir:       tempDir,
		network:       "sigil-e2e-" + suffix,
		serverName:    "sigil-e2e-server-" + suffix,
		clientName:    "sigil-e2e-client-" + suffix,
		serverImage:   "sigil-e2e-sigils:" + suffix,
		clientImage:   "sigil-e2e-sigilc:" + suffix,
		serverPort:    port,
		serverDataDir: filepath.Join(tempDir, "server-data"),
		clientDataDir: filepath.Join(tempDir, "client-data"),
		certOutputDir: filepath.Join(tempDir, "cert-output"),
		sharedDir:     filepath.Join(tempDir, "shared"),
	}
	for _, dir := range []string{s.serverDataDir, s.clientDataDir, s.certOutputDir, s.sharedDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			s.cleanup()
			return nil, err
		}
	}
	if err := s.writeFixtures(); err != nil {
		s.cleanup()
		return nil, err
	}
	return s, nil
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

	serverArgs := []string{
		"run", "-d",
		"--name", s.serverName,
		"--network", s.network,
		"--network-alias", "sigils",
		"-p", fmt.Sprintf("127.0.0.1:%d:18443", s.serverPort),
		"-e", "SIGILS_CONFIG=/e2e/shared/server.yaml",
		"-v", bindMount(s.tempDir, "/e2e", false),
		s.serverImage,
	}
	if out, err := s.run(serverArgs...); err != nil {
		return fmt.Errorf("start sigils: %w\n%s", err, out)
	}
	if err := waitForHTTP(s.hostServerURL()+"/install.sh", startupTimeout); err != nil {
		return fmt.Errorf("wait for sigils: %w\n%s", err, s.logs(s.serverName))
	}
	if out, err := s.exec(s.serverName,
		"curl", "--fail", "--silent", "--show-error",
		"--unix-socket", "/var/run/sigil/sigils.sock",
		"-H", "Content-Type: application/json",
		"--data-binary", "@/e2e/shared/seed-cert.json",
		"http://localhost/ipc/v1/certs",
	); err != nil {
		return fmt.Errorf("seed certificate: %w\n%s", err, out)
	}

	clientArgs := []string{
		"run", "-d",
		"--name", s.clientName,
		"--network", s.network,
		"--network-alias", "sigilc",
		"--entrypoint", "/bin/sh",
		"-e", "SIGILC_CONFIG=/e2e/client-data/client.yaml",
		"-v", bindMount(s.tempDir, "/e2e", false),
		s.clientImage,
		"-c", "while :; do sleep 3600; done",
	}
	if out, err := s.run(clientArgs...); err != nil {
		return fmt.Errorf("start sigilc container: %w\n%s", err, out)
	}
	return nil
}

func (s *e2eStack) writeFixtures() error {
	serverConfig := `server:
  listen: ":18443"
  data_dir: "/e2e/server-data"
  public_url: "https://sigils:18443"

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
    subscribers: ["web-1"]
`
	clientConfig := `client:
  name: web-1
  server_url: "https://sigils:18443"
  pull_interval: 30s
  data_dir: "/e2e/client-data"

outputs:
  test-cert:
    - format: pem-fullchain
      path: /e2e/cert-output/test-cert/fullchain.pem
    - format: pem-key
      path: /e2e/cert-output/test-cert/key.pem
`
	if err := os.WriteFile(filepath.Join(s.sharedDir, "server.yaml"), []byte(serverConfig), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.clientDataDir, "client.yaml"), []byte(clientConfig), 0o600); err != nil {
		return err
	}
	record, err := seededCertificate()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.sharedDir, "seed-cert.json"), raw, 0o600)
}

func seededCertificate() (*store.CertRecord, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
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
		NotAfter:        template.NotAfter,
		Fingerprint:     "sha256:" + hex.EncodeToString(sum[:]),
		IssuedAt:        now,
		UpdatedAt:       now,
	}, nil
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

func waitForHTTP(target string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second, Transport: insecureTransport()}
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

func (s *e2eStack) hostServerURL() string {
	return fmt.Sprintf("https://127.0.0.1:%d", s.serverPort)
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

func (s *e2eStack) startClientDaemon() error {
	if out, err := s.removeContainer(s.clientName); err != nil {
		return fmt.Errorf("remove bootstrap client: %w\n%s", err, out)
	}
	args := []string{
		"run", "-d",
		"--name", s.clientName,
		"--network", s.network,
		"--network-alias", "sigilc",
		"-e", "SIGILC_CONFIG=/e2e/client-data/client.yaml",
		"-v", bindMount(s.tempDir, "/e2e", false),
		s.clientImage,
	}
	if out, err := s.run(args...); err != nil {
		return fmt.Errorf("start sigilc daemon container: %w\n%s", err, out)
	}
	return nil
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
	if s.runtime.name == "wslc" {
		_, _ = s.removeContainer(s.clientName)
		_, _ = s.removeContainer(s.serverName)
	} else {
		_, _ = s.removeContainer(s.clientName)
		_, _ = s.removeContainer(s.serverName)
	}
	s.removeNetwork()
	_, _ = s.run("rmi", "-f", s.clientImage)
	_, _ = s.run("rmi", "-f", s.serverImage)
	if strings.HasPrefix(filepath.Base(s.tempDir), "sigil-wslc-e2e-") {
		_ = os.RemoveAll(s.tempDir)
	}
}

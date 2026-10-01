package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/ca"
	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/logging"
	"github.com/Oganneson-Studio/certfold/internal/renewal"
)

// assertTLSEvents checks that ring holds one event for each entry of want, as
// "LEVEL message attrs" starting with the entry.
func assertTLSEvents(t *testing.T, ring *logging.Ring, want ...string) {
	t.Helper()
	var got []string
	for _, e := range ring.Since(0) {
		got = append(got, e.Level+" "+e.Message+" "+e.Attrs)
	}
	match := len(got) == len(want)
	for i := 0; match && i < len(want); i++ {
		match = strings.HasPrefix(got[i], want[i])
	}
	if !match {
		t.Fatalf("events:\n  %s\nwant, each starting with:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// tlsFilesConfig returns a configuration naming TLS files in a new directory.
func tlsFilesConfig(t *testing.T) *config.ServerConfig {
	t.Helper()
	dir := t.TempDir()
	return &config.ServerConfig{Server: config.ServerSection{
		TLSCertFile: filepath.Join(dir, "tls.crt"),
		TLSKeyFile:  filepath.Join(dir, "tls.key"),
	}}
}

// tlsPair is a certificate for localhost and its key.
type tlsPair struct {
	cert, key []byte
	serial    *big.Int
}

func issueTLSPair(t *testing.T, miniCA *ca.MiniCA) tlsPair {
	t.Helper()
	certPEM, keyPEM, err := miniCA.IssueServerCert([]string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return tlsPair{cert: certPEM, key: keyPEM, serial: leaf.SerialNumber}
}

// write writes the pair to the TLS files of cfg, dated mtime.
func (p tlsPair) write(t *testing.T, cfg *config.ServerConfig, mtime time.Time) {
	t.Helper()
	writeTLSFile(t, cfg.Server.TLSCertFile, p.cert, mtime)
	writeTLSFile(t, cfg.Server.TLSKeyFile, p.key, mtime)
}

// writeTLSFile writes data to path, dated mtime: each test gives each version
// of a file its own time, whatever the resolution of the file system's clock.
func writeTLSFile(t *testing.T, path string, data []byte, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// servedSerial returns the serial of the certificate src gives a handshake.
func servedSerial(t *testing.T, src *tlsSource) *big.Int {
	t.Helper()
	cert, err := src.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatalf("GetCertificate returned %+v, want a certificate", cert)
	}
	return cert.Leaf.SerialNumber
}

// newFilesTLSSource writes first to new TLS files, dated start, and returns a
// tlsSource for them.
func newFilesTLSSource(t *testing.T, miniCA *ca.MiniCA, first tlsPair, start time.Time) (*tlsSource, *config.ServerConfig) {
	t.Helper()
	cfg := tlsFilesConfig(t)
	first.write(t, cfg, start)
	src, err := newTLSSource(miniCA, cfg, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if got := servedSerial(t, src); got.Cmp(first.serial) != 0 {
		t.Fatalf("served serial %s, want %s from the files", got, first.serial)
	}
	return src, cfg
}

func TestTLSSourceLoadsReplacedFiles(t *testing.T) {
	events := setupLogs(t, io.Discard).Events
	miniCA := mustBootstrapTLSCA(t)
	start := time.Now().Add(-time.Hour)
	src, cfg := newFilesTLSSource(t, miniCA, issueTLSPair(t, miniCA), start)

	second := issueTLSPair(t, miniCA)
	second.write(t, cfg, start.Add(time.Minute))
	for range 2 {
		if got := servedSerial(t, src); got.Cmp(second.serial) != 0 {
			t.Fatalf("served serial %s after the files were replaced, want %s", got, second.serial)
		}
	}
	assertTLSEvents(t, events, "INFO server TLS certificate reloaded not_after=")
}

// A pair caught halfway through its replacement does not load. The old
// certificate stays in use, and the failure is logged once, until the other
// file is written too.
func TestTLSSourceKeepsCertificateThroughHalfWrittenPair(t *testing.T) {
	events := setupLogs(t, io.Discard).Events
	miniCA := mustBootstrapTLSCA(t)
	start := time.Now().Add(-time.Hour)
	first := issueTLSPair(t, miniCA)
	src, cfg := newFilesTLSSource(t, miniCA, first, start)

	second := issueTLSPair(t, miniCA)
	writeTLSFile(t, cfg.Server.TLSCertFile, second.cert, start.Add(time.Minute))
	for range 2 {
		if got := servedSerial(t, src); got.Cmp(first.serial) != 0 {
			t.Fatalf("served serial %s with only the certificate file replaced, want the old %s", got, first.serial)
		}
	}
	assertTLSEvents(t, events, "WARN server TLS certificate not reloaded error=")

	writeTLSFile(t, cfg.Server.TLSKeyFile, second.key, start.Add(2*time.Minute))
	if got := servedSerial(t, src); got.Cmp(second.serial) != 0 {
		t.Fatalf("served serial %s once the key was written, want %s", got, second.serial)
	}
	assertTLSEvents(t, events,
		"WARN server TLS certificate not reloaded error=",
		"INFO server TLS certificate reloaded not_after=")
}

func TestTLSSourceKeepsCertificateWhenFilesAreRemoved(t *testing.T) {
	events := setupLogs(t, io.Discard).Events
	miniCA := mustBootstrapTLSCA(t)
	start := time.Now().Add(-time.Hour)
	first := issueTLSPair(t, miniCA)
	src, cfg := newFilesTLSSource(t, miniCA, first, start)

	if err := os.Remove(cfg.Server.TLSCertFile); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got := servedSerial(t, src); got.Cmp(first.serial) != 0 {
			t.Fatalf("served serial %s with the certificate file removed, want the old %s", got, first.serial)
		}
	}
	assertTLSEvents(t, events, "WARN server TLS certificate not reloaded error=")

	second := issueTLSPair(t, miniCA)
	second.write(t, cfg, start.Add(time.Minute))
	if got := servedSerial(t, src); got.Cmp(second.serial) != 0 {
		t.Fatalf("served serial %s once the files were back, want %s", got, second.serial)
	}
	assertTLSEvents(t, events,
		"WARN server TLS certificate not reloaded error=",
		"INFO server TLS certificate reloaded not_after=")
}

// newMiniCATLSSource returns a tlsSource whose certificate the mini-CA under
// dataDir issues, and which reads the time from *now.
func newMiniCATLSSource(t *testing.T, dataDir string, now *time.Time) *tlsSource {
	t.Helper()
	miniCA, err := ca.Bootstrap(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.ServerConfig{Server: config.ServerSection{Listen: "127.0.0.1:8443"}}
	src, err := newTLSSource(miniCA, cfg, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// The clock of a tlsSource only decides when its certificate is due: the
// mini-CA dates each certificate it issues by the real time. A clock set far
// ahead therefore finds every new certificate due at once as well, so these
// tests make one handshake per step of the clock.

func TestTLSSourceReissuesMiniCACertificateWhenDue(t *testing.T) {
	events := setupLogs(t, io.Discard).Events
	now := time.Now()
	src := newMiniCATLSSource(t, t.TempDir(), &now)
	cert, err := src.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	first := cert.Leaf.SerialNumber
	due, err := renewal.RenewAt(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})))
	if err != nil {
		t.Fatal(err)
	}

	now = due.Add(-time.Second)
	if got := servedSerial(t, src); got.Cmp(first) != 0 {
		t.Fatalf("served serial %s a second before the certificate is due, want %s", got, first)
	}
	assertTLSEvents(t, events)

	now = due
	if got := servedSerial(t, src); got.Cmp(first) == 0 {
		t.Fatalf("served the certificate %s once it is due, want a new one", got)
	}
	assertTLSEvents(t, events, "INFO server TLS certificate reissued not_after=")
}

// breakMiniCA keeps the mini-CA under dataDir from issuing certificates until
// repairMiniCA: it cannot store the next serial under data_dir/ca while a file
// takes the place of that directory.
func breakMiniCA(t *testing.T, dataDir string) {
	t.Helper()
	caDir := filepath.Join(dataDir, "ca")
	if err := os.RemoveAll(caDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func repairMiniCA(t *testing.T, dataDir string) {
	t.Helper()
	caDir := filepath.Join(dataDir, "ca")
	if err := os.Remove(caDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
}

// A certificate the mini-CA cannot issue leaves the old one in use. The
// failure is logged once while it lasts, however often it is tried, and again
// when it recurs after a success.
func TestTLSSourceLogsReissueFailureOnce(t *testing.T) {
	events := setupLogs(t, io.Discard).Events
	dataDir := t.TempDir()
	now := time.Now()
	src := newMiniCATLSSource(t, dataDir, &now)
	first := servedSerial(t, src)

	breakMiniCA(t, dataDir)
	now = now.Add(365 * 24 * time.Hour)
	// Two tries, as far apart as the wait between them.
	for range 2 {
		if got := servedSerial(t, src); got.Cmp(first) != 0 {
			t.Fatalf("served serial %s while no certificate can be issued, want the old %s", got, first)
		}
		now = now.Add(reissueRetry)
	}
	assertTLSEvents(t, events, "WARN server TLS certificate not reissued error=")

	repairMiniCA(t, dataDir)
	second := servedSerial(t, src)
	if second.Cmp(first) == 0 {
		t.Fatal("did not issue a new certificate once the mini-CA could store its serial again")
	}
	assertTLSEvents(t, events,
		"WARN server TLS certificate not reissued error=",
		"INFO server TLS certificate reissued not_after=")

	breakMiniCA(t, dataDir)
	now = now.Add(365 * 24 * time.Hour)
	if got := servedSerial(t, src); got.Cmp(second) != 0 {
		t.Fatalf("served serial %s while no certificate can be issued, want the old %s", got, second)
	}
	assertTLSEvents(t, events,
		"WARN server TLS certificate not reissued error=",
		"INFO server TLS certificate reissued not_after=",
		"WARN server TLS certificate not reissued error=")
}

// After a failed try to issue a new certificate, the handshakes of the next
// reissueRetry do not try again, even once the mini-CA could issue: any
// connection starts one. The first handshake after the wait does.
func TestTLSSourceWaitsBeforeRetryingReissue(t *testing.T) {
	events := setupLogs(t, io.Discard).Events
	dataDir := t.TempDir()
	now := time.Now()
	src := newMiniCATLSSource(t, dataDir, &now)
	first := servedSerial(t, src)

	breakMiniCA(t, dataDir)
	now = now.Add(365 * 24 * time.Hour)
	if got := servedSerial(t, src); got.Cmp(first) != 0 {
		t.Fatalf("served serial %s while no certificate can be issued, want the old %s", got, first)
	}
	// A try would succeed from now on, so only the wait keeps the old
	// certificate in use.
	repairMiniCA(t, dataDir)
	now = now.Add(reissueRetry - time.Second)
	if got := servedSerial(t, src); got.Cmp(first) != 0 {
		t.Fatalf("served a new certificate %s %s after the failed try, want the old %s", got, reissueRetry-time.Second, first)
	}
	now = now.Add(time.Second)
	if got := servedSerial(t, src); got.Cmp(first) == 0 {
		t.Fatalf("still served %s %s after the failed try, want a new certificate", got, reissueRetry)
	}
	assertTLSEvents(t, events,
		"WARN server TLS certificate not reissued error=",
		"INFO server TLS certificate reissued not_after=")
}

// TestTLSSourceServesReplacedFilesToNewConnections makes handshakes with a
// real listener on both sides of a replacement of the files, the later ones
// concurrently.
func TestTLSSourceServesReplacedFilesToNewConnections(t *testing.T) {
	setupLogs(t, io.Discard)
	miniCA := mustBootstrapTLSCA(t)
	start := time.Now().Add(-time.Hour)
	first := issueTLSPair(t, miniCA)
	src, cfg := newFilesTLSSource(t, miniCA, first, start)

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: src.GetCertificate})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(miniCA.Cert())
	handshake := func() (*big.Int, error) {
		conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "localhost"})
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber, nil
	}

	if got, err := handshake(); err != nil || got.Cmp(first.serial) != 0 {
		t.Fatalf("first handshake: serial %v, error %v; want %s", got, err, first.serial)
	}
	second := issueTLSPair(t, miniCA)
	second.write(t, cfg, start.Add(time.Minute))
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			if got, err := handshake(); err != nil || got.Cmp(second.serial) != 0 {
				errs <- fmt.Errorf("handshake after the replacement: serial %v, error %v; want %s", got, err, second.serial)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// A mini-CA root certificate that expires within a year is warned of at
// startup, whichever certificate the listener serves.
func TestTLSSourceWarnsOfRootExpiryAtStartup(t *testing.T) {
	miniCA := mustBootstrapTLSCA(t)
	notAfter := miniCA.Cert().NotAfter
	withFiles := tlsFilesConfig(t)
	issueTLSPair(t, miniCA).write(t, withFiles, time.Now())
	for name, cfg := range map[string]*config.ServerConfig{
		"mini-CA":   {Server: config.ServerSection{Listen: "127.0.0.1:8443"}},
		"TLS files": withFiles,
	} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				left time.Duration
				want []string
			}{
				{left: rootExpiryWarning + time.Hour},
				{left: rootExpiryWarning - time.Hour, want: []string{"WARN mini-CA root certificate expires within a year not_after="}},
			} {
				events := setupLogs(t, io.Discard).Events
				now := notAfter.Add(-tc.left)
				if _, err := newTLSSource(miniCA, cfg, func() time.Time { return now }); err != nil {
					t.Fatal(err)
				}
				assertTLSEvents(t, events, tc.want...)
			}
		})
	}
}

// Each certificate the mini-CA issues once its root expires within a year
// repeats the warning.
func TestTLSSourceWarnsOfRootExpiryOnReissue(t *testing.T) {
	events := setupLogs(t, io.Discard).Events
	dataDir := t.TempDir()
	miniCA, err := ca.Bootstrap(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := miniCA.Cert().NotAfter
	// The first certificate the mini-CA issues is dated by the real time, so
	// on this clock it is due at the first handshake, and so is each next.
	now := notAfter.Add(-rootExpiryWarning - time.Hour)
	src := newMiniCATLSSource(t, dataDir, &now)
	servedSerial(t, src)
	now = notAfter.Add(-rootExpiryWarning + time.Hour)
	servedSerial(t, src)
	assertTLSEvents(t, events,
		"INFO server TLS certificate reissued not_after=",
		"INFO server TLS certificate reissued not_after=",
		"WARN mini-CA root certificate expires within a year not_after=")
}

func mustBootstrapTLSCA(t *testing.T) *ca.MiniCA {
	t.Helper()
	miniCA, err := ca.Bootstrap(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return miniCA
}

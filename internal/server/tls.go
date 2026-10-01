package server

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/ca"
	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/renewal"
)

// tlsSource supplies the certificate of the HTTPS listener to each handshake
// and replaces it without a restart. It is safe for concurrent use.
//   - With server.tls_cert_file, each handshake stats the certificate and key
//     files. Once the modification time or size of either changed, the pair
//     is loaded again. A pair that does not load, such as one caught halfway
//     through its replacement, leaves the certificate in use. Each change is
//     tried, and logged, once; so is a stat that fails.
//   - Otherwise the mini-CA issues the certificate, and a new one once it is
//     due for renewal. A try that fails waits reissueRetry before the next,
//     and the failure is logged once until a try succeeds.
//
// A handshake always gets a certificate: whatever fails keeps the one in use.
type tlsSource struct {
	miniCA *ca.MiniCA
	// cfg is the configuration certfolds started with. The TLS files, the public
	// URL and the listen address it takes from cfg need a restart to change.
	cfg *config.ServerConfig
	now func() time.Time

	mu   sync.Mutex
	cert *tls.Certificate
	// files is what the TLS files were at the last try to load them, or zero
	// once a stat of them failed.
	files [2]fileVersion
	// issueAt is when the mini-CA is to issue the next certificate: when the
	// one in use is due for renewal, or reissueRetry after a try that failed.
	issueAt time.Time
	// reissueFailed is set while a new mini-CA certificate cannot be issued,
	// so that the failure is logged once.
	reissueFailed bool
}

// reissueRetry is how long the mini-CA waits after a failed try to issue a
// new certificate. Any connection, authenticated or not, starts a handshake,
// and each try generates a key and stores a serial while every handshake
// waits for it.
const reissueRetry = time.Minute

// rootExpiryWarning is how long before the mini-CA root certificate expires
// certfolds starts warning of it, at startup and whenever the mini-CA issues a
// new HTTPS certificate. The root signs every client certificate, and nothing
// replaces it: once it expires, no client can connect.
const rootExpiryWarning = 365 * 24 * time.Hour

// fileVersion tells versions of a file apart by modification time and size.
type fileVersion struct {
	modTime int64 // Unix nanoseconds
	size    int64
}

// newTLSSource loads the configured TLS files, or has the mini-CA issue a
// certificate. now decides when that certificate is due for renewal.
func newTLSSource(miniCA *ca.MiniCA, cfg *config.ServerConfig, now func() time.Time) (*tlsSource, error) {
	s := &tlsSource{miniCA: miniCA, cfg: cfg, now: now}
	s.warnRootExpiry()
	if cfg.Server.TLSCertFile == "" {
		cert, renewAt, err := s.issue()
		if err != nil {
			return nil, err
		}
		s.cert, s.issueAt = cert, renewAt
		return s, nil
	}
	// Stat before the load, so that a change made during it is loaded at the
	// next handshake.
	files, err := statTLSFiles(cfg)
	if err != nil {
		return nil, fmt.Errorf("load configured TLS certificate: %w", err)
	}
	cert, err := serverTLSCertificate(miniCA, cfg)
	if err != nil {
		return nil, err
	}
	s.cert, s.files = &cert, files
	return s, nil
}

// GetCertificate is the tls.Config.GetCertificate of the HTTPS listener.
func (s *tlsSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Server.TLSCertFile != "" {
		s.reloadFiles()
	} else if !s.now().Before(s.issueAt) {
		s.reissue()
	}
	return s.cert, nil
}

// reloadFiles loads the TLS files if they changed since the last try.
func (s *tlsSource) reloadFiles() {
	files, err := statTLSFiles(s.cfg)
	if err != nil {
		if s.files != [2]fileVersion{} {
			slog.Warn("server TLS certificate not reloaded", "error", err)
			s.files = [2]fileVersion{}
		}
		return
	}
	if files == s.files {
		return
	}
	s.files = files
	cert, err := serverTLSCertificate(s.miniCA, s.cfg)
	if err != nil {
		slog.Warn("server TLS certificate not reloaded", "error", err)
		return
	}
	s.cert = &cert
	slog.Info("server TLS certificate reloaded", "not_after", cert.Leaf.NotAfter)
}

// reissue replaces the mini-CA certificate with a new one.
func (s *tlsSource) reissue() {
	cert, renewAt, err := s.issue()
	if err != nil {
		s.issueAt = s.now().Add(reissueRetry)
		if !s.reissueFailed {
			slog.Warn("server TLS certificate not reissued", "error", err)
			s.reissueFailed = true
		}
		return
	}
	s.cert, s.issueAt, s.reissueFailed = cert, renewAt, false
	slog.Info("server TLS certificate reissued", "not_after", cert.Leaf.NotAfter)
	s.warnRootExpiry()
}

// warnRootExpiry logs a warning if the mini-CA root certificate expires
// within rootExpiryWarning.
func (s *tlsSource) warnRootExpiry() {
	if notAfter := s.miniCA.Cert().NotAfter; s.now().Add(rootExpiryWarning).After(notAfter) {
		slog.Warn("mini-CA root certificate expires within a year", "not_after", notAfter)
	}
}

// issue has the mini-CA issue a certificate, and returns it with the time it
// is due for renewal.
func (s *tlsSource) issue() (*tls.Certificate, time.Time, error) {
	cert, err := serverTLSCertificate(s.miniCA, s.cfg)
	if err != nil {
		return nil, time.Time{}, err
	}
	renewAt, err := renewal.RenewAt(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})))
	if err != nil {
		return nil, time.Time{}, err
	}
	return &cert, renewAt, nil
}

// statTLSFiles returns the versions of the configured certificate and key
// files.
func statTLSFiles(cfg *config.ServerConfig) ([2]fileVersion, error) {
	var files [2]fileVersion
	for i, path := range []string{cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile} {
		info, err := os.Stat(path)
		if err != nil {
			return [2]fileVersion{}, err
		}
		files[i] = fileVersion{modTime: info.ModTime().UnixNano(), size: info.Size()}
	}
	return files, nil
}

// serverTLSCertificate builds the hosts list from the config and issues a
// server TLS cert signed by the mini-CA.
func serverTLSCertificate(miniCA *ca.MiniCA, cfg *config.ServerConfig) (tls.Certificate, error) {
	if cfg.Server.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load configured TLS certificate: %w", err)
		}
		return cert, nil
	}

	hosts := []string{"localhost", "127.0.0.1", "::1"}

	// Extract hostname from public_url if set.
	if cfg.Server.PublicURL != "" {
		if u, err := url.Parse(cfg.Server.PublicURL); err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
	}

	// Extract hostname from listen address if it has one (e.g. "certfold.internal:8443").
	if h, _, err := net.SplitHostPort(cfg.Server.Listen); err == nil && h != "" {
		hosts = append(hosts, h)
	}

	certPEM, keyPEM, err := miniCA.IssueServerCert(hosts)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

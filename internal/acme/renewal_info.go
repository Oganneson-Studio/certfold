package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// ErrNoRenewalInfo reports that a CA offers no renewal information (RFC
// 9773) for a certificate: its directory has no renewalInfo, or the
// certificate has no authority key identifier to name it by. Check for it
// with errors.Is.
var ErrNoRenewalInfo = api.ErrNoARI

// RenewalInfo is the window in which a CA suggests renewing a certificate.
type RenewalInfo struct {
	// Start and End bound the window: End is after Start, Start is before
	// the certificate's NotAfter, and End is no later than it.
	Start, End time.Time
	// RetryAfter is when to ask again, 0 when the CA did not say.
	RetryAfter time.Duration
	// ExplanationURL is the page the CA gives for the window, if any.
	ExplanationURL string
}

// RenewalInfo asks the CA of spec for the renewal window of the first
// certificate of certPEM. That is an unauthenticated GET: it reads the CA's
// directory with a throwaway key, and neither registers nor uses the ACME
// account, nor touches the store.
//
// lego decodes the answer whatever its HTTP status, so a problem document
// reads as an empty window; the window is checked here.
func (i *Issuer) RenewalInfo(cfg *config.ServerConfig, spec config.CertificateSpec, certPEM []byte) (*RenewalInfo, error) {
	leaf, err := firstCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	if len(leaf.AuthorityKeyId) == 0 {
		return nil, fmt.Errorf("%w: certificate has no authority key identifier", ErrNoRenewalInfo)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	legoCfg := lego.NewConfig(&legoUser{email: cfg.ACME.Email, key: key})
	legoCfg.CADirURL = cfg.ACME.CAs[spec.CA].Directory
	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("lego client: %w", err)
	}
	info, err := client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf})
	if err != nil {
		return nil, err
	}
	start, end := info.SuggestedWindow.Start, info.SuggestedWindow.End
	if !end.After(start) || !start.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("invalid renewal window [%s, %s)", start.Format(time.RFC3339), end.Format(time.RFC3339))
	}
	if end.After(leaf.NotAfter) {
		end = leaf.NotAfter
	}
	return &RenewalInfo{Start: start, End: end, RetryAfter: info.RetryAfter, ExplanationURL: info.ExplanationURL}, nil
}

// ariCertID returns the RFC 9773 identifier of the first certificate of
// certPEM, which an order that replaces it names, or false when the
// certificate cannot be read or has no authority key identifier.
func ariCertID(certPEM []byte) (string, bool) {
	leaf, err := firstCertificate(certPEM)
	if err != nil || len(leaf.AuthorityKeyId) == 0 {
		return "", false
	}
	id, err := certificate.MakeARICertID(leaf)
	return id, err == nil
}

// firstCertificate parses the first certificate of certPEM.
func firstCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

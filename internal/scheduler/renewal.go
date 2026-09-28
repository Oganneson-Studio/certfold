package scheduler

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// shortLifetime is the lifetime below which a certificate is renewed halfway
// through it instead of with a third of it left.
const shortLifetime = 10 * 24 * time.Hour

// RenewAt returns when the first certificate of fullchainPEM is due for
// renewal: when a third of its lifetime, NotAfter - NotBefore, is left, or
// half of it for a lifetime under 10 days. This is what Let's Encrypt
// recommends to clients that do not use ARI. It fails if the certificate
// cannot be parsed, or its NotAfter is not after its NotBefore.
func RenewAt(fullchainPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(fullchainPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("no certificate PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if lifetime <= 0 {
		return time.Time{}, fmt.Errorf("certificate NotAfter %s is not after its NotBefore %s",
			leaf.NotAfter.UTC().Format(time.RFC3339), leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if lifetime < shortLifetime {
		return leaf.NotAfter.Add(-lifetime / 2), nil
	}
	return leaf.NotAfter.Add(-lifetime / 3), nil
}

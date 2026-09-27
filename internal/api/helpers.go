package api

import (
	"crypto/x509"
	"fmt"
)

func parseCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	return csr, nil
}

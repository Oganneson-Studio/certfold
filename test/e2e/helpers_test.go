//go:build e2e

package e2e

import (
	"crypto/tls"
	"net/http"
)

func insecureTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for e2e test servers
	}
}

func insecureHTTPGet(url string) (*http.Response, error) {
	client := &http.Client{Transport: insecureTransport()}
	return client.Get(url)
}

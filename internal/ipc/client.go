package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/store"
)

// Client is an IPC client that communicates with the daemon over the local
// socket. Use NewClient to construct one.
type Client struct {
	http *http.Client
	base string // e.g. "http://ipc"
}

// NewClient dials the IPC socket at path and returns a ready Client.
// Pass an empty path to use the platform default.
func NewClient(path string) (*Client, error) {
	conn, err := Dial(path)
	if err != nil {
		return nil, fmt.Errorf("ipc dial: %w", err)
	}
	return newClientFromConn(conn), nil
}

func newClientFromConn(conn net.Conn) *Client {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return conn, nil
		},
	}
	return &Client{
		http: &http.Client{Transport: transport, Timeout: 5 * time.Minute},
		base: "http://ipc",
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var bodyReader *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = strings.NewReader(string(b))
	}
	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(ctx, method, c.base+path, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, c.base+path, nil)
	}
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("ipc request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		detail := strings.TrimSpace(string(message))
		if detail != "" {
			return fmt.Errorf("ipc %s %s: server returned %d: %s", method, path, resp.StatusCode, detail)
		}
		return fmt.Errorf("ipc %s %s: server returned %d", method, path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// ListCerts returns certificate metadata from the daemon store.
func (c *Client) ListCerts(ctx context.Context) ([]*CertificateInfo, error) {
	var out []*CertificateInfo
	return out, c.do(ctx, http.MethodGet, "/ipc/v1/certs", nil, &out)
}

// UpsertCert inserts or updates a certificate record.
func (c *Client) UpsertCert(ctx context.Context, rec *store.CertRecord) error {
	return c.do(ctx, http.MethodPost, "/ipc/v1/certs", rec, nil)
}

// DeleteCert removes a certificate record by name.
func (c *Client) DeleteCert(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/ipc/v1/certs/"+name, nil, nil)
}

// RenewCert asks the running sigils daemon to issue and persist a certificate
// immediately, bypassing its normal expiry threshold and retry backoff.
func (c *Client) RenewCert(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/ipc/v1/certs/renew", certNameRequest{Name: name}, nil)
}

// ReloadServer asks sigils to validate and atomically apply server.yaml.
func (c *Client) ReloadServer(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/ipc/v1/server/reload", struct{}{}, nil)
}

// ListClients returns enrolled-client metadata.
func (c *Client) ListClients(ctx context.Context) ([]*ClientInfo, error) {
	var out []*ClientInfo
	return out, c.do(ctx, http.MethodGet, "/ipc/v1/clients", nil, &out)
}

// DeleteClient removes a client record by name.
func (c *Client) DeleteClient(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/ipc/v1/clients/"+name, nil, nil)
}

// CreateToken asks the daemon to create an enrollment token.
func (c *Client) CreateToken(ctx context.Context, req createTokenRequest) (string, error) {
	var resp createTokenResponse
	if err := c.do(ctx, http.MethodPost, "/ipc/v1/tokens", req, &resp); err != nil {
		return "", err
	}
	return resp.Token, nil
}

// ListTokens returns enrollment-token metadata.
func (c *Client) ListTokens(ctx context.Context) ([]*TokenInfo, error) {
	var out []*TokenInfo
	return out, c.do(ctx, http.MethodGet, "/ipc/v1/tokens", nil, &out)
}

// DeleteToken removes an enrollment token by ID.
func (c *Client) DeleteToken(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/ipc/v1/tokens/"+id, nil, nil)
}

// GetState returns the full daemon state (certs, clients, tokens).
func (c *Client) GetState(ctx context.Context) (*ServerState, error) {
	var out ServerState
	return &out, c.do(ctx, http.MethodGet, "/ipc/v1/state", nil, &out)
}

// GetClientState returns the current sigilc runtime status.
func (c *Client) GetClientState(ctx context.Context) (*ClientState, error) {
	var out ClientState
	return &out, c.do(ctx, http.MethodGet, "/ipc/v1/client/state", nil, &out)
}

// FetchClient asks sigilc to pull immediately. An empty name fetches all
// subscribed certificates whose fingerprints changed.
func (c *Client) FetchClient(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/ipc/v1/client/fetch", fetchClientRequest{Name: name}, nil)
}

// ReloadClient asks sigilc to re-read and apply client.yaml.
func (c *Client) ReloadClient(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/ipc/v1/client/reload", struct{}{}, nil)
}

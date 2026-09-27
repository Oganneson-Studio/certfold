package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

const pushRequestTimeout = 15 * time.Second

type pushTarget struct {
	endpoint string
	token    string
}

// HTTPPushNotifier delivers renewal notifications to HTTPS endpoints declared
// in server.yaml. Clients without a configured endpoint continue to rely on
// periodic pulls.
type HTTPPushNotifier struct {
	client *http.Client
}

// NewHTTPPushNotifier constructs a notifier. httpClient may be supplied by
// tests; nil uses the default transport. Redirects are always disabled so
// bearer tokens cannot be forwarded to a different URL.
func NewHTTPPushNotifier(httpClient *http.Client) *HTTPPushNotifier {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	clientCopy := *httpClient
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = pushRequestTimeout
	}
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &HTTPPushNotifier{client: &clientCopy}
}

// Notify sends one authenticated notification. Missing endpoints are a no-op
// because periodic pulls remain the default delivery path.
func (n *HTTPPushNotifier) Notify(ctx context.Context, cfg *config.ServerConfig, clientName, certName string) error {
	target, ok := pushTargetFor(cfg, clientName)
	if !ok {
		return nil
	}
	body, err := json.Marshal(proto.PushNotify{CertName: certName})
	if err != nil {
		return fmt.Errorf("encode push notification: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build push request for %s: %w", clientName, err)
	}
	req.Header.Set("Authorization", "Bearer "+target.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sigils-push")

	resp, err := n.client.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("deliver push to %s: %w", clientName, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("deliver push to %s: server returned %s", clientName, resp.Status)
	}
	return nil
}

func pushTargetFor(cfg *config.ServerConfig, clientName string) (pushTarget, bool) {
	if cfg == nil {
		return pushTarget{}, false
	}
	for _, registration := range cfg.Clients {
		if registration.Name == clientName && registration.PushEndpoint != "" {
			return pushTarget{
				endpoint: registration.PushEndpoint,
				token:    registration.PushToken,
			}, true
		}
	}
	return pushTarget{}, false
}

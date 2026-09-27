package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

const testPushToken = "0123456789abcdef0123456789abcdef"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func pushConfig(registrations ...config.ClientRegistration) *config.ServerConfig {
	return &config.ServerConfig{Clients: registrations}
}

func TestHTTPPushNotifierDeliversAuthenticatedNotification(t *testing.T) {
	var got proto.PushNotify
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer "+testPushToken {
			t.Errorf("Authorization = %q", auth)
		}
		if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
			t.Errorf("Content-Type = %q", contentType)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := pushConfig(config.ClientRegistration{
		Name:         "web-1",
		PushEndpoint: server.URL + "/v1/push/notify",
		PushToken:    testPushToken,
	})
	notifier := NewHTTPPushNotifier(server.Client())
	if err := notifier.Notify(context.Background(), cfg, "web-1", "api-prod"); err != nil {
		t.Fatal(err)
	}
	if got.CertName != "api-prod" {
		t.Fatalf("cert_name = %q, want api-prod", got.CertName)
	}
}

func TestHTTPPushNotifierSkipsUnconfiguredClient(t *testing.T) {
	notifier := NewHTTPPushNotifier(nil)
	if err := notifier.Notify(context.Background(), &config.ServerConfig{}, "web-1", "api-prod"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPPushNotifierUsesCurrentConfigGeneration(t *testing.T) {
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path+" "+r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	notifier := NewHTTPPushNotifier(server.Client())

	first := pushConfig(config.ClientRegistration{
		Name: "web-1", PushEndpoint: server.URL + "/old", PushToken: testPushToken,
	})
	secondToken := "fedcba9876543210fedcba9876543210"
	second := pushConfig(config.ClientRegistration{
		Name: "web-1", PushEndpoint: server.URL + "/new", PushToken: secondToken,
	})
	if err := notifier.Notify(context.Background(), first, "web-1", "api-prod"); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Notify(context.Background(), second, "web-1", "api-prod"); err != nil {
		t.Fatal(err)
	}
	want := []string{"/old Bearer " + testPushToken, "/new Bearer " + secondToken}
	if len(requests) != len(want) || requests[0] != want[0] || requests[1] != want[1] {
		t.Fatalf("requests = %q, want %q", requests, want)
	}
}

func TestHTTPPushNotifierReportsNonSuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cfg := pushConfig(config.ClientRegistration{
		Name:         "web-1",
		PushEndpoint: server.URL,
		PushToken:    testPushToken,
	})
	notifier := NewHTTPPushNotifier(server.Client())
	err := notifier.Notify(context.Background(), cfg, "web-1", "api-prod")
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("error = %v, want status 503", err)
	}
}

func TestHTTPPushNotifierRedactsEndpointFromTransportErrors(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed")
	})}
	notifier := NewHTTPPushNotifier(client)
	cfg := pushConfig(config.ClientRegistration{
		Name: "web-1", PushEndpoint: "https://push.example.com/private-path", PushToken: testPushToken,
	})
	err := notifier.Notify(context.Background(), cfg, "web-1", "api-prod")
	if err == nil || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "private-path") || strings.Contains(err.Error(), "push.example.com") {
		t.Fatalf("transport error leaked endpoint: %v", err)
	}
}

func TestHTTPPushNotifierDoesNotFollowRedirects(t *testing.T) {
	var sinkCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/sink", http.StatusTemporaryRedirect)
			return
		}
		sinkCalls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	cfg := pushConfig(config.ClientRegistration{
		Name:         "web-1",
		PushEndpoint: server.URL + "/redirect",
		PushToken:    testPushToken,
	})
	notifier := NewHTTPPushNotifier(server.Client())
	err := notifier.Notify(context.Background(), cfg, "web-1", "api-prod")
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("error = %v, want redirect status", err)
	}
	if got := sinkCalls.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests", got)
	}
}

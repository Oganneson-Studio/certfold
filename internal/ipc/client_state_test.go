package ipc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientStateListsCertificates(t *testing.T) {
	notAfter := time.Date(2026, 12, 27, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		certs []ClientCertState
		want  string
	}{
		{
			name: "stored certificates",
			certs: []ClientCertState{
				{Name: "api-prod", Fingerprint: "sha256:AA", NotAfter: notAfter, Outputs: 2, OnChange: true, HookPending: true},
				{Name: "tls-internal", Fingerprint: "sha256:BB", NotAfter: notAfter},
			},
			want: `[{"name":"api-prod","fingerprint":"sha256:AA","not_after":"2026-12-27T10:00:00Z","outputs":2,"on_change":true,"hook_pending":true},` +
				`{"name":"tls-internal","fingerprint":"sha256:BB","not_after":"2026-12-27T10:00:00Z","outputs":0,"on_change":false,"hook_pending":false}]`,
		},
		{name: "none", want: `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &ipcHandlers{deps: ServerDeps{Client: &ClientControlDeps{
				State: func(context.Context) (ClientState, error) {
					return ClientState{Name: "web-1", Certs: tc.certs}, nil
				},
			}}}
			ts := httptest.NewServer(buildIPCRouter(h))
			defer ts.Close()

			resp, err := ts.Client().Get(ts.URL + "/ipc/v1/client/state")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			if got := string(fields["certs"]); got != tc.want {
				t.Fatalf("certs:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

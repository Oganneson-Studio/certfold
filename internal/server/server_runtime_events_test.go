package server

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerConfigRuntimeLogsReloads(t *testing.T) {
	logs := setupLogs(t, io.Discard)
	path := filepath.Join(t.TempDir(), "server.yaml")
	runtime := newServerConfigRuntime(path, parseRuntimeConfig(t, initialRuntimeConfig), func() {}, publishNow)

	writeRuntimeConfig(t, path, strings.Replace(initialRuntimeConfig, "ops@example.com", "security@example.com", 1))
	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	writeRuntimeConfig(t, path, strings.Replace(initialRuntimeConfig, `listen: ":8443"`, `listen: ":9443"`, 1))
	if err := runtime.Reload(context.Background()); err == nil {
		t.Fatal("Reload accepted a new server.listen")
	}

	events := logs.Events.Since(0)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want one per reload", events)
	}
	if e := events[0]; e.Level != "INFO" || e.Message != "configuration reloaded" || e.Attrs != "" {
		t.Errorf("event of the published reload = %+v", e)
	}
	if e := events[1]; e.Level != "WARN" || e.Message != "configuration reload rejected" ||
		!strings.HasPrefix(e.Attrs, `error="cannot hot reload changes to server.listen;`) {
		t.Errorf("event of the rejected reload = %+v", e)
	}
}

package service

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	ksvc "github.com/kardianos/service"
)

// ---------------------------------------------------------------------------
// buildServiceConfig
// ---------------------------------------------------------------------------

func mustBuildServiceConfig(t *testing.T, cfg Config) *ksvc.Config {
	t.Helper()
	sc, err := buildServiceConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestBuildServiceConfig_Server(t *testing.T) {
	cfg := mustBuildServiceConfig(t, Config{Role: RoleServer})
	if cfg.Name != "sigils" {
		t.Errorf("Name: got %q, want %q", cfg.Name, "sigils")
	}
	if cfg.DisplayName != "Sigil Server" {
		t.Errorf("DisplayName: got %q", cfg.DisplayName)
	}
	if len(cfg.Arguments) == 0 || cfg.Arguments[0] != "serve" {
		t.Errorf("Arguments: got %v, want first elem 'serve'", cfg.Arguments)
	}
}

func TestBuildServiceConfig_WindowsRestartsOnFailure(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("recovery actions are a Windows service option")
	}
	opts := mustBuildServiceConfig(t, Config{Role: RoleServer}).Option
	if got := opts["OnFailure"]; got != "restart" {
		t.Errorf("OnFailure: got %v, want restart", got)
	}
	if got, ok := opts["OnFailureDelayDuration"].(string); !ok || got != "10s" {
		t.Errorf("OnFailureDelayDuration: got %v, want 10s", opts["OnFailureDelayDuration"])
	}
	// kardianos reads the reset period with an int type assertion and falls
	// back to 10 seconds for any other type.
	if got, ok := opts["OnFailureResetPeriod"].(int); !ok || got != 86400 {
		t.Errorf("OnFailureResetPeriod: got %#v, want int 86400", opts["OnFailureResetPeriod"])
	}
}

func TestBuildServiceConfig_Client(t *testing.T) {
	cfg := mustBuildServiceConfig(t, Config{Role: RoleClient})
	if cfg.Name != "sigilc" {
		t.Errorf("Name: got %q, want %q", cfg.Name, "sigilc")
	}
	if cfg.DisplayName != "Sigil Client" {
		t.Errorf("DisplayName: got %q", cfg.DisplayName)
	}
}

func TestBuildServiceConfig_ExplicitConfigPath(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "server.yaml")
	args := mustBuildServiceConfig(t, Config{Role: RoleServer, ConfigPath: custom}).Arguments
	if want := []string{"serve", "--config", custom}; !slices.Equal(args, want) {
		t.Errorf("Arguments = %q, want %q", args, want)
	}
}

// TestBuildServiceConfigRegistersAbsoluteConfigPath covers
// `sigils --config server.yaml service install` run from the directory that
// holds server.yaml. The service manager starts the daemon in another working
// directory (/ under systemd, System32 under the SCM), so a relative path
// registered as is names a file the daemon cannot find: it fails at start and
// is restarted every 5 or 10 seconds without end.
func TestBuildServiceConfigRegistersAbsoluteConfigPath(t *testing.T) {
	want, err := filepath.Abs("server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []Role{RoleServer, RoleClient} {
		args := mustBuildServiceConfig(t, Config{Role: role, ConfigPath: "server.yaml"}).Arguments
		if len(args) != 3 || args[0] != "serve" || args[1] != "--config" {
			t.Fatalf("role %d: arguments = %q, want serve --config <path>", role, args)
		}
		if args[2] != want {
			t.Errorf("role %d: service registered with the config path %q, want %q", role, args[2], want)
		}
	}
}

func TestBuildServiceConfig_DefaultConfigPath(t *testing.T) {
	// When ConfigPath is empty the platform default should appear in Arguments.
	cfg := mustBuildServiceConfig(t, Config{Role: RoleServer})
	joined := strings.Join(cfg.Arguments, " ")
	want := defaultServerConfigPath()
	if !strings.Contains(joined, want) {
		t.Errorf("expected default config path %q in arguments %q", want, joined)
	}
}

// ---------------------------------------------------------------------------
// isBinaryName
// ---------------------------------------------------------------------------

func TestIsBinaryName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"sigilc-linux-amd64", true},
		{"sigilc-darwin-arm64", true},
		{"sigilc-windows-amd64.exe", true},
		{"README", false},
		{"sigilc", false}, // no dash after "sigilc"
		{"", false},
		{"sigils-linux-amd64", false},
	}
	for _, c := range cases {
		if got := isBinaryName(c.name); got != c.want {
			t.Errorf("isBinaryName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// UnpackClients
// ---------------------------------------------------------------------------

func TestUnpackClients_EmptyFS(t *testing.T) {
	// An FS with only a README should produce 0 files and a warning.
	fsys := fstest.MapFS{
		"README": &fstest.MapFile{Data: []byte("placeholder")},
	}
	dir := t.TempDir()
	var buf bytes.Buffer
	n, err := UnpackClients(fsys, dir, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expected 0 binaries, got %d", n)
	}
	if !strings.Contains(buf.String(), "warning") {
		t.Errorf("expected warning in output, got: %q", buf.String())
	}
}

func TestUnpackClients_WithBinaries(t *testing.T) {
	content := []byte("fake-binary-content")
	fsys := fstest.MapFS{
		"sigilc-linux-amd64":       &fstest.MapFile{Data: content},
		"sigilc-darwin-arm64":      &fstest.MapFile{Data: content},
		"sigilc-windows-amd64.exe": &fstest.MapFile{Data: content},
		"README":                   &fstest.MapFile{Data: []byte("skip me")},
	}
	dir := t.TempDir()
	var buf bytes.Buffer
	n, err := UnpackClients(fsys, dir, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("expected 3 binaries unpacked, got %d", n)
	}

	// Verify each binary exists on disk with the right content.
	for _, name := range []string{"sigilc-linux-amd64", "sigilc-darwin-arm64", "sigilc-windows-amd64.exe"} {
		got, err := os.ReadFile(filepath.Join(dir, "binaries", name))
		if err != nil {
			t.Errorf("missing file %s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("content mismatch for %s", name)
		}
	}

	// README must NOT be copied.
	if _, err := os.Stat(filepath.Join(dir, "binaries", "README")); !os.IsNotExist(err) {
		t.Error("README should not have been copied")
	}
}

func TestUnpackClients_CreatesDestDir(t *testing.T) {
	fsys := fstest.MapFS{
		"sigilc-linux-amd64": &fstest.MapFile{Data: []byte("x")},
	}
	dir := filepath.Join(t.TempDir(), "deep", "nested")
	_, err := UnpackClients(fsys, dir, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "binaries")); err != nil {
		t.Errorf("dest dir not created: %v", err)
	}
}

func TestUnpackClients_AtomicWrite(t *testing.T) {
	// Verify the file is created via temp+rename (no partial writes observed).
	// We can't easily intercept the rename, but we can verify the result is
	// exactly what was written.
	data := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 256)
	fsys := fstest.MapFS{
		"sigilc-linux-amd64": &fstest.MapFile{Data: data},
	}
	dir := t.TempDir()
	_, err := UnpackClients(fsys, dir, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "binaries", "sigilc-linux-amd64"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("written content does not match source")
	}
}

// ---------------------------------------------------------------------------
// NoopDaemon
// ---------------------------------------------------------------------------

func TestNoopDaemon(t *testing.T) {
	d := NoopDaemon()
	// NoopDaemon must satisfy the Daemon interface; the compiler check is enough,
	// but we also verify Start/Stop return nil.
	if err := d.Start(nil); err != nil {
		t.Errorf("NoopDaemon.Start: %v", err)
	}
	if err := d.Stop(nil); err != nil {
		t.Errorf("NoopDaemon.Stop: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DefaultConfigPath exports
// ---------------------------------------------------------------------------

func TestDefaultConfigPaths_NonEmpty(t *testing.T) {
	if DefaultServerConfigPath() == "" {
		t.Error("DefaultServerConfigPath() returned empty string")
	}
	if DefaultClientConfigPath() == "" {
		t.Error("DefaultClientConfigPath() returned empty string")
	}
}

// ---------------------------------------------------------------------------
// New (smoke test – no OS service interaction)
// ---------------------------------------------------------------------------

func TestNew_ReturnsService(t *testing.T) {
	svc, err := New(NoopDaemon(), Config{Role: RoleServer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc == nil {
		t.Fatal("New returned nil service")
	}
}

// ---------------------------------------------------------------------------
// ClientBinariesFS
// ---------------------------------------------------------------------------

func TestClientBinariesFS_ContainsREADME(t *testing.T) {
	fsys := ClientBinariesFS()
	// At minimum the dist/README we placed should be present.
	_, err := fs.Stat(fsys, "dist/README")
	if err != nil {
		t.Errorf("dist/README not found in ClientBinariesFS: %v", err)
	}
}

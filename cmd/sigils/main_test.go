package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// runMainEnv, when set, makes the test binary run main with its arguments
// instead of the tests.
const runMainEnv = "SIGILS_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) != "" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// The errors sigils prints may quote what it reads, as the error of an
// invalid server.yaml quotes the names of its DNS providers: they reach the
// terminal without control characters.
func TestErrorIsPrintable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	// A YAML escape: a raw control character would fail the YAML parser.
	if err := os.WriteFile(path, []byte("dns_providers:\n  \"x\\e]0;pwned\\a\":\n    type: exec\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "config", "validate", "--config", path)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("sigils config validate: %v, want exit status 1; stderr:\n%s", err, stderr.String())
	}
	printed := stderr.String()
	if !strings.Contains(printed, "error: validation failed:\n") || !strings.Contains(printed, "dns_providers.x ]0;pwned .command: required") {
		t.Fatalf("sigils config validate printed %q, want the invalid DNS provider on a line of its own", printed)
	}
	if i := strings.IndexFunc(printed, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }); i >= 0 {
		t.Fatalf("sigils config validate printed a control character: %q", printed)
	}
}

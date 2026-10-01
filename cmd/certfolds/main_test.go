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
const runMainEnv = "CERTFOLDS_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) != "" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// The errors certfolds prints may quote what it reads, as a type error of
// server.yaml quotes the value: they reach the terminal without control
// characters, and with the newlines between errors.
func TestErrorIsPrintable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	// A YAML escape: a raw control character would fail the YAML parser.
	if err := os.WriteFile(path, []byte("dns_providers:\n  p:\n    type: exec\n    skip_propagation_check: \"\\e]0;pwned\\a\"\n"), 0o600); err != nil {
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
		t.Fatalf("certfolds config validate: %v, want exit status 1; stderr:\n%s", err, stderr.String())
	}
	printed := stderr.String()
	if !strings.Contains(printed, "error: parse yaml: yaml: unmarshal errors:\n") || !strings.Contains(printed, "cannot unmarshal !!str ` ]0;pwned ` into bool") {
		t.Fatalf("certfolds config validate printed %q, want the type error with its value on a line of its own", printed)
	}
	if i := strings.IndexFunc(printed, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }); i >= 0 {
		t.Fatalf("certfolds config validate printed a control character: %q", printed)
	}
}

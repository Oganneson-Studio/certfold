//go:build windows

package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

func TestCreateTempGrantsConfiguredOwner(t *testing.T) {
	// A syntactically valid SID with no SDDL alias; it need not exist.
	const owner = "S-1-5-21-1-2-3-1001"
	tmp, err := createTemp(outputDir(t), config.OutputSpec{Format: "pem-key", Path: "key.pem", Owner: owner})
	if err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if sddl := fileSecurity(t, tmp.Name()).String(); !strings.Contains(sddl, "(A;;FR;;;"+owner+")") {
		t.Fatalf("DACL does not grant the configured owner read access only: %s", sddl)
	}
}

// TestOwnerSDDLAliasGrantsNoGroup covers an owner written as an SDDL alias:
// "BU" must not grant Users access to the key. Failing to resolve it is fine.
func TestOwnerSDDLAliasGrantsNoGroup(t *testing.T) {
	tmp, err := createTemp(outputDir(t), config.OutputSpec{Format: "pem-key", Path: "key.pem", Owner: "BU"})
	if err != nil {
		return
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if sddl := fileSecurity(t, tmp.Name()).String(); strings.Contains(sddl, ";;;BU)") {
		t.Fatalf("owner BU granted Users access: %s", sddl)
	}
}

// TestWriteReplacesInheritedReadableKey covers a key file that an earlier
// version wrote with the directory's ACL: the next write must replace it with
// one that only the allowed accounts can open.
func TestWriteReplacesInheritedReadableKey(t *testing.T) {
	path := filepath.Join(outputDir(t), "key.pem")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sddl := fileSecurity(t, path).String(); !strings.Contains(sddl, ";;;BU)") {
		t.Fatalf("the old key should inherit Users read access: %s", sddl)
	}

	if err := Write(makeBundle(t), config.OutputSpec{Format: "pem-key", Path: path}); err != nil {
		t.Fatal(err)
	}
	checkMode(t, path, 0o600)
}

// TestWriteTwiceWithReadOnlyMode covers an explicit mode without the owner
// write bit. Chmod would mark the output read-only on Windows, and the next
// rewrite could not replace it.
func TestWriteTwiceWithReadOnlyMode(t *testing.T) {
	dir := outputDir(t)
	for _, format := range []string{"pem-key", "pem-cert"} {
		spec := config.OutputSpec{Format: format, Path: filepath.Join(dir, format), Mode: 0o440}
		for attempt := 1; attempt <= 2; attempt++ {
			if err := Write(makeBundle(t), spec); err != nil {
				t.Fatalf("%s write %d: %v", format, attempt, err)
			}
		}
	}
}

// TestWriteUnknownOwnerFailsClosed covers an owner that does not resolve: the
// write must fail before the key exists anywhere with the directory's ACL.
func TestWriteUnknownOwnerFailsClosed(t *testing.T) {
	dir := outputDir(t)
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	spec := config.OutputSpec{Format: "pem-key", Path: path, Owner: "sigil-test-no-such-account"}
	if err := Write(makeBundle(t), spec); err == nil {
		t.Fatal("expected an unknown owner to fail the write")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "old" {
		t.Fatalf("existing output changed: %q, %v", data, err)
	}
	if left, err := filepath.Glob(filepath.Join(dir, ".sigil-tmp-*")); err != nil || len(left) != 0 {
		t.Fatalf("temporary files left behind: %v, %v", left, err)
	}
}

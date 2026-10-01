//go:build windows

package output

import (
	"strings"
	"testing"

	"github.com/Oganneson-Studio/certfold/internal/config"
)

func TestCreateTempGrantsConfiguredOwner(t *testing.T) {
	// A syntactically valid SID with no SDDL alias; it need not exist. Windows
	// accepts SID strings in any case, so a lowercase spelling must work too.
	const sid = "S-1-5-21-1-2-3-1001"
	for _, owner := range []string{sid, strings.ToLower(sid)} {
		t.Run(owner, func(t *testing.T) {
			tmp, err := createTemp(outputDir(t), config.OutputSpec{Format: "pem-key", Path: "key.pem", Owner: owner})
			if err != nil {
				t.Fatal(err)
			}
			if err := tmp.Close(); err != nil {
				t.Fatal(err)
			}
			if sddl := fileSecurity(t, tmp.Name()).String(); !strings.Contains(sddl, "(A;;FR;;;"+sid+")") {
				t.Fatalf("DACL does not grant the configured owner read access only: %s", sddl)
			}
		})
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

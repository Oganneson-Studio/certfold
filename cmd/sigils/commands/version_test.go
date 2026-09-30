package commands

import (
	"encoding/json"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/version"
)

// TestVersionPrintsJSON covers `sigils --json version`, which printed text:
// the global --json flag applies to it as to the other commands that print
// something to read.
func TestVersionPrintsJSON(t *testing.T) {
	printed := runSigils(t, "--json", "version")
	var got struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	if err := json.Unmarshal([]byte(printed), &got); err != nil {
		t.Fatalf("version --json printed %q: %v", printed, err)
	}
	if got.Version != version.Version || got.Commit != version.Commit {
		t.Errorf("version --json = %+v, want version %q and commit %q", got, version.Version, version.Commit)
	}
	if text := runSigils(t, "version"); text != "sigils "+version.String()+"\n" {
		t.Errorf("version printed %q, want sigils %s", text, version.String())
	}
}

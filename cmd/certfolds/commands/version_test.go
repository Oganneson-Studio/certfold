package commands

import (
	"encoding/json"
	"testing"

	"github.com/Oganneson-Studio/certfold/internal/version"
)

// TestVersionPrintsJSON covers `certfolds --json version`, which printed text:
// the global --json flag applies to it as to the other commands that print
// something to read.
func TestVersionPrintsJSON(t *testing.T) {
	printed := runCertfolds(t, "--json", "version")
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
	if text := runCertfolds(t, "version"); text != "certfolds "+version.String()+"\n" {
		t.Errorf("version printed %q, want certfolds %s", text, version.String())
	}
}

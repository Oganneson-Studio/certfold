package api

import (
	"strings"
	"testing"
)

// TestInstallPs1StopsBeforeItChangesAnything checks the two lines that keep
// the Windows installer from going on after a failure, both of which must
// come before the first change it makes:
//   - $ErrorActionPreference = 'Stop' makes a failed cmdlet, such as a
//     download that gets a 404, end the script. Without it the error ends
//     only its own statement, and the script goes on: it runs the certfoldc.exe
//     an earlier install left, or, when there is none, gets past each check
//     of a $LASTEXITCODE that an earlier command of the session left at 0.
//   - The elevation check, since the steps after it fail halfway without
//     administrator rights.
func TestInstallPs1StopsBeforeItChangesAnything(t *testing.T) {
	script := getInstallScript(t, "/install.ps1").Body.String()
	firstChange := strings.Index(script, "New-Item ")
	if firstChange < 0 {
		t.Fatalf("script has no New-Item:\n%s", script)
	}
	for _, want := range []string{
		"\n$ErrorActionPreference = 'Stop'\n",
		"\nif (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {\n    throw ",
	} {
		switch i := strings.Index(script, want); {
		case i < 0:
			t.Errorf("script lacks %q:\n%s", want, script)
		case i > firstChange:
			t.Errorf("%q comes after the first change the script makes:\n%s", want, script)
		}
	}
}

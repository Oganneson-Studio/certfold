package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

const installTestURL = "https://sigil.example.com:8443"

// getInstallScript serves GET target from a server whose public URL is
// installTestURL.
func getInstallScript(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	deps := buildDeps(t)
	deps.ServerCfg.Server.PublicURL = installTestURL
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", target, rec.Code, rec.Body.String())
	}
	return rec
}

// TestInstallPs1IgnoresQuery checks that no part of the URL reaches the script
// PowerShell runs: the token is the -Token argument of the command.
func TestInstallPs1IgnoresQuery(t *testing.T) {
	plain := getInstallScript(t, "/install.ps1")
	payload := `x'; Remove-Item C:\sigil; $([Environment]::MachineName) "`
	withToken := getInstallScript(t, "/install.ps1?token="+url.QueryEscape(payload))
	if withToken.Body.String() != plain.Body.String() {
		t.Fatalf("the query changed the script:\n%s", withToken.Body.String())
	}
	if got := withToken.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain; charset=utf-8", got)
	}
}

// TestInstallPs1Script checks the rules the Windows installer follows to run
// alike in Windows PowerShell 5.1 and PowerShell 7, as a script block in the
// operator's session.
func TestInstallPs1Script(t *testing.T) {
	script := getInstallScript(t, "/install.ps1").Body.String()
	lines := strings.Split(script, "\n")

	for i, r := range script {
		if r > unicode.MaxASCII {
			t.Fatalf("non-ASCII %q at byte %d", r, i)
		}
	}

	// Only comments may come before the param block.
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if want := `param([Parameter(Mandatory = $true)][string]$Token)`; line != want {
			t.Errorf("first statement = %q, want %q", line, want)
		}
		break
	}

	// exit would close the operator's session.
	if exit := regexp.MustCompile(`(?im)(^|[;{}])\s*exit\b`).FindString(script); exit != "" {
		t.Errorf("script calls exit: %q", exit)
	}

	// PowerShell does not stop when sigilc fails, so each run of it must be
	// followed by a check of its exit code.
	calls := 0
	for i, line := range lines {
		if !strings.HasPrefix(line, "& ") {
			continue
		}
		calls++
		if i+1 == len(lines) || !strings.HasPrefix(lines[i+1], "if ($LASTEXITCODE -ne 0) { throw ") {
			t.Errorf("%q is not followed by a check of $LASTEXITCODE", line)
		}
	}
	if calls != 3 {
		t.Errorf("script runs sigilc %d times, want 3: enroll, service install and service start", calls)
	}

	_, usage := InstallCommands(installTestURL, "<TOKEN>")
	for _, want := range []string{
		"#   " + usage + "\n",
		"$ServerURL = '" + installTestURL + "'\n",
		// Server Core has no Internet Explorer engine for Invoke-WebRequest
		// to parse with.
		"Invoke-WebRequest -UseBasicParsing ",
		"'AMD64' { 'amd64' }",
		"'ARM64' { 'arm64' }",
		"'X86'   { '386' }",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
}

func TestInstallShUsage(t *testing.T) {
	script := getInstallScript(t, "/install.sh").Body.String()
	usage, _ := InstallCommands(installTestURL, "<TOKEN>")
	if !strings.Contains(script, "\n# Usage: "+usage+"\n") {
		t.Errorf("script lacks the usage %q:\n%s", usage, script)
	}
}

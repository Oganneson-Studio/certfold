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
	deps.CurrentServer().Server.PublicURL = installTestURL
	rec := httptest.NewRecorder()
	newHandler(deps).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
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

	// Only comments may come before the param block. Its parameter sets make
	// PowerShell ask for the token, which -Upgrade does not take.
	first := 0
	for first < len(lines) && (lines[first] == "" || strings.HasPrefix(lines[first], "#")) {
		first++
	}
	params := strings.Join([]string{
		`[CmdletBinding(DefaultParameterSetName = 'Install')]`,
		`param(`,
		`    [Parameter(Mandatory = $true, ParameterSetName = 'Install')][string]$Token,`,
		`    [Parameter(Mandatory = $true, ParameterSetName = 'Upgrade')][switch]$Upgrade`,
		`)`,
	}, "\n") + "\n"
	if rest := strings.Join(lines[first:], "\n"); !strings.HasPrefix(rest, params) {
		t.Errorf("script does not start with the param block\n%s\nbut with\n%s", params, rest)
	}

	// exit would close the operator's session.
	if exit := regexp.MustCompile(`(?im)(^|[;{}])\s*exit\b`).FindString(script); exit != "" {
		t.Errorf("script calls exit: %q", exit)
	}

	// PowerShell does not stop when sigilc fails, so each run of it must be
	// followed by a check of its exit code.
	calls := 0
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimLeft(line, " "), "& ") {
			continue
		}
		calls++
		if i+1 == len(lines) || !strings.HasPrefix(strings.TrimLeft(lines[i+1], " "), "if ($LASTEXITCODE -ne 0) { throw ") {
			t.Errorf("%q is not followed by a check of $LASTEXITCODE", line)
		}
	}
	if calls != 6 {
		t.Errorf("script runs sigilc %d times, want 6: version, enroll, service start after a failed enrollment, "+
			"service uninstall, install and start", calls)
	}

	_, withToken := InstallCommands(installTestURL, "<TOKEN>")
	for _, want := range []string{
		"#   " + withToken + "\n",
		"#   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; " +
			"& ([scriptblock]::Create((irm '" + installTestURL + "/install.ps1')))\n",
		"#   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; " +
			"& ([scriptblock]::Create((irm '" + installTestURL + "/install.ps1'))) -Upgrade\n",
		"#   sigils token create --name <name> --replace\n",
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

// TestInstallPs1KeepsTokenOffCommandLines checks that install.ps1 hands the
// token to sigilc through its environment, and takes it out of the
// operator's session again, whether enroll fails or not.
func TestInstallPs1KeepsTokenOffCommandLines(t *testing.T) {
	script := getInstallScript(t, "/install.ps1").Body.String()
	if strings.Contains(script, "enroll --token") {
		t.Errorf("script passes the token to sigilc as an argument:\n%s", script)
	}
	inOrder(t, script,
		"\n    $env:SIGILC_TOKEN = $Token\n    try {\n        & $Dest enroll\n",
		"\n    } finally {\n        Remove-Item -Path Env:\\SIGILC_TOKEN\n    }\n",
	)
}

// TestInstallPs1ReplacesSigilc checks the steps of install.ps1, which are
// those of install.sh (TestInstallShReplacesSigilc). Windows does not let a
// sigilc.exe that runs be replaced, so the service stops first.
func TestInstallPs1ReplacesSigilc(t *testing.T) {
	script := getInstallScript(t, "/install.ps1").Body.String()
	if strings.Contains(script, "-OutFile $Dest") {
		t.Errorf("script downloads over sigilc.exe:\n%s", script)
	}
	inOrder(t, script,
		"\n$Download = 'C:\\Program Files\\Sigil\\sigilc.download.exe'\n",
		"\n$Service = Get-Service -Name sigilc -ErrorAction SilentlyContinue\n",
		"\nif ($Upgrade -and -not $Service) {\n    throw ",
		"\nNew-Item ",
		" -OutFile $Download\n",
		"\n& $Download version\n",
		"\nif ($Service) {\n    Write-Host 'Stopping service...'\n    Stop-Service -Name sigilc\n}\n",
		"\nMove-Item -Force -LiteralPath $Download -Destination $Dest\n",
		"\nif (-not $Upgrade) {\n",
		"\n        & $Dest enroll\n",
		"\n    if ($Service) {\n",
		"\n        & $Dest service uninstall\n",
		"\n    & $Dest service install\n",
		"\n}\n",
		"\n& $Dest service start\n",
	)
}

// TestInstallPs1StartsServiceWhenEnrollFails checks that a reinstall whose
// enrollment fails starts the service it stopped, which goes on with the
// client.yaml the failed enrollment left, and fails with both errors when
// that start fails too.
func TestInstallPs1StartsServiceWhenEnrollFails(t *testing.T) {
	script := getInstallScript(t, "/install.ps1").Body.String()
	inOrder(t, script,
		"\n        & $Dest enroll\n",
		"\n    } catch {\n",
		"\n        $EnrollError = $_\n        if (-not $Service) { throw }\n",
		"\n        & $Dest service start\n"+
			"        if ($LASTEXITCODE -ne 0) { throw \"$EnrollError; starting the sigilc service again",
		"\n        throw \"$EnrollError. The sigilc service runs again with its earlier client.yaml; "+
			"fix what the error says, then run the installer again.\"\n",
		"\n    } finally {\n",
	)
}

// TestInstallShUsage checks the commands that the comment of install.sh
// gives: with a token, as sigils token create prints it; asking for the
// token; and to upgrade. It names --replace, which the token for a reinstall
// needs, as does the usage the script prints.
func TestInstallShUsage(t *testing.T) {
	script := getInstallScript(t, "/install.sh").Body.String()
	withToken, _ := InstallCommands(installTestURL, "<TOKEN>")
	for _, want := range []string{
		"\n#   " + withToken + "\n",
		"\n#   curl -fsSL '" + installTestURL + "/install.sh' | sudo sh\n",
		"\n#   curl -fsSL '" + installTestURL + "/install.sh' | sudo sh -s -- --upgrade\n",
		"\n#   sigils token create --name <name> --replace\n",
		`echo "client, create the token with: sigils token create --name <name> --replace" >&2`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
}

// TestInstallShStartsServiceWhenEnrollFails checks that a reinstall whose
// enrollment fails starts the service it stopped, which goes on with the
// client.yaml the failed enrollment left, and says so; when that start fails
// too, it says that both failed, whose errors sigilc printed.
func TestInstallShStartsServiceWhenEnrollFails(t *testing.T) {
	script := getInstallScript(t, "/install.sh").Body.String()
	inOrder(t, script,
		"\n  if ! SIGILC_TOKEN=\"$TOKEN\" \"$DEST\" enroll; then\n",
		"\n    if [ -n \"$INSTALLED\" ]; then\n      if \"$DEST\" service start; then\n",
		"\n        echo \"Enrolling failed. The sigilc service runs again with its earlier client.yaml; "+
			"fix what the error above says, then run the installer again.\" >&2\n      else\n",
		"\n        echo \"Enrolling failed, and so did starting the sigilc service again with its earlier client.yaml: "+
			"see both errors above.\" >&2\n",
		"\n    exit 1\n",
	)
}

// inOrder checks that script holds each of parts after the one before it.
func inOrder(t *testing.T, script string, parts ...string) {
	t.Helper()
	rest := script
	for i, part := range parts {
		at := strings.Index(rest, part)
		if at < 0 {
			if i == 0 {
				t.Errorf("script lacks %q:\n%s", part, script)
			} else {
				t.Errorf("script lacks %q after %q:\n%s", part, parts[i-1], script)
			}
			return
		}
		// The next part may begin with the newline that ends this one.
		rest = rest[at+1:]
	}
}

// TestInstallShKeepsTokenOffCommandLines checks that install.sh hands the
// token to sigilc through its environment, and asks for it on the terminal,
// without echo, when --token does not give it: the script runs from a pipe,
// which is its standard input. The EXIT trap that restores echo is set before
// echo goes off, and the trap for signals makes them run it.
func TestInstallShKeepsTokenOffCommandLines(t *testing.T) {
	script := getInstallScript(t, "/install.sh").Body.String()
	if !strings.Contains(script, "\n  if ! SIGILC_TOKEN=\"$TOKEN\" \"$DEST\" enroll; then\n") {
		t.Errorf("script does not pass the token to sigilc enroll as SIGILC_TOKEN:\n%s", script)
	}
	if strings.Contains(script, "enroll --token") {
		t.Errorf("script passes the token to sigilc as an argument:\n%s", script)
	}
	inOrder(t, script,
		"\ntrap 'exit 1' HUP INT TERM\n",
		"\n  if ! (: </dev/tty) 2>/dev/null; then\n",
		"\n  trap 'stty echo </dev/tty' EXIT\n",
		"\n  stty -echo </dev/tty\n",
		"\n  read -r TOKEN </dev/tty || :\n",
		"\n  stty echo </dev/tty\n",
		"\n  if [ -z \"$TOKEN\" ]; then usage; fi\n",
		// All of it before anything changes.
		"\nTMP=$(mktemp ",
	)
}

// TestInstallShReplacesSigilc checks the steps of install.sh: the download
// goes to a file beside sigilc, which runs once before anything changes, and
// which one rename puts in place, so an interrupted download leaves the
// sigilc there as it was. On a host with the service, the service stops
// before the rename, and is uninstalled after the new enrollment and before
// it is installed again. --upgrade skips the enrollment and needs the
// service.
func TestInstallShReplacesSigilc(t *testing.T) {
	script := getInstallScript(t, "/install.sh").Body.String()
	if strings.Contains(script, `-o "$DEST"`) {
		t.Errorf("script downloads over sigilc:\n%s", script)
	}
	inOrder(t, script,
		"\n    --upgrade) UPGRADE=1; shift ;;\n",
		"\nTMP=$(mktemp \"$DEST.XXXXXX\")\ntrap 'rm -f \"$TMP\"' EXIT\n",
		` -o "$TMP"`,
		"\n\"$TMP\" version\n",
		"\nfor f in /etc/systemd/system/sigilc.service /Library/LaunchDaemons/sigilc.plist; do\n"+
			"  if [ -e \"$f\" ]; then INSTALLED=1; fi\ndone\n",
		"\nif [ -n \"$UPGRADE\" ] && [ -z \"$INSTALLED\" ]; then\n",
		"\n  \"$TMP\" service stop\n",
		"\nmv -f \"$TMP\" \"$DEST\"\n",
		"\nif [ -z \"$UPGRADE\" ]; then\n",
		"\" enroll; then\n",
		"\n    exit 1\n  fi\n",
		"\n    \"$DEST\" service uninstall\n",
		"\n  \"$DEST\" service install\n",
		"\nfi\n",
		"\n\"$DEST\" service start\n",
	)
}

// TestInstallShArchitectures checks that install.sh names each machine that
// uname -m reports as the GOARCH the binaries directory uses, as install.ps1
// does its Windows counterparts.
func TestInstallShArchitectures(t *testing.T) {
	script := getInstallScript(t, "/install.sh").Body.String()
	for _, want := range []string{
		"  x86_64) ARCH=amd64 ;;\n",
		"  aarch64|arm64) ARCH=arm64 ;;\n",
		"  i386|i686) ARCH=386 ;;\n",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
}

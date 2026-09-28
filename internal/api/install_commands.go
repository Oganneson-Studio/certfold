package api

import "fmt"

// InstallCommands returns the one-line commands that download sigilc from
// the server at serverURL, enroll it with token and start its service: sh
// for a Linux or macOS shell, run by a user who may sudo, and ps1 for an
// elevated Windows PowerShell 5.1 or 7. Both quote serverURL and token with
// single quotes, so neither may hold one; tokens are base64url.
//
// ps1 first adds TLS 1.2 (3072) to the protocols Windows PowerShell 5.1
// offers, which older Windows versions leave out. Where the setting is
// SystemDefault, this leaves only TLS 1.2, so the server must accept it.
func InstallCommands(serverURL, token string) (sh, ps1 string) {
	sh = fmt.Sprintf("curl -fsSL '%s/install.sh' | sudo sh -s -- --token '%s'", serverURL, token)
	ps1 = fmt.Sprintf("[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; "+
		"& ([scriptblock]::Create((irm '%s/install.ps1'))) -Token '%s'", serverURL, token)
	return sh, ps1
}

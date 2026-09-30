package api

import "fmt"

// InstallCommands returns the one-line commands that download sigilc from
// the server at serverURL, enroll it with token and start its service: sh
// for a Linux or macOS shell, run by a user who may sudo, and ps1 for an
// elevated Windows PowerShell 5.1 or 7. Both quote serverURL and token with
// single quotes, so neither may hold one; tokens are base64url. sh has curl
// fetch the script over https alone, redirects included.
//
// ps1 first adds TLS 1.2 (3072) to the protocols Windows PowerShell 5.1
// offers, which older Windows versions leave out. Where the setting is
// SystemDefault, this leaves only TLS 1.2, so the server must accept it.
func InstallCommands(serverURL, token string) (sh, ps1 string) {
	return installCommands(serverURL, " -s -- --token '"+token+"'", " -Token '"+token+"'")
}

// installCommands returns the commands of InstallCommands that pass the
// install scripts shArgs and ps1Args, each empty or starting with a space.
func installCommands(serverURL, shArgs, ps1Args string) (sh, ps1 string) {
	sh = fmt.Sprintf("curl -fsSL --proto '=https' --proto-redir '=https' '%s/install.sh' | sudo sh%s", serverURL, shArgs)
	ps1 = fmt.Sprintf("[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; "+
		"& ([scriptblock]::Create((irm '%s/install.ps1')))%s", serverURL, ps1Args)
	return sh, ps1
}

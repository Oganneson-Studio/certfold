package api

import "testing"

// TestInstallCommands pins the commands that sigils token create prints and
// the usage comments of both install scripts repeat.
func TestInstallCommands(t *testing.T) {
	sh, ps1 := InstallCommands("https://sigil.example.com:8443", "tok_EN-123")
	if want := "curl -fsSL 'https://sigil.example.com:8443/install.sh' | sudo sh -s -- --token 'tok_EN-123'"; sh != want {
		t.Errorf("sh command:\n got %s\nwant %s", sh, want)
	}
	want := "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; " +
		"& ([scriptblock]::Create((irm 'https://sigil.example.com:8443/install.ps1'))) -Token 'tok_EN-123'"
	if ps1 != want {
		t.Errorf("ps1 command:\n got %s\nwant %s", ps1, want)
	}
}

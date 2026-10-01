package commands

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
)

// privateConfigPath returns the path of a client.yaml in a directory that
// does not exist yet. Enrollment refuses a directory that accounts it does
// not trust may write to, as the temporary directory may be: enroll and
// securefile create this one private.
func privateConfigPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "etc", "client.yaml")
}

// reloadHint is the part of the line that enroll prints when it replaced the
// identity of a client.yaml that was there before while a daemon answers.
const reloadHint = "until `sigilc reload` or a restart of the sigilc service"

// TestEnrollAgainKeepsConfigWithServiceVariables enrolls again, as the
// install scripts do on a host that has sigilc, with a token for the name and
// server URL of the client.yaml there. That client.yaml takes a password
// from a variable that only the service's environment sets, which sudo does
// not pass to the installer: enroll must not need it, and must keep it.
func TestEnrollAgainKeepsConfigWithServiceVariables(t *testing.T) {
	srv := newSigningEnrollServer(t)
	cfgPath := privateConfigPath(t)
	const passwordRef = "${SIGIL_TEST_SERVICE_ONLY_PASSWORD}"
	existing := fmt.Sprintf(`client:
  name: web-1
  server_url: %q
  data_dir: %q
certificates:
  api:
    outputs:
      - format: pkcs12
        path: %q
        password: %s
`, srv.URL, t.TempDir(), filepath.Join(t.TempDir(), "api.p12"), passwordRef)
	if err := securefile.WriteFile(cfgPath, []byte(existing)); err != nil {
		t.Fatal(err)
	}

	// An endpoint of its own, so that a daemon of this host is not dialed.
	if _, err := runSigilcErr(t, "--ipc", missingIPCSocket(t), "--config", cfgPath, "enroll", "--token", srv.token(t, "web-1")); err != nil {
		t.Fatalf("enroll again: %v", err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "password: "+passwordRef+"\n") {
		t.Errorf("client.yaml after enroll lost the password reference:\n%s", raw)
	}
	t.Setenv("SIGIL_TEST_SERVICE_ONLY_PASSWORD", "secret")
	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		t.Fatalf("load client.yaml in the service's environment: %v", err)
	}
	if cfg.Identity.ClientCert == "" || cfg.Certificates["api"].Outputs[0].Password != "secret" {
		t.Fatalf("client.yaml after enroll: identity set %t, api password %q; want an identity and the password",
			cfg.Identity.ClientCert != "", cfg.Certificates["api"].Outputs[0].Password)
	}
}

// enrollAgain enrolls web-1 over a client.yaml that names it, with socket as
// the endpoint of the daemon, and returns what enroll printed.
func enrollAgain(t *testing.T, socket string) string {
	t.Helper()
	srv := newSigningEnrollServer(t)
	cfgPath := privateConfigPath(t)
	existing := fmt.Sprintf("client:\n  name: web-1\n  server_url: %q\n", srv.URL)
	if err := securefile.WriteFile(cfgPath, []byte(existing)); err != nil {
		t.Fatal(err)
	}
	out, err := runSigilcErr(t, "--ipc", socket, "--config", cfgPath, "enroll", "--token", srv.token(t, "web-1"))
	if err != nil {
		t.Fatalf("enroll again: %v", err)
	}
	return out
}

// TestEnrollAgainTellsARunningDaemonToReload checks that enrolling again
// while a daemon answers says that it goes on with the identity it loaded.
func TestEnrollAgainTellsARunningDaemonToReload(t *testing.T) {
	if out := enrollAgain(t, serveEvents(t, logging.NewRing())); !strings.Contains(out, reloadHint) {
		t.Errorf("enroll again with a daemon running printed:\n%s\nwant a line that says %q", out, reloadHint)
	}
}

// TestEnrollAgainWithoutADaemonSaysNothingOfReload checks that enrolling
// again with no daemon running, as the install scripts do once they have
// stopped the service, does not send the operator to reload one.
func TestEnrollAgainWithoutADaemonSaysNothingOfReload(t *testing.T) {
	if out := enrollAgain(t, missingIPCSocket(t)); strings.Contains(out, reloadHint) {
		t.Errorf("enroll again without a daemon printed:\n%s\nwant no line about reloading a daemon", out)
	}
}

// TestEnrollFirstTimeSaysNothingOfReload checks that the first enrollment,
// which writes client.yaml, does not tell of a daemon that cannot run yet.
func TestEnrollFirstTimeSaysNothingOfReload(t *testing.T) {
	srv := newSigningEnrollServer(t)
	cfgPath := privateConfigPath(t)
	out, err := runSigilcErr(t, "--config", cfgPath, "enroll", "--token", srv.token(t, "web-1"))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if strings.Contains(out, reloadHint) {
		t.Errorf("first enrollment printed:\n%s\nwant no line about reloading a daemon", out)
	}
}

// TestEnrollSaysTheTokenIsSpentWhenSavingFails checks the error of an
// enrollment that the server took, and replaced the identity of the client
// for, but whose identity sigilc could not save: the earlier identity no
// longer works, and enrolling again needs a new token for the name.
func TestEnrollSaysTheTokenIsSpentWhenSavingFails(t *testing.T) {
	srv := newSigningEnrollServer(t)
	cfgPath := privateConfigPath(t)
	existing := fmt.Sprintf("client:\n  name: web-1\n  server_url: %q\n", srv.URL)
	if err := securefile.WriteFile(cfgPath, []byte(existing)); err != nil {
		t.Fatal(err)
	}
	// Once the server has signed, client.yaml is no mapping to save into.
	srv.signed = func() {
		if err := os.WriteFile(cfgPath, []byte("not a mapping\n"), 0o600); err != nil {
			t.Error(err)
		}
	}
	_, err := runSigilcErr(t, "--config", cfgPath, "enroll", "--token", srv.token(t, "web-1"))
	for _, want := range []string{"save identity: ", "the server took the token, so any earlier identity of \"web-1\" no longer works", "sigils token create --name web-1 --replace"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("enroll error = %v, want one that says %q", err, want)
		}
	}
}

// TestEnrollSaysTheTokenIsSpentWhenTheAnswerIsBad checks the error of an
// enrollment that the server answered with 200, and so took the token for,
// but whose answer sigilc cannot use: the earlier identity no longer works,
// as when saving fails. A refused enrollment spends nothing, and says
// nothing of it.
func TestEnrollSaysTheTokenIsSpentWhenTheAnswerIsBad(t *testing.T) {
	for _, answer := range []string{`{"client_cert":"not a certificate"}`, `not JSON`} {
		t.Run(answer, func(t *testing.T) {
			srv := &refusingEnrollServer{}
			srv.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				srv.requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(answer))
			}))
			t.Cleanup(srv.Close)
			_, err := runSigilcErr(t, "--config", privateConfigPath(t), "enroll", "--token", srv.token(t, "web-1"))
			for _, want := range []string{"enroll: ", "the server took the token, so any earlier identity of \"web-1\" no longer works", "sigils token create --name web-1 --replace"} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("enroll error = %v, want one that says %q", err, want)
				}
			}
		})
	}

	refusing := newRefusingEnrollServer(t)
	_, err := runSigilcErr(t, "--config", privateConfigPath(t), "enroll", "--token", refusing.token(t, "web-1"))
	if err == nil || strings.Contains(err.Error(), "took the token") {
		t.Errorf("refused enrollment error = %v, want one that does not say the token was taken", err)
	}
}

// TestEnrollRefusesAnotherClientsConfig checks that a client.yaml for
// another name or server is left alone, before the token is sent, with an
// error that says which file stands in the way.
func TestEnrollRefusesAnotherClientsConfig(t *testing.T) {
	srv := newRefusingEnrollServer(t)
	for _, tc := range []struct{ name, serverURL string }{
		{"web-2", srv.URL},
		{"web-1", "https://other.example.com"},
	} {
		t.Run(tc.name+" at "+tc.serverURL, func(t *testing.T) {
			cfgPath := privateConfigPath(t)
			existing := fmt.Sprintf("client:\n  name: %s\n  server_url: %q\n", tc.name, tc.serverURL)
			if err := securefile.WriteFile(cfgPath, []byte(existing)); err != nil {
				t.Fatal(err)
			}
			before := srv.requests.Load()
			err := runEnrollCommand(cfgPath, srv.token(t, "web-1"))
			if err == nil || !strings.Contains(err.Error(), "remove "+cfgPath+" and try again") {
				t.Fatalf("enroll error = %v, want one that says to remove %s", err, cfgPath)
			}
			if n := srv.requests.Load() - before; n != 0 {
				t.Fatalf("sent the token %d times for a client.yaml of another client", n)
			}
			if got, err := os.ReadFile(cfgPath); err != nil || string(got) != existing {
				t.Fatalf("client.yaml after a refused enrollment = %q (error %v), want it unchanged", got, err)
			}
		})
	}
}

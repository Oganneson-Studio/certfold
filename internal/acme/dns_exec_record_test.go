package acme

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestExecProviderRejectsUnsafeRecordName covers record names that hold what
// cmd.exe or a shell interprets, or that could pass for an option: the
// program must not run with them. lego passes the provider the identifier of
// the CA's authorization, which it does not compare with the order, and on
// Windows Go runs a batch file through cmd.exe, which expands %VAR% and splits
// the command line at & and |. Names in the case and with the underscores of
// real CNAME targets must still run.
func TestExecProviderRejectsUnsafeRecordName(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(testHookDirEnv, dir)
	captureLog(t)
	p := hookProvider(t, "record", "--token="+argvSecret)

	for _, domain := range []string{
		"a&b.example.test",
		"a|b.example.test",
		"a%OS%b.example.test",
		"a^b.example.test",
		"a<b.example.test",
		"a`b`.example.test",
		"a$b.example.test",
		"a!b.example.test",
		"a b.example.test",
		"a\nb.example.test",
		"a..b.example.test",
		"-rf.example.test",
		"bücher.example.test",
	} {
		err := p.Present(domain, "token", "token.thumbprint")
		if err == nil {
			t.Errorf("Present(%q) succeeded, want the record name refused", domain)
		} else if msg := err.Error(); !strings.HasPrefix(msg, "exec: present: record name ") ||
			!strings.HasSuffix(msg, " is not a host name") || strings.Contains(msg, argvSecret) {
			t.Errorf("Present(%q) error = %q, want the record name refused", domain, msg)
		}
	}
	if runs := recordedRuns(t, dir); len(runs) != 0 {
		t.Fatalf("the program ran with an unsafe record name: %s", strings.Join(runs, "\n"))
	}

	// Mixed case and underscores are ordinary in delegated challenge names.
	if err := p.Present("_Sub.WWW.Example-1.test", "token", "token.thumbprint"); err != nil {
		t.Fatalf("Present with a mixed-case name: %v", err)
	}
	if runs := recordedRuns(t, dir); len(runs) != 1 {
		t.Fatalf("runs = %q, want the one for the mixed-case name", runs)
	}
}

// TestExecProviderRejectsUnsafeCNAMETarget covers the record name taken from
// a CNAME: lego follows the CNAME of the challenge record before it calls the
// provider, and miekg/dns escapes only . ( ) ; space @ " and \ when it unpacks
// a name, so a resolver, a man in the middle of plain DNS or whoever holds the
// DNS provider's credentials chooses the record name the program receives. A
// CNAME to an ordinary name must still be followed: delegating the challenge
// record to another zone is what CNAME support is for.
//
// Like TestSetDNSResolvers it runs in a child process: the resolvers lego uses
// are process-wide.
func TestExecProviderRejectsUnsafeCNAMETarget(t *testing.T) {
	const childEnv = "CERTFOLD_TEST_UNSAFE_CNAME"
	if os.Getenv(childEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestExecProviderRejectsUnsafeCNAMETarget$", "-test.v", "-test.timeout=1m")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		// Without the PASS line the child may have run no test at all.
		if err != nil || !strings.Contains(string(out), "--- PASS: TestExecProviderRejectsUnsafeCNAMETarget") {
			t.Fatalf("child process: %v\n%s", err, out)
		}
		return
	}

	// Backquotes, $ and | pass through miekg/dns unescaped.
	cnames := map[string]string{
		"_acme-challenge.unsafe.example.test.": "`id`$HOME|x.evil.test.",
		"_acme-challenge.option.example.test.": "-rf.evil.test.",
		"_acme-challenge.safe.example.test.":   "_acme-challenge.delegated.example.net.",
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        conn,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			q := r.Question[0]
			if target, ok := cnames[q.Name]; ok && q.Qtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
					Target: target,
				})
			} else {
				m.Rcode = dns.RcodeNameError
			}
			_ = w.WriteMsg(m)
		}),
	}
	served := make(chan error, 1)
	go func() { served <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-served:
		t.Fatalf("DNS server: %v", err)
	}
	defer server.Shutdown()
	SetDNSResolvers([]string{conn.LocalAddr().String()})

	dir := t.TempDir()
	t.Setenv(testHookDirEnv, dir)
	p := hookProvider(t, "record")
	// hookProvider turns CNAME support off; certfolds runs with lego's default.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "")

	if err := p.Present("safe.example.test", "token", "token.thumbprint"); err != nil {
		t.Fatalf("Present through an ordinary CNAME: %v", err)
	}
	for _, domain := range []string{"unsafe.example.test", "option.example.test"} {
		if err := p.Present(domain, "token", "token.thumbprint"); err == nil {
			t.Errorf("Present(%q) succeeded, want the CNAME target refused", domain)
		}
	}

	// Without the delegated run, a DNS server the test failed to reach would
	// pass it.
	runs := recordedRuns(t, dir)
	want := fmt.Sprintf("%q", []string{"present", "_acme-challenge.delegated.example.net.", txtValue("token.thumbprint")})
	if len(runs) != 1 || runs[0] != want {
		t.Fatalf("runs = %q, want only %s", runs, want)
	}
}

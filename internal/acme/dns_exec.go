package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/proc"
)

// Bounds on one run of an exec provider's program. They are variables only so
// tests can shorten them.
var (
	// dnsHookTimeout bounds one run; when it expires the program is killed
	// along with the processes it started.
	dnsHookTimeout = 2 * time.Minute
	// dnsHookWaitDelay bounds how long the program's output may stay open
	// after it exits or is killed, typically because a process it started
	// still holds it.
	dnsHookWaitDelay = 5 * time.Second
)

// execProvider is the exec DNS provider. For each challenge record it runs
//
//	argv... present|cleanup <fqdn> <value>
//
// the calling convention of lego's exec provider in its default mode: fqdn is
// the challenge record name after following CNAMEs, with a trailing dot, and
// value is the TXT record content. A record name that is not a host name is
// refused without running the program. The program inherits the environment
// of sigils and must exit 0 on success.
//
// Unlike lego's exec provider it bounds each run, takes an argv instead of a
// single program path, and does not implement Sequential, so lego does not
// wait between the domains of a certificate. Runs for different certificates
// may overlap: the program must cope with concurrent runs.
type execProvider struct {
	// ctx is the Issuer's: when it ends, a program still running is killed
	// along with the processes it started. It is not the ctx of Issue,
	// which for a manual renewal is that of an IPC request.
	ctx  context.Context
	argv []string
}

func (p *execProvider) Present(domain, _, keyAuth string) error {
	return p.run("present", domain, keyAuth)
}

func (p *execProvider) CleanUp(domain, _, keyAuth string) error {
	return p.run("cleanup", domain, keyAuth)
}

func (p *execProvider) Timeout() (timeout, interval time.Duration) {
	return dnsPropagationTimeout, dnsPollingInterval
}

// run runs the program for action, through proc.Run: a run that times out,
// or whose ctx ends, is killed along with the processes the program started,
// so that none of them changes the record after lego has moved on. The error it returns names only
// the action, the record and the exit status or timeout: it becomes the
// certificate's last error, which IPC shows, while the arguments may hold
// credentials and the output may repeat them. The last 4 KiB of the output
// are logged instead, as a Private value that only the service log holds.
func (p *execProvider) run(action, domain, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	// The record name comes from the network: from the identifier of the
	// CA's authorization, which lego does not compare with the order, and
	// from the CNAME records lego follows, over plain DNS. Windows runs a
	// batch file through cmd.exe, which parses the arguments again, and a
	// script may hand them to a shell, so only a host name may reach the
	// program; one beginning with '-' could pass for an option.
	if !isHostName(info.EffectiveFQDN) {
		return fmt.Errorf("exec: %s: record name %q is not a host name", action, info.EffectiveFQDN)
	}

	// Clone first: appending to the shared argv in place would let concurrent
	// runs overwrite each other's arguments in its spare capacity.
	argv := append(slices.Clone(p.argv), action, info.EffectiveFQDN, info.Value)
	out, err := proc.Run(p.ctx, argv, dnsHookTimeout, dnsHookWaitDelay)
	if err == nil {
		return nil
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// Unlike on_change, a failure: the process may yet change the record.
		err = errors.New("exit status 0, but a process it started still holds its output")
	}
	if len(out) > 0 {
		slog.Warn("exec DNS provider failed",
			"action", action, "record", info.EffectiveFQDN, "error", err, "output", logging.Private(out))
	}
	return fmt.Errorf("exec: %s %s: %w", action, info.EffectiveFQDN, err)
}

// isHostName reports whether name, a record name with its trailing dot, is
// made of labels of ASCII letters, digits, '-' and '_', none of them empty or
// beginning with '-'. Challenge records and the CNAME targets they are
// delegated to have underscores, and their case varies.
func isHostName(name string) bool {
	for label := range strings.SplitSeq(strings.TrimSuffix(name, "."), ".") {
		if label == "" || label[0] == '-' || strings.ContainsFunc(label, func(r rune) bool {
			return !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '-' || r == '_')
		}) {
			return false
		}
	}
	return true
}

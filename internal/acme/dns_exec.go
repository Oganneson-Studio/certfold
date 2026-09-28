package acme

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"slices"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// Bounds on one run of an exec provider's program. They are variables only so
// tests can shorten them.
var (
	// dnsHookTimeout bounds one run; when it expires the program is killed.
	dnsHookTimeout = 2 * time.Minute
	// dnsHookWaitDelay bounds how long the program's output may stay open
	// after it exits or is killed, typically because a process it started
	// (such as the curl of a killed shell script) still holds it.
	dnsHookWaitDelay = 5 * time.Second
)

// dnsHookLogLimit caps the program output logged after a failed run. The end
// of the output, where errors usually are, is kept.
const dnsHookLogLimit = 4 << 10

// execProvider is the exec DNS provider. For each challenge record it runs
//
//	argv... present|cleanup <fqdn> <value>
//
// the calling convention of lego's exec provider in its default mode: fqdn is
// the challenge record name after following CNAMEs, with a trailing dot, and
// value is the TXT record content. The program inherits the environment of
// sigils and must exit 0 on success.
//
// Unlike lego's exec provider it bounds each run, takes an argv instead of a
// single program path, and does not implement Sequential, so lego does not
// wait between the domains of a certificate. Runs for different certificates
// may overlap: the program must cope with concurrent runs.
type execProvider struct {
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

// run runs the program for action. The error it returns names only the
// action, the record and the exit status or timeout: it becomes the
// certificate's last error, which IPC shows, while the arguments may hold
// credentials and the output may repeat them. The output is logged instead,
// as a Private value that only the service log holds.
func (p *execProvider) run(action, domain, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	ctx, cancel := context.WithTimeout(context.Background(), dnsHookTimeout)
	defer cancel()
	// Clone first: appending to the shared argv in place would let concurrent
	// runs overwrite each other's arguments in its spare capacity.
	args := append(slices.Clone(p.argv[1:]), action, info.EffectiveFQDN, info.Value)
	cmd := exec.CommandContext(ctx, p.argv[0], args...)
	cmd.WaitDelay = dnsHookWaitDelay
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		// Wait reports the killed process's exit status, not the timeout.
		err = fmt.Errorf("timed out after %s", dnsHookTimeout)
	}
	if len(out) > 0 {
		if n := len(out); n > dnsHookLogLimit {
			out = append([]byte("..."), out[n-dnsHookLogLimit:]...)
		}
		slog.Warn("exec DNS provider failed",
			"action", action, "record", info.EffectiveFQDN, "error", err, "output", logging.Private(out))
	}
	return fmt.Errorf("exec: %s %s: %w", action, info.EffectiveFQDN, err)
}

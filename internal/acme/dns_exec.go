package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"slices"
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

// run runs the program for action, through proc.Run: a run that times out is
// killed along with the processes the program started, so that none of them
// changes the record after lego has moved on. The error it returns names only
// the action, the record and the exit status or timeout: it becomes the
// certificate's last error, which IPC shows, while the arguments may hold
// credentials and the output may repeat them. The last 4 KiB of the output
// are logged instead, as a Private value that only the service log holds.
func (p *execProvider) run(action, domain, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	// Clone first: appending to the shared argv in place would let concurrent
	// runs overwrite each other's arguments in its spare capacity.
	argv := append(slices.Clone(p.argv), action, info.EffectiveFQDN, info.Value)
	out, err := proc.Run(context.Background(), argv, dnsHookTimeout, dnsHookWaitDelay)
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

// Package sysx is the thin layer between the agents and the operating system.
//
// Everything that changes system state goes through a Runner, which makes two
// things possible: observe mode, where decisions are computed and logged but
// never applied, and a recorded journal of every command issued, so the
// portal can show exactly what the agent did and `failoverctl revert` can
// undo it.
package sysx

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Runner executes system commands.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
	// Applying reports whether this runner actually changes system state.
	Applying() bool
}

// ExecRunner really runs commands.
type ExecRunner struct {
	Log *slog.Logger
}

// Run executes a command and returns its combined output.
func (r *ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	text := strings.TrimSpace(out.String())
	if err != nil {
		if r.Log != nil {
			r.Log.Debug("command failed", "cmd", name, "args", args, "err", err, "output", text)
		}
		return text, fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, text)
	}
	return text, nil
}

// Applying reports true: this runner changes the system.
func (r *ExecRunner) Applying() bool { return true }

// DryRunner logs what would happen and changes nothing. This is what backs
// observe mode.
type DryRunner struct {
	Log *slog.Logger

	mu    sync.Mutex
	calls []string
}

// Run records the command without executing it. Read-only `ip`/`wg`/`nft`
// queries are still executed, because observing needs to see reality.
func (r *DryRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if isReadOnly(name, args) {
		real := &ExecRunner{Log: r.Log}
		return real.Run(ctx, name, args...)
	}
	line := name + " " + strings.Join(args, " ")
	r.mu.Lock()
	r.calls = append(r.calls, line)
	if len(r.calls) > 200 {
		r.calls = r.calls[len(r.calls)-200:]
	}
	r.mu.Unlock()
	if r.Log != nil {
		r.Log.Info("observe mode: would run", "cmd", line)
	}
	return "", nil
}

// Applying reports false: nothing is changed.
func (r *DryRunner) Applying() bool { return false }

// Calls returns the recorded would-be commands, newest last.
func (r *DryRunner) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

// isReadOnly decides which commands observe mode still executes.
//
// Getting this wrong is worse than it looks, because of the shape of the
// mistake. A command misclassified as a mutation is not executed and returns
// ("", nil) - success, with empty output - and every caller in this package
// reads empty-and-no-error as "the thing is not installed". So a misclassified
// *read* does not fail loudly; it silently tells the agent the opposite of the
// truth, and the agent then installs what is already there.
//
// Three were wrong. `tc qdisc show` was live: EnsureQdisc is called with the
// gated runner, so in observe mode the readback always said "no shaper", and
// every reconcile tick proposed replacing one that was already correct. The two
// `nft` forms were latent only because every caller happens to pass
// realRunner() - `nft -a list chain` and `nft -j list table` both failed
// `args[0] == "list"` on the flag.
func isReadOnly(name string, args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch name {
	case "wg":
		return true
	case "ip", "tc":
		// Both put the verb after a subsystem word - `ip route show`,
		// `tc qdisc show` - so the whole argument list is scanned. None of the
		// mutating forms carry any of these words.
		for _, a := range args {
			if a == "show" || a == "get" || a == "list" {
				return true
			}
		}
	case "nft":
		// The verb, skipping the output flags: `-a` for handles and `-j` for
		// JSON both come before it, and testing args[0] alone read the flag.
		return nftVerb(args) == "list"
	case "sysctl":
		return args[0] == "-n" // -w is the write form
	}
	return false
}

// nftVerb returns nft's command word, which is the first argument that is not
// an option. Deliberately not a scan for "list" anywhere in the arguments: a
// comment or a set element could contain the word, and this must never let a
// mutation through.
func nftVerb(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

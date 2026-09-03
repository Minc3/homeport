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

// maxCommandOutput bounds what one command may hand back. The readbacks are
// small by construction - the protection listing is terse and the state sets
// are fetched by name - but a listing is still the kernel's answer to a
// question, and a set an attacker filled is a large answer. A command that
// exceeds this fails, which every caller treats as a failed read, rather than
// growing the process by whatever the kernel had to say.
const maxCommandOutput = 64 << 20

// cappedBuffer is a bytes.Buffer that refuses to grow past maxCommandOutput.
// The refusal fails the command: exec reports the write error, and the
// output seen so far is discarded with it, because half a listing is not a
// listing.
type cappedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.Len()+len(p) > maxCommandOutput {
		c.overflow = true
		return 0, fmt.Errorf("output exceeds %d bytes", maxCommandOutput)
	}
	return c.Buffer.Write(p)
}

// Run executes a command and returns its combined output.
func (r *ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out cappedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if out.overflow {
		err = fmt.Errorf("output exceeds %d bytes", maxCommandOutput)
		out.Reset()
	}
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
		// Only the show forms. Nothing here issues `wg set` today, but "every
		// wg is a read" would run one for real in observe mode the day
		// something does - the reverse of the failure direction above, and the
		// one direction observe mode must never fail in.
		return args[0] == "show" || args[0] == "showconf"
	case "ip", "tc":
		// Both put the verb after a subsystem word - `ip route show`,
		// `tc qdisc show` - with output flags (-o, -j, -4, -br) ahead of
		// the subsystem. The verb is read from that position and nowhere
		// else. This used to scan every argument for show, get or list,
		// and every one of those is a legal Linux interface name: a path
		// whose tunnel was called `list` turned `ip route replace ... dev
		// list` into a read, which observe mode then ran for real. That is
		// the one direction observe mode must never fail in, and an
		// interface name is operator text.
		verb := ipVerb(args)
		return verb == "show" || verb == "get" || verb == "list" || verb == ""
	case "nft":
		// The verb, skipping the output flags: `-a` for handles and `-j` for
		// JSON both come before it, and testing args[0] alone read the flag.
		return nftVerb(args) == "list"
	case "sysctl":
		return args[0] == "-n" // -w is the write form
	}
	return false
}

// ipVerb returns the command word of an `ip` or `tc` invocation: the token
// after the subsystem word, which is itself the first token that is not an
// option. `ip route` with no verb at all is a show, and reports as "".
func ipVerb(args []string) string {
	rest := args
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return ""
	}
	return rest[1]
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

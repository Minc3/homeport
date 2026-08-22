package sysx

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/quinlan102/homeport/internal/model"
)

// Frontend routing model
// ----------------------
// One route in the main table decides where backend-bound traffic goes:
//
//	ip route replace 10.99.0.2/32 dev wg-main src 10.99.0.1
//
// Failover replaces the dev. The source and destination addresses never
// change, so conntrack entries and the client's 5-tuple survive the switch.
// That is the whole reason GMod sessions and established TCP connections do
// not drop.
//
// Three extra tables exist purely so the prober can reach the backend through
// one specific tunnel regardless of which one is currently active:
//
//	ip rule  add fwmark 0x101 lookup 101      pref 30001
//	ip rule  add fwmark 0x101 unreachable     pref 31001
//	ip route replace 10.99.0.2/32 dev wg-main src 10.99.0.1 table 101
//
// The second rule is what makes a probe fail closed. A rule whose table has
// no matching route is simply skipped, and the lookup carries on to main -
// which on the frontend always has a default route out the public interface.
// So with the tunnel absent, the probes did not fail: they left by the
// datacentre's uplink, addressed to a private address, and on a site with
// backend egress on they matched `ip saddr 10.99.0.0/24 oifname eth0 snat`
// on the way out. A source NAT binding belongs to the conntrack entry, not to
// the interface, and the prober keeps one socket for as long as sends succeed,
// so every later probe from that socket carried the public address down the
// tunnel once it existed. The backend answered to the public address, from an
// ephemeral port that matched no conntrack entry, and nothing was listening
// there. A frontend that booted before its tunnels never saw a reply on any
// path, for as long as the process lived. See ProbeDenyRulePrefBase.

// EnsureOverlayAddress makes sure the stable overlay address exists on its own
// dummy interface, creating both if needed.
//
// Nothing works without this. The route the agent installs uses the overlay
// address as its source, and the probe sockets bind to it, so if the address is
// missing every path fails in a way that looks like all three tunnels being
// down. It is created here rather than left to the operator because it is the
// single most load-bearing prerequisite in the system, and re-ensured on every
// start so a reboot needs no separate networkd unit.
func EnsureOverlayAddress(ctx context.Context, r Runner, ip, dev string) error {
	if ip == "" {
		return fmt.Errorf("no overlay address configured")
	}
	if dev == "" {
		dev = "dummy0"
	}
	out, err := r.Run(ctx, "ip", "-o", "addr", "show")
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	if strings.Contains(out, " "+ip+"/32 ") {
		return nil
	}

	// "File exists" here just means another run already made the device.
	if _, err := r.Run(ctx, "ip", "link", "add", dev, "type", "dummy"); err != nil &&
		!strings.Contains(err.Error(), "File exists") {
		return fmt.Errorf("create %s: %w", dev, err)
	}
	if _, err := r.Run(ctx, "ip", "addr", "add", ip+"/32", "dev", dev); err != nil &&
		!strings.Contains(err.Error(), "File exists") {
		return fmt.Errorf("add %s to %s: %w", ip, dev, err)
	}
	if _, err := r.Run(ctx, "ip", "link", "set", dev, "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", dev, err)
	}
	return nil
}

// EnsureProbeRoutes installs the per-path probe tables and fwmark rules. It is
// idempotent and safe to call on every config change.
//
// Both ends use it, with the addresses swapped. On the frontend it steers
// outbound probes into a specific tunnel; on the backend it steers each probe
// reply back out the tunnel its request arrived on, which is what makes the
// measurement a genuine round trip over one path rather than a mix of two.
func EnsureProbeRoutes(ctx context.Context, r Runner, paths []model.PathConfig, dstIP, srcIP string) error {
	// One full listing for every path. Each path inspects only the lines
	// carrying its own mark, and nothing below adds or removes a line with
	// another path's mark, so the listing stays valid across the loop.
	all, err := listRules(ctx, r)
	if err != nil {
		return err
	}
	var problems []string
	configured := map[string]bool{}
	for _, p := range paths {
		configured[fmt.Sprintf("0x%x", p.Mark)] = true
		// The rules go in whether or not the tunnel exists. They select on a
		// mark, not on a device, so nothing about them needs the interface -
		// and the unreachable rule is needed most precisely when the
		// interface is missing, because that is when an unguarded probe
		// would fall through to main and leave by the public uplink. Before
		// this the whole path was skipped, rules included, on a frontend that
		// booted ahead of wg-quick, and the leak described at the top of this
		// file followed.
		if err := ensureProbeRules(ctx, r, p, all); err != nil {
			// A rule that cannot be installed is not a per-path problem: the
			// rules are shared plumbing, and failing to add one means policy
			// routing is not working at all. A listing that cannot be read
			// is this path's problem alone, as it always was.
			var re ruleAddError
			if errors.As(err, &re) {
				return err
			}
			problems = append(problems, p.Name+": "+err.Error())
			continue
		}
		// A tunnel that does not exist yet is expected: wg-quick may not have
		// run, or the interface may be being rebuilt. The path simply probes as
		// down until it appears, and the reconciler installs the route then.
		if !IfaceExists(p.Iface) {
			problems = append(problems, p.Name+": interface "+p.Iface+" does not exist")
			continue
		}
		// Anything that fails here - most often the overlay source address
		// missing - leaves just this path unprobeable, and silently skipping
		// it would report a healthy link as an unreachable one.
		if err := ensureProbeRouteOnly(ctx, r, p, dstIP, srcIP); err != nil {
			problems = append(problems, p.Name+": "+err.Error())
		}
	}
	// A refusal is keyed to a mark, and a mark can change: edit one in the
	// portal, or start a backend on the shipped defaults and then receive the
	// site's real paths. The rule for the old mark would outlive both, and
	// unlike an orphaned lookup rule - which selects an empty table and does
	// nothing - an orphaned refusal blackholes every packet carrying that
	// mark, on a host that may select on it for its own policy routing.
	// Everything in the deny band is this system's, so anything there with a
	// mark no path carries is swept.
	for _, d := range denyRulesInBand(all) {
		if configured[d.mark] {
			continue
		}
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", d.mark, "unreachable",
			"pref", strconv.Itoa(d.pref))
	}
	if len(problems) > 0 {
		return fmt.Errorf("some paths cannot be probed: %s", strings.Join(problems, "; "))
	}
	return nil
}

// EnsureProbeRoute installs one path's probe table entry and fwmark rule.
//
// It exists for the reconcilers. Deleting an interface - which is exactly what
// `wg-quick down` does - takes every route that used it with it, so restarting
// one tunnel leaves precisely one table empty while the rest of the system is
// still correct. Repairing that one path is cheaper and quieter than
// reapplying the whole configuration.
//
// The caller is responsible for knowing the interface exists; a reconciler has
// already had to check that to decide there was anything to repair.
func EnsureProbeRoute(ctx context.Context, r Runner, p model.PathConfig, dstIP, srcIP string) error {
	all, err := listRules(ctx, r)
	if err != nil {
		return err
	}
	// Same order as EnsureProbeRoutes, so the two entry points cannot drift:
	// rules first, then the route.
	if err := ensureProbeRules(ctx, r, p, all); err != nil {
		return err
	}
	return ensureProbeRouteOnly(ctx, r, p, dstIP, srcIP)
}

// ruleAddError marks a failure to install an ip rule, which is fatal for a
// whole batch rather than for one path.
type ruleAddError struct{ err error }

func (e ruleAddError) Error() string { return e.err.Error() }
func (e ruleAddError) Unwrap() error { return e.err }

// ensureProbeRouteOnly installs the table entry and nothing else. It needs the
// interface to exist, which is the caller's business to know.
func ensureProbeRouteOnly(ctx context.Context, r Runner, p model.PathConfig, dstIP, srcIP string) error {
	_, err := r.Run(ctx, "ip", "route", "replace", dstIP+"/32",
		"dev", p.Iface, "src", srcIP, "table", strconv.Itoa(p.Table))
	return err
}

// ensureProbeRules installs the two rules for one path's mark: the lookup into
// its table, and the unreachable behind it. Neither needs the interface. all
// is the full `ip rule show` listing, which the unreachable rule has to be
// read from - it names no table and so cannot be asked for by one.
func ensureProbeRules(ctx context.Context, r Runner, p model.PathConfig, all string) error {
	table := strconv.Itoa(p.Table)
	mark := fmt.Sprintf("0x%x", p.Mark)

	// Read this path's own table rather than grepping the whole listing for a
	// number. `ip rule show` prints a table's *name* wherever
	// /etc/iproute2/rt_tables gives it one, so on a host that has named 101 the
	// agent cannot recognise the rule it installed seconds earlier: it re-adds
	// it every tick, logs "File exists" forever, and - because a failed add is
	// fatal for the whole batch - the paths after this one never get their
	// rules at all. Asking the kernel by number always works; the alias changes
	// how a rule is printed, never how it is selected.
	existing, err := listRulesInTable(ctx, r, p.Table)
	if err != nil {
		return err
	}

	// The per-path rules must outrank everything else that could claim the
	// same packet - see ProbeRulePrefBase. Anything found at another priority
	// is a rule from an older build and has to go, or the ordering it caused
	// survives the upgrade. The listing is already scoped to this table, so the
	// mark alone identifies the rule.
	want := probeRulePref(p)
	found := markRulePrefs(existing, mark, "")
	correct := false
	for _, pref := range found {
		if pref == want {
			correct = true
			break
		}
	}
	// The correct rule goes in before the stale ones come out, so there is
	// never a moment with no rule at all. In that window a marked probe matches
	// nothing and follows the single main-table route down whichever tunnel is
	// active, which is a measurement of the wrong path rather than a missing
	// one - the same wrong answer this priority exists to prevent.
	if !correct {
		if _, err := r.Run(ctx, "ip", "rule", "add", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(want)); err != nil {
			return ruleAddError{fmt.Errorf("add rule for %s: %w", p.Name, err)}
		}
	}
	for _, pref := range found {
		if pref == want {
			continue
		}
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(pref))
	}

	// The backstop, with the same treatment as the lookup above: the pinned
	// one goes in if it is missing, and any copy at another priority comes
	// out afterwards. A stray matters more here than for the lookup, because
	// a refusal that has drifted *ahead* of the lookup band answers every
	// probe with ENETUNREACH before its table is consulted - a path that
	// reads down forever while this reports success. Add before delete, so
	// there is no moment with no refusal at all.
	// Only rules inside the band are considered, in both directions. A fwmark
	// is only a number, and a host that already policy-routes may refuse on
	// the same value for its own reasons (invariant 8): a rule of theirs
	// outside the band is neither "already installed" nor a stray.
	deny := probeDenyRulePref(p)
	found = denyRulePrefs(all, mark)
	correct = false
	for _, pref := range found {
		if pref == deny {
			correct = true
			break
		}
	}
	if !correct {
		if _, err := r.Run(ctx, "ip", "rule", "add", "fwmark", mark, "unreachable",
			"pref", strconv.Itoa(deny)); err != nil {
			return ruleAddError{fmt.Errorf("add unreachable rule for %s: %w", p.Name, err)}
		}
	}
	for _, pref := range found {
		if pref == deny {
			continue
		}
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "unreachable",
			"pref", strconv.Itoa(pref))
	}
	return nil
}

// ProbeDenyRulePrefBase is the priority band of the per-path unreachable
// rules: behind the lookup band (and behind the egress rule, which selects a
// different mark and is not in play), ahead of everything that could otherwise
// claim a marked packet - the backend's source rules and main.
//
// A rule whose table has no route for the destination is skipped, not
// terminal, so on its own `fwmark 0x101 lookup 101` fails open: the moment the
// tunnel is deleted, or has not been created yet, a probe marked for it goes
// on to whatever the next rule says. On the frontend that is main and the
// public uplink; on the backend it is `from 10.99.0.2 lookup 100` and the
// active tunnel, which is the mixed measurement invariant 3 exists to prevent.
// With this rule behind the lookup, a marked packet with no route in its own
// table gets ENETUNREACH instead - which is what the prober's hold path was
// always written for, and had never actually been reached on a host with a
// default route.
//
// It is a rule rather than an `unreachable default` inside the table so that
// the table itself carries only the one route this system installs. The
// number belongs to the host (invariant 8); a default it did not choose would
// be a change to a table it may be using for its own policy routing.
const ProbeDenyRulePrefBase = 31000

func probeDenyRulePref(p model.PathConfig) int { return ProbeDenyRulePrefBase + p.ID }

// ProbeDenyBandSize is how many priorities the deny band spans, and therefore
// the bound on path ids: the lookup band has the egress rule sitting this far
// above its base, so an id at or past it would collide there first.
const ProbeDenyBandSize = EgressRulePref - ProbeRulePrefBase

// inProbeDenyBand reports whether a priority is one this system hands out for
// refusals. That is the ownership test: a fwmark is only a number, and an
// unreachable rule on the same value anywhere else belongs to the host.
func inProbeDenyBand(pref int) bool {
	return pref > ProbeDenyRulePrefBase && pref < ProbeDenyRulePrefBase+ProbeDenyBandSize
}

type denyRule struct {
	pref int
	mark string
}

// denyRulesInBand returns every unreachable rule sitting in the deny band,
// whatever its mark.
func denyRulesInBand(rules string) []denyRule {
	var out []denyRule
	for _, d := range unreachableRules(rules) {
		if inProbeDenyBand(d.pref) {
			out = append(out, d)
		}
	}
	return out
}

// unreachableRules returns every mark-selected unreachable rule in a listing.
// The kernel prints one as "<pref>:\tfrom all fwmark 0x101 unreachable".
func unreachableRules(rules string) []denyRule {
	var out []denyRule
	for _, line := range strings.Split(rules, "\n") {
		pref, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(pref)
		if err != nil {
			continue
		}
		fields := strings.Fields(rest)
		var mark string
		var unreachable bool
		for i, f := range fields {
			switch f {
			case "fwmark":
				if i+1 < len(fields) {
					mark = fields[i+1]
				}
			case "unreachable":
				unreachable = true
			}
		}
		if mark != "" && unreachable {
			out = append(out, denyRule{pref: n, mark: mark})
		}
	}
	return out
}

// ensureUnreachableRule installs a refusal for one mark at one pinned priority,
// and leaves every other refusal on that mark alone: the priority is the
// ownership test, because a fwmark is only a number and a host may refuse on
// the same value for its own reasons. all is the full `ip rule show` listing.
func ensureUnreachableRule(ctx context.Context, r Runner, mark string, pref int, all string) error {
	for _, d := range unreachableRules(all) {
		if d.mark == mark && d.pref == pref {
			return nil
		}
	}
	_, err := r.Run(ctx, "ip", "rule", "add", "fwmark", mark, "unreachable",
		"pref", strconv.Itoa(pref))
	return err
}

// removeUnreachableRule takes one back out, by its pinned priority only.
func removeUnreachableRule(ctx context.Context, r Runner, mark string, pref int) {
	all, err := listRules(ctx, r)
	if err != nil {
		return
	}
	for _, d := range unreachableRules(all) {
		if d.mark == mark && d.pref == pref {
			_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "unreachable",
				"pref", strconv.Itoa(pref))
			return
		}
	}
}

// denyRulePrefs returns the priorities of this system's unreachable rules
// selecting on one mark.
func denyRulePrefs(rules, mark string) []int {
	var prefs []int
	for _, d := range denyRulesInBand(rules) {
		if d.mark == mark {
			prefs = append(prefs, d.pref)
		}
	}
	return prefs
}

// ProbeRulePrefBase is the priority band the per-path fwmark rules live in.
//
// The priority is explicit because the default is actively wrong. `ip rule add`
// with no preference takes the priority of the first existing rule minus one,
// so each rule added ends up *ahead* of the ones added before it - and the
// backend installs its per-path rules before `from <overlay> lookup 100`. That
// left the source rule outranking all three path rules, so every probe reply,
// whichever tunnel its request arrived on, was routed by the return table and
// left down the active tunnel instead.
//
// Nothing about that is visible from the outside. The standby paths still get
// replies, so they read healthy; what they are actually measuring is forward
// over their own tunnel and back over a different one, which is precisely the
// mix per-path tables exist to prevent, and it means a tunnel that is dead in
// the return direction tests as fine. Only packets the agent has marked are
// affected, so nothing else moves when these rules jump the queue.
const ProbeRulePrefBase = 30000

func probeRulePref(p model.PathConfig) int { return ProbeRulePrefBase + p.ID }

// markRulePrefs returns the priorities of every rule selecting on this mark
// and table. `ip rule show` renders one rule per line as "<pref>:\t<selectors>".
func markRulePrefs(rules, mark, table string) []int {
	var prefs []int
	for _, line := range strings.Split(rules, "\n") {
		pref, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(pref)
		if err != nil {
			continue
		}
		// Matched on whole fields, not substrings: "lookup 101" is a prefix of
		// "lookup 1010", and deleting the wrong rule here would strand a path.
		var hasMark, hasLookup, hasTable bool
		fields := strings.Fields(rest)
		for i, f := range fields {
			if i+1 >= len(fields) {
				break
			}
			switch f {
			case "fwmark":
				hasMark = hasMark || fields[i+1] == mark
			case "lookup":
				hasLookup = true
				hasTable = hasTable || fields[i+1] == table
			}
		}
		// An empty table means the listing was already filtered to one by the
		// kernel, so there is nothing to match here - see listRulesInTable.
		// A rule with no lookup at all - the unreachable backstop carries the
		// same mark - selects no table and is never one of these.
		if hasMark && hasLookup && (hasTable || table == "") {
			prefs = append(prefs, n)
		}
	}
	return prefs
}

// SetActivePath points the main-table route for the backend at one interface.
// This single command is the entire failover action.
// dstPrefix is a prefix, not an address, because the frontend's side of it
// widens to the whole overlay range on a site that runs linker agents. The
// backend's route to the frontend is always a /32 - there is only ever one
// frontend - so the two call sites deliberately pass different shapes.
func SetActivePath(ctx context.Context, r Runner, dstPrefix, srcIP, iface string) error {
	_, err := r.Run(ctx, "ip", "route", "replace", dstPrefix,
		"dev", iface, "src", srcIP)
	return err
}

// ActiveIface reports which interface the backend route currently uses,
// read back from the kernel rather than from the agent's own memory.
func ActiveIface(ctx context.Context, r Runner, backendIP string) (string, error) {
	return RouteVia(ctx, r, backendIP, 0)
}

// RouteVia reports which interface a destination routes out of in one table,
// or "" when there is no route for it at all. Table 0 means the main table.
//
// The empty answer is the one that matters. When an interface is deleted the
// kernel silently discards every route that used it, and recreating the
// interface does not bring them back - so the only way to notice that a
// tunnel restart has emptied a path's table is to read the kernel.
// dstPrefix must be the prefix that was installed, not merely an address inside
// it. `ip route show` filters on an exact prefix - unlike `ip route get`, it
// will not report a /24 when asked about a /32 within it - so a caller that
// installs the overlay range and reads back a host address sees "no route" on
// every tick and reinstalls a route that was already there.
//
// A table that has never held a route is reported by the kernel as not
// existing at all, and `ip route show` turns that into an error ("FIB table
// does not exist", exit 2) rather than an empty listing. That is the same
// answer as an empty table for every caller here - there is no route - and
// treating it as an error was the boot failure: a frontend that started
// before wg-quick had no interface to install a route on, so the probe table
// was never created, and the reconciler skipped the path on the error every
// tick from then on. A tunnel restart empties a table, which reads back as
// empty and was repaired; a tunnel that was absent at startup never got a
// table, which read back as an error and was not. The service restart that
// fixed it was simply one where every interface existed before the routes
// were installed.
func RouteVia(ctx context.Context, r Runner, dstPrefix string, table int) (string, error) {
	args := []string{"route", "show", dstPrefix}
	if table > 0 {
		args = append(args, "table", strconv.Itoa(table))
	}
	out, err := r.Run(ctx, "ip", args...)
	if err != nil {
		if tableDoesNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return devFrom(out), nil
}

// DefaultVia reports which interface the default route in a table points at,
// or "" when the table has no default route - or no table, see RouteVia.
func DefaultVia(ctx context.Context, r Runner, table int) (string, error) {
	out, err := r.Run(ctx, "ip", "route", "show", "default", "table", strconv.Itoa(table))
	if err != nil {
		if tableDoesNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return devFrom(out), nil
}

// tableDoesNotExist recognises the kernel's answer for a routing table nothing
// has ever written to. ExecRunner carries the command's stderr in the error.
func tableDoesNotExist(err error) bool {
	return strings.Contains(err.Error(), "FIB table does not exist")
}

func devFrom(out string) string {
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// Backend routing model
// ---------------------
// The frontend DNATs published ports to the backend but never SNATs, so the
// backend sees real client IPs. For replies to reach those clients they must
// go back out the same tunnel instead of out pfSense to the internet:
//
//	ip rule  add from 10.99.0.2 lookup 100
//	ip route replace default dev wg-main table 100
//
// Only traffic sourced from the overlay address uses it. The backend's own
// normal traffic still egresses via pfSense as usual.

// ReturnTable is the routing table the backend uses for reply traffic.
const ReturnTable = 100

// EnsureReturnRule installs the source-based rules for reply traffic leaving by
// the tunnel.
//
// It is variadic because a site running linker agents needs a second source: a
// linker's outbound traffic reaches the backend over the LAN as a brand new
// connection, so it carries no connection mark and the mark-based rule beside
// this one cannot see it. The overlay range is the only thing that identifies
// it. Without that rule a linker's traffic - the server-browser heartbeat
// above all - leaves by the house's own service instead, silently, which is
// the exact failure the egress feature exists to prevent.
//
// Sites with no linkers pass one source and get precisely the rule they had.
func EnsureReturnRule(ctx context.Context, r Runner, sources ...string) error {
	existing, err := listRulesInTable(ctx, r, ReturnTable)
	if err != nil {
		return err
	}
	table := strconv.Itoa(ReturnTable)
	seen := map[string]bool{}
	idx := 0
	for _, src := range sources {
		if src == "" || seen[src] {
			continue
		}
		seen[src] = true
		want := ReturnRulePrefBase + idx
		idx++

		found := sourceRulePrefs(existing, src, "")
		correct := false
		for _, pref := range found {
			if pref == want {
				correct = true
				break
			}
		}
		// The pinned rule goes in before any stray comes out, like every other
		// rule move here (invariant 3). In the gap the other order opens, a
		// reply sourced from the overlay matches no rule, falls through to
		// main, and leaves by the LAN to pfSense - a dropped reply to a real
		// client, on the upgrade that moves the rule.
		if !correct {
			if _, err := r.Run(ctx, "ip", "rule", "add", "from", src, "lookup", table,
				"pref", strconv.Itoa(want)); err != nil {
				return err
			}
		}
		for _, pref := range found {
			if pref == want {
				continue
			}
			// Anything at another priority came from a build that let the
			// kernel choose one. Added last, it lands ahead of the probe rules
			// and swallows their replies - see ReturnRulePrefBase.
			_, _ = r.Run(ctx, "ip", "rule", "del", "from", src, "lookup", table,
				"pref", strconv.Itoa(pref))
		}
	}
	return nil
}

// ReturnRulePrefBase is the priority band for the backend's source-based return
// rules. It must stay *behind* ProbeRulePrefBase and ahead of main (32766).
//
// Explicit for the same reason the probe rules are, and this is the second time
// the default has caused the same bug. `ip rule add` with no preference takes
// the lowest existing priority minus one, so a rule added after the per-path
// rules lands in front of them. The per-path rules are pinned at 30001-30003;
// a return rule added afterwards was handed 30000.
//
// The consequence is invisible from the outside. A probe reply is sourced from
// the overlay address, so a `from <overlay range>` rule sitting in front of the
// per-path rules matches it first, sends it to the return table, and it leaves
// by whichever tunnel is currently active instead of the one its request
// arrived on. Standby paths still receive replies and still read healthy - what
// they are measuring is a round trip over two different tunnels, which means a
// standby that is dead in one direction tests as perfect.
const ReturnRulePrefBase = 32500

// sourceRulePrefs returns the priorities of every rule selecting on this source
// and table, matched on whole fields so "lookup 100" cannot match "lookup 1000".
func sourceRulePrefs(rules, source, table string) []int {
	var prefs []int
	for _, line := range strings.Split(rules, "\n") {
		pref, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(pref)
		if err != nil {
			continue
		}
		var hasSource, hasTable bool
		fields := strings.Fields(rest)
		for i, f := range fields {
			if i+1 >= len(fields) {
				break
			}
			switch f {
			case "from":
				hasSource = hasSource || fields[i+1] == source
			case "lookup":
				hasTable = hasTable || fields[i+1] == table
			}
		}
		if hasSource && (hasTable || table == "") {
			prefs = append(prefs, n)
		}
	}
	return prefs
}

// EgressRulePref is where the egress mark rule sits. In the same explicit band
// as the probe rules, for the same reason: an auto-assigned priority depends on
// what happens to be installed already.
const EgressRulePref = ProbeRulePrefBase + 100

// EnsureEgressRule routes traffic marked for egress into the return table,
// which already points at whichever tunnel is active.
func EnsureEgressRule(ctx context.Context, r Runner) error {
	// Filtered by the kernel rather than grepped for "lookup 100": a host that
	// has named table 100 in /etc/iproute2/rt_tables prints the name instead,
	// and the number match would then never see the rule this installed.
	existing, err := listRulesInTable(ctx, r, ReturnTable)
	if err != nil {
		return err
	}
	table := strconv.Itoa(ReturnTable)
	mark := fmt.Sprintf("0x%x", EgressMark)
	found := markRulePrefs(existing, mark, "")
	correct := false
	for _, pref := range found {
		if pref == EgressRulePref {
			correct = true
			break
		}
	}
	// In place before anything is withdrawn. Deleting first and then failing to
	// add would drop the marked networks back onto the local service silently,
	// which is the failure this feature exists to prevent.
	if !correct {
		if _, err := r.Run(ctx, "ip", "rule", "add", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(EgressRulePref)); err != nil {
			return err
		}
	}
	// Strays go even when the right rule is already there. A duplicate at
	// another priority is not idle: it selects the same packets and may sit
	// ahead of this one.
	for _, pref := range found {
		if pref == EgressRulePref {
			continue
		}
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(pref))
	}

	// The same backstop the probe rules carry, for the same reason. With the
	// active tunnel deleted, table 100 has no default and a marked container
	// packet falls through to main - out the LAN to pfSense, where Docker's
	// masquerade gives it the house's address. That binding belongs to the
	// connection, so once the tunnel is back the same flow is sent down it
	// carrying an address the frontend's NAT does not match, and it is dead
	// until the entry expires - never, for a UDP flow that keeps sending. And
	// a heartbeat sent in the gap lists the server at the house's address,
	// which is the one thing this feature exists to prevent. Refused instead,
	// the flow stalls for the gap and resumes intact.
	all, err := listRules(ctx, r)
	if err != nil {
		return err
	}
	return ensureUnreachableRule(ctx, r, mark, EgressDenyRulePref, all)
}

// EgressDenyRulePref is where the egress mark's refusal sits: just past the
// per-path deny band, as EgressRulePref sits just past the lookup band.
const EgressDenyRulePref = ProbeDenyRulePrefBase + ProbeDenyBandSize

// RemoveEgressRule takes the egress mark rule back out, by every priority it is
// found at. Leaving it behind would keep steering a network onto the tunnel
// after the feature that put it there was turned off.
func RemoveEgressRule(ctx context.Context, r Runner) {
	existing, err := listRulesInTable(ctx, r, ReturnTable)
	if err != nil {
		return
	}
	table := strconv.Itoa(ReturnTable)
	mark := fmt.Sprintf("0x%x", EgressMark)
	for _, pref := range markRulePrefs(existing, mark, "") {
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(pref))
	}
	removeUnreachableRule(ctx, r, mark, EgressDenyRulePref)
}

// EnsureReturnMarkRule routes marked reply traffic into the return table.
//
// This is the companion to the connection marking in the backend's nftables
// ruleset, and it exists because the source-address rule beside it cannot see
// through a second layer of NAT: a container's reply is routed while it still
// carries the container's address.
func EnsureReturnMarkRule(ctx context.Context, r Runner) error {
	existing, err := listRulesInTable(ctx, r, ReturnTable)
	if err != nil {
		return err
	}
	table := strconv.Itoa(ReturnTable)
	mark := fmt.Sprintf("0x%x", ReturnMark)
	found := markRulePrefs(existing, mark, "")
	correct := false
	for _, pref := range found {
		if pref == ReturnMarkRulePref {
			correct = true
			break
		}
	}
	// Added before the stale one is withdrawn: without a rule, a reply carrying
	// the restored mark falls through to main and leaves by the LAN to pfSense
	// instead of down the tunnel it arrived on, which is a dropped reply to a
	// real client rather than a slow one.
	if !correct {
		if _, err := r.Run(ctx, "ip", "rule", "add", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(ReturnMarkRulePref)); err != nil {
			return err
		}
	}
	for _, pref := range found {
		if pref == ReturnMarkRulePref {
			continue
		}
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(pref))
	}
	return nil
}

// SetReturnPath points the backend's reply route at one tunnel. It must track
// the frontend's choice, or replies leave by a different tunnel than requests
// arrived on and pfSense state breaks.
func SetReturnPath(ctx context.Context, r Runner, iface string) error {
	_, err := r.Run(ctx, "ip", "route", "replace", "default", "dev", iface, "table", strconv.Itoa(ReturnTable))
	return err
}

// ControlTable carries traffic the frontend itself originates towards the
// backend overlay - the control channel, and nothing else.
//
// It exists because the main-table route to the backend is the failover action
// and is therefore suppressed in observe mode, while the control channel has
// to work in observe mode: that is precisely when usage accounting is being
// collected for days on end. Without a route the frontend answers the
// backend's TCP connection out its public interface and the channel never
// comes up.
const ControlTable = 100

// ControlMark stamps the frontend's control-channel socket so its packets are
// steered by fwmark, exactly like probes are.
//
// The obvious alternative - a rule matching "from the frontend overlay to the
// backend overlay" - is wrong, and subtly so: probe packets have those same
// two addresses, so such a rule captures every probe and sends all three paths
// down one tunnel, which is precisely the failure the per-path marks exist to
// prevent. A dedicated mark cannot collide, whatever priority the rules end up
// with. Path marks start at 0x101 to leave this one free.
const ControlMark = 0x100

// ControlRulePref is where the frontend's control-channel rule sits.
//
// Explicit, because invariant 3 admits no exceptions and this was one: the rule
// was added with no preference, so the kernel gave it the first existing rule's
// priority minus one. Since applySystemConfig installs the per-path rules
// first, that landed it at 30000 - immediately ahead of the 30001-30003 band.
// Harmless only for as long as no path shares the control mark, which is a
// property of the configuration rather than of this code, and precisely the
// coincidence the two bugs recorded above both turned on.
//
// The value keeps the rule exactly where the kernel had been putting it, ahead
// of the probe rules. Nothing sits between 29999 and 30001, so pinning it
// changes no ordering on a running host; it only stops the ordering depending
// on what happened to be installed first.
const ControlRulePref = ProbeRulePrefBase - 1

// ReturnMarkRulePref is where the backend's connection-mark rule sits, pinned
// for the same reason and in the same way: it was also added without one, and
// also landed at 30000 because the per-path rules go in ahead of it.
const ReturnMarkRulePref = ProbeRulePrefBase - 2

// EnsureControlRoute routes the frontend's own traffic to the backend overlay
// down one tunnel.
//
// The rule is selected by source address, so only packets the frontend
// originates from its overlay address match it. DNAT'd client traffic carries
// a real client source address and never matches, which is what keeps observe
// mode honest: published traffic still cannot reach the backend.
func EnsureControlRoute(ctx context.Context, r Runner, routePrefix, backendIP, frontendIP, iface string) error {
	// Filtered by the kernel, for the reason listRulesInTable exists: a host
	// that has named table 100 makes every "lookup 100" text match fail, and
	// this would then re-add its rule on every tick and log "File exists"
	// forever while the rule it was complaining about sat right there.
	existing, err := listRulesInTable(ctx, r, ControlTable)
	if err != nil {
		return err
	}
	table := strconv.Itoa(ControlTable)
	mark := fmt.Sprintf("0x%x", ControlMark)

	found := markRulePrefs(existing, mark, "")
	correct := false
	for _, pref := range found {
		if pref == ControlRulePref {
			correct = true
			break
		}
	}
	// Added before anything is removed: for the moments in between, a control
	// packet carrying the mark would match no rule and fall through to main,
	// which in observe mode has no route to the backend at all.
	if !correct {
		if _, err := r.Run(ctx, "ip", "rule", "add", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(ControlRulePref)); err != nil {
			return err
		}
	}
	// Anything at another priority came from a build that let the kernel choose
	// one - see ControlRulePref.
	for _, pref := range found {
		if pref == ControlRulePref {
			continue
		}
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(pref))
	}

	// Clean up the source-matched rule shipped briefly before this: left in
	// place it outranks the per-path fwmark rules and swallows every probe.
	// The listing is already scoped to this table, so the addresses alone
	// identify it.
	if strings.Contains(existing, "from "+frontendIP+" to "+backendIP) {
		_, _ = r.Run(ctx, "ip", "rule", "del", "from", frontendIP, "to", backendIP, "lookup", table)
	}

	// The whole overlay range, not just the backend's address, once a subnet
	// is configured.
	//
	// The listening socket carries ControlMark, and an accepted connection
	// inherits it, so every reply the frontend sends on a control channel is
	// steered into this table - including replies to a linker. With only the
	// backend's /32 here a linker's SYN-ACK matched nothing, fell through to
	// main, and in observe mode main has no overlay route at all: the reply
	// left by the public interface and vanished. The linker retried forever
	// with "dial 10.99.0.1:51998: i/o timeout" while its SYN was arriving
	// perfectly, and the backend's own channel stayed up throughout, because
	// the backend is the one address this table knew.
	if _, err := r.Run(ctx, "ip", "route", "replace", routePrefix,
		"dev", iface, "src", frontendIP, "table", table); err != nil {
		return err
	}

	// And the host route it supersedes, for the same reason invariant 21 gives
	// on the main table: replace writes the new prefix and leaves the old one
	// alone, and the /32 is more specific - so the backend's control channel
	// would stay pinned to whichever tunnel was active when the subnet was set
	// while everything else followed the failover.
	host := backendIP + "/32"
	if routePrefix != host {
		if via, err := RouteVia(ctx, r, host, ControlTable); err == nil && via != "" {
			_, _ = r.Run(ctx, "ip", "route", "del", host, "table", table)
		}
	}
	return nil
}

// RemoveControlRoute undoes EnsureControlRoute.
func RemoveControlRoute(ctx context.Context, r Runner, routePrefix, backendIP, frontendIP string) {
	table := strconv.Itoa(ControlTable)
	mark := fmt.Sprintf("0x%x", ControlMark)

	// By the priority it is actually at, and every stray at another one: `ip
	// rule del` given only a selector drops one arbitrary match, so a duplicate
	// left by a build that pinned no priority would survive the revert.
	if existing, err := listRulesInTable(ctx, r, ControlTable); err == nil {
		for _, pref := range markRulePrefs(existing, mark, "") {
			_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark,
				"lookup", table, "pref", strconv.Itoa(pref))
		}
	} else {
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table)
	}
	_, _ = r.Run(ctx, "ip", "rule", "del", "from", frontendIP, "to", backendIP, "lookup", table)

	// The routes by name, never a flush of the table. The number belongs to the
	// host rather than to this system - invariant 8 - and a frontend that
	// already policy-routes may keep its own entries in 100, which a flush
	// would take with it while reporting a clean revert.
	_, _ = r.Run(ctx, "ip", "route", "del", routePrefix, "table", table)
	if host := backendIP + "/32"; routePrefix != host {
		_, _ = r.Run(ctx, "ip", "route", "del", host, "table", table)
	}
}

// EnsureSysctls relaxes reverse-path filtering. During a switch the forward
// and reverse paths can briefly disagree, and strict rp_filter would drop
// exactly the packets that prove a path recovered.
func EnsureSysctls(ctx context.Context, r Runner, ifaces []string) {
	set := func(key, val string) {
		_, _ = r.Run(ctx, "sysctl", "-w", key+"="+val)
	}

	// rp_filter must be OFF on the tunnels, not merely loose.
	//
	// Loose mode is documented as "accept if the source is reachable via any
	// interface", but that is not what the kernel does on an interface with no
	// IPv4 address - which is exactly what a wg-quick tunnel with Table = off
	// and no Address is. In __fib_validate_source, when the reverse lookup
	// resolves to a different device than the packet arrived on, the kernel
	// checks no_addr (true here) and jumps straight to last_resort, which
	// drops for any non-zero rp_filter. Loose mode's second lookup never runs.
	//
	// Reverse-path validation cannot work here in principle: the forward route
	// for each path lives in its own fwmark table, and an arriving packet
	// carries no mark, so the lookup can only ever find the one route in main.
	// Whichever tunnel that names, the other two are dropped - probe replies
	// and the backend's control connection alike, silently, below the socket.
	// The effective value is max(all, dev), so both have to be zero.
	set("net.ipv4.conf.all.rp_filter", "0")
	for _, i := range ifaces {
		set("net.ipv4.conf."+i+".rp_filter", "0")
	}
	set("net.ipv4.ip_forward", "1")
}

// RPFilterOff disables reverse-path filtering on one interface, reporting
// whether it had to change anything.
//
// This has to be re-checked, not just set once at startup, because the setting
// belongs to the interface and not to the name. `wg-quick down` deletes the
// device; `wg-quick up` creates a new one, and a new device inherits
// net.ipv4.conf.default.rp_filter - which systemd ships as 2 - rather than the
// zero the agent set on the device it replaced. The effective value is
// max(all, dev), so a zero on `all` does not save it.
//
// The consequence is total and silent: the main-table reverse route for the
// far end names whichever tunnel is currently active, so a probe arriving on
// any other tunnel reverse-resolves to a different device and is dropped below
// the socket. The interface counters show the probes arriving and no replies
// leaving, `wg show` looks perfect, and the path reads as 100% loss forever.
// That is what a restarted tunnel did before this existed.
func RPFilterOff(ctx context.Context, r Runner, iface string) (bool, error) {
	key := "net.ipv4.conf." + iface + ".rp_filter"
	out, err := r.Run(ctx, "sysctl", "-n", key)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(out) == "0" {
		return false, nil
	}
	if _, err := r.Run(ctx, "sysctl", "-w", key+"=0"); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveProbeRoutes tears down everything EnsureProbeRoutes created. Used by
// `failoverctl revert`.
//
// Two prefixes, because the two routes are not the same shape and each call
// site knows its own. probeDst is the far end's /32, which is what every probe
// table carries whether or not a subnet is configured; dataPrefix is what the
// main-table route was installed as, so revert takes down the same prefix it
// put up rather than a /32 that may not exist. Invariant 20.
func RemoveProbeRoutes(ctx context.Context, r Runner, paths []model.PathConfig, probeDst, dataPrefix string) {
	// Delete by explicit priority. Deleting without one removes a single
	// arbitrary match, which would leave duplicates from an older build behind
	// - and a leftover rule still steers probes into a table that revert has
	// just emptied. The listing is per table and filtered by the kernel, so a
	// host that has named one of these tables does not hide its own rules.
	all, _ := listRules(ctx, r)
	for _, p := range paths {
		table := strconv.Itoa(p.Table)
		mark := fmt.Sprintf("0x%x", p.Mark)
		existing, _ := listRulesInTable(ctx, r, p.Table)
		for _, pref := range markRulePrefs(existing, mark, "") {
			_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table,
				"pref", strconv.Itoa(pref))
		}
		// The backstop behind it. Left in place it would refuse every packet
		// carrying this mark, and a host that selects on the same value for
		// its own policy routing would find that traffic blackholed by a
		// system it had just uninstalled. By band, not by the marks in the
		// configuration: a mark that was changed while the agent ran has
		// already been swept, but one changed while it was stopped has not,
		// and every rule in the band is this system's to remove.
		for _, pref := range denyRulePrefs(all, mark) {
			_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "unreachable",
				"pref", strconv.Itoa(pref))
		}
		// The one route this installed, by name, never a flush of the table.
		// 101 to 103 are numbers this system picked, not property it owns: a
		// host that already policy-routes may keep its own entries in them, and
		// a flush would take those with it while reporting a clean revert.
		// Invariant 8, and the same reasoning RemoveControlRoute and
		// RemoveReturnRoutes were already written to.
		_, _ = r.Run(ctx, "ip", "route", "del", probeDst, "table", table)
	}
	for _, d := range denyRulesInBand(all) {
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", d.mark, "unreachable",
			"pref", strconv.Itoa(d.pref))
	}
	_, _ = r.Run(ctx, "ip", "route", "del", dataPrefix)
}

// RemoveReturnRoutes undoes the backend's reply-path routing.
//
// Variadic, because EnsureReturnRule is: a site with an overlay subnet has a
// second rule for the range, and taking down only the backend's own address
// would leave that one behind - still selecting a linker's traffic into a table
// whose default route this has just removed.
//
// Rules go by the priority they were found at. `ip rule del` given only a
// selector removes a single arbitrary match, so a duplicate from a build that
// pinned no priority would survive the revert - and a leftover rule here is not
// inert, it is a source-matched rule with nothing behind it.
//
// The default route is deleted rather than the table flushed. A routing table
// number belongs to the host, not to this system: a backend that already
// policy-routes may keep its own entries in 100, and flushing would take them
// with it - the same hazard the linker's table carries and the one thing a
// revert must never do.
func RemoveReturnRoutes(ctx context.Context, r Runner, sources ...string) {
	table := strconv.Itoa(ReturnTable)
	existing, _ := listRulesInTable(ctx, r, ReturnTable)

	seen := map[string]bool{}
	for _, src := range sources {
		if src == "" || seen[src] {
			continue
		}
		seen[src] = true
		for _, pref := range sourceRulePrefs(existing, src, "") {
			_, _ = r.Run(ctx, "ip", "rule", "del", "from", src, "lookup", table,
				"pref", strconv.Itoa(pref))
		}
	}

	mark := fmt.Sprintf("0x%x", ReturnMark)
	for _, pref := range markRulePrefs(existing, mark, "") {
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(pref))
	}

	_, _ = r.Run(ctx, "ip", "route", "del", "default", "table", table)
}

// listRulesInTable returns only the rules that select one routing table.
//
// Filtered by the kernel rather than grepped out of the full listing, because
// `ip rule show` prints a table's *name* wherever /etc/iproute2/rt_tables gives
// it one. A host that called table 200 "isp2" - an entirely ordinary dual-ISP
// setup - made every `lookup 200` comparison in this package fail, so the agent
// could not recognise rules it had installed seconds earlier and tried to add
// them again on every tick, forever, logging "File exists" each time.
//
// Asking by number always works: the alias affects how rules are printed, never
// how they are selected.
func listRulesInTable(ctx context.Context, r Runner, table int) (string, error) {
	out, err := r.Run(ctx, "ip", "rule", "show", "table", strconv.Itoa(table))
	if err != nil {
		return "", fmt.Errorf("list ip rules for table %d: %w", table, err)
	}
	return out, nil
}

func listRules(ctx context.Context, r Runner) (string, error) {
	out, err := r.Run(ctx, "ip", "rule", "show")
	if err != nil {
		return "", fmt.Errorf("list ip rules: %w", err)
	}
	return out, nil
}

// DeleteRoute removes one prefix from the main table.
func DeleteRoute(ctx context.Context, r Runner, prefix string) error {
	_, err := r.Run(ctx, "ip", "route", "del", prefix)
	return err
}

// OverlayLocalRulePref is the priority of the rule that keeps overlay-internal
// traffic in the main table. Immediately ahead of the source-based return rules,
// because it is an exception to them.
const OverlayLocalRulePref = ReturnRulePrefBase - 1

// EnsureOverlayLocalRule keeps traffic *between* overlay hosts out of the
// return table.
//
// The return rule matches on source, and once a subnet is configured that
// source is the whole overlay range - which includes the frontend. So a packet
// the frontend sends to a linker arrives at the backend, matches
// `from 10.99.0.0/24 lookup 100`, and is routed by a table whose default points
// back down the tunnel it just came out of. It never reaches the linker.
//
// Nothing reports it, and published traffic is unaffected: a client's source
// address is a public one, so it never matches the return rule and is forwarded
// to the linker normally. Only overlay-to-overlay traffic is bounced, which in
// practice means exactly the linker's control channel - the frontend's SYN-ACK
// goes back to the frontend and the connection never completes.
//
// The main table already knows how to reach every overlay host: the backend's
// own address is local, the frontend is out the active tunnel, and each linker
// is a neighbour. So the fix is to let it answer.
//
// Only installed when a subnet is configured. Without one the return rule names
// a single address and cannot match the frontend, so a site with no linkers
// generates exactly what it always did.
func EnsureOverlayLocalRule(ctx context.Context, r Runner, subnet string) error {
	if subnet == "" {
		return nil
	}
	existing, err := listRules(ctx, r)
	if err != nil {
		return err
	}
	want := strconv.Itoa(OverlayLocalRulePref)
	for _, line := range strings.Split(existing, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		for i, tok := range f {
			if tok == "to" && i+1 < len(f) && f[i+1] == subnet &&
				strings.HasPrefix(line, want+":") {
				return nil
			}
		}
	}
	_, err = r.Run(ctx, "ip", "rule", "add", "to", subnet, "lookup", "main", "pref", want)
	return err
}

// RemoveOverlayLocalRule withdraws it.
func RemoveOverlayLocalRule(ctx context.Context, r Runner, subnet string) {
	if subnet == "" {
		return
	}
	_, _ = r.Run(ctx, "ip", "rule", "del", "to", subnet, "lookup", "main",
		"pref", strconv.Itoa(OverlayLocalRulePref))
}

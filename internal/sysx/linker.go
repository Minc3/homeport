package sysx

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Linker routing model
// --------------------
// A linker is a host that holds an overlay address but terminates no tunnels.
// It needs exactly two things, and they are the mirror of what the backend
// installs for itself:
//
//	ip rule  add from 10.99.0.3 lookup 200
//	ip route replace default via <backend LAN address> table 200
//
// Traffic the host sends from its overlay address goes to the backend, which
// already tracks which tunnel is active. Nothing here knows or needs to know
// which one that is - the linker is stateless with respect to failover, and
// that is the whole reason it can be this small.
//
// Everything else on the box is untouched. Only packets sourced from the
// overlay address match the rule, and nothing uses that address unless a
// service was deliberately bound to it, so installing this on a working host
// changes nothing until something opts in.

// DefaultLinkerTable is the routing table a linker sends its overlay traffic to
// unless the operator names another.
//
// Deliberately not 100, which is the backend's return table, nor 101-103, which
// are the probe tables. A number that means one thing wherever it is read is
// worth more than a reused constant, and a host could in principle be both.
const DefaultLinkerTable = 200

// LinkerTable is the compatibility name for the default. Prefer passing the
// configured table: a host that already policy-routes may be using this number,
// and two systems writing one table fight over its default route.
const LinkerTable = DefaultLinkerTable

// EnsureLinkerRule installs the policy rule that catches traffic sourced from
// the linker's overlay address.
//
// Harmless on its own: an empty table 200 falls through to the next rule and
// then to main, so the rule can exist before the route does without stranding
// anything.
func EnsureLinkerRule(ctx context.Context, r Runner, overlayIP string, tbl int) error {
	if overlayIP == "" {
		return fmt.Errorf("no overlay address configured")
	}
	// Two listings, and both are needed. The filtered one says which rules are
	// in the table this agent is configured for; the full one finds rules for
	// this address that point *somewhere else* - left behind by an older build
	// that pinned no priority, or by the table being changed in the portal. A
	// stale rule is not merely untidy: it is matched on source like ours and can
	// sit at a lower priority, so it silently wins and sends everything this
	// host sends from its overlay address to a table nobody meant.
	mine, err := listRulesInTable(ctx, r, tbl)
	if err != nil {
		return err
	}
	all, err := listRules(ctx, r)
	if err != nil {
		return err
	}
	table := strconv.Itoa(tbl)
	want := LinkerRulePrefBase

	// Ours is the rule at the pinned priority in this table, matched on both:
	// see tableTokens for why the priority alone is not enough.
	mineTokens := tableTokens(mine)
	strays := make([]sourceRule, 0, 2)
	correct := false
	for _, rule := range sourceRuleTables(all, overlayIP) {
		if rule.pref == want && mineTokens[rule.table] {
			correct = true
			continue
		}
		strays = append(strays, rule)
	}
	// In place before anything is withdrawn, like every other rule this system
	// installs. In the gap this host's overlay traffic matches no rule, falls
	// through to main and leaves by the LAN instead of going to the backend,
	// which is the failure the rule exists to prevent.
	if !correct {
		if _, err := r.Run(ctx, "ip", "rule", "add", "from", overlayIP, "lookup", table,
			"pref", strconv.Itoa(want)); err != nil {
			return err
		}
	}
	for _, rule := range strays {
		// Deleted with the table token exactly as the kernel printed it, and
		// with the full selector. `ip rule del pref N` alone is not safe: the
		// local table's rule also lives at priority 0, and deleting that would
		// take the host's own address resolution with it.
		_, _ = r.Run(ctx, "ip", "rule", "del", "from", overlayIP,
			"lookup", rule.table, "pref", strconv.Itoa(rule.pref))
	}
	return nil
}

// sourceRule is one `from <addr> lookup <table>` rule, with the table recorded
// exactly as printed so it can be named back to iproute2 when deleting.
type sourceRule struct {
	pref  int
	table string
}

// sourceRuleTables finds every rule selecting on this source address, whatever
// table it points at.
func sourceRuleTables(rules, source string) []sourceRule {
	var out []sourceRule
	for _, line := range strings.Split(rules, "\n") {
		pref, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(pref)
		if err != nil {
			continue
		}
		var hasSource bool
		var table string
		fields := strings.Fields(rest)
		for i, f := range fields {
			if i+1 >= len(fields) {
				break
			}
			switch f {
			case "from":
				hasSource = hasSource || fields[i+1] == source
			case "lookup":
				table = fields[i+1]
			}
		}
		if hasSource && table != "" {
			out = append(out, sourceRule{pref: n, table: table})
		}
	}
	return out
}

// markRuleTables finds every rule selecting on this fwmark, whatever table it
// points at, with the table recorded exactly as printed so it can be named back
// to iproute2 when deleting. The companion to sourceRuleTables.
func markRuleTables(rules, mark string) []sourceRule {
	var out []sourceRule
	for _, line := range strings.Split(rules, "\n") {
		pref, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(pref)
		if err != nil {
			continue
		}
		var hasMark bool
		var table string
		fields := strings.Fields(rest)
		for i, f := range fields {
			if i+1 >= len(fields) {
				break
			}
			switch f {
			case "fwmark":
				hasMark = hasMark || fields[i+1] == mark
			case "lookup":
				table = fields[i+1]
			}
		}
		if hasMark && table != "" {
			out = append(out, sourceRule{pref: n, table: table})
		}
	}
	return out
}

// tableTokens returns every token a per-table listing prints after "lookup".
//
// listRulesInTable asks the kernel to filter by number, so whatever those rules
// print is this table's own name: `isp2` where /etc/iproute2/rt_tables gives it
// one, the number where it does not. That is what lets a rule found in the
// *full* listing be told apart from one of ours, which a priority cannot do on
// its own - two rules may share a priority, and a stray left behind by a change
// of linker.table sits at exactly the priority ours is pinned to, because the
// build that installed it pinned it there too.
func tableTokens(listing string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "lookup" && i+1 < len(fields) {
				out[fields[i+1]] = true
			}
		}
	}
	return out
}

// ensureLinkerMarkRule installs one of the linker's mark rules at its pinned
// priority, and clears the same mark from anywhere else.
//
// Both of its callers used to accept a rule at any priority, which is invariant
// 3 with only one side pinned: a rule left at whatever the kernel chose sits
// wherever it happens to sit relative to the source rule beside it, and nothing
// would ever move it. The second listing catches the other half of that, a rule
// pointing at a table this host no longer uses - which is what changing
// linker.table leaves behind, and it is not inert: it still claims the marked
// packets and sends them to a table whose route nothing maintains.
//
// Added before the stray is withdrawn. In the gap a marked reply matches no
// rule and falls through to main, which sends it out the LAN default route
// instead of to the backend: a dropped answer to a real client rather than a
// slow one. Same ordering, and the same reason, as ensureProbeRoute.
func ensureLinkerMarkRule(ctx context.Context, r Runner, tbl int, mark string, want int) error {
	mine, err := listRulesInTable(ctx, r, tbl)
	if err != nil {
		return err
	}
	all, err := listRules(ctx, r)
	if err != nil {
		return err
	}
	table := strconv.Itoa(tbl)

	// Ours is the rule at the pinned priority *in this table*. Both halves are
	// needed: the priority alone would call a stray in another table correct,
	// and leave it there for as long as the two agreed on a number.
	mineTokens := tableTokens(mine)
	strays := make([]sourceRule, 0, 2)
	correct := false
	for _, rule := range markRuleTables(all, mark) {
		if rule.pref == want && mineTokens[rule.table] {
			correct = true
			continue
		}
		strays = append(strays, rule)
	}
	if !correct {
		if _, err := r.Run(ctx, "ip", "rule", "add", "fwmark", mark, "lookup", table,
			"pref", strconv.Itoa(want)); err != nil {
			return err
		}
	}
	for _, rule := range strays {
		// With the table token exactly as the kernel printed it: a host that
		// has named the table in rt_tables prints the name, and the number is
		// still accepted, but the name is what the listing gave us.
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", rule.table,
			"pref", strconv.Itoa(rule.pref))
	}
	return nil
}

// removeLinkerMarkRule withdraws one of them, at every priority it is found at.
//
// `ip rule del` given only a selector removes one arbitrary match, so a
// duplicate from a build that pinned nothing would survive the revert and go on
// steering marked packets into a table this has just emptied.
func removeLinkerMarkRule(ctx context.Context, r Runner, tbl int, mark string) {
	table := strconv.Itoa(tbl)
	found := 0
	if existing, err := listRulesInTable(ctx, r, tbl); err == nil {
		for _, pref := range markRulePrefs(existing, mark, "") {
			found++
			_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table,
				"pref", strconv.Itoa(pref))
		}
	}
	if found == 0 {
		_, _ = r.Run(ctx, "ip", "rule", "del", "fwmark", mark, "lookup", table)
	}
}

// EnsureLinkerRoute points the linker's table at the backend.
//
// `via` an address rather than `dev` an interface, because the backend is a
// neighbour on the LAN rather than the far end of a point-to-point link. That
// also means the kernel drops this route if the LAN interface goes down, which
// is why the reconciler re-reads it rather than installing it once.
func EnsureLinkerRoute(ctx context.Context, r Runner, backendLAN string, tbl int) error {
	if backendLAN == "" {
		return fmt.Errorf("no backend LAN address configured")
	}
	_, err := r.Run(ctx, "ip", "route", "replace", "default",
		"via", backendLAN, "table", strconv.Itoa(tbl))
	return err
}

// LinkerRouteVia reports the gateway currently installed in the linker's table,
// or "" if there is none. It is the readback the reconciler compares against.
func LinkerRouteVia(ctx context.Context, r Runner, tbl int) (string, error) {
	out, err := r.Run(ctx, "ip", "route", "show", "default", "table", strconv.Itoa(tbl))
	if err != nil {
		return "", err
	}
	return gatewayFrom(out), nil
}

// gatewayFrom pulls the address out of `default via 192.168.1.2 dev eth0`.
func gatewayFrom(out string) string {
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// RemoveLinkerRouting takes down everything EnsureLinkerRule and
// EnsureLinkerRoute installed, and nothing else.
//
// The overlay address is deliberately left alone: a service may still be bound
// to it, and pulling the address out from under a running process turns a
// routing change into a crash.
func RemoveLinkerRouting(ctx context.Context, r Runner, overlayIP, backendLAN string, tbl int) {
	table := strconv.Itoa(tbl)

	// By the priority each rule was found at. `ip rule del` given only a
	// selector removes one arbitrary match, so a duplicate left by an older
	// build survives the revert, and a leftover here is not inert: it still
	// steers everything this host sends from its overlay address into a table
	// whose route has just been taken out.
	found := 0
	if existing, err := listRulesInTable(ctx, r, tbl); err == nil {
		for _, pref := range sourceRulePrefs(existing, overlayIP, "") {
			found++
			_, _ = r.Run(ctx, "ip", "rule", "del", "from", overlayIP, "lookup", table,
				"pref", strconv.Itoa(pref))
		}
	}
	// A backstop for the case where the listing could not be read, or read
	// nothing. The selector alone is only unsafe where duplicates exist, and
	// duplicates are exactly what the loop above has just proved it can see.
	if found == 0 {
		_, _ = r.Run(ctx, "ip", "rule", "del", "from", overlayIP, "lookup", table)
	}

	// The default route by name, never a flush. This table belongs to the host
	// rather than to this system, and 200 is the number the first real
	// deployment found already in use for a second ISP: flushing it would have
	// deleted that machine's own routing while reporting a clean revert.
	// Invariant 8.
	//
	// Qualified by the gateway, which is what makes this a deletion of our own
	// route rather than of whatever default the table happens to hold. On the
	// host this exists for those are not the same thing: the agent overwrote
	// that machine's `default via <isp2 gateway>` when it installed, and if the
	// operator has since put theirs back - noticed the fault, or their own
	// tooling reasserted it on the next boot - then an unqualified delete
	// removes the route they repaired, on the command they ran to undo us. With
	// the gateway named it simply fails, which is the correct outcome: there is
	// nothing of ours left in the table.
	if backendLAN != "" {
		_, _ = r.Run(ctx, "ip", "route", "del", "default", "via", backendLAN, "table", table)
		return
	}
	// Only where the caller has no backend address to name, which LoadBootstrap
	// refuses to start a linker without.
	_, _ = r.Run(ctx, "ip", "route", "del", "default", "table", table)
}

// RPFilterOn reports whether reverse-path filtering is enabled system-wide.
//
// Read-only on purpose. The other two agents turn it off because their tunnels
// carry no address of their own, which makes even "loose" mode drop probe
// replies - there, it is broken by construction. A linker has an ordinary LAN
// interface with an ordinary address, and on a host with one route to the
// internet the reverse lookup for a client address lands on the interface the
// packet arrived on, so filtering passes and there is nothing to fix. Changing
// it anyway would be an unannounced system-wide change to a machine that is
// somebody's server first. Report it, and let them decide.
func RPFilterOn(ctx context.Context, r Runner) (bool, error) {
	out, err := r.Run(ctx, "sysctl", "-n", "net.ipv4.conf.all.rp_filter")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "0", nil
}

// Reaching a linker from the backend
// ----------------------------------
// The two helpers above run *on* a linker. These run on the backend, and are
// the other half of the same path: the frontend DNATs a published port to
// 10.99.0.3 and routes the whole overlay range down the active tunnel, so the
// packet arrives at the backend addressed to a host that is not the backend.
// Forwarding it needs a next hop, and nothing else in the system supplies one -
// the overlay address says nothing about which machine holds it.
//
//	ip route replace 10.99.0.3/32 via 10.1.1.4
//
// Installed from configuration pushed by the frontend rather than by hand,
// which is what makes it survive a reboot and get repaired when something
// flushes it.

// EnsureLinkerHostRoute points the backend at one linker.
//
// A plain `via` route in the main table: the linker is an ordinary neighbour on
// the backend's network, and this is ordinary forwarding. It is a /32 because
// each linker is a single host - the range as a whole belongs to the tunnel,
// not to the LAN, and routing it here would send the backend's own overlay
// traffic to a neighbour.
func EnsureLinkerHostRoute(ctx context.Context, r Runner, overlayIP, viaIP string) error {
	if overlayIP == "" || viaIP == "" {
		return fmt.Errorf("linker route needs both an overlay address and a next hop")
	}
	_, err := r.Run(ctx, "ip", "route", "replace", overlayIP+"/32", "via", viaIP)
	return err
}

// LinkerHostRouteVia reports the next hop currently installed for one linker,
// or "" if there is no route. It is the readback the backend's reconciler
// compares against, so a route lost with an interface comes back.
func LinkerHostRouteVia(ctx context.Context, r Runner, overlayIP string) (string, error) {
	out, err := r.Run(ctx, "ip", "route", "show", overlayIP+"/32")
	if err != nil {
		return "", err
	}
	return gatewayFrom(out), nil
}

// RemoveLinkerHostRoute withdraws one linker's route.
//
// Used when a linker is disabled or deleted in the portal, and by revert. The
// frontend stops publishing to it at the same moment, so leaving the route
// behind would be a quiet inconsistency rather than a harmless leftover.
func RemoveLinkerHostRoute(ctx context.Context, r Runner, overlayIP string) {
	if overlayIP == "" {
		return
	}
	_, _ = r.Run(ctx, "ip", "route", "del", overlayIP+"/32")
}

// Containers on a linker
// ----------------------
// Binding the overlay address is enough for a service running on the host, and
// it is what the two rules above are for. A container on a bridge network
// cannot do it: the overlay address does not exist in its network namespace, so
// it is published the way containers always are, with Docker DNAT'ing the port
// to the container's own address.
//
// That breaks the source rule. The reply comes back from the container still
// carrying its 172.x address, and it is *routed in that state* - the reverse
// translation that would restore the overlay address has not happened yet - so
// `from 10.99.0.3 lookup 200` never matches and the reply leaves by the host's
// ordinary default route instead of going to the backend. The request arrives,
// the container answers, and the answer is lost: a timeout, which reads as the
// container being down.
//
// The fix is the one the backend already uses for the same problem, with one
// difference. The backend can tell published traffic apart by the interface it
// arrived on, because only published traffic comes off a tunnel. Everything
// reaches a linker on the same LAN interface, so the discriminator here is the
// destination: a connection addressed to this host's overlay address is one
// whose replies belong back at the backend. Marking happens at mangle priority,
// which runs ahead of dstnat, so the overlay address is still on the packet
// when it is matched.

// NFTLinkerReturnTable is the linker's own table. It carries no NAT - only
// connection marking - so the rule that published traffic is never source-NATed
// holds here exactly as it does everywhere else.
const NFTLinkerReturnTable = "failover_linker_return"

// LinkerReturnMark stamps connections that arrived for this host's overlay
// address.
//
// Deliberately not the backend's ReturnMark: a host could be both, and a mark
// that means one thing wherever it is read is worth more than a reused
// constant.
const LinkerReturnMark = 0x201

// LinkerRulePrefBase is the priority band for the linker's own rules.
//
// Explicit, like every other rule in this system, and for the reason invariant
// 3 records: `ip rule add` without a priority takes the first rule's minus one,
// so each rule added lands *ahead* of the last and the order silently depends
// on the sequence they happened to be installed in. Ahead of the backend's
// return band, so that on a host which is somehow both, traffic for this host's
// own overlay address is treated as this host's.
const LinkerRulePrefBase = 32400

// BuildLinkerReturnRuleset marks connections addressed to the overlay address
// so their replies can be routed back to the backend whatever source address
// they are carrying at the time.
//
// Inert until something is actually published here: nothing sends to this
// address unless the frontend's DNAT points at it, and that is gated by the
// frontend's own observe mode. That is what lets a linker keep having no
// observe mode of its own.
func BuildLinkerReturnRuleset(overlayIP string) string {
	var b strings.Builder
	b.WriteString("# generated by failover-linker - do not edit by hand\n")
	b.WriteString("# marks connections arriving for this host's overlay address\n")
	b.WriteString("# so their replies route back to the backend, even after a\n")
	b.WriteString("# container DNAT has rewritten their source address.\n\n")

	fmt.Fprintf(&b, "table ip %s\n", NFTLinkerReturnTable)
	fmt.Fprintf(&b, "delete table ip %s\n\n", NFTLinkerReturnTable)
	fmt.Fprintf(&b, "table ip %s {\n", NFTLinkerReturnTable)
	b.WriteString("\tchain prerouting {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")

	if overlayIP != "" {
		// `ct direction original` is load-bearing, exactly as on the backend.
		// Without it this also stamps the replies to connections the host
		// *started* from the overlay address, which arrive addressed to it -
		// and those would then be marked and routed to the backend instead of
		// being delivered to the process waiting for them here.
		fmt.Fprintf(&b, "\t\tip daddr %s ct direction original ct mark set %#x\n",
			overlayIP, LinkerReturnMark)
	}
	b.WriteString("\t\tct direction reply meta mark set ct mark\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// ApplyLinkerReturnRuleset writes and loads the marking table.
func ApplyLinkerReturnRuleset(ctx context.Context, r Runner, stateDir, ruleset string) (string, error) {
	return applyRuleset(ctx, r, filepath.Join(stateDir, "linker-return.nft"), ruleset)
}

// EnsureLinkerMarkRule routes marked replies to the linker's table.
//
// The companion to the source rule, not a replacement for it: a service bound
// to the overlay address on the host itself is still matched by source, and
// costs no connection tracking to route.
func EnsureLinkerMarkRule(ctx context.Context, r Runner, tbl int) error {
	return ensureLinkerMarkRule(ctx, r, tbl,
		fmt.Sprintf("0x%x", LinkerReturnMark), LinkerRulePrefBase+1)
}

// RemoveLinkerReturnRuleset takes down the marking table and its rule.
func RemoveLinkerReturnRuleset(ctx context.Context, r Runner, tbl int) {
	removeLinkerMarkRule(ctx, r, tbl, fmt.Sprintf("0x%x", LinkerReturnMark))
	_, _ = r.Run(ctx, "nft", "delete", "table", "ip", NFTLinkerReturnTable)
}

// LinkerEgressMark stamps traffic being pulled onto the overlay from a network
// on this host, so it is routed to the backend rather than out the local
// default route.
const LinkerEgressMark = 0x301

// NFTLinkerEgressTable is the linker's source NAT table, kept separate from its
// marking table so the two features can be removed independently.
const NFTLinkerEgressTable = "failover_linker_egress"

// BuildLinkerEgressRuleset pulls container networks onto the overlay.
//
// This is the mirror of the backend's egress ruleset, reshaped for a host that
// terminates no tunnels. The backend marks its containers into table 100 and
// SNATs them to its own overlay address scoped to the tunnels; a linker marks
// them into table 200 and SNATs them to its own overlay address scoped to the
// LAN interface, because the thing it sends them to is a neighbour rather than
// a tunnel.
//
// Two rules doing two jobs, as on the backend. The prerouting mark diverts the
// traffic - a forwarded packet is routed after that hook, so the mark is what
// sends it to the backend instead of out the local default route. The
// postrouting SNAT is what gives it the overlay address, which is what the
// backend's return rule and the frontend's egress NAT both key on: without it
// the packet arrives at the backend carrying a container address that nothing
// downstream will route a reply to.
//
// The SNAT sits at priority -10, ahead of srcnat where Docker installs its
// masquerade. Allowed to run first, Docker would rewrite the source to this
// host's LAN address and the packet would leave as ordinary local traffic.
func BuildLinkerEgressRuleset(cidrs []string, lanIface, overlayIP string) string {
	if len(cidrs) == 0 || lanIface == "" || overlayIP == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("# generated by failover-linker - do not edit by hand\n")
	b.WriteString("# pulls these networks onto the overlay so their traffic leaves\n")
	b.WriteString("# by the frontend's public address rather than this host's.\n\n")

	fmt.Fprintf(&b, "table ip %s\n", NFTLinkerEgressTable)
	fmt.Fprintf(&b, "delete table ip %s\n\n", NFTLinkerEgressTable)
	fmt.Fprintf(&b, "table ip %s {\n", NFTLinkerEgressTable)

	b.WriteString("\tchain prerouting {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	for _, c := range cidrs {
		fmt.Fprintf(&b, "\t\tip saddr %s meta mark set %#x\n", c, LinkerEgressMark)
	}
	b.WriteString("\t}\n")

	b.WriteString("\tchain postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority -10; policy accept;\n")
	for _, c := range cidrs {
		fmt.Fprintf(&b, "\t\tip saddr %s oifname %q snat to %s\n", c, lanIface, overlayIP)
	}
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// ApplyLinkerEgressRuleset writes and loads the source NAT table.
func ApplyLinkerEgressRuleset(ctx context.Context, r Runner, stateDir, ruleset string) (string, error) {
	return applyRuleset(ctx, r, filepath.Join(stateDir, "linker-egress.nft"), ruleset)
}

// RemoveLinkerEgressRuleset takes it down again, for when the last network is
// removed from the portal or the feature is switched off.
func RemoveLinkerEgressRuleset(ctx context.Context, r Runner, tbl int) {
	removeLinkerMarkRule(ctx, r, tbl, fmt.Sprintf("0x%x", LinkerEgressMark))
	_, _ = r.Run(ctx, "nft", "delete", "table", "ip", NFTLinkerEgressTable)
}

// EnsureLinkerEgressRule routes marked egress traffic to the linker's table.
func EnsureLinkerEgressRule(ctx context.Context, r Runner, tbl int) error {
	return ensureLinkerMarkRule(ctx, r, tbl,
		fmt.Sprintf("0x%x", LinkerEgressMark), LinkerRulePrefBase+2)
}

// LanIfaceTo reports which interface this host reaches an address through.
//
// The linker needs its LAN interface name to scope the egress SNAT, and asking
// the kernel which device carries the route to the backend is more reliable
// than making the operator name it: it is discovered rather than configured, so
// it cannot be configured wrongly, and it follows a host that is re-cabled.
func LanIfaceTo(ctx context.Context, r Runner, addr string) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("no address to look up")
	}
	out, err := r.Run(ctx, "ip", "route", "get", addr)
	if err != nil {
		return "", err
	}
	return devFrom(out), nil
}

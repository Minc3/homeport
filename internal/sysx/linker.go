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
//
// A stray for this rule is not merely untidy: it is matched on source like
// ours and can sit at a lower priority, so it silently wins and sends
// everything this host sends from its overlay address to a table nobody meant.
// The table a stray points at is one this system stopped using - which is what
// a change of linker.table leaves behind - and it may still hold this system's
// default route, with the host's own rules still pointing at it. backendLAN is
// what lets that route go with the rule, qualified by gateway so a default
// belonging to the host is never touched.
func EnsureLinkerRule(ctx context.Context, r Runner, overlayIP, backendLAN string, tbl int) error {
	if overlayIP == "" {
		return fmt.Errorf("no overlay address configured")
	}
	return ensurePinnedRule(ctx, r, tbl, "from", overlayIP, LinkerRulePrefBase, true, backendLAN)
}

// sourceRule is one policy rule, with the table recorded exactly as printed so
// it can be named back to iproute2 when deleting.
type sourceRule struct {
	pref  int
	table string
}

// selectorRules finds every rule whose selector field - "from" for the source
// rule, "fwmark" for the mark rules - carries this value, whatever table it
// points at.
func selectorRules(rules, key, value string) []sourceRule {
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
		var matched bool
		var table string
		fields := strings.Fields(rest)
		for i, f := range fields {
			if i+1 >= len(fields) {
				break
			}
			switch f {
			case key:
				matched = matched || fields[i+1] == value
			case "lookup":
				table = fields[i+1]
			}
		}
		if matched && table != "" {
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

// ensurePinnedRule installs one of the linker's rules at its pinned priority,
// and clears the strays it can prove are this system's.
//
// Every caller used to accept a rule at any priority, which is invariant 3
// with only one side pinned: a rule left at whatever the kernel chose sits
// wherever it happens to sit relative to the rules beside it, and nothing
// would ever move it. The second listing catches the other half of that, a
// rule pointing at a table this host no longer uses - which is what changing
// linker.table leaves behind, and it is not inert: it still claims the packets
// and sends them to a table whose route nothing maintains.
//
// ownAnyTable is the ownership test for a rule found pointing somewhere else.
// The source rule may claim every match: the overlay address exists for this
// system alone, so a rule selecting on it is ours wherever it points and
// whatever priority it sits at. The mark rules may not. A fwmark is only a
// number, and the linker's host archetype is a machine that already
// policy-routes - exactly how the table-200 collision happened - so its own
// `fwmark <n> lookup <its table>` rule must survive every reconcile tick and
// every revert (invariant 8). web.validate keeps this system's *path* marks
// off the linker marks, but it constrains this system's configuration, not
// the host's. A mark rule is therefore swept only when something ties it to
// this system: it points at the configured table, or it sits at the exact
// priority this system pins. What that leaves behind - our mark value, another
// table, another priority - is an unpinned older build surviving a change of
// linker.table, indistinguishable from a rule the host owns, and invariant 8
// says the tie goes to leaving it.
//
// Added before the stray is withdrawn. In the gap a matching packet falls
// through to main, which sends it out the LAN default route instead of to the
// backend: a dropped answer to a real client rather than a slow one. Same
// ordering, and the same reason, as ensureProbeRules.
//
// A stray pointing at another table marks that table as one this system
// stopped using, and it may still hold our default route. backendLAN is what
// lets cleanAbandonedTable take that route out - and the rule is withdrawn
// only once the table is confirmed clean, because the rule is the only
// evidence the table was ever ours. See cleanAbandonedTable for why the order
// is load-bearing.
func ensurePinnedRule(ctx context.Context, r Runner, tbl int, key, value string, want int, ownAnyTable bool, backendLAN string) error {
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
	// and leave it there for as long as the two agreed on a number. The
	// configured number is always one of this table's tokens, even when the
	// filtered listing was empty and could name nothing.
	mineTokens := tableTokens(mine)
	mineTokens[table] = true
	strays := make([]sourceRule, 0, 2)
	correct := false
	for _, rule := range selectorRules(all, key, value) {
		if rule.pref == want && mineTokens[rule.table] {
			correct = true
			continue
		}
		if ownAnyTable || mineTokens[rule.table] || rule.pref == want {
			strays = append(strays, rule)
		}
	}
	if !correct {
		if _, err := r.Run(ctx, "ip", "rule", "add", key, value, "lookup", table,
			"pref", strconv.Itoa(want)); err != nil {
			return err
		}
	}
	for _, rule := range strays {
		// A stray in another table is kept until that table is confirmed
		// relieved of our default route: it is the marker the next tick needs
		// to try again.
		if !mineTokens[rule.table] && !cleanAbandonedTable(ctx, r, backendLAN, rule.table) {
			continue
		}
		// Deleted with the table token exactly as the kernel printed it, and
		// with the full selector. A host that has named the table in rt_tables
		// prints the name, and the number is still accepted, but the name is
		// what the listing gave us - and `ip rule del pref N` alone is not
		// safe: the local table's rule also lives at priority 0, and deleting
		// that would take the host's own address resolution with it.
		_, _ = r.Run(ctx, "ip", "rule", "del", key, value, "lookup", rule.table,
			"pref", strconv.Itoa(rule.pref))
	}
	return nil
}

// removePinnedRule withdraws one of the linker's rules wherever it is found,
// under the same ownership test as ensurePinnedRule.
//
// `ip rule del` given only a selector removes one arbitrary match, so a
// duplicate from a build that pinned nothing would survive the revert and go on
// steering packets into a table this has just emptied.
//
// The whole listing rather than this table's, because the rule left behind by a
// change of linker.table points at the old one, and a revert that looked only
// at the configured table would leave it behind. Strays in other tables get the
// same route cleanup, and the same ordering, as on the ensure path: a rule this
// could not finish cleaning up after is deliberately left, because it is the
// only marker of where our route still sits.
func removePinnedRule(ctx context.Context, r Runner, tbl int, key, value string, want int, ownAnyTable bool, backendLAN string) {
	table := strconv.Itoa(tbl)
	mineTokens := map[string]bool{table: true}
	if mine, err := listRulesInTable(ctx, r, tbl); err == nil {
		for tok := range tableTokens(mine) {
			mineTokens[tok] = true
		}
	}
	found := 0
	if all, err := listRules(ctx, r); err == nil {
		for _, rule := range selectorRules(all, key, value) {
			if !ownAnyTable && !mineTokens[rule.table] && rule.pref != want {
				// Not provably this system's: see ensurePinnedRule.
				continue
			}
			// Counted whether or not it is deleted below: a rule kept as the
			// marker of an uncleaned table must also keep the backstop from
			// firing, or the backstop deletes it by selector.
			found++
			if !mineTokens[rule.table] && !cleanAbandonedTable(ctx, r, backendLAN, rule.table) {
				continue
			}
			_, _ = r.Run(ctx, "ip", "rule", "del", key, value, "lookup", rule.table,
				"pref", strconv.Itoa(rule.pref))
		}
	}
	// A backstop for a listing that could not be read. The selector alone is
	// only unsafe where duplicates exist, and duplicates are what the loop
	// above has just proved it can see.
	if found == 0 {
		_, _ = r.Run(ctx, "ip", "rule", "del", key, value, "lookup", table)
	}
}

// cleanAbandonedTable relieves a table this system stopped using of its
// `default via <backend>`, and reports whether the stray rule pointing at it
// may now be withdrawn.
//
// Without this, a change of linker.table moved the rules and left the route
// sitting in the old table forever - and on the host the configurable table
// exists for, that table is the host's own, with the host's own rules still
// pointing at it, so its traffic kept going to the backend with nothing
// anywhere reporting it. Qualified by the gateway for the same reason as in
// RemoveLinkerRouting: a default the operator has since put back, or one this
// system never installed, is not ours to delete.
//
// The order against the rule delete is load-bearing. The stray rule is the
// only evidence the table was ever this system's - once it is gone, nothing
// can tell our leftover default from the host's own routing, so nothing may
// ever try again. Deleting the rule first therefore turns any failure here -
// the agent killed between the two deletes, a transient `ip route del` error -
// into the permanent misroute this cleanup exists to fix. So the route goes
// first, the answer is read back rather than assumed, and on any failure the
// caller keeps the rule as the marker the next reconcile tick retries from. A
// revert has no next tick, but the same answer holds: a rule left standing
// beside our route is a visible leftover, an orphaned route alone is an
// invisible one.
func cleanAbandonedTable(ctx context.Context, r Runner, backendLAN, table string) bool {
	if backendLAN == "" {
		return true
	}
	// A table that has never been written to does not exist to the kernel
	// and reads as empty here - see showRoutes. That is not the "cannot be
	// read" case below: an absent table cannot be holding our route, so the
	// marker has nothing left to protect. Left standing it would outlive
	// every reconcile tick and the revert, a rule nothing maintains
	// steering this host's overlay traffic into a table with no route.
	out, err := showRoutes(ctx, r, "default", "table", table)
	if err != nil {
		return false
	}
	if gatewayFrom(out) != backendLAN {
		// No default left, or one the host owns: nothing of ours to clean.
		return true
	}
	_, err = r.Run(ctx, "ip", "route", "del", "default", "via", backendLAN, "table", table)
	return err == nil
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
//
// A table that has never held a route does not exist to the kernel, which
// reports that as an error rather than an empty listing - see RouteVia. Here
// that is a linker whose LAN interface was not up when the agent started: the
// first install failed, the table was never created, and the reconciler would
// have skipped the repair on the error every tick from then on.
func LinkerRouteVia(ctx context.Context, r Runner, tbl int) (string, error) {
	out, err := showRoutes(ctx, r, "default", "table", strconv.Itoa(tbl))
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

	// Wherever the rule is found, not only in the configured table: the source
	// selector proves ownership on its own, and a change of linker.table
	// leaves the old table's rule behind where a filtered listing would never
	// show it. Each stray's table is also relieved of this system's default
	// route on the way, gateway-qualified for the reason below - the same
	// pairing, in the same order, as the ensure path on every tick.
	removePinnedRule(ctx, r, tbl, "from", overlayIP, LinkerRulePrefBase, true, backendLAN)

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
	// Bootstrap-owned rather than pushed, so this is consistency rather than a
	// boundary - but the generators should not each have their own answer to
	// what an address is.
	if overlayIP = AddressLiteral(overlayIP); overlayIP == "" {
		return ""
	}
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

	// `ct direction original` is load-bearing, exactly as on the backend.
	// Without it this also stamps the replies to connections the host
	// *started* from the overlay address, which arrive addressed to it - and
	// those would then be marked and routed to the backend instead of being
	// delivered to the process waiting for them here.
	fmt.Fprintf(&b, "\t\tip daddr %s ct direction original ct mark set %#x\n",
		overlayIP, LinkerReturnMark)
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
func EnsureLinkerMarkRule(ctx context.Context, r Runner, backendLAN string, tbl int) error {
	return ensurePinnedRule(ctx, r, tbl, "fwmark",
		fmt.Sprintf("0x%x", LinkerReturnMark), LinkerRulePrefBase+1, false, backendLAN)
}

// RemoveLinkerReturnRuleset takes down the marking table and its rule.
func RemoveLinkerReturnRuleset(ctx context.Context, r Runner, backendLAN string, tbl int) {
	removePinnedRule(ctx, r, tbl, "fwmark",
		fmt.Sprintf("0x%x", LinkerReturnMark), LinkerRulePrefBase+1, false, backendLAN)
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
//
// overlaySubnet, when set, is marked and translated as well as the internet:
// a linker's main table has no route to the overlay range - only its table
// does, selected by the overlay source or by this mark - so a container here
// talking to a service bound to the backend's overlay address has no "normal
// route" to be left on. That traffic rode the mark before the internet-only
// qualifier existed and keeps doing so.
func BuildLinkerEgressRuleset(cidrs []string, lanIface, overlayIP, overlaySubnet string) string {
	// Re-parsed and re-rendered before a byte of it reaches the file. This is
	// the host where that matters most: see EgressNetworks, and proto.Auth for
	// what could reach this function before the handshake proved both ends.
	cidrs = EgressNetworks(cidrs)
	overlayIP = AddressLiteral(overlayIP)
	// The subnet rides the same bootstrap file, and it was the one value here
	// still reaching the rules with a bare %s. It is dropped rather than
	// refused, like a bad entry in the list above: a subnet nft cannot load
	// rejects the whole table, taking the mark chain and the source NAT with
	// it, and the mark rule is installed before this runs - so a container's
	// traffic would be marked into a table with no ruleset behind it. Without
	// the subnet the overlay rules are simply not emitted, which is exactly
	// what a site that has not set one gets. See invariant 19.
	overlaySubnet = NetworkLiteral(overlaySubnet)
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
	// Internet destinations only, as on the backend - see nonInternetDestinations
	// - plus the overlay, which this host can reach no other way.
	for _, c := range cidrs {
		if overlaySubnet != "" {
			fmt.Fprintf(&b, "\t\tip saddr %s ip daddr %s meta mark set %#x\n", c, overlaySubnet, LinkerEgressMark)
		}
		fmt.Fprintf(&b, "\t\tip saddr %s %s meta mark set %#x\n", c, internetOnly, LinkerEgressMark)
	}
	b.WriteString("\t}\n")

	// The same limit on the translation, and here it matters more than it
	// does on the backend: the backend's SNAT is scoped to the tunnels, which
	// only internet-bound traffic leaves by, but a linker's one interface is
	// both its way to the backend and its way to everything else on the LAN.
	// Unqualified, a container's packet to a printer or a database down the
	// hall left with the overlay address as its source, and the reply went
	// to the LAN's default gateway instead of back here.
	b.WriteString("\tchain postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority -10; policy accept;\n")
	for _, c := range cidrs {
		if overlaySubnet != "" {
			fmt.Fprintf(&b, "\t\tip saddr %s ip daddr %s oifname %q snat to %s\n", c, overlaySubnet, lanIface, overlayIP)
		}
		fmt.Fprintf(&b, "\t\tip saddr %s %s oifname %q snat to %s\n", c, internetOnly, lanIface, overlayIP)
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
func RemoveLinkerEgressRuleset(ctx context.Context, r Runner, backendLAN string, tbl int) {
	removePinnedRule(ctx, r, tbl, "fwmark",
		fmt.Sprintf("0x%x", LinkerEgressMark), LinkerRulePrefBase+2, false, backendLAN)
	removeUnreachableRule(ctx, r, fmt.Sprintf("0x%x", LinkerEgressMark), LinkerEgressDenyRulePref)
	_, _ = r.Run(ctx, "nft", "delete", "table", "ip", NFTLinkerEgressTable)
}

// LinkerEgressDenyRulePref is where the linker's egress refusal sits, behind
// the lookup it backs.
const LinkerEgressDenyRulePref = LinkerRulePrefBase + 3

// EnsureLinkerEgressRule routes marked egress traffic to the linker's table,
// and refuses it when the table cannot. The refusal matters more here than on
// the backend: on the dual-ISP host this agent was first deployed to, a
// marked packet falling through to main leaves by the second ISP, Docker
// masquerades it to that address, and the binding follows the flow to the
// backend once the LAN route is back, where nothing can answer it.
func EnsureLinkerEgressRule(ctx context.Context, r Runner, backendLAN string, tbl int) error {
	mark := fmt.Sprintf("0x%x", LinkerEgressMark)
	if err := ensurePinnedRule(ctx, r, tbl, "fwmark", mark, LinkerRulePrefBase+2, false, backendLAN); err != nil {
		return err
	}
	all, err := listRules(ctx, r)
	if err != nil {
		return err
	}
	return ensureUnreachableRule(ctx, r, mark, LinkerEgressDenyRulePref, all)
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

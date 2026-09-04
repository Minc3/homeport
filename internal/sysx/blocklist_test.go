package sysx

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func blocklistSpec() BlocklistSpec {
	return BlocklistSpec{Enabled: true, PublicIface: "eth0"}
}

// The feature off must generate nothing at all, so a site that never turns it
// on loads exactly the tables it always did.
func TestBlocklistOffGeneratesNothing(t *testing.T) {
	if got := BuildBlocklistRuleset(BlocklistSpec{PublicIface: "eth0"}); got != "" {
		t.Fatalf("the blocklist is off and it generated a ruleset:\n%s", got)
	}
}

// Without an interface to scope to, the drop rule would also match traffic
// arriving on a tunnel: the probes and the control channel. A third party's
// list could then condemn a healthy link and move traffic to a metered one.
// validate refuses the save, and the generator refuses the blob.
func TestBlocklistWithNoPublicInterfaceGeneratesNothing(t *testing.T) {
	if got := BuildBlocklistRuleset(BlocklistSpec{Enabled: true}); got != "" {
		t.Fatalf("no public interface and it generated a ruleset:\n%s", got)
	}
}

// The safety property, stated as the protection table's is: the first rule of
// the chain leaves everything that did not arrive on the public interface.
func TestBlocklistChainExcludesNonPublicTrafficFirst(t *testing.T) {
	rs := BuildBlocklistRuleset(blocklistSpec())
	lines := strings.Split(rs, "\n")
	for i, l := range lines {
		if !strings.Contains(l, "hook prerouting") {
			continue
		}
		// The first rule after the hook declaration.
		for _, next := range lines[i+1:] {
			next = strings.TrimSpace(next)
			if next == "" || strings.HasPrefix(next, "#") {
				continue
			}
			if next != `iifname != "eth0" accept` {
				t.Fatalf("the chain's first rule is %q, not the public-interface guard", next)
			}
			break
		}
	}
}

// The system's own traffic must be unreachable from here, which the interface
// scoping already gives - this pins the consequence rather than the mechanism,
// exactly as the protection table's test does.
func TestBlocklistNeverMentionsTheSystemsOwnAddressesOrPorts(t *testing.T) {
	spec := blocklistSpec()
	spec.Exceptions = []string{"203.0.113.0/24"}
	rs := BuildBlocklistRuleset(spec)
	for _, bad := range []string{"10.99.0.1", "10.99.0.2", "51999", "51998", "51820"} {
		if strings.Contains(rs, bad) {
			t.Errorf("the blocklist ruleset mentions %q, which is this system's own traffic:\n%s", bad, rs)
		}
	}
}

// Invariant 2. This table drops; it must never translate.
func TestBlocklistNeverTranslates(t *testing.T) {
	rs := BuildBlocklistRuleset(blocklistSpec())
	for _, bad := range []string{"dnat", "snat", "masquerade", "redirect"} {
		if strings.Contains(rs, bad) {
			t.Errorf("the blocklist ruleset contains %q:\n%s", bad, rs)
		}
	}
}

// TCP only, deliberately: a false positive on a UDP game port drops a player
// mid-match, where on TCP it is a connection that does not open.
func TestBlocklistDropsOnlyTCP(t *testing.T) {
	rs := BuildBlocklistRuleset(blocklistSpec())
	var drop string
	for _, l := range strings.Split(rs, "\n") {
		if strings.Contains(l, "drop") {
			drop = strings.TrimSpace(l)
		}
	}
	if drop == "" {
		t.Fatal("no drop rule at all")
	}
	if !strings.Contains(drop, "meta l4proto tcp") {
		t.Errorf("the drop rule is not limited to TCP: %q", drop)
	}
	if !strings.Contains(drop, "@"+BlocklistFeedSet) {
		t.Errorf("the drop rule does not consult the feed set: %q", drop)
	}
}

// The chain has to run ahead of the protection table's raw chain, so a listed
// source costs one set lookup and nothing else: no conntrack entry, no limiter
// state, no region set walk.
func TestBlocklistRunsAheadOfTheProtectionChains(t *testing.T) {
	if blocklistPriority >= -300 {
		t.Fatalf("the blocklist chain is at priority %d, which is not ahead of the protection raw chain at -300",
			blocklistPriority)
	}
	rs := BuildBlocklistRuleset(blocklistSpec())
	if !strings.Contains(rs, "hook prerouting priority -310;") {
		t.Errorf("the generated chain does not carry the pinned priority:\n%s", rs)
	}
}

// A limiter nobody can see is worse than none: "some visitors cannot connect"
// and "the feed lists them" look identical from outside.
func TestBlocklistDropIsCounted(t *testing.T) {
	rs := BuildBlocklistRuleset(blocklistSpec())
	if !strings.Contains(rs, `counter drop comment "`+CounterBlocklist+`"`) {
		t.Errorf("the drop is not counted and named:\n%s", rs)
	}
}

// The exceptions are checked before the feed, because the failure this feature
// produces is silent and an operator who has found one needs an override that
// is not "turn the whole list off".
func TestBlocklistExceptionsAreAcceptedBeforeTheFeed(t *testing.T) {
	spec := blocklistSpec()
	spec.Exceptions = []string{"203.0.113.0/24"}
	rs := BuildBlocklistRuleset(spec)
	accept := strings.Index(rs, "@"+BlocklistAllowSet+" accept")
	drop := strings.Index(rs, "@"+BlocklistFeedSet+" counter drop")
	if accept < 0 {
		t.Fatalf("no accept rule for the exceptions:\n%s", rs)
	}
	if drop < 0 || accept > drop {
		t.Fatalf("the exceptions are not consulted before the feed:\n%s", rs)
	}
	if !strings.Contains(rs, "203.0.113.0/24") {
		t.Errorf("the exception network is not in the allow set:\n%s", rs)
	}
}

// A set nothing consults is dead weight the kernel holds, and a set list a
// reader cannot trust to mean the rule list - the reasoning the protection
// table already applies to its own optional sets.
func TestBlocklistWithNoExceptionsDeclaresNoAllowSet(t *testing.T) {
	rs := BuildBlocklistRuleset(blocklistSpec())
	if strings.Contains(rs, "set "+BlocklistAllowSet+" {") {
		t.Errorf("an allow set was declared with no exceptions:\n%s", rs)
	}
	if strings.Contains(rs, "@"+BlocklistAllowSet) {
		t.Errorf("a rule consults an allow set that does not exist:\n%s", rs)
	}
}

// The feed set is filled from the control plane, never from the packet path,
// so it needs neither the dynamic flag nor a size - and a size would be a
// ceiling on a list whose length is somebody else's decision.
func TestBlocklistFeedSetIsAPlainIntervalSet(t *testing.T) {
	rs := BuildBlocklistRuleset(blocklistSpec())
	i := strings.Index(rs, "set "+BlocklistFeedSet+" {")
	if i < 0 {
		t.Fatalf("no feed set:\n%s", rs)
	}
	block := rs[i:]
	block = block[:strings.Index(block, "\n\t}")]
	if !strings.Contains(block, "flags interval") {
		t.Errorf("the feed set is not an interval set, so a CIDR element would be refused:\n%s", block)
	}
	if strings.Contains(block, "dynamic") {
		t.Errorf("the feed set is dynamic, which nothing writes to it from the packet path:\n%s", block)
	}
	if strings.Contains(block, "size ") {
		t.Errorf("the feed set carries a size, which caps somebody else's list:\n%s", block)
	}
}

// The refresh has to be one transaction, or there is an instant at which the
// list is half replaced and the frontend is admitting what it was blocking.
func TestBlocklistElementsAreOneFlushAndAdd(t *testing.T) {
	out := BuildBlocklistElements([]string{"203.0.113.0/24", "198.51.100.7/32"})
	flush := strings.Index(out, "flush set ip "+NFTBlocklistTable+" "+BlocklistFeedSet)
	add := strings.Index(out, "add element ip "+NFTBlocklistTable+" "+BlocklistFeedSet)
	if flush < 0 || add < 0 {
		t.Fatalf("the element file is not a flush and an add:\n%s", out)
	}
	if flush > add {
		t.Fatalf("the add comes before the flush, so the new list would be flushed away:\n%s", out)
	}
	if strings.Count(out, "flush set") != 1 || strings.Count(out, "add element") != 1 {
		t.Fatalf("more than one statement of either kind:\n%s", out)
	}
	// And nothing that would rebuild the table, which would reset the counter
	// and drop everything the protection table holds beside it.
	for _, bad := range []string{"delete table", "table ip " + NFTBlocklistTable + " {", "chain "} {
		if strings.Contains(out, bad) {
			t.Errorf("the element file contains %q, so a refresh rebuilds rules:\n%s", bad, out)
		}
	}
}

// The feed aggregates several sources whose networks routinely nest, and nft
// rejects a whole set literal over one contained duplicate - which would take
// the blocklist down entirely on an ordinary day's feed.
func TestBlocklistElementsMergeNestedNetworks(t *testing.T) {
	out := BuildBlocklistElements([]string{
		"203.0.113.0/24",
		"203.0.113.16/28", // inside the above
		"203.0.113.0/24",  // an exact duplicate
		"198.51.100.0/24",
	})
	if strings.Contains(out, "203.0.113.16/28") {
		t.Errorf("a contained network survived the merge; nft would refuse the set:\n%s", out)
	}
	if n := strings.Count(out, "203.0.113.0/24"); n != 1 {
		t.Errorf("the duplicate was kept %d times:\n%s", n, out)
	}
	if !strings.Contains(out, "198.51.100.0/24") {
		t.Errorf("the disjoint network was dropped:\n%s", out)
	}
}

// The one filter that protects real people rather than the ruleset: a feed
// that ever listed a slice of carrier-grade NAT would drop a large number of
// mobile players at once, each of whom sees the service as down.
func TestBlocklistElementsDropCarrierNATAndPrivateSpace(t *testing.T) {
	out := BuildBlocklistElements([]string{
		"100.64.0.0/16",  // carrier-grade NAT
		"10.1.0.0/16",    // private
		"192.168.5.0/24", // private
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local
		"224.0.0.0/4",    // multicast
		"0.0.0.0/8",      // this network
		"203.0.113.0/24", // the one real entry
	})
	for _, bad := range []string{"100.64", "10.1.", "192.168.5", "127.0", "169.254", "224.0", "0.0.0.0"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q survived into the loaded set:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "203.0.113.0/24") {
		t.Errorf("the routable entry was dropped with them:\n%s", out)
	}
}

// A network that overlaps carrier-grade NAT without sitting inside it does
// the same damage, so the test is overlap rather than containment.
func TestBlocklistElementsDropNetworksOverlappingReservedSpace(t *testing.T) {
	// 100.0.0.0/9 spans 100.0.0.0 to 100.127.255.255, which reaches into
	// 100.64.0.0/10.
	out := BuildBlocklistElements([]string{"100.0.0.0/9", "203.0.113.0/24"})
	if strings.Contains(out, "100.0.0.0/9") {
		t.Errorf("a network overlapping carrier-grade NAT was loaded:\n%s", out)
	}
	if !strings.Contains(out, "203.0.113.0/24") {
		t.Errorf("the routable entry was dropped with it:\n%s", out)
	}
}

// The feed is the one list here nobody in this deployment reviewed, so every
// element is re-parsed and re-rendered rather than interpolated: an entry
// carrying a newline is not one bad element, it is a free hand with a file
// nft loads as root.
func TestBlocklistElementsRefuseInjectedSyntax(t *testing.T) {
	out := BuildBlocklistElements([]string{
		"203.0.113.0/24",
		"198.51.100.0/24 }\nadd rule ip failover_blocklist raw accept\n",
		"not-a-network",
		"2001:db8::/32",
	})
	for _, bad := range []string{"add rule", "accept", "not-a-network", "2001:db8"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q reached the generated file:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "203.0.113.0/24") {
		t.Errorf("the usable entry beside them was dropped:\n%s", out)
	}
}

// Nothing usable means a fault, not an instruction. Emptying the set on the
// word of a bad list is the one failure this feature must not have, because
// it is silent: the rules stay, the portal says the list is on, and every
// listed source is admitted.
func TestBlocklistElementsWithNothingUsableRenderNothing(t *testing.T) {
	if out := BuildBlocklistElements([]string{"not-a-network", "10.0.0.0/8"}); out != "" {
		t.Fatalf("an unusable list rendered a transaction that would flush the set:\n%s", out)
	}
	if out := BuildBlocklistElements(nil); out != "" {
		t.Fatalf("an empty list rendered a transaction that would flush the set:\n%s", out)
	}
}

// The portal reports the loaded figure, so it has to come from the same
// arithmetic the loaded set does rather than from len(): the elements
// CheckBlocklist hands back are what RenderBlocklistElements loads, and
// their count is what the card shows.
func TestCheckBlocklistElementsMatchWhatIsLoaded(t *testing.T) {
	in := []string{"203.0.113.0/24", "203.0.113.16/28", "10.0.0.0/8", "198.51.100.0/24"}
	elems, err := CheckBlocklist(in)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(elems), 2; got != want {
		t.Fatalf("counted %d networks, want %d", got, want)
	}
	out := RenderBlocklistElements(elems)
	if n := strings.Count(out, "/"); n != 2 {
		t.Fatalf("the rendered file holds %d networks, which the count disagrees with:\n%s", n, out)
	}
	if out != BuildBlocklistElements(in) {
		t.Fatal("rendering the checked elements differs from building from the raw list")
	}
}

// The counter is what the portal attributes drops to, and it is read back out
// of the kernel because reloading the table resets it.
func TestBlocklistStateParsesTheCounter(t *testing.T) {
	const listing = `{"nftables":[
		{"table":{"family":"ip","name":"failover_blocklist"}},
		{"set":{"family":"ip","table":"failover_blocklist","name":"feed"}},
		{"rule":{"family":"ip","table":"failover_blocklist","chain":"raw","comment":"blocklist",
			"expr":[{"counter":{"packets":42,"bytes":2520}},{"drop":null}]}}
	]}`
	r := &stubRunner{out: listing}
	c, err := BlocklistState(context.Background(), r)
	if err != nil {
		t.Fatalf("BlocklistState: %v", err)
	}
	if c.Packets != 42 || c.Bytes != 2520 {
		t.Errorf("counter is %d packets / %d bytes, want 42 / 2520", c.Packets, c.Bytes)
	}
	if !c.Drops {
		t.Error("the counter does not report that its packets were dropped")
	}
	// Terse, because the feed set is thousands of elements and this runs on
	// the engine's own goroutine in front of the decision loop.
	if !strings.Contains(r.last, " -t ") {
		t.Errorf("the readback is not terse, so it serialises every element: %q", r.last)
	}
}

// A loaded table whose rule has counted nothing is the ordinary state of a
// working blocklist on a quiet day, and must not read as a missing table.
func TestBlocklistStateOnAQuietTableIsNotAnError(t *testing.T) {
	r := &stubRunner{out: `{"nftables":[{"table":{"family":"ip","name":"failover_blocklist"}}]}`}
	c, err := BlocklistState(context.Background(), r)
	if err != nil {
		t.Fatalf("BlocklistState: %v", err)
	}
	if c.Packets != 0 || c.Name != CounterBlocklist {
		t.Errorf("got %+v, want a zeroed %s counter", c, CounterBlocklist)
	}
}

type stubRunner struct {
	out  string
	last string
}

func (s *stubRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	s.last = name + " " + strings.Join(args, " ")
	return s.out, nil
}

func (s *stubRunner) Applying() bool { return true }

// The parse and the shrink guard count entries and say nothing about how
// much address space an entry covers, so nine perfect lines could take half
// the routable internet's TCP off every published port. The floor is applied
// to what survives the reserved-space strip, because the honest feed carries
// 224.0.0.0/4 and 10.0.0.0/8 from its bogon source and a floor on the raw
// list would refuse it every day.
func TestBlocklistRefusesAShortPrefixOnlyAfterTheReservedStrip(t *testing.T) {
	if _, err := CheckBlocklist([]string{"203.0.113.0/24", "32.0.0.0/3", "198.51.100.0/24"}); err == nil ||
		!strings.Contains(err.Error(), "32.0.0.0/3") {
		t.Fatalf("a /3 survived the floor: %v", err)
	}
	elems, err := CheckBlocklist([]string{"224.0.0.0/4", "240.0.0.0/4", "10.0.0.0/8", "0.0.0.0/8", "203.0.113.0/24"})
	if err != nil || len(elems) != 1 {
		t.Fatalf("the honest reserved entries were refused rather than stripped: n=%d err=%v", len(elems), err)
	}
	if _, err := CheckBlocklist([]string{"1.0.0.0/8"}); err != nil {
		t.Fatalf("a /8 exactly is the floor and must pass: %v", err)
	}
}

// The ceiling is on merged address coverage, not on entries. A list of a few
// thousand /24s and /16s is the honest shape and loads; one that has absorbed
// a quarter of the internet does not, however few lines it took.
func TestBlocklistRefusesCoverageOverTheCeiling(t *testing.T) {
	var honest []string
	for i := 0; i < 2000; i++ {
		honest = append(honest, fmt.Sprintf("203.%d.%d.0/24", i/256, i%256))
	}
	for i := 0; i < 200; i++ {
		honest = append(honest, fmt.Sprintf("5.%d.0.0/16", i))
	}
	if _, err := CheckBlocklist(honest); err != nil {
		t.Fatalf("an ordinary list was refused: %v", err)
	}
	// A /8 is 2^24 addresses, so eight /8s are 2^27 exactly, at the
	// ceiling, and nine are over it.
	var wide []string
	for i := 1; i <= 9; i++ {
		wide = append(wide, fmt.Sprintf("%d.0.0.0/8", i*3))
	}
	if _, err := CheckBlocklist(wide); err == nil {
		t.Fatal("nine /8s, one over the 2^27 ceiling, passed it")
	}
	// Precisely 2^27 is admitted: eight /8s.
	if _, err := CheckBlocklist(wide[:8]); err != nil {
		t.Fatalf("coverage at the ceiling was refused: %v", err)
	}
}

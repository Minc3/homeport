package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

// protectedConfig is a site that has turned on shaping and one rate limit.
func protectedConfig() model.Config {
	cfg := model.Defaults()
	cfg.Mode = model.ModeArmed
	cfg.Frontend.PublicIface = "eth0"
	cfg.Protect.Enabled = true
	cfg.Protect.PacketsPerSec = 400
	cfg.Paths[0].Shape.ToBackendMbit = 40
	return cfg
}

// Observe mode's promise is that nothing the agent does can be felt by a
// player. A shaper decides what gets dropped and when, so it belongs with the
// DNAT rules, not with the measurement plumbing that is installed regardless.
func TestObserveModeShapesNothing(t *testing.T) {
	cfg := protectedConfig()
	cfg.Mode = model.ModeObserve

	e, q := engineForReconcile(t, healthyKernel())
	e.cfg = cfg
	e.runner = &dryRunner{q}

	e.applyShaping(context.Background(), cfg, e.runner)

	for _, c := range q.writes() {
		if strings.HasPrefix(c, "tc qdisc replace") || strings.HasPrefix(c, "tc qdisc del") {
			t.Errorf("observe mode changed the shaping: %q", c)
		}
	}
}

// The same for the limiters: a drop rule loaded in observe mode is traffic
// being affected by a system that promised not to.
func TestObserveModeLoadsNoProtectionRules(t *testing.T) {
	cfg := protectedConfig()
	cfg.Mode = model.ModeObserve

	e, q := engineForReconcile(t, healthyKernel())
	e.cfg = cfg
	gated := &dryRunner{q}

	e.applyProtect(context.Background(), cfg, gated, e.real)

	for _, c := range q.writes() {
		if strings.HasPrefix(c, "nft -f") {
			t.Errorf("observe mode loaded a protection ruleset: %q", c)
		}
	}
}

// A site with the feature off must never run nft for it - and must still have
// the table removed, because turning it off generates nothing to load and an
// empty load would leave the old rules running.
func TestDisablingProtectionRemovesTheTable(t *testing.T) {
	cfg := model.Defaults()
	cfg.Mode = model.ModeArmed

	e, q := engineForReconcile(t, healthyKernel())
	e.cfg = cfg

	e.applyProtect(context.Background(), cfg, e.runner, e.real)

	if q.count("nft delete table ip failover_protect") != 1 {
		t.Errorf("the protection table was not removed; writes were %v", q.writes())
	}
	if e.protectOn {
		t.Error("protection is reported as running with the feature off")
	}
}

// The queue discipline belongs to the interface, and `wg-quick down` deletes
// the interface. Nothing else notices: traffic keeps flowing, unshaped, and
// only the latency-under-load gets quietly worse.
func TestReconcileRestoresShapingLostWithTheTunnel(t *testing.T) {
	kernel := healthyKernel()
	kernel["tc qdisc show dev wg-main"] = "qdisc noqueue 0: root refcnt 2"
	kernel["tc qdisc show dev wg-lte1"] = "qdisc noqueue 0: root refcnt 2"
	kernel["tc qdisc show dev wg-lte2"] = "qdisc noqueue 0: root refcnt 2"

	e, q := engineForReconcile(t, kernel)
	e.cfg = protectedConfig()

	e.reconcileRouting(context.Background())

	if q.count("tc qdisc replace dev wg-main root cake bandwidth 40mbit") != 1 {
		t.Errorf("shaping was not restored; writes were %v", q.writes())
	}
}

// An intact shaper must be left completely alone. Replacing it on every tick
// would discard the queue state that is doing the work, ten times a minute.
func TestReconcileLeavesIntactShapingAlone(t *testing.T) {
	kernel := healthyKernel()
	kernel["tc qdisc show dev wg-main"] = "qdisc cake 8003: root refcnt 2 bandwidth 40Mbit besteffort overhead 80"

	e, q := engineForReconcile(t, kernel)
	e.cfg = protectedConfig()

	e.reconcileRouting(context.Background())

	if got := q.writes(); len(got) != 0 {
		t.Errorf("reconcile wrote %v to a system that was already correct", got)
	}
}

// An unshaped path must not even be asked about. This is what keeps a site that
// never turned shaping on identical to one built before the feature existed.
func TestReconcileIgnoresPathsWithNoShapingConfigured(t *testing.T) {
	e, q := engineForReconcile(t, healthyKernel())

	e.reconcileRouting(context.Background())

	for _, c := range q.calls {
		if strings.HasPrefix(c, "tc ") {
			t.Errorf("ran tc on a site with no shaping configured: %q", c)
		}
	}
}

// Revert takes down what the agent installed. It must remove the shaper from
// the tunnels it shaped, and must not touch one it never shaped - that queue
// discipline belongs to whoever put it there.
func TestRevertRemovesOnlyTheShapersItInstalled(t *testing.T) {
	e, q := engineForReconcile(t, healthyKernel())
	e.cfg = protectedConfig() // only main is shaped

	e.Revert(context.Background())

	if q.count("tc qdisc del dev wg-main root") != 1 {
		t.Errorf("did not remove the shaper it installed; writes were %v", q.writes())
	}
	for _, iface := range []string{"wg-lte1", "wg-lte2"} {
		if q.count("tc qdisc del dev "+iface+" root") != 0 {
			t.Errorf("removed a queue discipline on %s, which this agent never shaped", iface)
		}
	}
	if q.count("nft delete table ip failover_protect") != 1 {
		t.Errorf("revert left the protection table in place; writes were %v", q.writes())
	}
}

// dryRunner reports every command as observed rather than applied, the way the
// real observe-mode runner does, while still recording what was asked for.
type dryRunner struct{ *queryRunner }

func (d *dryRunner) Applying() bool { return false }

func (d *dryRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	// Readbacks still have to work in observe mode - measurement is not gated -
	// so those run for real and everything else is swallowed.
	if len(args) > 0 && (args[len(args)-1] == "show" || hasArg(args, "show") || name == "sysctl") {
		return d.queryRunner.Run(ctx, name, args...)
	}
	return "", nil
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// The fault this exists to catch, and the reason it gets an alert of its own
// rather than a mark on a path card: each of these tunnels is healthy, probes
// perfectly and reports nothing wrong. What has failed is the assumption
// underneath the whole system - three independent links - and pfSense sending
// two tunnels out one WAN is invisible from every other signal here.
func TestTwoTunnelsOnOneServiceAreReported(t *testing.T) {
	kernel := healthyKernel()
	kernel["wg show all endpoints"] = "wg-main\tkeyA=\t203.0.113.10:51820\n" +
		"wg-lte1\tkeyB=\t198.51.100.20:41234\n" +
		"wg-lte2\tkeyC=\t198.51.100.20:52001" // same address, different NAT port

	e, _ := engineForReconcile(t, kernel)

	e.samplePeerEndpoints(context.Background())

	st := e.Status()
	if len(st.SharedEndpoints) != 1 {
		t.Fatalf("reported %+v, want the one clash", st.SharedEndpoints)
	}
	got := st.SharedEndpoints[0]
	if got.Address != "198.51.100.20" {
		t.Errorf("reported address %q", got.Address)
	}
	if len(got.Paths) != 2 || got.Paths[0] != "lte1" || got.Paths[1] != "lte2" {
		t.Errorf("reported paths %v, want lte1 and lte2", got.Paths)
	}
	// The address is on the paths themselves too, so a card can say where its
	// traffic is really arriving from.
	for _, p := range st.Paths {
		if p.PeerEndpoint == "" {
			t.Errorf("path %s reports no endpoint", p.Name)
		}
	}
}

// Three services, three addresses: silence. An alert that fires on a correctly
// configured system is one nobody reads when it matters.
func TestSeparateServicesReportNoClash(t *testing.T) {
	kernel := healthyKernel()
	kernel["wg show all endpoints"] = "wg-main\tkeyA=\t203.0.113.10:51820\n" +
		"wg-lte1\tkeyB=\t198.51.100.20:41234\n" +
		"wg-lte2\tkeyC=\t198.51.100.99:52001"

	e, _ := engineForReconcile(t, kernel)

	e.samplePeerEndpoints(context.Background())

	if got := e.Status().SharedEndpoints; len(got) != 0 {
		t.Errorf("a correctly separated system reported %+v", got)
	}
}

// A tunnel that has not handshaked yet has no address to compare, and two of
// them must not read as two tunnels sharing one - "unknown" is not a value.
func TestTunnelsWithNoHandshakeAreNotTreatedAsSharing(t *testing.T) {
	kernel := healthyKernel()
	kernel["wg show all endpoints"] = "wg-main\tkeyA=\t203.0.113.10:51820\n" +
		"wg-lte1\tkeyB=\t(none)\n" +
		"wg-lte2\tkeyC=\t(none)"

	e, _ := engineForReconcile(t, kernel)

	e.samplePeerEndpoints(context.Background())

	if got := e.Status().SharedEndpoints; len(got) != 0 {
		t.Errorf("tunnels with no handshake were reported as sharing an address: %+v", got)
	}
}

// A reload is not free: it resets the counters, unparks every blocked source
// and releases every engaged region lock. A save that did not change the
// protection ruleset must therefore not reload it - an operator saving a
// probe interval mid-flood would otherwise hand the flood a clean slate. A
// save that does change it still reloads, which is the documented reset.
func TestAnUnchangedSaveDoesNotReloadProtection(t *testing.T) {
	cfg := protectedConfig()
	e, q := engineForReconcile(t, healthyKernel())
	e.cfg = cfg

	e.applyProtect(context.Background(), cfg, e.runner, e.real)
	e.applyProtect(context.Background(), cfg, e.runner, e.real)
	if n := q.count("nft -f"); n != 1 {
		t.Errorf("an unchanged configuration loaded the ruleset %d times, want 1", n)
	}

	changed := cfg
	changed.Protect.DropSpoofed = true
	e.applyProtect(context.Background(), changed, e.runner, e.real)
	if n := q.count("nft -f"); n != 2 {
		t.Errorf("a changed limit did not reload the ruleset (loads: %d, want 2)", n)
	}
}

// Turning the feature off throws the last samples away with the table. Kept,
// they would be served again the moment protection was re-armed, for up to
// one sample tick - and a stale engaged-lock reading is an attack alert for
// a lock that is not in the kernel.
func TestDisablingProtectionClearsTheSamples(t *testing.T) {
	e, _ := engineForReconcile(t, healthyKernel())
	e.protectOn = true
	e.protectApplied = "old ruleset"
	e.protectCounters = []model.ProtectCounter{{Name: "geo:src", Packets: 4}}
	e.protectBlocked = []model.BlockedSource{{Address: "198.51.100.7"}}
	e.protectGeoLocked = []model.GeoLockedPort{{Proto: "udp", Port: 27015}}

	off := model.Defaults()
	off.Mode = model.ModeArmed
	e.applyProtect(context.Background(), off, e.runner, e.real)

	if e.protectCounters != nil || e.protectBlocked != nil || e.protectGeoLocked != nil {
		t.Errorf("stale samples survived the feature being turned off: %+v %+v %+v",
			e.protectCounters, e.protectBlocked, e.protectGeoLocked)
	}
	if e.protectApplied != "" {
		t.Error("the reload latch survived the table being removed")
	}
}

// Revert clears every protection sample, the engaged locks included. The
// first build cleared two of the three, and the stale third resurfaced when
// protection was next re-armed - as a "region lock engaged" alert for a lock
// the revert had removed from the kernel days earlier.
func TestRevertClearsTheEngagedLockSample(t *testing.T) {
	e, _ := engineForReconcile(t, healthyKernel())
	e.protectOn = true
	e.protectApplied = "old ruleset"
	e.protectCounters = []model.ProtectCounter{{Name: "geo:src", Packets: 4}}
	e.protectBlocked = []model.BlockedSource{{Address: "198.51.100.7"}}
	e.protectGeoLocked = []model.GeoLockedPort{{Proto: "udp", Port: 27015}}

	e.Revert(context.Background())

	if e.protectCounters != nil || e.protectBlocked != nil || e.protectGeoLocked != nil {
		t.Errorf("stale samples survived the revert: %+v %+v %+v",
			e.protectCounters, e.protectBlocked, e.protectGeoLocked)
	}
	if e.protectApplied != "" {
		t.Error("the reload latch survived the revert")
	}
}

// The counters feed the portal's protection card and nothing else: no
// decision, no alert, nothing written down. So with nobody watching, reading
// them out of the kernel is process spawns every five seconds for the life of
// the process, and the kernel goes on counting regardless - nothing is lost
// by not looking.
func TestProtectCountersAreNotSampledWithNobodyWatching(t *testing.T) {
	e, q := engineForReconcile(t, healthyKernel())
	e.protectOn = true
	// Nobody has asked for status since well before the idle window.
	e.statusAt.Store(time.Now().Add(-2 * protectSampleIdleAfter).UnixNano())

	e.sampleProtect(context.Background())

	if n := q.count("nft -j"); n != 0 {
		t.Errorf("ran %d nft listings for a portal nobody has open", n)
	}
}

// And it must come straight back, or the card is dead rather than idle. The
// status request is what opens the gate, so the tick after somebody loads the
// portal samples again.
func TestProtectCountersResumeWhenThePortalIsOpened(t *testing.T) {
	e, q := engineForReconcile(t, healthyKernel())
	e.protectOn = true
	e.statusAt.Store(time.Now().Add(-2 * protectSampleIdleAfter).UnixNano())

	// The portal loads. Status is what stamps the clock, so this is the real
	// path rather than a store of our own.
	_ = e.Status()
	e.sampleProtect(context.Background())

	if n := q.count("nft -j -t list table ip failover_protect"); n != 1 {
		t.Errorf("the counters were sampled %d times after the portal was opened, want 1", n)
	}
}

// The gate is on the portal being open, never on the feature being on: a site
// with protection off must still run no nft at all, which is the older
// promise and the one every ordinary site relies on.
func TestProtectionOffSamplesNothingEvenWithThePortalOpen(t *testing.T) {
	e, q := engineForReconcile(t, healthyKernel())
	e.protectOn = false

	_ = e.Status()
	e.sampleProtect(context.Background())

	if n := q.count("nft"); n != 0 {
		t.Errorf("ran %d nft commands on a site with protection off", n)
	}
}

// A sample taken while the portal was open is not served after it has been
// closed, which is the same rule applyProtect and Revert already hold: the
// portal states these as live facts - "N sources currently parked", "Releases
// in Ns", an engaged region lock that reads as the service being down to
// everybody outside the region - and the gate stops the sampling without
// stopping the serving, so the reading offered on the first request back is as
// old as the idle spell rather than one tick old.
func TestStaleProtectSamplesAreNotServedAfterAnIdleSpell(t *testing.T) {
	e, _ := engineForReconcile(t, healthyKernel())
	e.protectOn = true
	e.protectCounters = []model.ProtectCounter{{Name: "geo:src", Packets: 4}}
	e.protectBlocked = []model.BlockedSource{{Address: "198.51.100.7"}}
	e.protectGeoLocked = []model.GeoLockedPort{{Proto: "udp", Port: 27015, ExpiresSec: 47}}

	// Nobody has looked since well before the idle window, so nothing has been
	// sampled in that time either.
	e.statusAt.Store(time.Now().Add(-2 * protectSampleIdleAfter).UnixNano())

	st := e.Status()
	if st.Protect == nil {
		t.Fatal("the protection card vanished; protection is still on")
	}
	if len(st.Protect.GeoLocked) != 0 {
		t.Errorf("served a region lock measured before the idle spell: %+v", st.Protect.GeoLocked)
	}
	if len(st.Protect.Blocked) != 0 {
		t.Errorf("served parked sources measured before the idle spell: %+v", st.Protect.Blocked)
	}
	if len(st.Protect.Counters) != 0 {
		t.Errorf("served counters measured before the idle spell: %+v", st.Protect.Counters)
	}
}

// And a portal that is being watched keeps its numbers. The gate is on the
// idle spell, not on every request: dropping the sample each time would leave
// the card blank between ticks for somebody polling every second.
func TestProtectSamplesSurviveWhileThePortalIsWatched(t *testing.T) {
	e, _ := engineForReconcile(t, healthyKernel())
	e.protectOn = true
	e.protectGeoLocked = []model.GeoLockedPort{{Proto: "udp", Port: 27015}}

	_ = e.Status() // opens the gate, and drops the sample taken before it
	e.protectGeoLocked = []model.GeoLockedPort{{Proto: "udp", Port: 27015}}

	st := e.Status()
	if st.Protect == nil || len(st.Protect.GeoLocked) != 1 {
		t.Errorf("a live sample was dropped from a portal that is being polled: %+v", st.Protect)
	}
}

// Dropping the stale sample leaves the card empty, so the same edge has to ask
// for a fresh one. Without it the panel is blank until the 5s tick on every
// load, and the reload latch goes untested for that long too - a save landing
// in the window skips a reload the table needed.
func TestOpeningThePortalWakesTheProtectionSample(t *testing.T) {
	e, _ := engineForReconcile(t, healthyKernel())
	e.protectOn = true
	e.statusAt.Store(time.Now().Add(-2 * protectSampleIdleAfter).UnixNano())

	_ = e.Status()

	select {
	case <-e.sampleWake:
	default:
		t.Error("opening the portal did not wake the sampler; the card stays blank until the tick")
	}
}

// And only on that edge. The gate opens once per idle spell: a portal polling
// every second must not have every request spawning nft, which is the cost the
// gate was added to remove.
func TestPollingDoesNotWakeTheProtectionSampleEveryRequest(t *testing.T) {
	e, _ := engineForReconcile(t, healthyKernel())
	e.protectOn = true
	e.statusAt.Store(time.Now().Add(-2 * protectSampleIdleAfter).UnixNano())

	_ = e.Status() // the edge
	select {
	case <-e.sampleWake:
	default:
		t.Fatal("the edge did not wake the sampler")
	}

	for i := 0; i < 5; i++ {
		_ = e.Status()
	}
	select {
	case <-e.sampleWake:
		t.Error("a poll on an already-open gate woke the sampler")
	default:
	}
}

// Invariant 13 for the protection table, and the fix the blocklist got
// first: disarming is not a teardown, so a table loaded while armed is still
// in the kernel, still dropping and still parking. Recorded as unloaded, the
// card vanished and nothing was sampled, so a source parked mid-flood read
// as protection being off.
func TestDisarmingLeavesProtectionRecordedAsLoaded(t *testing.T) {
	cfg := protectedConfig()
	e, q := engineForReconcile(t, healthyKernel())
	e.cfg = cfg
	e.applyProtect(context.Background(), cfg, e.runner, e.real)
	if !e.protectOn {
		t.Fatal("the armed apply did not record the table as loaded")
	}

	observe := cfg
	observe.Mode = model.ModeObserve
	e.applyProtect(context.Background(), observe, &dryRunner{q}, e.real)

	if !e.protectOn {
		t.Error("a disarm recorded protection as unloaded while its table is still in the kernel and still dropping")
	}
	if e.protectApplied != "" {
		t.Error("the reload latch survived a disarm; what is loaded is no longer this ruleset")
	}
	if n := q.count("nft delete table ip failover_protect"); n != 0 {
		t.Errorf("a disarm removed the table %d times; disarming is not a teardown", n)
	}
}

// A read that fails drops the samples whatever the failure, because the
// portal states them as live facts, but drops the record of the table only
// when the kernel says the table is not there. Cleared on a timeout it is
// cleared by one slow nft, and the sampler that would set it again runs only
// while the portal is open.
func TestAFailedProtectReadDropsTheSamplesAndKeepsTheRecord(t *testing.T) {
	e, q := engineForReconcile(t, healthyKernel())
	const list = "nft -j -t list table ip failover_protect"
	q.fails = map[string]string{list: "Error: timed out"}
	e.protectOn = true
	e.protectApplied = "table ip failover_protect {}"
	e.protectCounters = []model.ProtectCounter{{Name: "geo:src", Packets: 4}}
	e.protectBlocked = []model.BlockedSource{{Address: "198.51.100.7"}}
	e.protectGeoLocked = []model.GeoLockedPort{{Proto: "udp", Port: 27015}}

	_ = e.Status()
	e.sampleProtect(context.Background())
	if e.protectCounters != nil || e.protectBlocked != nil || e.protectGeoLocked != nil {
		t.Error("samples the kernel would not confirm were kept to be served as live facts")
	}
	if !e.protectOn {
		t.Error("one failed read that said nothing about the table cleared the record of it being loaded")
	}
	if e.protectApplied != "" {
		t.Error("the reload latch survived a failed read")
	}

	q.fails[list] = "Error: No such file or directory"
	e.sampleProtect(context.Background())
	if e.protectOn {
		t.Error("a table the kernel cannot find is still recorded as loaded")
	}
}

// The unit runs under Restart=always and a restart into observe mode installs
// nothing, so a table left loaded by the armed process this one replaced is
// found only by reading the kernel. Gated on the record alone, a cleared
// record would have been permanent and the card absent for a table that was
// dropping.
func TestTheProtectReadbackFindsATableLeftBehind(t *testing.T) {
	cfg := protectedConfig()
	e, q := engineForReconcile(t, healthyKernel())
	e.cfg = cfg
	q.replies["nft -j -t list table ip failover_protect"] = `{"nftables":[]}`
	e.protectOn = false

	_ = e.Status()
	e.sampleProtect(context.Background())
	if !e.protectOn {
		t.Error("a protection table the kernel answered for was not recorded as loaded")
	}
}

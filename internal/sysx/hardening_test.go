package sysx

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

// nftables reads a quoted string as everything up to the next double quote
// with no escape processing, so Go's %q was not the boundary it looked like:
// a name carrying a quote ended the string early and the rest was lexed as
// rule text, loaded as root. The generator drops what nft cannot carry, and
// leaves a clean name byte for byte alone so no existing ruleset moves.
func TestOperatorStringsCannotBreakOutOfAQuotedToken(t *testing.T) {
	bad := "eth0\" accept comment \"x\n; \\ tail"
	if got := nftSafe(bad); got != "eth0 accept comment x;  tail" {
		t.Fatalf("nftSafe(%q) = %q", bad, got)
	}
	if got := nftSafe("wg-main"); got != "wg-main" {
		t.Fatalf("a clean name was changed to %q", got)
	}
	if got := nftSafe("café \x7f"); got != "caf " {
		t.Fatalf("non-ASCII and DEL were not dropped: %q", got)
	}
	if got := nftSafe(strings.Repeat("a", 500)); len(got) != nftMaxString {
		t.Fatalf("a long name was not capped: %d bytes", len(got))
	}

	cfg := defaultsPublishing()
	cfg.Frontend.PublicIface = "ens3\" accept comment \""
	cfg.Services[0].Name = "gmod\"; jump evil; comment \""
	cfg.Paths[0].Iface = "wg-main\"\n\t\taccept"
	// What nft would lex: everything inside a balanced pair of quotes is one
	// token, so the test removes the quoted tokens and looks at what is left
	// as rule text.
	quoted := regexp.MustCompile(`"[^"]*"`)
	for _, rs := range []string{BuildRuleset(cfg), BuildEgressRuleset(cfg), BuildReturnRuleset(pathIfaces(cfg))} {
		for _, line := range strings.Split(rs, "\n") {
			if strings.Count(line, "\"")%2 != 0 {
				t.Fatalf("a line carries an unbalanced quote: %q", line)
			}
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			bare := quoted.ReplaceAllString(line, "")
			if strings.Contains(bare, "evil") || strings.Contains(bare, "jump") || strings.TrimSpace(bare) == "accept" {
				t.Fatalf("injected rule text reached the ruleset outside a quoted token: %q", line)
			}
		}
	}
}

// A repeated element in an anonymous set has nft reject the whole table, and
// two paths on one tunnel is a blob a build before the validate refusal
// could store. Rendered once, in path order.
func TestTwoPathsOnOneInterfaceRenderItOnce(t *testing.T) {
	cfg := defaultsPublishing()
	cfg.Paths[1].Iface = cfg.Paths[0].Iface
	if got := pathIfaces(cfg); len(got) != 2 || got[0] != cfg.Paths[0].Iface || got[1] != cfg.Paths[2].Iface {
		t.Fatalf("pathIfaces = %v", got)
	}
	rs := BuildRuleset(cfg)
	want := fmt.Sprintf("oifname { %q, %q }", cfg.Paths[0].Iface, cfg.Paths[2].Iface)
	if !strings.Contains(rs, want) {
		t.Fatalf("clamp set not deduplicated; want %s in:\n%s", want, rs)
	}
}

// The dotted sysctl key splits on every dot, so a VLAN sub-interface's
// rp_filter was written to a device that does not exist, failed on every
// tick, and left the filter on: the §8 fault, from a legal interface name.
func TestAnInterfaceWithADotKeepsItsWholeNameInTheSysctlKey(t *testing.T) {
	f := &fakeRunner{}
	EnsureSysctls(context.Background(), f, []string{"eth0.100"})
	if !f.ran("sysctl -w net/ipv4/conf/eth0.100/rp_filter=0") {
		t.Fatalf("per-interface key does not carry the whole name: %v", f.calls)
	}
	g := &fakeRunner{replies: map[string]string{"sysctl -n net/ipv4/conf/eth0.100/rp_filter": "2\n"}}
	if changed, err := RPFilterOff(context.Background(), g, "eth0.100"); err != nil || !changed {
		t.Fatalf("RPFilterOff on a dotted name = %v, %v", changed, err)
	}
}

// The parked-source set is sized for a quarter of a million entries, and a
// flood that fills a share of it is exactly when this readback runs every
// five seconds and lands in every status poll. A bounded share comes back,
// longest-remaining first, and the count comes with it.
func TestParkedSourcesAreReportedBoundedWithTheTotal(t *testing.T) {
	const n = maxBlockedReported + 57
	elems := make([]string, 0, n)
	for i := 0; i < n; i++ {
		elems = append(elems, fmt.Sprintf(`{"elem":{"val":"10.%d.%d.1","expires":%d}}`, i/256, i%256, i))
	}
	f := &shapeRunner{replies: map[string]string{
		"nft -j -t list table": `{"nftables":[{"set":{"name":"blocked"}}]}`,
		"nft -j list set":      `{"nftables":[{"set":{"name":"blocked","elem":[` + strings.Join(elems, ",") + `]}}]}`,
	}}
	_, blocked, total, _, err := ProtectState(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if total != n {
		t.Fatalf("total = %d, want %d", total, n)
	}
	if len(blocked) != maxBlockedReported {
		t.Fatalf("%d sources handed back, want the cap of %d", len(blocked), maxBlockedReported)
	}
	if blocked[0].ExpiresSec != n-1 {
		t.Fatalf("the longest-remaining source is not first: %+v", blocked[0])
	}
	if b, _ := json.Marshal(model.ProtectStatus{Blocked: blocked, BlockedTotal: total}); !strings.Contains(string(b), `"blocked_total":157`) {
		t.Fatalf("the total does not reach the portal: %s", b[:80])
	}
}

// A command's output is bounded before it is buffered. Every readback here
// is small by construction, but a set an attacker filled is a large answer,
// and a large answer must fail the read rather than grow the process.
func TestCommandOutputIsCapped(t *testing.T) {
	var b cappedBuffer
	if _, err := b.Write(make([]byte, maxCommandOutput)); err != nil {
		t.Fatalf("output at the cap refused: %v", err)
	}
	if _, err := b.Write([]byte("x")); err == nil || !b.overflow {
		t.Fatal("output past the cap was accepted")
	}
}

// Command failoverctl is a thin CLI over the frontend's local control socket.
//
// The portal is the primary way to manage the system; this exists for the
// cases where a browser is not available, and for the one-command rollback.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

var version = "dev"

func main() {
	socket := flag.String("socket", "/var/lib/failover/ctl/ctl.sock", "path to the frontend control socket")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	c := &client{socket: *socket}
	var err error
	switch args[0] {
	case "status":
		err = c.status()
	case "events":
		err = c.events(args[1:])
	case "pin":
		err = c.pin(args[1:])
	case "unpin":
		err = c.post("/api/pin", map[string]any{"path_id": 0}, "automatic selection resumed")
	case "approve":
		err = c.approve(args[1:])
	case "revoke":
		err = c.pathAction("/api/revoke", args[1:], "approval revoked")
	case "clear-quarantine":
		err = c.pathAction("/api/quarantine/clear", args[1:], "quarantine cleared")
	case "passwd":
		err = c.passwd(args[1:])
	case "mode":
		err = c.mode(args[1:])
	case "revert":
		err = c.post("/api/revert", map[string]any{}, "reverted: nftables table and policy routes removed")
	case "version":
		fmt.Println("failoverctl", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `failoverctl - control the path failover frontend

usage: failoverctl [-socket PATH] <command>

commands:
  status                       show paths, health, quota and the active route
  events [n]                   show the most recent activity log entries
  pin <path>                   force a specific path regardless of priority
  unpin                        return to automatic selection
  approve <path> <hours> [gb]  allow an over-quota path for a limited time
  revoke <path>                cancel an overage approval
  clear-quarantine <path>      lift the circuit breaker on a path
  mode <observe|armed>         arm the agent or put it back in observe mode
  passwd [user] [password]     set a portal password; generated if omitted
  revert                       remove every routing and nftables change
  version

`)
}

type client struct{ socket string }

func (c *client) http() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", c.socket)
			},
		},
	}
}

func (c *client) get(path string, out any) error {
	resp, err := c.http().Get("http://localhost" + path)
	if err != nil {
		return fmt.Errorf("cannot reach the frontend at %s: %w", c.socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeError(resp)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *client) post(path string, payload any, okMessage string) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := c.http().Post("http://localhost"+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("cannot reach the frontend at %s: %w", c.socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeError(resp)
	}
	if okMessage != "" {
		fmt.Println(okMessage)
	}
	return nil
}

func decodeError(resp *http.Response) error {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Error != "" {
		return fmt.Errorf("%s", body.Error)
	}
	return fmt.Errorf("request failed: %s", resp.Status)
}

type statusResponse struct {
	Status struct {
		Mode       string `json:"mode"`
		ActiveName string `json:"active_name"`
		Held       bool   `json:"held"`
		HeldReason string `json:"held_reason"`
		BackendUp  bool   `json:"backend_up"`
		Paths      []struct {
			ID         int     `json:"id"`
			Name       string  `json:"name"`
			Iface      string  `json:"iface"`
			Priority   int     `json:"priority"`
			Health     string  `json:"health"`
			Block      string  `json:"block"`
			Active     bool    `json:"active"`
			RTTms      float64 `json:"rtt_ms"`
			LossPct    float64 `json:"loss_pct"`
			JitterMs   float64 `json:"jitter_ms"`
			UsedBytes  int64   `json:"used_bytes"`
			LimitBytes int64   `json:"limit_bytes"`
		} `json:"paths"`
	} `json:"status"`
	Pinned int `json:"pinned"`
}

func (c *client) status() error {
	var out statusResponse
	if err := c.get("/api/status", &out); err != nil {
		return err
	}
	s := out.Status

	fmt.Printf("mode:    %s\n", s.Mode)
	if s.ActiveName != "" {
		fmt.Printf("active:  %s\n", s.ActiveName)
	} else {
		fmt.Printf("active:  none\n")
	}
	fmt.Printf("backend: %s\n", boolWord(s.BackendUp, "connected", "unreachable"))
	if out.Pinned != 0 {
		fmt.Printf("pinned:  path %d (automatic selection disabled)\n", out.Pinned)
	}
	if s.Held {
		fmt.Printf("\nHELD: %s\n", s.HeldReason)
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PATH\tIFACE\tPRIO\tHEALTH\tBLOCK\tRTT\tLOSS\tJITTER\tQUOTA")
	for _, p := range s.Paths {
		marker := ""
		if p.Active {
			marker = " *"
		}
		block := p.Block
		if block == "" {
			block = "-"
		}
		q := "-"
		if p.LimitBytes > 0 {
			q = fmt.Sprintf("%s / %s", human(p.UsedBytes), human(p.LimitBytes))
		}
		fmt.Fprintf(w, "%s%s\t%s\t%d\t%s\t%s\t%.1fms\t%.1f%%\t%.1fms\t%s\n",
			p.Name, marker, p.Iface, p.Priority, p.Health, block, p.RTTms, p.LossPct, p.JitterMs, q)
	}
	return w.Flush()
}

func (c *client) events(args []string) error {
	limit := 30
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil {
			limit = n
		}
	}
	var out []struct {
		TS      int64  `json:"ts"`
		Kind    string `json:"kind"`
		Message string `json:"message"`
	}
	if err := c.get("/api/events?limit="+strconv.Itoa(limit), &out); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for i := len(out) - 1; i >= 0; i-- {
		e := out[i]
		fmt.Fprintf(w, "%s\t%s\t%s\n",
			time.Unix(e.TS, 0).Format("2006-01-02 15:04:05"), e.Kind, e.Message)
	}
	return w.Flush()
}

func (c *client) resolvePath(name string) (int, error) {
	if id, err := strconv.Atoi(name); err == nil {
		return id, nil
	}
	var out statusResponse
	if err := c.get("/api/status", &out); err != nil {
		return 0, err
	}
	for _, p := range out.Status.Paths {
		if strings.EqualFold(p.Name, name) {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("no path named %q", name)
}

func (c *client) pin(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: failoverctl pin <path>")
	}
	id, err := c.resolvePath(args[0])
	if err != nil {
		return err
	}
	return c.post("/api/pin", map[string]any{"path_id": id}, "pinned to "+args[0])
}

func (c *client) pathAction(endpoint string, args []string, okMessage string) error {
	if len(args) != 1 {
		return fmt.Errorf("a path name or id is required")
	}
	id, err := c.resolvePath(args[0])
	if err != nil {
		return err
	}
	return c.post(endpoint, map[string]any{"path_id": id}, okMessage)
}

func (c *client) approve(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: failoverctl approve <path> <hours> [gb]")
	}
	id, err := c.resolvePath(args[0])
	if err != nil {
		return err
	}
	hours, err := strconv.ParseFloat(args[1], 64)
	if err != nil {
		return fmt.Errorf("hours must be a number")
	}
	var gb float64
	if len(args) > 2 {
		if gb, err = strconv.ParseFloat(args[2], 64); err != nil {
			return fmt.Errorf("gb must be a number")
		}
	}
	return c.post("/api/approve", map[string]any{"path_id": id, "hours": hours, "extra_gb": gb},
		fmt.Sprintf("%s approved for %g hours (expires on its own)", args[0], hours))
}

func (c *client) mode(args []string) error {
	if len(args) != 1 || (args[0] != "observe" && args[0] != "armed") {
		return fmt.Errorf("usage: failoverctl mode <observe|armed>")
	}
	return c.post("/api/mode", map[string]any{"mode": args[0]}, "mode set to "+args[0])
}

// passwd sets a portal password from the machine itself.
//
// This is the recovery path, and the reason it asks for no current password:
// the first-run one is printed to the journal once, and an operator who has
// lost it has no way back in through the portal at all. Anyone who can reach
// this socket is already root on the host, where the database is readable
// anyway - demanding the old password here would protect nothing and would
// leave a locked-out operator with no way in short of deleting the account row
// by hand.
func (c *client) passwd(args []string) error {
	user, password := "", ""
	switch len(args) {
	case 0:
	case 1:
		user = args[0]
	case 2:
		user, password = args[0], args[1]
	default:
		return fmt.Errorf("usage: failoverctl passwd [user] [password]")
	}

	generated := false
	if password == "" {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		password = hex.EncodeToString(b)
		generated = true
	}
	body := map[string]any{"new": password}
	if user != "" {
		body["username"] = user
	}
	if err := c.post("/api/password", body, ""); err != nil {
		return err
	}
	if user == "" {
		user = "admin"
	}
	if generated {
		fmt.Printf("password for %s set to: %s\n", user, password)
	} else {
		fmt.Printf("password for %s changed\n", user)
	}
	fmt.Println("every existing portal session for that account has been logged out")
	return nil
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func human(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTP"[exp])
}

// Command failover-backend runs on the home Debian host that terminates the
// three WireGuard tunnels.
//
// It answers path probes, keeps its reply routing in step with the frontend's
// decision, and meters LTE usage. It deliberately has no web interface and
// makes no routing decisions of its own: the frontend is authoritative, and it
// is the side that stays reachable when every path is down.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/quinlan102/homeport/internal/agent"
	"github.com/quinlan102/homeport/internal/model"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/failover/backend.json", "path to the bootstrap config file")
	revert := flag.Bool("revert", false,
		"remove every routing and nftables change this agent installed, then exit "+
			"(run `failoverctl revert` on the frontend first)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("failover-backend", version)
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	agent.Version = version

	boot, err := model.LoadBootstrap(*cfgPath)
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
	boot.LogWarnings(log)

	a := agent.New(log, boot)

	// The frontend's revert never reached this host, so everything the backend
	// installed - the reply rules, table 100's default route, the marking table,
	// the routes to any extra hosts - stayed behind after a rollback that
	// reported itself complete.
	//
	// A flag rather than something the frontend can trigger: revert is the
	// panic button, and a panic button that travels over the control channel is
	// one a lost frame can press. Ordering matters and the log says so.
	if *revert {
		a.Revert(context.Background())
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version,
		"frontend", boot.Overlay.FrontendIP, "backend", boot.Overlay.BackendIP,
		"state_dir", boot.StateDir)

	if err := a.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
	log.Info("shut down")
}

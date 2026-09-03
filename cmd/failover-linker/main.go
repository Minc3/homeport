// Command failover-linker runs on an extra host behind the backend.
//
// It holds an overlay address so the frontend can publish services to this
// machine, and routes anything sent from that address to the backend, which
// puts it on whichever tunnel is currently active. It terminates no tunnels,
// answers no probes and makes no decisions.
//
// Most sites never run this. It exists for the case where the box terminating
// the tunnels is not the box doing the work - a small dedicated backend with
// the game servers and the websites on separate machines behind it.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/quinlan102/homeport/internal/linker"
	"github.com/quinlan102/homeport/internal/model"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/failover/linker.json", "path to the bootstrap config file")
	revert := flag.Bool("revert", false, "remove the overlay policy rule and table, then exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("failover-linker", version)
		return
	}

	// Stamped here rather than read back from the binary, so the portal reports
	// the same string as `failover-linker -version`.
	linker.Version = version

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log, *cfgPath, *revert); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, cfgPath string, revert bool) error {
	boot, err := model.LoadBootstrap(cfgPath)
	if err != nil {
		return err
	}
	// Error rather than Warn: these are the shared secret being weak or
	// readable, and a line an operator learns to skip is a line that was never
	// written. Not fatal, because refusing to start is an outage on the host
	// that may be the only thing keeping traffic flowing.
	for _, w := range boot.Warnings {
		log.Error("bootstrap config", "warning", w)
	}
	// A frontend or backend config here would start an agent that installs a
	// rule for an address this host does not hold, which is a quiet way to do
	// nothing at all.
	if boot.Role != model.RoleLinker {
		return fmt.Errorf("%s has role %q; failover-linker needs a config with role %q",
			cfgPath, boot.Role, model.RoleLinker)
	}

	l := linker.New(log, boot)

	if revert {
		l.Revert(context.Background())
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version,
		"overlay", boot.Linker.OverlayIP, "backend", boot.Linker.BackendLAN)

	err = l.Run(ctx)
	log.Info("shut down")
	return err
}

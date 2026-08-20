// Command failover-frontend runs on the datacentre Debian host.
//
// It probes the backend through every WireGuard tunnel, decides which one
// carries traffic, publishes services with destination NAT, and serves the
// management portal.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/quinlan102/homeport/internal/engine"
	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/store"
	"github.com/quinlan102/homeport/internal/web"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/failover/frontend.json", "path to the bootstrap config file")
	adminUser := flag.String("admin-user", "admin", "username created on first run")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("failover-frontend", version)
		return
	}

	// Stamped here rather than read back from the binary, so the portal reports
	// the same string as `failover-frontend -version`.
	engine.Version = version

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log, *cfgPath, *adminUser); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, cfgPath, adminUser string) error {
	boot, err := model.LoadBootstrap(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(boot.StateDir, 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	st, err := store.Open(boot.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	// Asked before LoadConfig, which seeds the defaults and would make every
	// start look like the first one.
	configured, err := st.HasConfig()
	if err != nil {
		return err
	}

	cfg, err := st.LoadConfig()
	if err != nil {
		return err
	}
	// The bootstrap file wins for overlay addressing: it is what the backend
	// was told to dial, and the two must agree before anything else works.
	cfg.Overlay = boot.Overlay
	// The public interface is only seeded, and only once. The installer can
	// discover it and Defaults() cannot - eth0 is wrong on most modern hosts -
	// but it is a portal setting, so an operator who changes it there must not
	// find the bootstrap file has quietly put it back on the next restart.
	if !configured && boot.PublicIface != "" {
		cfg.Frontend.PublicIface = boot.PublicIface
		log.Info("first run: seeded the public interface from the bootstrap file",
			"iface", boot.PublicIface)
	}
	if err := st.SaveConfig(cfg); err != nil {
		return err
	}

	notifier := notify.New(log)
	notifier.SetConfig(cfg.Notify)

	eng := engine.New(log, st, notifier, cfg, boot.Key(), boot.StateDir)
	portal := web.New(eng, st, log)

	password, err := portal.EnsureAdmin(adminUser)
	if err != nil {
		return err
	}
	if password != "" {
		log.Warn("first run: portal account created",
			"username", adminUser, "password", password,
			"note", "this line stays in the journal in the clear; change it in Settings -> Portal account, "+
				"or with `failoverctl passwd` if it is ever lost")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("starting", "version", version, "mode", cfg.Mode,
		"portal", boot.PortalListen, "state_dir", boot.StateDir)
	if cfg.Mode == model.ModeObserve {
		log.Warn("running in observe mode: decisions are computed but nothing is applied")
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		if err := eng.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("engine stopped", "err", err)
			stop()
		}
	}()

	go func() {
		defer wg.Done()
		control := engine.NewControlServer(eng, boot.Key())
		if err := control.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("control server stopped", "err", err)
			stop()
		}
	}()

	go func() {
		defer wg.Done()
		socket := filepath.Join(boot.StateDir, "ctl", "ctl.sock")
		if err := portal.Serve(ctx, boot.PortalListen, socket); err != nil && ctx.Err() == nil {
			log.Error("portal stopped", "err", err)
			stop()
		}
	}()

	wg.Wait()
	log.Info("shut down")
	return nil
}

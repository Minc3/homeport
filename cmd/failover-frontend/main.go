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

	// The timezone database, embedded, used only when the host has none.
	//
	// quota.Location answers a zone it cannot load with time.UTC, silently, and
	// that answer decides which billing period every metered byte lands in. A
	// frontend whose /usr/share/zoneinfo goes missing mid-life - a tzdata
	// removed by a rebuilt image, a minimal container - therefore starts drawing
	// the boundary eleven hours from where the carrier draws it, reads the
	// current period as empty because the rows are under a different
	// period_start, and never trips a quota again, with nothing anywhere saying
	// so. web.validate cannot catch it because it runs at save time on a host
	// that still had the file.
	//
	// This is the whole of the cost: about 450 KB in a static binary that is
	// already eleven megabytes, and the stdlib prefers the system copy whenever
	// there is one, so a host with tzdata behaves exactly as before.
	_ "time/tzdata"
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
	// 0700, because of what ends up in here rather than because of tidiness.
	// The database holds portal session tokens in the clear beside the password
	// hashes, so a world-readable state directory is a world-readable login to
	// the thing that arms the data plane and serves the shared secret. Nothing
	// outside this process reads any of it: the portal serves embedded assets,
	// ruleset.nft is a record for whoever is already root, and the failoverctl
	// socket has its own 0700 directory below this one.
	//
	// Chmod as well as MkdirAll, because MkdirAll does nothing to a directory
	// that already exists and every deployment predating this has one at 0755.
	// The unit file asks systemd for the same mode, which covers a first start;
	// this covers every upgrade.
	if err := os.MkdirAll(boot.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	if err := os.Chmod(boot.StateDir, 0o700); err != nil {
		log.Warn("cannot restrict the state directory; it holds portal session tokens",
			"dir", boot.StateDir, "err", err)
	}

	st, err := store.Open(boot.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	// Said out loud rather than swallowed. The database holds live session
	// tokens beside the password hashes, so a chmod that quietly did nothing -
	// a filesystem that ignores it, an export where this process does not own
	// the file - leaves a world-readable login to the thing that arms the data
	// plane, with nothing anywhere reporting it. Not fatal: a database that
	// opened is one the frontend can run on, and refusing to start over a mode
	// bit trades a hardening step for the outage it exists to prevent.
	for _, w := range st.PermissionWarnings() {
		log.Warn("cannot restrict a database file; it holds portal session tokens", "err", w)
	}

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
	portal := web.New(eng, st, log, boot.PSK)

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

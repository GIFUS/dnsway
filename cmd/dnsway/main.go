package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"dnsway/internal/api"
	"dnsway/internal/cache"
	"dnsway/internal/config"
	"dnsway/internal/router"
	"dnsway/internal/rules"
	"dnsway/internal/server"
	"dnsway/internal/stats"
	"dnsway/internal/upstream"
	"dnsway/internal/watcher"
)

const version = "dev"

func main() {
	if err := run(); err != nil {
		if !errors.Is(err, errCheckFailed) {
			slog.Error("dnsway stopped", "err", err)
		}
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.json", "path to config file")
	check := flag.Bool("check", false, "validate configuration and test upstream servers")
	showVersion := flag.Bool("version", false, "print version and exit")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	store, err := rules.New(cfg)
	if err != nil {
		return err
	}
	if *check {
		return runCheck(cfg, *configPath, os.Stdout, upstream.New(cfg))
	}

	resolvers := upstream.New(cfg)
	var c *cache.Cache
	if cfg.Cache.Enabled {
		c = cache.New(cfg.Cache.MaxSize, cfg.Cache.MinTTL.Duration(), cfg.Cache.MaxTTL.Duration(), cfg.Cache.NegativeTTLDuration())
	}
	var collector *stats.Collector
	if cfg.API.Enabled {
		collector = stats.New()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	watch, err := watcher.New(cfg.RuleFiles(), func() error {
		if err := store.Reload(cfg); err != nil {
			return err
		}
		if c != nil {
			c.Clear()
		}
		return nil
	}, logger)
	if err != nil {
		return err
	}
	go watch.Run(ctx)

	srv := server.New(cfg.DNS.Listen, router.New(cfg, store, c, resolvers), logger, collector)
	var apiSrv *api.Server
	if cfg.API.Enabled {
		apiSrv, err = api.New(cfg.API, collector, c, cfg.Cache.MaxSize)
		if err != nil {
			return err
		}
	}
	logger.Info("starting dnsway",
		"listen", cfg.DNS.Listen,
		"upstreams", len(resolvers),
		"rules", len(cfg.Rules),
		"cache", c != nil,
		"api", cfg.API.Enabled,
	)
	if apiSrv == nil {
		err = srv.Run(ctx)
	} else {
		err = runServices(ctx, srv, apiSrv)
	}
	logger.Info("dnsway stopped")
	return err
}

func runServices(ctx context.Context, dnsSrv *server.Server, apiSrv *api.Server) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error, 2)
	go func() { errs <- dnsSrv.Run(ctx) }()
	go func() { errs <- apiSrv.Run(ctx) }()

	err := <-errs
	cancel()
	<-errs
	return err
}

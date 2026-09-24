package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xylandev/xsync/internal/app"
	"github.com/xylandev/xsync/internal/config"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initCommand(os.Args[2:])
	case "validate-config":
		err = validateCommand(os.Args[2:])
	case "serve":
		err = serveCommand(os.Args[2:])
	case "account":
		err = accountCommand(os.Args[2:])
	case "cert":
		err = certCommand(os.Args[2:])
	case "admin":
		err = adminCommand(os.Args[2:])
	case "catalog":
		err = catalogCommand(os.Args[2:])
	case "volume":
		err = volumeCommand(os.Args[2:])
	case "healthcheck":
		err = healthcheckCommand(os.Args[2:])
	case "version":
		fmt.Printf("xsync-server %s (commit %s, built %s)\n", version, commit, buildDate)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "xsync-server:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: xsync-server <command> [options]

  init              create the configuration, CA, keys and data volume marker
  serve             run the server
  validate-config   check the configuration and accounts
  account           add | list | update | disable | enable | remove | rotate
  cert              renew | info
  admin             reload | tenants | parked | requeue | delete | purge | check | rebuild-indexes
  catalog           check | repair (offline, server stopped)
  volume            adopt (mark an existing data directory)
  healthcheck       probe the local health endpoint
  version`)
}

func healthcheckCommand(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	target := fs.String("url", "http://127.0.0.1:9090/healthz", "health endpoint URL")
	timeout := fs.Duration("timeout", 3*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*target)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	return nil
}

func serveCommand(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	level := fs.String("log-level", "info", "log level: debug, info, warn, error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(*level))); err != nil {
		return fmt.Errorf("invalid --log-level: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	reload := make(chan struct{}, 1)
	go func() {
		for range hup {
			select {
			case reload <- struct{}{}:
			default:
			}
		}
	}()
	return app.RunWithOptions(ctx, cfg, logger, app.Options{Reload: reload, Version: version})
}

func validateCommand(args []string) error {
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	asJSON := fs.Bool("json", false, "print the effective configuration without secrets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	count := len(cfg.Tenants)
	if *asJSON {
		cfg.Tenants = nil
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))
	}
	fmt.Printf("configuration is valid (%d accounts)\n", count)
	return nil
}

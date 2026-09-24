package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/xylandev/xsync/internal/config"
	"github.com/xylandev/xsync/internal/store"
)

// adminCommand talks to the running server's admin API on the metrics
// listener. Operations that change the catalog go through the server because
// only one process can hold the catalog open.
func adminCommand(args []string) error {
	usage := errors.New("usage: xsync-server admin <reload|tenants|parked|requeue|delete|purge|check|rebuild-indexes> [--config] [--tenant] [--id]")
	if len(args) == 0 {
		return usage
	}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	endpoint := fs.String("url", "", "admin endpoint (defaults to the metrics listener)")
	tenant := fs.String("tenant", "", "account ID")
	id := fs.String("id", "", "object ID")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	base := *endpoint
	if base == "" {
		host, port, err := net.SplitHostPort(cfg.Metrics.Listen)
		if err != nil {
			return fmt.Errorf("metrics listener: %w", err)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		base = "http://" + net.JoinHostPort(host, port)
	}
	token, err := os.ReadFile(cfg.AdminTokenPath())
	if err != nil {
		return fmt.Errorf("read admin token: %w", err)
	}
	q := url.Values{}
	if *tenant != "" {
		q.Set("tenant", *tenant)
	}
	need := func(v *string, name string) error {
		if *v == "" {
			return fmt.Errorf("--%s is required", name)
		}
		return nil
	}
	var method, path string
	switch args[0] {
	case "reload":
		method, path = http.MethodPost, "/admin/reload"
	case "tenants":
		method, path = http.MethodGet, "/admin/tenants"
	case "parked":
		if err := need(tenant, "tenant"); err != nil {
			return err
		}
		method, path = http.MethodGet, "/admin/parked"
	case "requeue", "delete":
		if err := errors.Join(need(tenant, "tenant"), need(id, "id")); err != nil {
			return err
		}
		method, path = http.MethodPost, "/admin/objects/"+url.PathEscape(*id)+"/requeue"
		if args[0] == "delete" {
			method, path = http.MethodDelete, "/admin/objects/"+url.PathEscape(*id)
		}
	case "purge":
		if err := need(tenant, "tenant"); err != nil {
			return err
		}
		method, path = http.MethodPost, "/admin/tenants/"+url.PathEscape(*tenant)+"/purge"
	case "check":
		method, path = http.MethodGet, "/admin/check"
	case "rebuild-indexes":
		method, path = http.MethodPost, "/admin/rebuild-indexes"
	default:
		return usage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	target := base + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin API unreachable (is the server running?): %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	if len(raw) > 0 {
		var pretty any
		if json.Unmarshal(raw, &pretty) == nil {
			out, _ := json.MarshalIndent(pretty, "", "  ")
			fmt.Println(string(out))
		} else {
			fmt.Println(string(raw))
		}
	} else {
		fmt.Println("ok")
	}
	return nil
}

// catalogCommand works on the catalog directly while the server is stopped.
func catalogCommand(args []string) error {
	if len(args) == 0 || (args[0] != "check" && args[0] != "repair") {
		return errors.New("usage: xsync-server catalog <check|repair> --config <file> (server must be stopped)")
	}
	fs := flag.NewFlagSet("catalog "+args[0], flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir, nil, nil)
	if err != nil {
		return fmt.Errorf("open catalog (stop the server first): %w", err)
	}
	defer st.Close()
	if args[0] == "repair" {
		if err := st.RebuildIndexes(); err != nil {
			return err
		}
		if err := st.Reconcile(context.Background(), time.Hour); err != nil {
			return err
		}
		fmt.Println("indexes rebuilt and orphaned files removed")
	}
	problems, err := st.Check()
	if err != nil {
		return err
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d problems found", len(problems))
	}
	fmt.Println("catalog is consistent")
	return nil
}

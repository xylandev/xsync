package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xylandev/xsync/internal/bundle"
	"github.com/xylandev/xsync/internal/config"
)

func accountCommand(args []string) error {
	usageErr := errors.New("usage: xsync-server account <add|list|update|disable|enable|remove|rotate> [options]")
	if len(args) == 0 {
		return usageErr
	}
	switch args[0] {
	case "add":
		return accountAddCommand(args[1:])
	case "list":
		return accountListCommand(args[1:])
	case "update":
		return accountUpdateCommand(args[1:])
	case "disable":
		return accountSetDisabled(args[1:], true)
	case "enable":
		return accountSetDisabled(args[1:], false)
	case "remove":
		return accountRemoveCommand(args[1:])
	case "rotate":
		return accountRotateCommand(args[1:])
	}
	return usageErr
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// policyFlags are the per-account settings shared by add and update.
type policyFlags struct {
	fs             *flag.FlagSet
	weight         *int
	maxConcurrent  *int
	maxUploadBPS   *int64
	maxStoredBytes *int64
	allowPlainFTP  *bool
	overwrite      *string
	noHold         *bool
	holdPatterns   multiFlag
	publishDelay   *time.Duration
	maxAttempts    *int
}

func addPolicyFlags(fs *flag.FlagSet) *policyFlags {
	p := &policyFlags{fs: fs}
	p.weight = fs.Int("weight", 1, "upload fairness weight")
	p.maxConcurrent = fs.Int("max-concurrent", 8, "maximum concurrent uploads")
	p.maxUploadBPS = fs.Int64("max-upload-bps", 0, "per-account upload limit in bytes/s; 0 is unlimited")
	p.maxStoredBytes = fs.Int64("max-stored-bytes", 0, "per-account storage quota in bytes; 0 is unlimited")
	p.allowPlainFTP = fs.Bool("allow-plain-ftp", false, "allow unencrypted FTP for this account")
	p.overwrite = fs.String("overwrite", "", "re-uploaded paths: supersede (drop undelivered old versions, default) or keep (deliver every version)")
	p.noHold = fs.Bool("no-hold", false, "deliver files under temporary names (*.filepart, *.partial, *.tmp) instead of waiting for the rename")
	fs.Var(&p.holdPatterns, "hold-pattern", "temporary-name glob held back until renamed (repeatable; replaces the defaults)")
	p.publishDelay = fs.Duration("publish-delay", 0, "quiet period before a finished upload becomes deliverable")
	p.maxAttempts = fs.Int("max-attempts", 0, "deliveries before an object is parked; 0 uses the server default")
	return p
}

// apply copies the flags that were set on the command line onto t. With all
// set, every flag applies, as for a new account.
func (p *policyFlags) apply(t *config.Tenant, all bool) {
	set := map[string]bool{}
	p.fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	is := func(name string) bool { return all || set[name] }
	if is("weight") {
		t.Weight = *p.weight
	}
	if is("max-concurrent") {
		t.MaxConcurrent = *p.maxConcurrent
	}
	if is("max-upload-bps") {
		t.MaxUploadBPS = *p.maxUploadBPS
	}
	if is("max-stored-bytes") {
		t.MaxStoredBytes = *p.maxStoredBytes
	}
	if is("allow-plain-ftp") {
		t.AllowPlainFTP = *p.allowPlainFTP
	}
	if is("overwrite") {
		t.Overwrite = *p.overwrite
	}
	if is("no-hold") {
		t.NoHold = *p.noHold
	}
	if set["hold-pattern"] {
		t.HoldPatterns = append([]string(nil), p.holdPatterns...)
	}
	if is("publish-delay") {
		t.PublishDelay = *p.publishDelay
	}
	if is("max-attempts") {
		t.MaxAttempts = *p.maxAttempts
	}
}

const applyNote = "the running server applies account changes within 5 seconds; no restart is needed"

func accountAddCommand(args []string) error {
	fs := flag.NewFlagSet("account add", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	id := fs.String("id", "", "account ID and protocol username")
	s3Bucket := fs.String("s3-bucket", "", "S3 bucket name (defaults to account ID)")
	output := fs.String("client-config", "", "connection bundle output (defaults beside config.yaml; '-' prints it)")
	policy := addPolicyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("--id is required")
	}
	if !config.ValidTenantID(*id) {
		return fmt.Errorf("invalid account ID %q; use letters, digits, '.', '_' or '-'", *id)
	}
	bucket := *s3Bucket
	if bucket == "" {
		bucket = *id
	}
	if !validS3Bucket(bucket) {
		return fmt.Errorf("invalid S3 bucket %q; use 3-63 lowercase letters, digits, dots or hyphens", bucket)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	tenant := config.Tenant{ID: *id, SFTPUser: *id, FTPUser: *id, S3Bucket: bucket}
	policy.apply(&tenant, true)
	creds, err := issueCredentials(&tenant)
	if err != nil {
		return err
	}
	doc, err := bundle.New(cfg, tenant, creds)
	if err != nil {
		return err
	}
	bundlePath := *output
	if bundlePath == "" {
		bundlePath = bundle.DefaultPath(*configPath, tenant.ID)
	}
	if bundlePath != "-" {
		if err = bundle.Write(bundlePath, doc, false); err != nil {
			return err
		}
	}
	if err = config.AddTenant(*configPath, tenant); err != nil {
		if bundlePath != "-" {
			_ = os.Remove(bundlePath)
		}
		return err
	}
	return deliverBundle(*configPath, tenant.ID, bundlePath, doc)
}

func deliverBundle(configPath, id, bundlePath string, doc bundle.Document) error {
	if bundlePath == "-" {
		raw, err := bundle.Marshal(doc)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(raw)
		fmt.Fprintln(os.Stderr, applyNote)
		return err
	}
	fmt.Printf("config: %s\naccount: %s\nclient connection bundle: %s\n", configPath, id, bundlePath)
	fmt.Println("the bundle holds the account's secrets, which the server does not keep in readable form;")
	fmt.Println("hand it over securely, then delete it from this host")
	fmt.Println(applyNote)
	return nil
}

// issueCredentials generates fresh secrets for t. The account keeps only
// hashes (and the encrypted S3 secret); the plaintext goes into the bundle.
func issueCredentials(t *config.Tenant) (bundle.Secrets, error) {
	var s bundle.Secrets
	var err error
	if s.APIKey, err = secret(32); err != nil {
		return s, err
	}
	if s.SFTPPassword, err = secret(20); err != nil {
		return s, err
	}
	if s.FTPPassword, err = secret(20); err != nil {
		return s, err
	}
	if s.S3Secret, err = secret(32); err != nil {
		return s, err
	}
	access, err := secret(10)
	if err != nil {
		return s, err
	}
	sum := sha256.Sum256([]byte(s.APIKey))
	t.APIKeySHA256 = hex.EncodeToString(sum[:])
	if t.SFTPPasswordHash, err = config.HashSecret(s.SFTPPassword); err != nil {
		return s, err
	}
	if t.FTPPasswordHash, err = config.HashSecret(s.FTPPassword); err != nil {
		return s, err
	}
	t.SFTPPassword, t.FTPPassword = "", ""
	t.S3AccessKey, t.S3SecretKey = strings.ToUpper(access), s.S3Secret
	return s, nil
}

func secret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validS3Bucket(name string) bool {
	if len(name) < 3 || len(name) > 63 || strings.Contains(name, "..") || net.ParseIP(name) != nil {
		return false
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r == '-' && i > 0 && i < len(name)-1) || (r == '.' && i > 0 && i < len(name)-1) {
			continue
		}
		return false
	}
	return true
}

func accountListCommand(args []string) error {
	fs := flag.NewFlagSet("account list", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTATUS\tBUCKET\tWEIGHT\tCONCURRENT\tUPLOAD_BPS\tQUOTA\tOVERWRITE\tPLAIN_FTP")
	for _, t := range cfg.Tenants {
		status := "enabled"
		if t.Disabled {
			status = "disabled"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%v\n", t.ID, status, t.S3Bucket, t.Weight, t.MaxConcurrent, t.MaxUploadBPS, t.MaxStoredBytes, t.EffectiveOverwrite(), t.AllowPlainFTP)
	}
	return w.Flush()
}

func accountFlags(name string, args []string, extra func(*flag.FlagSet)) (string, string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", "/etc/xsync/config.yaml", "configuration file")
	id := fs.String("id", "", "account ID")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return "", "", err
	}
	if *id == "" {
		return "", "", errors.New("--id is required")
	}
	return *configPath, *id, nil
}

// modifyAccount applies fn to one account under the accounts lock.
func modifyAccount(configPath, id string, fn func(*config.Tenant) error) error {
	found := false
	err := config.UpdateAccounts(configPath, func(ts []config.Tenant) ([]config.Tenant, error) {
		for i := range ts {
			if ts[i].ID == id {
				found = true
				if err := fn(&ts[i]); err != nil {
					return nil, err
				}
			}
		}
		return ts, nil
	})
	if err == nil && !found {
		return fmt.Errorf("account %q not found", id)
	}
	return err
}

func accountUpdateCommand(args []string) error {
	var policy *policyFlags
	configPath, id, err := accountFlags("account update", args, func(fs *flag.FlagSet) { policy = addPolicyFlags(fs) })
	if err != nil {
		return err
	}
	if err := modifyAccount(configPath, id, func(t *config.Tenant) error { policy.apply(t, false); return nil }); err != nil {
		return err
	}
	fmt.Println("account updated;", applyNote)
	return nil
}

func accountSetDisabled(args []string, disabled bool) error {
	configPath, id, err := accountFlags("account", args, nil)
	if err != nil {
		return err
	}
	if err := modifyAccount(configPath, id, func(t *config.Tenant) error { t.Disabled = disabled; return nil }); err != nil {
		return err
	}
	state := "enabled"
	if disabled {
		state = "disabled: every protocol now refuses its credentials; stored data is kept"
	}
	fmt.Printf("account %s %s\n%s\n", id, state, applyNote)
	return nil
}

func accountRemoveCommand(args []string) error {
	configPath, id, err := accountFlags("account remove", args, nil)
	if err != nil {
		return err
	}
	removed := false
	if err := config.UpdateAccounts(configPath, func(ts []config.Tenant) ([]config.Tenant, error) {
		out := ts[:0]
		for _, t := range ts {
			if t.ID == id {
				removed = true
				continue
			}
			out = append(out, t)
		}
		return out, nil
	}); err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("account %q not found", id)
	}
	fmt.Printf("account %s removed; %s\n", id, applyNote)
	fmt.Printf("its stored objects remain until you run: xsync-server admin purge --tenant %s\n", id)
	return nil
}

// accountRotateCommand replaces every credential of an account and writes a
// new connection bundle, which also carries the current CA.
func accountRotateCommand(args []string) error {
	var output *string
	configPath, id, err := accountFlags("account rotate", args, func(fs *flag.FlagSet) {
		output = fs.String("client-config", "", "connection bundle output (defaults beside config.yaml; '-' prints it)")
	})
	if err != nil {
		return err
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	var rotated config.Tenant
	var creds bundle.Secrets
	if err := modifyAccount(configPath, id, func(t *config.Tenant) error {
		c, err := issueCredentials(t)
		creds, rotated = c, *t
		return err
	}); err != nil {
		return err
	}
	doc, err := bundle.New(cfg, rotated, creds)
	if err != nil {
		return err
	}
	bundlePath := *output
	if bundlePath == "" {
		bundlePath = bundle.DefaultPath(configPath, id)
	}
	if bundlePath != "-" {
		if err := bundle.Write(bundlePath, doc, true); err != nil {
			return fmt.Errorf("credentials were rotated but the bundle could not be written (rotate again): %w", err)
		}
	}
	fmt.Println("all credentials replaced; the old ones stop working when the server reloads")
	return deliverBundle(configPath, id, bundlePath, doc)
}

// ==============================================================================
// File name:     backup_cmd.go
// Description:   The "backup" subcommand: archive device configurations.
// License:       MIT
// ==============================================================================
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"netops/internal/backup"
	"netops/internal/compliance"
	"netops/internal/credentials"
	"netops/internal/inventory"
	"netops/internal/logging"
	"netops/internal/memory"
	"netops/internal/notifier"
	"netops/internal/report"
	"netops/internal/sshclient"
	"netops/internal/task"
	"netops/internal/vendor"
)

const backupUsageText = `netops backup: archive device configurations, detect changes and report drift.

Usage:
  netops backup [flags]                       back up the devices in the inventory
  netops backup show [flags] [node-name]      view or locate the newest saved backup
                                                 (see: netops backup show -h)
  netops backup redact [flags] <file-or-dir>  mask secrets in saved backup files or directories
                                                 (see: netops backup redact -h)

Each device's configuration is saved as <backup-dir>/<run>/<platform>/<host>.<ext>.
A device whose configuration is unchanged since its last backup is not written
again (volatile lines such as clock stamps are ignored when comparing). By default,
configurations are saved unredacted so they can be restored. Pass -redact to mask
passwords and secrets with <REDACTED>.

Credentials come from -env-file or the environment (NETOPS_USERNAME and
NETOPS_PASSWORD, or per credential group).

Exit status: 0 every device succeeded, 1 usage or configuration error,
2 at least one device failed.

Platforms: %s
`

// newBackupTransport builds the session opener for a backup run. Tests replace
// it to run the whole command without a network.
var newBackupTransport = func(hostKey sshclient.HostKeyCallback, legacy bool, pool *jumpPool, autoFallback []task.Target, tcpMSS int) task.Transport {
	return sshTransport{hostKey: hostKey, legacy: legacy, pool: pool, autoFallback: autoFallback, tcpMSS: tcpMSS}
}

// backupOpts holds the command line of "netops backup": the flags every
// connecting command shares, plus those specific to backups.
type backupOpts struct {
	commonFlags

	backupDir string
	logFormat string

	retries                       int
	retryDelay, dialJitter        time.Duration
	retentionCount                int
	retentionDays                 int
	redact, saveUnchanged, dryRun bool
	diff, ignoreVolatile          bool
	keepBanners                   bool
	resultTable                   bool
	insecureHostKey               bool
	verbose                       bool
	volatilePatterns              string
	goldenDir                     string
	complianceRules               string
	htmlReport, mdReport          string
	jsonReport, csvReport         string
}

// backupFlagGroups organises the help. Every flag of the command must appear in
// one of them (a test enforces it, and anything missed is still listed under
// "Other flags").
var backupFlagGroups = []flagGroup{
	{"Devices", []string{"inventory", "limit", "concurrency", "dry-run"}},
	{"Backups", []string{"backup-dir", "retention-count", "retention-days", "redact", "save-unchanged", "ignore-volatile", "volatile-patterns", "diff", "keep-banners"}},
	{"Reports and compliance", []string{"golden-dir", "compliance-rules", "result-table", "html-report", "md-changelog", "json-report", "csv-report"}},
	{"Connection", []string{"connect-timeout", "command-timeout", "retries", "retry-delay", "dial-jitter", "env-file", "key-file", "host-key-policy", "update-known-hosts", "known-hosts", "insecure-ignore-host-key", "legacy-algorithms", "tcp-mss"}},
	{"Jump hosts and routing", []string{"jump", "jump-host", "jump-user", "jump-key-file", "mesh-fallback", "memory", "memory-file"}},
	{"Logging", []string{"log-dir", "log-format", "no-color", "verbose"}},
}

// newBackupFlagSet declares the flags for netops backup.
func newBackupFlagSet(o *backupOpts, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("netops backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, backupUsageText, strings.Join(vendor.Names(), ", "))
		printFlagGroups(stderr, fs, backupFlagGroups)
	}
	o.register(fs)

	fs.StringVar(&o.backupDir, "backup-dir", "backups", "directory to write backup files into")
	fs.IntVar(&o.retentionCount, "retention-count", 10, "maximum number of recent backups to keep per device (0 to disable)")
	fs.IntVar(&o.retentionDays, "retention-days", 0, "prune backups older than N days per device (0 to disable)")
	fs.BoolVar(&o.redact, "redact", false, "mask passwords, pre-shared keys, and SNMP communities in saved files")
	fs.BoolVar(&o.saveUnchanged, "save-unchanged", false, "save a new backup file even if the configuration is identical to the previous backup")
	fs.BoolVar(&o.ignoreVolatile, "ignore-volatile", true, "ignore volatile lines (clock stamps, \"last changed\" comments, ...) when detecting changes; saved files are never modified")
	fs.StringVar(&o.volatilePatterns, "volatile-patterns", "", "optional file with extra volatile-line regular expressions, one per line (# starts a comment)")
	fs.BoolVar(&o.diff, "diff", true, "display a colorized diff against the previous backup when the configuration changes")
	fs.BoolVar(&o.keepBanners, "keep-banners", false, "preserve leading terminal banners (e.g. 'Building configuration...') in saved backups")
	fs.StringVar(&o.goldenDir, "golden-dir", "", "directory of <vendor>.golden baseline files (plus optional common.golden); enables golden-config drift checks")
	fs.StringVar(&o.complianceRules, "compliance-rules", "", "single compliance rules file with optional [vendor] sections; can be combined with -golden-dir")
	fs.StringVar(&o.htmlReport, "html-report", "", "write a standalone HTML run report to this path ({run}, {timestamp} and {date} are expanded)")
	fs.StringVar(&o.mdReport, "md-changelog", "", "write/update a Markdown changelog at this path, newest run first ({run}, {timestamp} and {date} are expanded)")
	fs.StringVar(&o.jsonReport, "json-report", "", "write a machine-readable JSON run report to this path ({run}, {timestamp} and {date} are expanded)")
	fs.StringVar(&o.csvReport, "csv-report", "", "write a machine-readable CSV run report to this path ({run}, {timestamp} and {date} are expanded)")
	fs.BoolVar(&o.resultTable, "result-table", true, "print a per-device result table to stdout after the run")
	fs.BoolVar(&o.dryRun, "dry-run", false, "test connection, login and paging setup without pulling or saving configuration")

	fs.IntVar(&o.retries, "retries", 0, "retry attempts per device after a connection failure (never after a rejected login)")
	fs.DurationVar(&o.retryDelay, "retry-delay", 2*time.Second, "delay between retries per device")
	fs.DurationVar(&o.dialJitter, "dial-jitter", 100*time.Millisecond, "random delay up to this value before each connection (0 to disable)")

	fs.BoolVar(&o.insecureHostKey, "insecure-ignore-host-key", false, "DANGEROUS: skip host key verification entirely (exposes connections to MITM)")

	fs.StringVar(&o.logFormat, "log-format", "text", "log format: only 'text' is supported (use -json-report for machine-readable results)")
	fs.BoolVar(&o.verbose, "verbose", false, "log the connection and login steps for each device")
	return fs
}

// runBackup is "netops backup".
func runBackup(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	// "backup show" and "backup redact" are subcommands of backup. Only the first argument
	// selects them, so a flag value that happens to match (-limit show) does not.
	if len(args) > 0 {
		switch args[0] {
		case "show":
			return runBackupShow(args[1:], stdin, stdout, stderr)
		case "redact":
			return runBackupRedact(args[1:], stdin, stdout, stderr)
		}
	}

	var o backupOpts
	fs := newBackupFlagSet(&o, stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return task.ExitOK
		}
		hintPasswordFlag(args, stderr)
		return task.ExitFatal
	}
	fatal := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "netops backup: "+format+"\n", a...)
		return task.ExitFatal
	}
	if fs.NArg() > 0 {
		return fatal("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if o.concurrency < 1 {
		return fatal("-concurrency must be at least 1")
	}
	if o.connectTimeout <= 0 || o.commandTimeout <= 0 {
		return fatal("-connect-timeout and -command-timeout must be positive")
	}
	if o.retries < 0 || o.retentionCount < 0 || o.retentionDays < 0 || o.dialJitter < 0 || o.retryDelay < 0 {
		return fatal("-retries, -retry-delay, -dial-jitter, -retention-count and -retention-days must not be negative")
	}
	if o.logFormat != "text" {
		return fatal("-log-format %q is not supported (only 'text'); use -json-report for machine-readable results", o.logFormat)
	}
	if o.updateKnownHosts {
		o.hostKeyPolicy = "update"
	}
	if o.insecureHostKey {
		o.hostKeyPolicy = string(sshclient.PolicyInsecure)
	}
	policy, err := sshclient.ParsePolicy(o.hostKeyPolicy)
	if err != nil {
		return fatal("%v", err)
	}

	color := !o.noColor && os.Getenv("NO_COLOR") == "" && isTerminalWriter(stderr)
	log, err := logging.New(logging.Options{Dir: o.logDir, Console: stderr, Color: color, Verbose: o.verbose})
	if err != nil {
		return fatal("%v", err)
	}
	defer log.Close()
	die := func(format string, a ...any) int {
		log.Errorf("", format, a...)
		return task.ExitFatal
	}
	log.Infof("", "netops %s backup starting; audit log: %s", version, log.Path())

	// ---- inputs ----------------------------------------------------------
	allDevs, err := inventory.Load(o.inventory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
			fmt.Fprintf(stderr, "\nTip: Run 'netops init' to create sample inventory.csv, commands.txt, and .env templates.\n\n")
		}
		return die("%v", err)
	}
	devs, err := inventory.Filter(allDevs, strings.Split(o.limit, ","))
	if err != nil {
		return die("%v", err)
	}

	// ---- credentials -----------------------------------------------------
	overrides := make(map[string]string)
	for name, val := range map[string]string{
		"NETOPS_KEY_FILE":      o.keyFile,
		"NETOPS_JUMP_USERNAME": o.jumpUser,
		"NETOPS_JUMP_KEY_FILE": o.jumpKeyFile,
		"NETOPS_JUMP_HOST":     o.jumpHost,
	} {
		if val != "" {
			overrides[name] = val
		}
	}
	dot, err := credentials.LoadDotEnv(o.envFile)
	if err != nil {
		return die("%v", err)
	}
	for _, w := range dot.Warnings {
		log.Warnf("", "%s", w)
	}
	resolver := &credentials.Resolver{DotEnv: dot.Values, LookupEnv: os.LookupEnv, Overrides: overrides}
	if credentials.IsTerminal(stdin) {
		resolver.Prompter = &credentials.TerminalPrompter{In: stdin, Out: stderr}
	}

	creds := make(map[string]credentials.Credential)
	credErrs := make(map[string]error)
	for _, d := range devs {
		if _, done := creds[d.Group]; done || credErrs[d.Group] != nil {
			continue
		}
		c, err := resolver.Resolve(d.Group)
		if err != nil {
			credErrs[d.Group] = err
			continue
		}
		log.AddSecret(c.Password)
		log.AddSecret(c.EnablePassword)
		creds[d.Group] = c
	}
	globalJump := resolver.JumpDefaults()
	jumps := make(map[string]credentials.JumpCredentials)
	if o.jump {
		for _, d := range devs {
			jc := jumpFor(resolver, d, o.jumpHost, globalJump)
			if jc.Password != "" {
				log.AddSecret(jc.Password)
			}
			jumps[deviceKey(d)] = jc
		}
		if o.jumpHost != "" {
			log.Infof("", "global jump host configured: %s (per-device overrides via the inventory jump_host column; disable with -jump=false)", o.jumpHost)
		} else if globalJump.Host != "" {
			log.Infof("", "global jump host configured via env: %s (per-device overrides via the inventory jump_host column; disable with -jump=false)", globalJump.Host)
		}
	} else {
		log.Infof("", "jump host routing disabled via -jump=false: all devices are connected directly")
	}

	// ---- transport -------------------------------------------------------
	knownHosts := o.knownHosts
	if knownHosts == "" {
		knownHosts = sshclient.DefaultKnownHostsFile()
	}
	hostKey, err := sshclient.NewHostKeyCallback(knownHosts, policy)
	if err != nil {
		return die("%v", err)
	}
	if policy == sshclient.PolicyInsecure {
		log.Warnf("", "host key verification is DISABLED (-host-key-policy insecure)")
	}
	var memStore *memory.Store
	if o.memory {
		memStore, err = memory.Load(o.memoryFile)
		if err != nil {
			log.Warnf("", "failed to load route memory %s: %v", o.memoryFile, err)
		} else if n := len(memStore.List()); n > 0 {
			log.Infof("", "loaded %d learned route(s) from persistent memory (%s)", n, o.memoryFile)
		}
	}
	var pool *jumpPool
	if o.jump {
		pool = newJumpPool(hostKey, o.legacyAlgorithms, memStore)
		defer pool.closeAll()
	}
	var autoFallback []task.Target
	if o.jump && o.meshFallback {
		for _, d := range allDevs {
			if d.Endpoint() == "" {
				continue
			}
			cred, ok := creds[d.Group]
			if !ok {
				if cred, err = resolver.Resolve(d.Group); err != nil {
					continue
				}
			}
			prof, _ := vendor.Lookup(d.Vendor)
			autoFallback = append(autoFallback, task.Target{
				Device: d, Profile: prof, Cred: cred,
				ConnectTimeout: o.connectTimeout, LoginTimeout: o.commandTimeout, TCPMSS: o.tcpMSS,
			})
		}
	}

	// ---- configuration ---------------------------------------------------
	console := backup.Console{Log: log}
	cfg := backup.Config{
		Transport: newBackupTransport(hostKey, o.legacyAlgorithms, pool, autoFallback, o.tcpMSS),
		Target: func(dev inventory.Device, _ *vendor.Profile) (task.Target, error) {
			if err := credErrs[dev.Group]; err != nil {
				return task.Target{}, &credentialError{group: dev.Group, err: err}
			}
			return task.Target{Cred: creds[dev.Group], JumpCred: jumps[deviceKey(dev)], TCPMSS: o.tcpMSS}, nil
		},
		Logf:                func(host, format string, args ...any) { log.Tracef(host, format, args...) },
		OutputDir:           o.backupDir,
		RunName:             backup.DefaultRunName(time.Now()),
		Concurrency:         o.concurrency,
		Redact:              o.redact,
		RetentionCount:      o.retentionCount,
		RetentionDays:       o.retentionDays,
		SaveUnchanged:       o.saveUnchanged,
		Retries:             o.retries,
		RetryDelay:          o.retryDelay,
		DialJitter:          o.dialJitter,
		ConnectTimeout:      o.connectTimeout,
		CommandTimeout:      o.commandTimeout,
		DryRun:              o.dryRun,
		ShowDiff:            o.diff,
		IgnoreVolatile:      o.ignoreVolatile,
		KeepTerminalBanners: o.keepBanners,
		OnProgress:          console.Progress,
	}
	configureSemanticDiff(log, &cfg, o)
	configureCompliance(log, &cfg, o)
	if o.diff {
		cfg.OnDiff = func(dev inventory.Device, lines []string, added, removed int) {
			log.Infof("", "[%s] configuration changes detected (+%d/-%d):", dev.Hostname, added, removed)
			console.DiffLines(dev.Hostname, "  ", lines)
		}
	}

	if cfg.DryRun {
		log.Infof("", "starting dry-run test: %d device(s), concurrency=%d", len(devs), cfg.Concurrency)
	} else {
		log.Infof("", "starting backup run: %d device(s), concurrency=%d, redact=%t, retention-count=%d, retention-days=%d",
			len(devs), cfg.Concurrency, cfg.Redact, cfg.RetentionCount, cfg.RetentionDays)
	}

	// ---- run -------------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			log.Warnf("", "interrupt received: no new devices will be started; sessions in progress are being closed (press Ctrl-C again to force quit)")
			stop()
		case <-finished:
		}
	}()
	runStart := time.Now()
	results := backup.RunAll(ctx, devs, cfg)
	total := time.Since(runStart)
	close(finished)

	failures := console.Summary(results, total)
	rows := report.FromResults(results)
	if o.resultTable {
		report.FprintSummaryTable(stdout, stderr, rows, color && isTerminalWriter(stdout), total)
	}
	writeBackupReports(log, o, cfg.RunName, rows)

	// Send Telegram notification if configured
	tg := notifier.NewTelegram(notifier.ConfigFromResolver(resolver))
	if tg != nil {
		defer tg.Close()
		var succ, fail, changed, unchanged, drifted int
		var failDetails []string
		for _, r := range results {
			if r.Success {
				succ++
				if r.HasDiff {
					changed++
				} else if r.Unchanged {
					unchanged++
				}
				if r.Compliance.Checked && len(r.Compliance.Drifts) > 0 {
					drifted++
				}
			} else {
				fail++
				errStr := "failed"
				if r.Err != nil {
					errStr = r.Err.Error()
				}
				failDetails = append(failDetails, fmt.Sprintf("%s: %s", r.Device.Hostname, errStr))
			}
		}
		tg.SendBackupSummary(notifier.BackupSummaryMetrics{
			TotalDevices: len(results),
			Succeeded:    succ,
			Failed:       fail,
			Changed:      changed,
			Unchanged:    unchanged,
			Drifted:      drifted,
			Duration:     total,
			DryRun:       o.dryRun,
			Failures:     failDetails,
		})
	}

	if failures > 0 {
		return task.ExitPartial
	}
	return task.ExitOK
}

// deviceKey identifies a device in the per-device maps built before the run.
func deviceKey(d inventory.Device) string { return d.Hostname + "\x00" + d.Address }

// credentialError is a missing or unusable credential. It is an "auth" kind
// failure: it classifies as AUTHENTICATION_FAILED and is never retried.
type credentialError struct {
	group string
	err   error
}

func (e *credentialError) Error() string {
	return fmt.Sprintf("credentials for group %q: %v", e.group, e.err)
}
func (e *credentialError) Unwrap() error     { return e.err }
func (e *credentialError) ErrorKind() string { return "auth" }

// jumpFor picks the bastion for a device: its inventory jump_host, else the
// -jump-host flag, else the global default from the environment.
// Values recognized by credentials.IsDirect ("direct", "none", "-", etc.)
// explicitly bypass any jump host, forcing a direct connection.
func jumpFor(r *credentials.Resolver, d inventory.Device, flagHost string, global credentials.JumpCredentials) credentials.JumpCredentials {
	switch {
	case credentials.IsDirect(d.JumpHost):
		return credentials.JumpCredentials{}
	case d.JumpHost != "":
		jc := r.ForJumpHost(d.JumpHost)
		if jc.Host == "" || strings.Contains(d.JumpHost, ":") {
			jc.Host = d.JumpHost // the inventory value is itself a host[:port]
		}
		return jc
	case flagHost != "":
		jc := r.ForJumpHost("")
		jc.Host = flagHost
		return jc
	default:
		return global
	}
}

// configureSemanticDiff wires the volatile-line filter into the backup
// config. A bad pattern or an unreadable patterns file only costs the extra
// patterns; the built-in rules always stay active.
func configureSemanticDiff(log *logging.Logger, cfg *backup.Config, o backupOpts) {
	if !o.ignoreVolatile {
		log.Infof("", "semantic diff disabled (-ignore-volatile=false): volatile lines such as timestamps count as changes")
		return
	}
	var extra []string
	if o.volatilePatterns != "" {
		patterns, err := backup.LoadVolatilePatterns(o.volatilePatterns)
		if err != nil {
			log.Warnf("", "volatile patterns: %v -- continuing with the built-in rules only", err)
		} else {
			extra = patterns
		}
	}
	filter, errs := backup.NewVolatileFilter(extra)
	for _, err := range errs {
		log.Warnf("", "%v -- pattern ignored", err)
	}
	cfg.VolatileFilter = filter
	log.Infof("", "semantic diff: ignoring volatile lines (%d rule(s) active)", filter.Len())
}

// configureCompliance loads the golden baselines when requested. Problems are
// warnings, never fatal: an unreadable baseline must not stop the nightly
// backups, it only turns drift checking off.
func configureCompliance(log *logging.Logger, cfg *backup.Config, o backupOpts) {
	if o.goldenDir == "" && o.complianceRules == "" {
		return
	}
	baseline, errs := compliance.Load(o.goldenDir, o.complianceRules)
	for _, err := range errs {
		log.Warnf("", "compliance: %v", err)
	}
	if baseline == nil {
		log.Warnf("", "compliance checking disabled: no usable baseline rules were loaded")
		return
	}
	cfg.Baseline = baseline
	log.Infof("", "compliance: checking devices against %d golden baseline rule(s)", baseline.Len())
}

// writeBackupReports produces the optional HTML, Markdown, JSON and CSV
// reports. They never abort a finished run: a failure is logged as a warning
// and the exit code is unaffected.
func writeBackupReports(log *logging.Logger, o backupOpts, runName string, rows []report.BackupResult) {
	info := report.RunInfo{RunName: runName, GeneratedAt: time.Now()}
	emit := func(kind, template string, write func(path string) ([]string, error)) {
		if template == "" {
			return
		}
		path := report.ExpandPath(template, info)
		defer func() {
			if r := recover(); r != nil {
				log.Warnf("", "%s report generation failed: %v", kind, r)
			}
		}()
		warnings, err := write(path)
		for _, w := range warnings {
			log.Warnf("", "%s", w)
		}
		if err != nil {
			log.Warnf("", "%s report not written to %s: %v", kind, path, err)
			return
		}
		log.Infof("", "%s report written to %s", kind, path)
	}
	emit("HTML", o.htmlReport, func(p string) ([]string, error) { return report.WriteHTML(p, info, rows) })
	emit("Markdown", o.mdReport, func(p string) ([]string, error) { return report.WriteMarkdown(p, info, rows) })
	emit("JSON", o.jsonReport, func(p string) ([]string, error) {
		return report.WriteJSON(p, info, report.FromResultsToAudit(rows))
	})
	emit("CSV", o.csvReport, func(p string) ([]string, error) {
		return report.WriteCSV(p, info, report.FromResultsToAudit(rows))
	})
}

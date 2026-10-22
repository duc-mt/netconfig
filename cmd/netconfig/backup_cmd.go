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

	"netconfig/internal/backup"
	"netconfig/internal/compliance"
	"netconfig/internal/credentials"
	"netconfig/internal/inventory"
	"netconfig/internal/logging"
	"netconfig/internal/memory"
	"netconfig/internal/report"
	"netconfig/internal/sshclient"
	"netconfig/internal/task"
	"netconfig/internal/vendor"
)

const backupUsageText = `netconfig backup: archive device configurations, detect changes and report drift.

Usage:
  netconfig backup [flags]

Each device's configuration is saved as <backup-dir>/<run>/<platform>/<host>.<ext>.
A device whose configuration is unchanged since its last backup is not written
again (volatile lines such as clock stamps are ignored when comparing), and
secrets are masked in the saved files unless -redact=false.

Exit status: 0 every device succeeded, 1 usage or configuration error,
2 at least one device failed.

Platforms: %s

Flags:
`

// newBackupTransport builds the session opener for a backup run. Tests replace
// it to run the whole command without a network.
var newBackupTransport = func(hostKey sshclient.HostKeyCallback, legacy bool, pool *jumpPool, autoFallback []task.Target, tcpMSS int) task.Transport {
	return sshTransport{hostKey: hostKey, legacy: legacy, pool: pool, autoFallback: autoFallback, tcpMSS: tcpMSS}
}

// backupOpts holds the command line of "netconfig backup".
type backupOpts struct {
	inventory, backupDir, logDir, logFormat, envFile, keyFile string
	limit                                                     string
	retries                                                   int
	retryDelay, dialJitter                                    time.Duration
	concurrency                                               int
	connectTimeout, commandTimeout                            time.Duration
	redact, force, dryRun, diff, ignoreVolatile               bool
	retentionCount, retentionDays                             int
	knownHosts, hostKeyPolicy                                 string
	updateKnownHosts, insecureHostKey                         bool
	legacyAlgorithms, resultTable                             bool
	volatilePatterns, goldenDir, complianceRules              string
	htmlReport, mdReport, jsonReport, csvReport               string
	jump                                                      bool
	jumpHost, jumpUser, jumpPassword, jumpKeyFile             string
	tcpMSS                                                    int
	memory                                                    bool
	memoryFile                                                string
	meshFallback, noColor, verbose                            bool
}

// newBackupFlagSet declares the flags. The names follow the task's
// specification; netbackup's own spellings (-out, -md-report, -save-unchanged,
// -known-hosts-policy, -show-diff, ...) stay accepted so existing scripts keep
// working.
func newBackupFlagSet(o *backupOpts, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("netconfig backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, backupUsageText, strings.Join(vendor.Names(), ", "))
		fs.PrintDefaults()
	}

	fs.StringVar(&o.inventory, "inventory", "inventory.csv", "inventory CSV: hostname,address,port,vendor,credential_group")
	fs.StringVar(&o.limit, "limit", "", "only these devices: comma-separated hostname globs, or @group")
	fs.StringVar(&o.backupDir, "backup-dir", "backups", "directory to write backup files into")
	fs.StringVar(&o.backupDir, "out", "backups", "alias for -backup-dir")
	fs.IntVar(&o.retentionCount, "retention-count", 10, "maximum number of recent backups to keep per device (0 to disable)")
	fs.IntVar(&o.retentionDays, "retention-days", 0, "prune backups older than N days per device (0 to disable)")
	fs.BoolVar(&o.redact, "redact", true, "mask passwords, pre-shared keys, and SNMP communities in saved files")
	fs.BoolVar(&o.force, "force", false, "save a new backup file even if the configuration is identical to the previous backup")
	fs.BoolVar(&o.force, "save-unchanged", false, "alias for -force")
	fs.BoolVar(&o.ignoreVolatile, "ignore-volatile", true, "ignore volatile lines (clock stamps, \"last changed\" comments, ...) when detecting changes; saved files are never modified")
	fs.StringVar(&o.volatilePatterns, "volatile-patterns", "", "optional file with extra volatile-line regular expressions, one per line (# starts a comment)")
	fs.BoolVar(&o.diff, "diff", true, "display a colorized diff against the previous backup when the configuration changes")
	fs.BoolVar(&o.diff, "show-diff", true, "alias for -diff")
	fs.StringVar(&o.goldenDir, "golden-dir", "", "directory of <vendor>.golden baseline files (plus optional common.golden); enables golden-config drift checks")
	fs.StringVar(&o.complianceRules, "compliance-rules", "", "single compliance rules file with optional [vendor] sections; can be combined with -golden-dir")
	fs.StringVar(&o.htmlReport, "html-report", "", "write a standalone HTML run report to this path ({run}, {timestamp} and {date} are expanded)")
	fs.StringVar(&o.mdReport, "md-changelog", "", "write/update a Markdown changelog at this path, newest run first ({run}, {timestamp} and {date} are expanded)")
	fs.StringVar(&o.mdReport, "md-report", "", "alias for -md-changelog")
	fs.StringVar(&o.jsonReport, "json-report", "", "write a machine-readable JSON run report to this path ({run}, {timestamp} and {date} are expanded)")
	fs.StringVar(&o.csvReport, "csv-report", "", "write a machine-readable CSV run report to this path ({run}, {timestamp} and {date} are expanded)")
	fs.BoolVar(&o.resultTable, "result-table", true, "print a per-device result table to stdout after the run")
	fs.BoolVar(&o.dryRun, "dry-run", false, "test connection, login and paging setup without pulling or saving configuration")

	fs.IntVar(&o.concurrency, "concurrency", 10, "maximum number of devices to back up in parallel")
	fs.IntVar(&o.retries, "retries", 0, "retry attempts per device after a connection failure (never after a rejected login)")
	fs.DurationVar(&o.retryDelay, "retry-delay", 2*time.Second, "delay between retries per device")
	fs.DurationVar(&o.dialJitter, "dial-jitter", 100*time.Millisecond, "random delay up to this value before each connection (0 to disable)")
	fs.DurationVar(&o.connectTimeout, "connect-timeout", 10*time.Second, "TCP connect + SSH handshake timeout per device")
	fs.DurationVar(&o.commandTimeout, "command-timeout", 30*time.Second, "per-command time budget; the backup command itself gets 3x")

	fs.StringVar(&o.envFile, "env-file", ".env", "optional .env file holding NETCONFIG_USERNAME / NETCONFIG_PASSWORD (NETBACKUP_* names are accepted too)")
	fs.StringVar(&o.keyFile, "key-file", "", "SSH private key file for device authentication (overrides NETCONFIG_KEY_FILE)")
	fs.StringVar(&o.knownHosts, "known-hosts", "", "OpenSSH known_hosts file used to verify device host keys (default: ~/.ssh/known_hosts)")
	fs.StringVar(&o.hostKeyPolicy, "host-key-policy", "update", "host keys: 'strict' (reject unknown/changed), 'accept-new' (learn new), or 'update' (learn new and replace changed keys)")
	fs.StringVar(&o.hostKeyPolicy, "known-hosts-policy", "update", "alias for -host-key-policy")
	fs.BoolVar(&o.updateKnownHosts, "update-known-hosts", false, "alias for -host-key-policy update")
	fs.BoolVar(&o.updateKnownHosts, "replace-host-keys", false, "alias for -update-known-hosts")
	fs.BoolVar(&o.insecureHostKey, "insecure-ignore-host-key", false, "DANGEROUS: skip host key verification entirely (exposes connections to MITM)")
	fs.BoolVar(&o.legacyAlgorithms, "legacy-algorithms", true, "allow legacy SSH algorithms (3des-cbc, diffie-hellman-group1-sha1, ssh-dss) as a fallback for older gear")
	fs.IntVar(&o.tcpMSS, "tcp-mss", 1360, "TCP Maximum Segment Size for outgoing SSH sockets (0 = OS default)")

	fs.BoolVar(&o.jump, "jump", true, "enable jump host / bastion routing (false connects every device directly)")
	fs.StringVar(&o.jumpHost, "jump-host", "", "global default bastion host[:port] for devices not reachable directly")
	fs.StringVar(&o.jumpUser, "jump-user", "", "SSH username for the global jump host (overrides NETCONFIG_JUMP_USERNAME)")
	fs.StringVar(&o.jumpPassword, "jump-password", "", "SSH password for the global jump host (visible in the process list; prefer NETCONFIG_JUMP_PASSWORD)")
	fs.StringVar(&o.jumpKeyFile, "jump-key-file", "", "SSH private key file for the global jump host (overrides NETCONFIG_JUMP_KEY_FILE)")
	fs.BoolVar(&o.meshFallback, "mesh-fallback", false, "if a direct connection fails, try tunnelling through neighbouring inventory devices (off by default: it routes credentials through other devices)")
	fs.BoolVar(&o.memory, "memory", true, "remember learned routing and fallback paths across runs")
	fs.StringVar(&o.memoryFile, "memory-file", memory.DefaultFile, "persistent memory file for learned device routes")

	fs.StringVar(&o.logDir, "log-dir", "logs", "directory to write run logs into")
	fs.StringVar(&o.logFormat, "log-format", "text", "log format: only 'text' is supported (use -json-report for machine-readable results)")
	fs.BoolVar(&o.noColor, "no-color", false, "disable colored output")
	fs.BoolVar(&o.verbose, "verbose", false, "log the connection and login steps for each device")
	return fs
}

// runBackup is "netconfig backup".
func runBackup(args []string, stdin *os.File, stdout, stderr io.Writer) int {
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
		fmt.Fprintf(stderr, "netconfig backup: "+format+"\n", a...)
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
	log.Infof("", "netconfig %s backup starting; audit log: %s", version, log.Path())

	// ---- inputs ----------------------------------------------------------
	allDevs, err := inventory.Load(o.inventory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
			fmt.Fprintf(stderr, "\nTip: Run 'netconfig -init' to create sample inventory.csv, commands.txt, and .env templates.\n\n")
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
		"NETCONFIG_KEY_FILE":      o.keyFile,
		"NETCONFIG_JUMP_USERNAME": o.jumpUser,
		"NETCONFIG_JUMP_PASSWORD": o.jumpPassword,
		"NETCONFIG_JUMP_KEY_FILE": o.jumpKeyFile,
		"NETCONFIG_JUMP_HOST":     o.jumpHost,
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
	values, migrated := migrateLegacyEnv(dot.Values)
	lookup, usedLegacy := legacyLookupEnv(os.LookupEnv)
	resolver := &credentials.Resolver{DotEnv: values, LookupEnv: lookup, Overrides: overrides}
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
	if len(migrated) > 0 || usedLegacy() {
		log.Warnf("", "using NETBACKUP_* variables; rename them to NETCONFIG_* (the NETBACKUP_* names will stop working in a future release)")
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
		Logf:           func(host, format string, args ...any) { log.Tracef(host, format, args...) },
		OutputDir:      o.backupDir,
		RunName:        backup.DefaultRunName(time.Now()),
		Concurrency:    o.concurrency,
		Redact:         o.redact,
		RetentionCount: o.retentionCount,
		RetentionDays:  o.retentionDays,
		SaveUnchanged:  o.force,
		Retries:        o.retries,
		RetryDelay:     o.retryDelay,
		DialJitter:     o.dialJitter,
		ConnectTimeout: o.connectTimeout,
		CommandTimeout: o.commandTimeout,
		DryRun:         o.dryRun,
		ShowDiff:       o.diff,
		IgnoreVolatile: o.ignoreVolatile,
		OnProgress:     console.Progress,
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
func jumpFor(r *credentials.Resolver, d inventory.Device, flagHost string, global credentials.JumpCredentials) credentials.JumpCredentials {
	switch {
	case d.JumpHost != "":
		jc := r.ForJumpHost(d.JumpHost)
		if jc.Host == "" {
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

// legacyEnvPrefix / envPrefix: netbackup read NETBACKUP_<X>, netconfig reads
// NETCONFIG_<X>; the rest of the name is identical.
const (
	legacyEnvPrefix = "NETBACKUP_"
	envPrefix       = "NETCONFIG_"
)

// migrateLegacyEnv returns the .env values with every NETBACKUP_<X> entry also
// available as NETCONFIG_<X> (an explicit NETCONFIG_<X> wins), and the names
// that were migrated. The input map is not modified.
func migrateLegacyEnv(values map[string]string) (map[string]string, []string) {
	out := make(map[string]string, len(values))
	for k, v := range values {
		out[k] = v
	}
	var migrated []string
	for k, v := range values {
		if rest, ok := strings.CutPrefix(k, legacyEnvPrefix); ok {
			if _, exists := out[envPrefix+rest]; !exists {
				out[envPrefix+rest] = v
				migrated = append(migrated, k)
			}
		}
	}
	return out, migrated
}

// legacyLookupEnv wraps an environment lookup so NETCONFIG_<X> falls back to
// NETBACKUP_<X>. The returned func reports whether a fallback was used.
func legacyLookupEnv(lookup func(string) (string, bool)) (func(string) (string, bool), func() bool) {
	used := false
	return func(key string) (string, bool) {
			if v, ok := lookup(key); ok {
				return v, true
			}
			if rest, ok := strings.CutPrefix(key, envPrefix); ok {
				if v, ok := lookup(legacyEnvPrefix + rest); ok {
					used = true
					return v, true
				}
			}
			return "", false
		}, func() bool {
			return used
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

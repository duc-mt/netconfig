// ==============================================================================
// File name:     ops_common.go
// Description:   Flags and setup shared by the automation subcommands
//
//	(user, passwd, vlan, facts, find, audit, diff).
//
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

	"netops/internal/credentials"
	"netops/internal/inventory"
	"netops/internal/logging"
	"netops/internal/memory"
	"netops/internal/notifier"
	"netops/internal/sshclient"
	"netops/internal/task"
	"netops/internal/vendor"
)

// newOpsTransport builds the session opener for the automation subcommands.
// Tests replace it to run a whole command without a network.
var newOpsTransport = func(hostKey sshclient.HostKeyCallback, legacy bool, pool *jumpPool, autoFallback []task.Target, tcpMSS int) task.Transport {
	return sshTransport{hostKey: hostKey, legacy: legacy, autoConfirm: true, pool: pool, autoFallback: autoFallback, tcpMSS: tcpMSS}
}

// opsFlags contains flags shared across automation subcommands.
// Read-only subcommands (facts, find, audit) register only targeting, connection,
// logging, and report flags (registerReadOnly). Change-oriented subcommands
// (config user/vlan/passwd, diff) additionally register safety and write-control
// flags (registerChangeSafety).
type opsFlags struct {
	inventory, limit, envFile, knownHosts, hostKeyPolicy, logDir, keyFile string
	jumpHost, jumpUser, jumpKeyFile, memoryFile                           string
	jsonReport, csvReport, backupDir                                      string

	concurrency, maxRetries, tcpMSS, canary, batchSize, maxFailPercent int
	connectTimeout, commandTimeout                                     time.Duration

	dryRun, yes, force, backup, rollbackOnFail, strictSafety, allowDangerous bool
	updateKnownHosts, legacy, verbose, noColor, jump, meshFallback, memory   bool
	failPercentSet                                                           bool
}

// registerReadOnly adds the flags that every subcommand (including read-only
// ones like facts, find and audit) understands: inventory targeting, SSH
// connection options, logging and reporting.
func (o *opsFlags) registerReadOnly(fs *flag.FlagSet) {
	fs.StringVar(&o.inventory, "inventory", "inventory.csv", "inventory CSV: hostname,address,port,vendor,credential_group")
	fs.StringVar(&o.limit, "limit", "", "only these devices: comma-separated hostname globs, or @group")
	fs.IntVar(&o.concurrency, "concurrency", 10, "maximum number of devices handled at the same time")
	fs.IntVar(&o.maxRetries, "max-retries", 0, "maximum automatic retries for transient SSH connection/session errors")
	fs.DurationVar(&o.connectTimeout, "connect-timeout", 10*time.Second, "TCP connect + SSH handshake budget per device")
	fs.DurationVar(&o.commandTimeout, "command-timeout", 30*time.Second, "budget per command (commit/save/config dumps get 3x)")
	fs.DurationVar(&o.commandTimeout, "timeout", 30*time.Second, "alias of -command-timeout")
	fs.StringVar(&o.keyFile, "key-file", "", "path to an SSH private key file for device authentication (overrides NETOPS_KEY_FILE)")
	fs.StringVar(&o.logDir, "log-dir", "logs", "directory for the timestamped audit log file")
	fs.StringVar(&o.envFile, "env-file", ".env", "credentials file (KEY=VALUE lines); missing is fine")
	fs.StringVar(&o.knownHosts, "known-hosts", "", "OpenSSH-format known_hosts file (defaults to ~/.ssh/known_hosts)")
	fs.StringVar(&o.hostKeyPolicy, "host-key-policy", "update", "host keys: 'strict' (reject unknown/changed), 'accept-new' (learn new), or 'update' (learn new, replace changed)")
	fs.BoolVar(&o.updateKnownHosts, "update-known-hosts", false, "alias for -host-key-policy update")
	fs.BoolVar(&o.legacy, "legacy-algorithms", true, "allow legacy SSH algorithms as a fallback for older network gear")
	fs.BoolVar(&o.verbose, "verbose", false, "show command/response traces on the console (always in the log file)")
	fs.BoolVar(&o.noColor, "no-color", false, "disable coloured console output")
	fs.StringVar(&o.jsonReport, "json-report", "", "write a JSON run report to this file path")
	fs.StringVar(&o.csvReport, "csv-report", "", "write a CSV run report to this file path")

	fs.BoolVar(&o.jump, "jump", true, "enable jump host / bastion routing (false: connect all devices directly)")
	fs.StringVar(&o.jumpHost, "jump-host", "", "global default bastion host[:port]")
	fs.StringVar(&o.jumpUser, "jump-user", "", "SSH username for the global jump host (overrides NETOPS_JUMP_USERNAME)")
	fs.StringVar(&o.jumpKeyFile, "jump-key-file", "", "SSH private key file for the global jump host (overrides NETOPS_JUMP_KEY_FILE)")
	fs.BoolVar(&o.meshFallback, "mesh-fallback", false, "try SSH jump tunnelling through neighbouring inventory devices if a direct connection fails")
	fs.IntVar(&o.tcpMSS, "tcp-mss", 1360, "TCP Maximum Segment Size for outgoing SSH sockets (0 = OS default)")
	fs.BoolVar(&o.memory, "memory", true, "remember learned routing and fallback paths across runs")
	fs.StringVar(&o.memoryFile, "memory-file", memory.DefaultFile, "persistent memory file for learned device routes")
}

// registerChangeSafety adds the write/change-control flags that only apply to
// subcommands that modify device state (config user/vlan/passwd, diff).
func (o *opsFlags) registerChangeSafety(fs *flag.FlagSet) {
	fs.BoolVar(&o.dryRun, "dry-run", false, "check and simulate only; never commits or saves anything")
	fs.BoolVar(&o.yes, "yes", false, "skip the [y/N] confirmation prompt")
	fs.BoolVar(&o.force, "force", false, "same as -yes; also accepts CRITICAL lockout risks that -strict-safety would block")
	fs.BoolVar(&o.backup, "backup", false, "save each device's running configuration before changing it")
	fs.StringVar(&o.backupDir, "backup-dir", "backups", "directory for -backup snapshots")
	fs.BoolVar(&o.rollbackOnFail, "rollback-on-fail", false, "restore the pre-change backup if a device fails (requires -backup)")
	fs.BoolVar(&o.strictSafety, "strict-safety", true, "abort before connecting when the pre-flight lint finds a CRITICAL lockout risk (accept with -force)")
	fs.BoolVar(&o.allowDangerous, "allow-dangerous", false, "accept intentionally destructive commands that -strict-safety would block")
	fs.IntVar(&o.canary, "canary", 0, "apply to N devices first; stop if any canary fails")
	fs.IntVar(&o.batchSize, "batch-size", 0, "apply to the remaining devices in sequential batches of N (0 = all at once)")
	fs.IntVar(&o.maxFailPercent, "max-fail-percent", 100, "abort later batches if the cumulative failure rate exceeds this % (0-100)")
}

// register adds all flags (read-only + change-safety) to fs. Used by
// subcommands that can modify device state (config user/vlan/passwd, diff).
func (o *opsFlags) register(fs *flag.FlagSet) {
	o.registerReadOnly(fs)
	o.registerChangeSafety(fs)
}

// noteSetFlags records which flags were given explicitly.
func (o *opsFlags) noteSetFlags(fs *flag.FlagSet) {
	o.failPercentSet = isFlagSet(fs, "max-fail-percent")
}

// opsEnv is a subcommand's connection to the outside world: logger, inventory,
// credentials and the session transport.
type opsEnv struct {
	name     string
	o        *opsFlags
	stdin    *os.File
	stdout   io.Writer
	stderr   io.Writer
	log      *logging.Logger
	color    bool
	devs     []inventory.Device
	resolver *credentials.Resolver
	hostKey  sshclient.HostKeyCallback
	pool     *jumpPool
	tr       task.Transport
	ctx      context.Context
	closers  []func()
	started  time.Time
}

// die logs a fatal error and returns the fatal exit code.
func (e *opsEnv) die(format string, a ...any) int {
	e.log.Errorf("", format, a...)
	return task.ExitFatal
}

func (e *opsEnv) close() {
	for i := len(e.closers) - 1; i >= 0; i-- {
		e.closers[i]()
	}
}

// newOpsEnv validates the shared flags and sets up logging, the inventory,
// credential resolution and the transport. A non-zero code means the command
// must exit with it (the problem has already been reported).
func newOpsEnv(name string, o *opsFlags, stdin *os.File, stdout, stderr io.Writer) (*opsEnv, int) {
	fatal := func(format string, a ...any) (*opsEnv, int) {
		fmt.Fprintf(stderr, "netops %s: "+format+"\n", append([]any{name}, a...)...)
		return nil, task.ExitFatal
	}
	switch {
	case o.concurrency < 1:
		return fatal("-concurrency must be at least 1")
	case o.connectTimeout <= 0 || o.commandTimeout <= 0:
		return fatal("-connect-timeout and -command-timeout must be positive")
	case o.maxRetries < 0 || o.canary < 0 || o.batchSize < 0:
		return fatal("-max-retries, -canary and -batch-size must not be negative")
	case o.maxFailPercent < 0 || o.maxFailPercent > 100:
		return fatal("-max-fail-percent must be between 0 and 100")
	case o.rollbackOnFail && !o.backup:
		return fatal("-rollback-on-fail requires -backup")
	}
	if o.updateKnownHosts {
		o.hostKeyPolicy = "update"
	}
	policy, err := sshclient.ParsePolicy(o.hostKeyPolicy)
	if err != nil {
		return fatal("%v", err)
	}

	e := &opsEnv{name: name, o: o, stdin: stdin, stdout: stdout, stderr: stderr, started: time.Now()}
	e.color = !o.noColor && os.Getenv("NO_COLOR") == "" && isTerminalWriter(stderr)
	e.log, err = logging.New(logging.Options{Dir: o.logDir, Console: stderr, Color: e.color, Verbose: o.verbose})
	if err != nil {
		return fatal("%v", err)
	}
	e.closers = append(e.closers, func() { _ = e.log.Close() })
	fail := func(format string, a ...any) (*opsEnv, int) {
		code := e.die(format, a...)
		e.close()
		return nil, code
	}
	e.log.Infof("", "netops %s %s starting; audit log: %s", version, name, e.log.Path())

	// ---- inventory ---------------------------------------------------------
	all, err := inventory.Load(o.inventory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
			fmt.Fprintf(stderr, "\nTip: Run 'netops -init' to create sample inventory.csv, commands.txt, and .env templates.\n\n")
		}
		return fail("%v", err)
	}
	if e.devs, err = inventory.Filter(all, strings.Split(o.limit, ",")); err != nil {
		return fail("%v", err)
	}

	// ---- credentials -------------------------------------------------------
	overrides := map[string]string{}
	for k, v := range map[string]string{
		"NETOPS_KEY_FILE": o.keyFile, "NETOPS_JUMP_USERNAME": o.jumpUser,
		"NETOPS_JUMP_KEY_FILE": o.jumpKeyFile, "NETOPS_JUMP_HOST": o.jumpHost,
	} {
		if v != "" {
			overrides[k] = v
		}
	}
	dot, err := credentials.LoadDotEnv(o.envFile)
	if err != nil {
		return fail("%v", err)
	}
	for _, w := range dot.Warnings {
		e.log.Warnf("", "%s", w)
	}
	e.resolver = &credentials.Resolver{DotEnv: dot.Values, LookupEnv: os.LookupEnv, Overrides: overrides}
	if credentials.IsTerminal(stdin) {
		e.resolver.Prompter = &credentials.TerminalPrompter{In: stdin, Out: stderr}
	}

	// ---- transport ---------------------------------------------------------
	knownHosts := o.knownHosts
	if knownHosts == "" {
		knownHosts = sshclient.DefaultKnownHostsFile()
	}
	if e.hostKey, err = sshclient.NewHostKeyCallback(knownHosts, policy); err != nil {
		return fail("%v", err)
	}
	if policy == sshclient.PolicyInsecure {
		e.log.Warnf("", "host key verification is DISABLED (-host-key-policy insecure)")
	}
	var memStore *memory.Store
	if o.memory {
		if memStore, err = memory.Load(o.memoryFile); err != nil {
			e.log.Warnf("", "failed to load route memory %s: %v", o.memoryFile, err)
		}
	}
	if o.jump {
		e.pool = newJumpPool(e.hostKey, o.legacy, memStore)
		e.closers = append(e.closers, e.pool.closeAll)
	}
	var fallback []task.Target
	if o.jump && o.meshFallback {
		for _, d := range all {
			if d.Endpoint() == "" {
				continue
			}
			cred, err := e.resolver.Resolve(d.Group)
			if err != nil {
				continue
			}
			prof, _ := vendor.Lookup(d.Vendor)
			fallback = append(fallback, task.Target{Device: d, Profile: prof, Cred: cred,
				ConnectTimeout: o.connectTimeout, LoginTimeout: o.commandTimeout, TCPMSS: o.tcpMSS})
		}
	}
	e.tr = newOpsTransport(e.hostKey, o.legacy, e.pool, fallback, o.tcpMSS)

	// Ctrl-C stops starting new devices; a second one kills the process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	e.ctx = ctx
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			e.log.Warnf("", "interrupt received: no new devices will be started; sessions in progress are being closed safely (press Ctrl-C again to force quit)")
			stop()
		case <-finished:
		}
	}()
	e.closers = append(e.closers, func() { close(finished); stop() })
	return e, task.ExitOK
}

// prepare resolves credentials and jump-host settings for every runnable job.
func (e *opsEnv) prepare(jobs []task.Job) {
	task.ResolveCredentials(jobs, func(group string) (credentials.Credential, error) {
		c, err := e.resolver.Resolve(group)
		if err == nil {
			e.log.AddSecret(c.Password)
			e.log.AddSecret(c.EnablePassword)
		}
		return c, err
	})
	if !e.o.jump {
		e.log.Infof("", "jump host routing disabled via -jump=false: all devices are connected directly")
		return
	}
	global := e.resolver.JumpDefaults()
	for i := range jobs {
		if jobs[i].Skip != "" {
			continue
		}
		var jc credentials.JumpCredentials
		switch {
		case jobs[i].Device.JumpHost != "":
			jc = e.resolver.ForJumpHost(jobs[i].Device.JumpHost)
			if jc.Host == "" {
				jc.Host = jobs[i].Device.JumpHost
			}
		case e.o.jumpHost != "":
			jc = e.resolver.ForJumpHost("")
			jc.Host = e.o.jumpHost
		case global.Host != "":
			jc = global
		}
		if jc.Password != "" {
			e.log.AddSecret(jc.Password)
		}
		jobs[i].JumpCred = jc
	}
}

// options builds the runner options from the shared flags.
func (e *opsEnv) options() task.Options {
	o := e.o
	return task.Options{
		Concurrency: o.concurrency, MaxRetries: o.maxRetries,
		ConnectTimeout: o.connectTimeout, CommandTimeout: o.commandTimeout,
		DryRun: o.dryRun, Backup: o.backup, BackupDir: o.backupDir, RollbackOnFail: o.rollbackOnFail,
		Canary: o.canary, BatchSize: o.batchSize, MaxFailPercent: o.maxFailPercent, FailThresholdSet: o.failPercentSet,
		Format: "text",
	}
}

// runner builds a Runner on the shared transport. confirmFn answers the
// candidate-diff prompt of platforms that preview before committing.
func (e *opsEnv) runner(h task.Handler) *task.Runner {
	return &task.Runner{Transport: e.tr, Log: e.log, Opts: e.options(), Handler: h}
}

// confirm asks the operator, unless -yes/-force was given. Without a terminal
// there is nobody to ask, so an unattended run must say -yes explicitly.
func (e *opsEnv) confirm(prompt string) (bool, error) {
	if e.o.yes || e.o.force {
		return true, nil
	}
	if !credentials.IsTerminal(e.stdin) {
		return false, errors.New("stdin is not a terminal, so there is nobody to confirm; pass -yes (or -force) to run unattended, or use -dry-run")
	}
	return confirm(e.stdin, e.stderr, prompt), nil
}

// finish prints the summary table, writes the reports and returns the exit code.
func (e *opsEnv) finish(results []task.Result) int {
	dur := time.Since(e.started)
	sum := task.Summarize(results, dur)
	console := task.RenderOptions{Color: e.color, DryRun: e.o.dryRun, Width: terminalWidth(e.stderr)}
	file := task.RenderOptions{DryRun: e.o.dryRun}
	e.log.Raw("\n"+sum.Render(console), "\n"+sum.Render(file))
	e.log.Infof("", "total runtime: %s", dur.Round(100*time.Millisecond))
	if e.o.backup {
		e.log.Infof("", "pre-change backups: %s", e.o.backupDir)
	}
	if e.o.jsonReport != "" {
		if err := task.WriteJSONReport(e.o.jsonReport, results, ""); err != nil {
			e.log.Errorf("", "JSON report: %v", err)
		} else {
			e.log.Infof("", "JSON report: %s", e.o.jsonReport)
		}
	}
	if e.o.csvReport != "" {
		if err := task.WriteCSVReport(e.o.csvReport, results, ""); err != nil {
			e.log.Errorf("", "CSV report: %v", err)
		} else {
			e.log.Infof("", "CSV report: %s", e.o.csvReport)
		}
	}
	e.log.Infof("", "audit log: %s", e.log.Path())

	tg := notifier.NewTelegram(notifier.ConfigFromResolver(e.resolver))
	if tg != nil {
		defer tg.Close()
		tg.SendTaskSummary("operation", sum, e.o.dryRun)
	}

	return task.ExitCode(results)
}

// ---- two-phase change driver ------------------------------------------------

// changeRun drives a read-then-apply workflow (user, passwd, vlan): it reads
// each device's state, shows what would change, asks for confirmation and
// applies through the normal runner. what names the operation in messages.
//
// guard, when set, runs once credentials are resolved and BEFORE any device is
// contacted; an error aborts the whole run.
func (e *opsEnv) changeRun(what string, jobs []task.Job, decide task.Decider, tune func(*task.Options), guard func([]task.Job) error) int {
	e.prepare(jobs)
	if guard != nil {
		if err := guard(jobs); err != nil {
			return e.die("%v", err)
		}
	}
	runnable := 0
	for _, j := range jobs {
		if j.Skip == "" {
			runnable++
		}
	}
	e.log.Infof("", "%d device(s) selected, %d runnable; concurrency=%d dry-run=%t backup=%t",
		len(jobs), runnable, e.o.concurrency, e.o.dryRun, e.o.backup)

	checkRunner := e.runner(nil)
	decisions, checked := checkRunner.Decide(e.ctx, jobs, decide)
	apply, index := task.BuildApplyJobs(jobs, checked, decisions)

	if len(apply) > 0 {
		for _, j := range apply {
			e.log.Infof(j.Device.Hostname, "will change: %s", decisions[deviceDecisionKey(j)].Detail)
		}
		if code, ok := e.vet(what, apply); !ok {
			return code
		}
	}

	applied := []task.Result{}
	if len(apply) > 0 {
		applyRunner := e.runner(nil)
		if tune != nil {
			tune(&applyRunner.Opts)
		}
		applied = applyRunner.Run(e.ctx, apply)
	}
	return e.finish(task.MergeResults(checked, index, applied))
}

// vet runs the pre-flight safety lint on the jobs about to be applied and asks
// the operator to confirm. ok is false when the run must stop with code.
func (e *opsEnv) vet(what string, apply []task.Job) (code int, ok bool) {
	hints := usernameHints(e.o.envFile, apply)
	safety := task.SafetyPolicy{Strict: e.o.strictSafety, Force: e.o.force, AllowDangerous: e.o.allowDangerous}
	var blocked []string
	for _, j := range apply {
		rep := task.LintJob(j, hints[j.Device.Group], false)
		rep.Log(e.log, j.Device.Hostname)
		if n := len(rep.Blocking(safety)); n > 0 {
			blocked = append(blocked, fmt.Sprintf("%s (%d)", j.Device.Hostname, n))
		}
	}
	if len(blocked) > 0 {
		if !e.o.dryRun {
			return e.die("pre-flight safety check blocked the change before anything was modified: %s; review the LINT messages above (-force accepts CRITICAL lockout risks)", strings.Join(blocked, ", ")), false
		}
		e.log.Warnf("", "dry-run: these findings would block a real run: %s", strings.Join(blocked, ", "))
	}
	if e.o.dryRun {
		return task.ExitOK, true
	}
	yes, err := e.confirm(fmt.Sprintf("%s on %d device(s)? [y/N]: ", what, len(apply)))
	if err != nil {
		return e.die("refusing to change devices: %v", err), false
	}
	if !yes {
		e.log.Warnf("", "aborted at the confirmation prompt; no device was changed")
		return task.ExitFatal, false
	}
	e.log.Infof("", "operator confirmed: %s on %d device(s)", what, len(apply))
	return task.ExitOK, true
}

func deviceDecisionKey(j task.Job) string { return j.Device.Hostname + "\x00" + j.Device.Address }

// readOnlyRun runs a handler on every selected device and returns its results.
func (e *opsEnv) readOnlyRun(jobs []task.Job, h task.Handler) []task.Result {
	e.prepare(jobs)
	n := 0
	for _, j := range jobs {
		if j.Skip == "" {
			n++
		}
	}
	e.log.Infof("", "%d device(s) selected, %d runnable; concurrency=%d (read-only)", len(jobs), n, e.o.concurrency)
	opts := e.options()
	opts.DryRun, opts.Backup, opts.RollbackOnFail = false, false, false
	r := &task.Runner{Transport: e.tr, Log: e.log, Opts: opts, Handler: h}
	return r.Run(e.ctx, jobs)
}

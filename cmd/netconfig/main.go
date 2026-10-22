// ==============================================================================
// Package main implements Implementation and logic for main..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run main.go [options]
// Notes:         Go package implementation
// ==============================================================================
// Command netconfig applies configuration commands to many network devices
// over SSH, concurrently, with a dry-run mode, an explicit confirmation step,
// optional pre-change backups and a full audit log. It is a single static
// binary with no runtime dependencies, intended for air-gapped management
// networks.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"netconfig/internal/credentials"
	"netconfig/internal/inventory"
	"netconfig/internal/logging"
	"netconfig/internal/memory"
	"netconfig/internal/sshclient"
	"netconfig/internal/task"
	"netconfig/internal/ui"
	"netconfig/internal/vendor"
)

//go:embed samples/inventory.csv
var sampleInventory []byte

//go:embed samples/env.example
var sampleEnv []byte

//go:embed samples/commands.txt
var sampleCommands []byte

// version is overridden at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

const usageText = `netconfig - apply configuration commands to many network devices over SSH

Usage:
  netconfig -commands commands.txt [flags]
  netconfig -template config.tmpl -var ntp=10.0.0.1 [flags]
  netconfig -op -commands <(echo "show ip ospf route") [flags]

Subcommands:
  netconfig backup [flags]              archive device configurations, detect changes (netconfig backup -h)
  netconfig show-backup [flags] [node]  view, diff or locate saved backups (netconfig show-backup -h)

Supported vendors: %s

Credentials are never accepted as flags (they would be visible in "ps").
Provide them in .env, in environment variables, or at the interactive prompt:
  NETCONFIG_USERNAME / NETCONFIG_PASSWORD                     all devices
  NETCONFIG_<GROUP>_USERNAME / NETCONFIG_<GROUP>_PASSWORD     one credential_group
  NETCONFIG_[<GROUP>_]ENABLE_PASSWORD                         optional enable secret
Precedence: .env file, then process environment, then interactive prompt;
a group-specific variable always overrides the global one.

Exit codes: 0 all devices succeeded, 1 fatal configuration error (or aborted
at the confirmation prompt), 2 some devices failed or were skipped.

Flags:
`

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// dispatch routes the first argument to a subcommand. Anything else is the
// classic configuration runner, so "netconfig -commands commands.txt" and
// "netconfig commands.txt" behave exactly as before. (A commands file that is
// literally named "backup" or "show-backup" must now be given as -commands.)
func dispatch(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "backup":
			return runBackup(args[1:], stdin, stdout, stderr)
		case "show-backup":
			return runShowBackup(args[1:], stdin, stdout, stderr)
		}
	}
	return run(args, stdin, stdout, stderr)
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netconfig", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, usageText, strings.Join(vendor.Names(), ", "))
		fs.PrintDefaults()
	}

	var vars stringList
	fs.Var(&vars, "var", "template variable `name=value` (repeatable)")
	var (
		invPath          = fs.String("inventory", "inventory.csv", "inventory CSV: hostname,address,port,vendor,credential_group")
		cmdsPath         = fs.String("commands", "", "plain text file with one configuration command per line")
		tmplPath         = fs.String("template", "", "Go text/template rendered once per device (alternative to -commands)")
		limit            = fs.String("limit", "", "only these devices: comma-separated hostname globs, or @group")
		opMode           = fs.Bool("op", false, "operational mode: run commands in the operational shell without configure/commit/save")
		dryRun           = fs.Bool("dry-run", false, "validate connectivity and simulate; never commits or saves anything")
		yes              = fs.Bool("yes", false, "skip the [y/N] confirmation prompt")
		force            = fs.Bool("force", false, "same as -yes; also accepts CRITICAL lockout risks that -strict-safety would block")
		backup           = fs.Bool("backup", false, "save each device's running configuration before changing it")
		backupDir        = fs.String("backup-dir", "backups", "directory for -backup snapshots")
		rollbackOnFail   = fs.Bool("rollback-on-fail", false, "restore pre-change backup if a device fails (requires -backup)")
		strictSafety     = fs.Bool("strict-safety", true, "abort before connecting when the pre-flight lint finds a CRITICAL lockout risk (accept with -force) or a destructive command (accept with -allow-dangerous)")
		allowDangerous   = fs.Bool("allow-dangerous", false, "accept intentionally destructive commands (no router bgp, delete interfaces, default interface, clear ip bgp *, ...) that -strict-safety would block")
		commitConfirm    = fs.Int("commit-confirm", 0, "arm an on-box deadman timer of `minutes`: the change reverts by itself unless confirmed after verification (0 = off)")
		allowRebootRB    = fs.Bool("allow-reboot-rollback", false, "permit 'reload in <min>' as the deadman on platforms without hitless rollback (classic IOS)")
		verifyFile       = fs.String("verify-file", "", "post-change health checks to run on each device (see README); '!@verify' blocks inside the commands file or template are honoured too")
		planMode         = fs.Bool("plan", false, "preview risk, impact and rollback safety per device, then ask before proceeding (combine with -dry-run)")
		showDiff         = fs.Bool("show-diff", false, "after a successful change, diff the post-change configuration against the pre-change backup (requires -backup)")
		outputDir        = fs.String("output-dir", "", "write per-device command output to <dir>/<hostname>.txt")
		jsonReport       = fs.String("json-report", "", "write a JSON run report to this file path")
		csvReport        = fs.String("csv-report", "", "write a CSV run report to this file path")
		concurrency      = fs.Int("concurrency", 10, "maximum number of devices configured at the same time")
		maxRetries       = fs.Int("max-retries", 0, "maximum automatic retries for transient SSH connection/session errors")
		connectTO        = fs.Duration("connect-timeout", 10*time.Second, "TCP connect + SSH handshake budget per device")
		commandTO        = fs.Duration("command-timeout", 30*time.Second, "budget per command (commit/save/backup get 3x)")
		keyFile          = fs.String("key-file", "", "path to an SSH private key file for device authentication (overrides NETCONFIG_KEY_FILE)")
		logDir           = fs.String("log-dir", "logs", "directory for the timestamped audit log file")
		envFile          = fs.String("env-file", ".env", "credentials file (KEY=VALUE lines); missing is fine")
		knownHosts       = fs.String("known-hosts", "", "OpenSSH-format known_hosts file for host key checks (defaults to ~/.ssh/known_hosts or %USERPROFILE%\\.ssh\\known_hosts)")
		hostKeyPolicy    = fs.String("host-key-policy", "update", "policy for host keys: 'strict' (reject unknown/changed), 'accept-new' (learn new), or 'update' (learn new and replace changed keys)")
		updateKnownHosts = fs.Bool("update-known-hosts", false, "automatically remove mismatched existing keys and learn new keys in known_hosts (alias for -host-key-policy update)")
		replaceHostKeys  = fs.Bool("replace-host-keys", false, "alias for -update-known-hosts")
		legacy           = fs.Bool("legacy-algorithms", true, "allow negotiation of legacy SSH algorithms (3des-cbc, diffie-hellman-group1-sha1, ssh-dss) as fallback for older network gear")
		autoConfirm      = fs.Bool("auto-confirm", true, "answer [y/n] / [confirm] dialogs raised by devices")
		verbose          = fs.Bool("verbose", false, "show command/response traces on the console (always in the log file)")
		noColor          = fs.Bool("no-color", false, "disable coloured console output")
		showVersion      = fs.Bool("version", false, "print the version and exit")

		// Jump host / bastion
		jumpEnabled  = fs.Bool("jump", true, "enable jump host / bastion routing (set false to connect all devices directly, overriding inventory and env config)")
		jumpHost     = fs.String("jump-host", "", "global default bastion host[:port] for devices not reachable directly (e.g. mgmt-gw.example.com:22)")
		jumpUser     = fs.String("jump-user", "", "SSH username for the global jump host (overrides NETCONFIG_JUMP_USERNAME)")
		jumpPassword = fs.String("jump-password", "", "SSH password for the global jump host (overrides NETCONFIG_JUMP_PASSWORD)")
		jumpKeyFile  = fs.String("jump-key-file", "", "SSH private key file for the global jump host (overrides NETCONFIG_JUMP_KEY_FILE)")
		meshFallback = fs.Bool("mesh-fallback", false, "attempt SSH jump tunneling through neighboring inventory devices if direct connection fails (disabled by default)")
		tcpMSS       = fs.Int("tcp-mss", 1360, "TCP Maximum Segment Size for outgoing SSH sockets (0=OS default, >0=clamp MSS to avoid PMTU issues)")

		// Route memory & auto-discovery
		memoryEnabled = fs.Bool("memory", true, "enable automatic memory of learned routing and fallback paths across runs")
		memoryFile    = fs.String("memory-file", memory.DefaultFile, "persistent memory file for learned device routes")
		clearMemory   = fs.Bool("clear-memory", false, "clear learned route memory and exit")
		showMemory    = fs.Bool("show-memory", false, "display learned route memory and exit")

		// Canary & phased rollouts
		canary         = fs.Int("canary", 0, "run N devices first as canary; abort run if any canary fails")
		batchSize      = fs.Int("batch-size", 0, "execute remaining devices in sequential batches of N (0 = all at once)")
		maxFailPercent = fs.Int("max-fail-percent", 100, "abort subsequent batches if cumulative failure rate exceeds this % (0-100)")

		// Pre-commit diff inspection
		preDiff     = fs.Bool("pre-diff", false, "inspect candidate configuration diff before committing on supported platforms (Junos, VyOS, Arista, etc.)")
		confirmDiff = fs.Bool("confirm-diff", false, "prompt operator confirmation before committing candidate diff (implies -pre-diff; bypassed with -yes/-force)")

		// Output format & dashboard
		format    = fs.String("format", "text", "output format: text | json (in -op mode, json parses operational show commands into structured data)")
		dashboard = fs.Bool("dashboard", true, "show live terminal ANSI progress dashboard (active on interactive terminals without -verbose)")

		// Init sample templates
		initConfig = fs.Bool("init", false, "generate sample inventory.csv, commands.txt, and .env template in current directory and exit")
	)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return task.ExitOK
		}
		hintPasswordFlag(args, stderr)
		return task.ExitFatal
	}
	fatal := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "netconfig: "+format+"\n", a...)
		return task.ExitFatal
	}
	if *showVersion {
		fmt.Fprintln(stdout, "netconfig", version)
		return task.ExitOK
	}
	if *initConfig {
		created := 0
		if _, err := os.Stat("inventory.csv"); os.IsNotExist(err) {
			if err := os.WriteFile("inventory.csv", sampleInventory, 0600); err != nil {
				return fatal("creating inventory.csv: %v", err)
			}
			fmt.Fprintln(stdout, "[+] Created sample inventory.csv")
			created++
		} else {
			fmt.Fprintln(stdout, "[.] inventory.csv already exists, skipping")
		}

		if _, err := os.Stat(".env"); os.IsNotExist(err) {
			if err := os.WriteFile(".env", sampleEnv, 0600); err != nil {
				return fatal("creating .env: %v", err)
			}
			fmt.Fprintln(stdout, "[+] Created sample .env template")
			created++
		} else {
			fmt.Fprintln(stdout, "[.] .env already exists, skipping")
		}

		if _, err := os.Stat("commands.txt"); os.IsNotExist(err) {
			if err := os.WriteFile("commands.txt", sampleCommands, 0600); err != nil {
				return fatal("creating commands.txt: %v", err)
			}
			fmt.Fprintln(stdout, "[+] Created sample commands.txt")
			created++
		} else {
			fmt.Fprintln(stdout, "[.] commands.txt already exists, skipping")
		}

		if created > 0 {
			fmt.Fprintln(stdout, "\nSample configuration created! Edit inventory.csv, .env, and commands.txt to match your environment.")
		}
		return task.ExitOK
	}
	if *showMemory {
		mem, err := memory.Load(*memoryFile)
		if err != nil {
			return fatal("load memory: %v", err)
		}
		routes := mem.List()
		if len(routes) == 0 {
			fmt.Fprintln(stdout, "No learned routes in memory.")
			return task.ExitOK
		}
		fmt.Fprintf(stdout, "%-20s %-18s %-20s %-20s %-8s %s\n", "TARGET HOST", "TARGET IP", "JUMP HOST", "JUMP ENDPOINT", "SUCCESS", "LAST USED")
		for _, r := range routes {
			fmt.Fprintf(stdout, "%-20s %-18s %-20s %-20s %-8d %s\n",
				r.TargetHost, r.TargetIP, r.JumpHost, r.JumpEndpoint, r.SuccessCount, r.LastUsedAt.Format("2006-01-02 15:04:05"))
		}
		return task.ExitOK
	}
	if *clearMemory {
		mem, err := memory.Load(*memoryFile)
		if err != nil {
			return fatal("load memory: %v", err)
		}
		if err := mem.Clear(); err != nil {
			return fatal("clear memory: %v", err)
		}
		fmt.Fprintf(stdout, "Route memory cleared (%s).\n", *memoryFile)
		return task.ExitOK
	}
	// Accept optional single positional argument as commands file (e.g. netconfig commands.txt)
	if *cmdsPath == "" && *tmplPath == "" {
		if fs.NArg() == 1 {
			*cmdsPath = fs.Arg(0)
		} else if fs.NArg() == 0 {
			// Default to commands.txt if it exists in current directory
			if _, err := os.Stat("commands.txt"); err == nil {
				*cmdsPath = "commands.txt"
			}
		}
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && *cmdsPath != fs.Arg(0)) {
		return fatal("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if (*cmdsPath == "") == (*tmplPath == "") {
		hint := "Tip: Run 'netconfig -init' to create sample inventory.csv, commands.txt, and .env templates.\n"
		fmt.Fprintln(stderr, hint)
		return fatal("exactly one of -commands (or commands.txt) or -template is required (see -h)")
	}
	if *concurrency < 1 {
		return fatal("-concurrency must be at least 1")
	}
	if *connectTO <= 0 || *commandTO <= 0 {
		return fatal("-connect-timeout and -command-timeout must be positive")
	}
	if *opMode && *dryRun {
		return fatal("-op and -dry-run are mutually exclusive")
	}
	if *rollbackOnFail && !*backup {
		return fatal("-rollback-on-fail requires -backup")
	}
	if *showDiff && !*backup {
		return fatal("-show-diff requires -backup")
	}
	if *commitConfirm < 0 {
		return fatal("-commit-confirm must not be negative")
	}
	if *commitConfirm > 0 && *opMode {
		return fatal("-commit-confirm protects configuration changes and cannot be used with -op")
	}
	if *verifyFile != "" && *opMode {
		return fatal("-verify-file checks the result of a change and cannot be used with -op")
	}
	if *confirmDiff {
		*preDiff = true
	}
	if *canary < 0 {
		return fatal("-canary must not be negative")
	}
	if *batchSize < 0 {
		return fatal("-batch-size must not be negative")
	}
	if *maxFailPercent < 0 || *maxFailPercent > 100 {
		return fatal("-max-fail-percent must be between 0 and 100")
	}
	if *format != "text" && *format != "json" {
		return fatal("-format must be 'text' or 'json'")
	}
	if *preDiff && *opMode {
		return fatal("-pre-diff inspects configuration changes and cannot be used with -op")
	}
	if *updateKnownHosts || *replaceHostKeys {
		*hostKeyPolicy = "update"
	}
	policy, err := sshclient.ParsePolicy(*hostKeyPolicy)
	if err != nil {
		return fatal("%v", err)
	}
	varMap, err := parseVars(vars)
	if err != nil {
		return fatal("%v", err)
	}

	color := !*noColor && os.Getenv("NO_COLOR") == "" && isTerminalWriter(stderr)
	log, err := logging.New(logging.Options{Dir: *logDir, Console: stderr, Color: color, Verbose: *verbose})
	if err != nil {
		return fatal("%v", err)
	}
	defer log.Close()
	die := func(format string, a ...any) int {
		log.Errorf("", format, a...)
		return task.ExitFatal
	}
	log.Infof("", "netconfig %s starting; audit log: %s", version, log.Path())

	// ---- inputs ----------------------------------------------------------
	allDevs, err := inventory.Load(*invPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
			fmt.Fprintf(stderr, "\nTip: Run 'netconfig -init' to create sample inventory.csv, commands.txt, and .env templates.\n\n")
		}
		return die("%v", err)
	}
	devs, err := inventory.Filter(allDevs, strings.Split(*limit, ","))
	if err != nil {
		return die("%v", err)
	}

	var src task.CommandSource
	if *cmdsPath != "" {
		cmds, err := task.ReadCommandsFile(*cmdsPath)
		if err != nil {
			return die("%v", err)
		}
		src = task.StaticCommands(cmds)
	} else {
		if src, err = task.ReadTemplateFile(*tmplPath, varMap); err != nil {
			return die("%v", err)
		}
	}
	jobs, err := task.BuildJobs(devs, src)
	if err != nil {
		return die("%v", err)
	}

	// Post-change health checks: inline "!@verify" blocks from the commands
	// file / template, plus the -verify-file.
	inlineFrom := *cmdsPath
	if inlineFrom == "" {
		inlineFrom = *tmplPath
	}
	verifyRules, err := task.ReadInlineVerify(inlineFrom)
	if err != nil {
		return die("%v", err)
	}
	if *verifyFile != "" {
		fileRules, err := task.ReadVerifyFile(*verifyFile)
		if err != nil {
			return die("%v", err)
		}
		verifyRules = append(verifyRules, fileRules...)
	}
	if *opMode {
		verifyRules = nil
	}
	if err := task.CheckConfirmWindow(verifyRules, *commitConfirm); err != nil {
		return die("%v", err)
	}
	if *allowRebootRB && *commitConfirm == 0 {
		log.Warnf("", "-allow-reboot-rollback has no effect without -commit-confirm")
	}

	log.Infof("", "%d device(s) selected; concurrency=%d connect-timeout=%s command-timeout=%s dry-run=%t op=%t backup=%t",
		len(jobs), *concurrency, *connectTO, *commandTO, *dryRun, *opMode, *backup)

	// ---- pre-flight safety lint ------------------------------------------
	// Static analysis only: no session is opened. A failure on one device
	// degrades to a warning for that device and never stops the others.
	hints := usernameHints(*envFile, jobs)
	safety := task.SafetyPolicy{Strict: *strictSafety, Force: *force, AllowDangerous: *allowDangerous}
	reports := make([]task.LintReport, len(jobs))
	var blocked []string
	for i, j := range jobs {
		if j.Skip != "" {
			continue
		}
		reports[i] = task.LintJob(j, hints[j.Device.Group], *opMode)
		reports[i].Log(log, j.Device.Hostname)
		if n := len(reports[i].Blocking(safety)); n > 0 {
			blocked = append(blocked, fmt.Sprintf("%s (%d)", j.Device.Hostname, n))
		}
	}
	if len(blocked) > 0 {
		if !*dryRun {
			return die("pre-flight safety check blocked the run before any device was contacted: %s; "+
				"review the LINT messages above. -force accepts CRITICAL lockout risks, -allow-dangerous accepts "+
				"destructive commands, -strict-safety=false downgrades both to warnings", strings.Join(blocked, ", "))
		}
		log.Warnf("", "dry-run: these findings would block a real run: %s", strings.Join(blocked, ", "))
	}

	// ---- confirmation ----------------------------------------------------
	runnable := 0
	for _, j := range jobs {
		if j.Skip == "" {
			runnable++
		}
	}
	// Op-mode runs are read-only; skip the destructive-change prompt.
	needConfirm := !*dryRun && !*opMode && !*yes && !*force && runnable > 0
	if *planMode {
		rows := task.BuildPlanRows(jobs, reports)
		ropts := task.PlanRenderOptions{DryRun: *dryRun, CommitConfirm: *commitConfirm}
		plain := task.RenderPlan(rows, ropts)
		ropts.Color = color
		log.Raw("\n"+task.RenderPlan(rows, ropts), "\n"+plain)
		printPlan(stderr, jobs, *backup, *backupDir, *opMode, *dryRun)
		if runnable > 0 && !*yes && !*force {
			if !credentials.IsTerminal(stdin) {
				return die("-plan needs a terminal to ask for confirmation; pass -yes (or -force) to proceed unattended")
			}
			if !confirm(stdin, stderr, fmt.Sprintf("Proceed with applying changes to %d device(s)? [y/N]: ", runnable)) {
				log.Warnf("", "aborted at the plan prompt; no device was changed")
				return task.ExitFatal
			}
			log.Infof("", "operator confirmed the plan for %d device(s)", runnable)
		}
	} else if needConfirm {
		if !credentials.IsTerminal(stdin) {
			return die("refusing to change devices: stdin is not a terminal, so there is nobody to confirm; pass -yes (or -force) to run unattended, or use -dry-run")
		}
		printPlan(stderr, jobs, *backup, *backupDir, false, false)
		if !confirm(stdin, stderr, fmt.Sprintf("Apply these changes to %d device(s)? [y/N]: ", runnable)) {
			log.Warnf("", "aborted at the confirmation prompt; no device was changed")
			return task.ExitFatal
		}
		log.Infof("", "operator confirmed the change for %d device(s)", runnable)
	}

	// ---- credentials -----------------------------------------------------
	overrides := make(map[string]string)
	if *keyFile != "" {
		overrides["NETCONFIG_KEY_FILE"] = *keyFile
	}
	if *jumpUser != "" {
		overrides["NETCONFIG_JUMP_USERNAME"] = *jumpUser
	}
	if *jumpPassword != "" {
		overrides["NETCONFIG_JUMP_PASSWORD"] = *jumpPassword
	}
	if *jumpKeyFile != "" {
		overrides["NETCONFIG_JUMP_KEY_FILE"] = *jumpKeyFile
	}
	if *jumpHost != "" {
		overrides["NETCONFIG_JUMP_HOST"] = *jumpHost
	}

	dot, err := credentials.LoadDotEnv(*envFile)
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
	task.ResolveCredentials(jobs, func(group string) (credentials.Credential, error) {
		c, err := resolver.Resolve(group)
		if err == nil {
			log.AddSecret(c.Password)
			log.AddSecret(c.EnablePassword)
		}
		return c, err
	})

	// Resolve jump host credentials per job
	globalJumpDef := resolver.JumpDefaults()
	if *jumpEnabled {
		if *jumpHost != "" {
			log.Infof("", "global jump host configured: %s (per-device overrides via inventory jump_host column; disable with -jump=false)", *jumpHost)
		} else if globalJumpDef.Host != "" {
			log.Infof("", "global jump host configured via env: %s (per-device overrides via inventory jump_host column; disable with -jump=false)", globalJumpDef.Host)
		}
		for i := range jobs {
			if jobs[i].Skip != "" {
				continue
			}
			var jc credentials.JumpCredentials
			switch {
			case jobs[i].Device.JumpHost != "":
				jc = resolver.ForJumpHost(jobs[i].Device.JumpHost)
				if jc.Host == "" {
					// Treat inventory jump_host value directly as host[:port]
					jc.Host = jobs[i].Device.JumpHost
				}
			case *jumpHost != "":
				jc = resolver.ForJumpHost("")
				jc.Host = *jumpHost
			case globalJumpDef.Host != "":
				jc = globalJumpDef
			}
			if jc.Password != "" {
				log.AddSecret(jc.Password)
			}
			jobs[i].JumpCred = jc
		}
	} else {
		log.Infof("", "jump host routing disabled via -jump=false -- all devices will be connected directly")
	}

	// ---- transport -------------------------------------------------------
	targetKnownHosts := *knownHosts
	if targetKnownHosts == "" {
		targetKnownHosts = sshclient.DefaultKnownHostsFile()
	}
	hostKey, err := sshclient.NewHostKeyCallback(targetKnownHosts, policy)
	if err != nil {
		return die("%v", err)
	}
	if policy == sshclient.PolicyInsecure {
		log.Warnf("", "host key verification is DISABLED (-host-key-policy insecure)")
	}

	var memStore *memory.Store
	if *memoryEnabled {
		var err error
		memStore, err = memory.Load(*memoryFile)
		if err != nil {
			log.Warnf("", "failed to load route memory %s: %v", *memoryFile, err)
		} else if len(memStore.List()) > 0 {
			log.Infof("", "loaded %d learned route(s) from persistent memory (%s)", len(memStore.List()), *memoryFile)
		}
	}

	var pool *jumpPool
	if *jumpEnabled {
		pool = newJumpPool(hostKey, *legacy, memStore)
		defer pool.closeAll()
	}

	var confirmMu sync.Mutex
	confirmFunc := func(host string, diff string) bool {
		if *yes || *force {
			return true
		}
		confirmMu.Lock()
		defer confirmMu.Unlock()
		if !credentials.IsTerminal(stdin) {
			log.Errorf(host, "cannot prompt for candidate diff confirmation: stdin is not a terminal (pass -yes or -force to proceed)")
			return false
		}
		return confirm(stdin, stderr, fmt.Sprintf("[%s] Candidate configuration diff displayed above. Proceed with commit? [y/N]: ", host))
	}

	var autoFallbackTargets []task.Target
	if *jumpEnabled && *meshFallback {
		for _, d := range allDevs {
			if d.Endpoint() == "" {
				continue
			}
			cred, err := resolver.Resolve(d.Group)
			if err != nil {
				continue
			}
			prof, _ := vendor.Lookup(d.Vendor)
			autoFallbackTargets = append(autoFallbackTargets, task.Target{
				Device:         d,
				Profile:        prof,
				Cred:           cred,
				ConnectTimeout: *connectTO,
				LoginTimeout:   *commandTO,
				TCPMSS:         *tcpMSS,
			})
		}
	}

	runner := &task.Runner{
		Transport:   sshTransport{hostKey: hostKey, legacy: *legacy, autoConfirm: *autoConfirm, pool: pool, autoFallback: autoFallbackTargets, tcpMSS: *tcpMSS},
		Log:         log,
		ConfirmFunc: confirmFunc,
		Opts: task.Options{
			Concurrency:    *concurrency,
			MaxRetries:     *maxRetries,
			ConnectTimeout: *connectTO,
			CommandTimeout: *commandTO,
			DryRun:         *dryRun,
			OpMode:         *opMode,
			Backup:         *backup,
			BackupDir:      *backupDir,
			RollbackOnFail: *rollbackOnFail,
			OutputDir:      *outputDir,
			ShowDiff:       *showDiff,

			CommitConfirm:       *commitConfirm,
			AllowRebootRollback: *allowRebootRB,
			Verify:              verifyRules,

			Canary:           *canary,
			BatchSize:        *batchSize,
			MaxFailPercent:   *maxFailPercent,
			FailThresholdSet: isFlagSet(fs, "max-fail-percent"),

			PreDiff:     *preDiff,
			ConfirmDiff: *confirmDiff,
			Format:      *format,
		},
	}

	dashEnabled := *dashboard && isTerminalWriter(stderr) && !*verbose && os.Getenv("TERM") != "dumb"
	var dash *ui.Dashboard
	if dashEnabled {
		dash = ui.New(ui.Config{
			Writer:       stderr,
			TotalDevices: len(jobs),
			Width:        terminalWidth(stderr),
			Enabled:      true,
		})
		runner.Observer = dash
		log.SetConsole(&dashWriter{dash: dash})
	}

	// ---- run -------------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			log.Warnf("", "interrupt received: no new devices will be started; sessions in progress are being closed safely (press Ctrl-C again to force quit)")
			stop() // restores default signal handling so a second Ctrl-C kills the process
		case <-finished:
		}
	}()
	runStart := time.Now()
	results := runner.Run(ctx, jobs)
	totalDuration := time.Since(runStart)
	close(finished)

	if dash != nil {
		dash.Stop()
		log.SetConsole(stderr)
	}

	if *opMode && *format == "json" {
		type opDeviceJSON struct {
			Hostname string         `json:"hostname"`
			Vendor   string         `json:"vendor"`
			Status   string         `json:"status"`
			Commands map[string]any `json:"commands,omitempty"`
		}
		var outList []opDeviceJSON
		for _, r := range results {
			outList = append(outList, opDeviceJSON{
				Hostname: r.Device.Hostname,
				Vendor:   r.Device.Vendor,
				Status:   r.Status.String(),
				Commands: r.ParsedOutput,
			})
		}
		if data, err := json.MarshalIndent(outList, "", "  "); err == nil {
			fmt.Fprintln(stdout, string(data))
		}
	}

	// ---- summary ---------------------------------------------------------
	sum := task.Summarize(results, totalDuration)
	consoleOpts := task.RenderOptions{Color: color, DryRun: *dryRun, Width: terminalWidth(stderr)}
	fileOpts := task.RenderOptions{Color: false, DryRun: *dryRun} // Width 0: a log file isn't screen-width constrained
	log.Raw("\n"+sum.Render(consoleOpts), "\n"+sum.Render(fileOpts))
	log.Infof("", "total runtime: %s", totalDuration.Round(100*time.Millisecond))
	if *backup {
		log.Infof("", "pre-change backups: %s", *backupDir)
	}
	if *outputDir != "" {
		log.Infof("", "per-device output: %s/", *outputDir)
	}
	if *jsonReport != "" {
		if err := task.WriteJSONReport(*jsonReport, results, *outputDir); err != nil {
			log.Errorf("", "JSON report: %v", err)
		} else {
			log.Infof("", "JSON report: %s", *jsonReport)
		}
	}
	if *csvReport != "" {
		if err := task.WriteCSVReport(*csvReport, results, *outputDir); err != nil {
			log.Errorf("", "CSV report: %v", err)
		} else {
			log.Infof("", "CSV report: %s", *csvReport)
		}
	}
	log.Infof("", "audit log: %s", log.Path())
	return task.ExitCode(results)
}

func parseVars(list []string) (map[string]string, error) {
	m := make(map[string]string, len(list))
	for _, kv := range list {
		k, v, ok := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid -var %q (want name=value)", kv)
		}
		m[k] = v
	}
	return m, nil
}

func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && credentials.IsTerminal(f)
}

// terminalWidth returns w's terminal width in columns, or 0 if w isn't a
// real terminal (piped output, a log file, redirected to /dev/null) or its
// size can't be determined -- 0 tells Summary.Render to use natural column
// widths instead of trying to fit a size that doesn't apply.
func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok || !credentials.IsTerminal(f) {
		return 0
	}
	width, _, err := term.GetSize(int(f.Fd()))
	if err != nil || width <= 0 {
		return 0
	}
	return width
}

// hintPasswordFlag explains why -password does not exist.
func hintPasswordFlag(args []string, w io.Writer) {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		switch name {
		case "password", "pass", "passwd", "pw", "enable-password":
			fmt.Fprintln(w, "netconfig: passwords are never accepted as command-line flags (they would leak through 'ps'); "+
				"set NETCONFIG_[<GROUP>_]PASSWORD in .env or the environment, or use the interactive prompt")
			return
		}
	}
}

// confirm prints prompt and reads one line from in; only y/yes means yes.
func confirm(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprint(out, prompt)
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := in.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			sb.WriteByte(buf[0])
		}
		if err != nil {
			break
		}
	}
	ans := strings.ToLower(strings.TrimSpace(sb.String()))
	return ans == "y" || ans == "yes"
}

// usernameHints returns, per credential group, the login name configured in
// the .env file or environment, without prompting. The pre-flight lint uses it
// to recognise commands that remove or alter the account the run logs in with.
func usernameHints(envFile string, jobs []task.Job) map[string]string {
	vals := map[string]string{}
	if dot, err := credentials.LoadDotEnv(envFile); err == nil && dot != nil {
		vals = dot.Values
	}
	r := &credentials.Resolver{DotEnv: vals, LookupEnv: os.LookupEnv}
	out := map[string]string{}
	for _, j := range jobs {
		if _, seen := out[j.Device.Group]; !seen {
			out[j.Device.Group] = r.Username(j.Device.Group)
		}
	}
	return out
}

// printPlan shows what is about to happen so the confirmation is informed.
func printPlan(w io.Writer, jobs []task.Job, backup bool, backupDir string, opMode, dryRun bool) {
	var active, skipped []task.Job
	for _, j := range jobs {
		if j.Skip != "" {
			skipped = append(skipped, j)
		} else {
			active = append(active, j)
		}
	}

	switch {
	case opMode:
		fmt.Fprintf(w, "\n%d device(s) will receive operational commands (no configuration changes):\n", len(active))
	case dryRun:
		fmt.Fprintf(w, "\n%d device(s) will be validated (dry-run: nothing is committed or saved):\n", len(active))
	default:
		fmt.Fprintf(w, "\n%d device(s) will be modified and their configuration saved/committed:\n", len(active))
	}
	for _, j := range active {
		fmt.Fprintf(w, "  %-24s %-26s %s\n", j.Device.Hostname, j.Device.Endpoint(), j.Profile.Display)
	}

	if len(active) > 0 {
		first := active[0]
		same := true
		for _, j := range active[1:] {
			if !slices.Equal(j.Commands, first.Commands) {
				same = false
				break
			}
		}
		if same {
			fmt.Fprintf(w, "\n%d command(s), identical for every device:\n", len(first.Commands))
		} else {
			fmt.Fprintf(w, "\nCommands differ per device (template); showing %s, %d command(s):\n", first.Device.Hostname, len(first.Commands))
		}
		const maxShown = 25
		for i, c := range first.Commands {
			if i == maxShown {
				fmt.Fprintf(w, "    ... %d more\n", len(first.Commands)-maxShown)
				break
			}
			fmt.Fprintf(w, "    %s\n", logging.RedactCommand(c))
		}
	}

	if backup {
		fmt.Fprintf(w, "\nPre-change backups go to %s/\n", backupDir)
	} else {
		fmt.Fprintln(w, "\nNo pre-change backup (add -backup to snapshot each device first).")
	}
	if len(skipped) > 0 {
		fmt.Fprintf(w, "\n%d device(s) will be skipped:\n", len(skipped))
		for _, j := range skipped {
			fmt.Fprintf(w, "  %-24s %s\n", j.Device.Hostname, j.Skip)
		}
	}
	fmt.Fprintln(w)
}

type dashWriter struct {
	dash *ui.Dashboard
}

func (dw *dashWriter) Write(p []byte) (n int, err error) {
	dw.dash.Log(strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

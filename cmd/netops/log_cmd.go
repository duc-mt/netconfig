// ==============================================================================
// File name:     log_cmd.go
// Description:   "netops log": passive network log monitoring and auto-triage.
//                The dispatcher, usage text and the flag/credential/transport
//                setup shared by the log subcommands. The subcommands live in
//                log_collect_cmd.go, log_query_cmd.go, log_listen_cmd.go,
//                log_top_cmd.go and log_diagnose_cmd.go.
// License:       MIT
// ==============================================================================

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/internal/credentials"
	"netops/internal/inventory"
	"netops/internal/log/pipeline"
	"netops/internal/sshclient"
	"netops/internal/task"
)

const logUsageText = `netops log: network log monitor and auto-triage.

Reads device logs over SSH or receives them as syslog, normalises and classifies
the events, detects anomalies and captures read-only diagnostics when something
breaks. It never changes a device: every command it sends is a show/display.

Usage:
  netops log <subcommand> [flags]

Subcommands:
  collect      poll all devices once, store logs, auto-triage anomalies, and exit
  monitor      continuous background polling daemon (--interval, optional --tui)
  listen       syslog listener daemon (UDP and TCP, RFC 3164/5424)
  query        search and filter stored log events
  timeline     cross-device chronological event stream with causal correlation
  incidents    list auto-triage incident reports, or view one with --id
  report       digest analytics: noisy devices, change accountability, trends, MTTR
  status       collection health per device (failing, silent, stale)
  top          live interactive terminal dashboard (TUI)
  diagnose     on-demand read-only diagnostics for a single device

Run "netops log <subcommand> -h" for the flags of a subcommand.

Credentials come from the same NETOPS_* variables and .env file as the other
netops commands (NETOPS_USERNAME, NETOPS_PASSWORD, NETOPS_<GROUP>_*,
NETOPS_JUMP_*). Sample files are written by "netops init"; Telegram alerts are
verified with "netops telegram-test".

Examples:
  netops log collect --dry-run                  test connectivity and clock skew
  netops log collect --inventory inventory.csv --data-dir data
  netops log monitor --interval 2m --data-dir data
  netops log diagnose core-gw-1 --raw           quick triage of one device
  netops log listen --port 5514                 live syslog intake (ports below 1024 need root)
  netops log query --category CONFIG --since 24h
  netops log query --limit core --severity CRITICAL --since today --format json
  netops log timeline --from "2026-10-20 10:10:00" --to "2026-10-20 10:25:00"
  netops log incidents --since 24h
  netops log incidents --id a1b2c3d4
  netops log report                             last 7 days, with week-over-week delta
  netops log status --stale-after 1h --fail     exit 1 if any device needs attention

Timestamps that devices print without a time zone are read in this host's
local zone (set TZ to change it); any zone difference is absorbed by the
per-poll clock-skew measurement.
`

// runLog is "netops log": it dispatches to the log subcommands. A bare
// "netops log" is a usage error, like a bare "netops config".
func runLog(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "netops log: missing subcommand")
		fmt.Fprintln(stderr)
		fmt.Fprint(stderr, logUsageText)
		return task.ExitFatal
	}
	rest := args[1:]
	switch args[0] {
	case "collect":
		return runLogCollect(rest, stdin, stdout, stderr, false)
	case "monitor":
		return runLogCollect(rest, stdin, stdout, stderr, true)
	case "listen":
		return runLogListen(rest, stdout, stderr)
	case "query":
		return runLogQuery(rest, stdout, stderr)
	case "timeline":
		return runLogTimeline(rest, stdout, stderr)
	case "incidents":
		return runLogIncidents(rest, stdout, stderr)
	case "report":
		return runLogReport(rest, stdout, stderr)
	case "status":
		return runLogStatus(rest, stdout, stderr)
	case "top":
		return runLogTop(rest, stdin, stdout, stderr)
	case "diagnose":
		return runLogDiagnose(rest, stdin, stdout, stderr)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, logUsageText)
		return task.ExitOK
	default:
		fmt.Fprintf(stderr, "netops log: unknown subcommand %q\n\n", args[0])
		fmt.Fprint(stderr, logUsageText)
		return task.ExitFatal
	}
}

// ==============================================================================
// Flag plumbing
// ==============================================================================

// newLogFlagSet declares an empty flag set for "netops log <name>" whose help
// is the given usage text followed by the flags in groups.
func newLogFlagSet(name string, stderr io.Writer, usage string, groups []flagGroup) *flag.FlagSet {
	fs := flag.NewFlagSet("netops log "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		printFlagGroups(stderr, fs, groups)
	}
	return fs
}

// parseLogFlags parses args. The second result is false when the command must
// stop with the returned exit code (help was shown or the flags were invalid).
func parseLogFlags(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return task.ExitOK, false
		}
		return task.ExitFatal, false
	}
	return 0, true
}

// logFail prints "netops log <cmd>: <message>" to stderr and returns the fatal
// exit code.
func logFail(stderr io.Writer, cmd, format string, a ...any) int {
	fmt.Fprintf(stderr, "netops log %s: %s\n", cmd, fmt.Sprintf(format, a...))
	return task.ExitFatal
}

// logNoArgs rejects stray positional arguments.
func logNoArgs(fs *flag.FlagSet, stderr io.Writer, cmd string) (int, bool) {
	if fs.NArg() > 0 {
		return logFail(stderr, cmd, "unexpected argument %q", fs.Arg(0)), false
	}
	return 0, true
}

// logFormatFlag registers --format with the netops "table|json" vocabulary.
func logFormatFlag(fs *flag.FlagSet, def string) *string {
	return fs.String("format", def, "output format: table | json")
}

// normalizeLogFormat maps the accepted --format spellings to "table" or "json".
// "text" is the pre-merge name of the table format and stays accepted.
func normalizeLogFormat(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "table", "text":
		return "table", true
	case "json":
		return "json", true
	}
	return "", false
}

// registerLimit declares --limit and its --host alias onto dst.
func registerLimit(fs *flag.FlagSet, dst *string) {
	fs.StringVar(dst, "limit", "", "only these devices: comma-separated hostname substrings or globs (case-insensitive)")
	fs.StringVar(dst, "host", "", "alias for -limit")
}

// logHostMatcher builds the --limit filter: a comma-separated list of
// hostname patterns, each a glob (when it contains * ? or [) or otherwise a
// case-insensitive substring, which is what "netlog query --host" always did.
// An empty limit matches everything.
func logHostMatcher(limit string) (func(host string) bool, error) {
	var pats []string
	for _, p := range strings.Split(limit, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			if strings.ContainsAny(p, "*?[") {
				if _, err := path.Match(p, ""); err != nil {
					return nil, fmt.Errorf("invalid pattern %q in --limit: %w", p, err)
				}
			}
			pats = append(pats, p)
		}
	}
	if len(pats) == 0 {
		return func(string) bool { return true }, nil
	}
	return func(host string) bool {
		host = strings.ToLower(host)
		for _, p := range pats {
			if strings.ContainsAny(p, "*?[") {
				if ok, _ := path.Match(p, host); ok {
					return true
				}
			} else if strings.Contains(host, p) {
				return true
			}
		}
		return false
	}, nil
}

// logAfterHoursDefault reads an after-hours hour from the environment for use as
// a flag default; anything outside 0-23 falls back to def.
func logAfterHoursDefault(key string, def int) int {
	if s := os.Getenv(key); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= 23 {
			return v
		}
	}
	return def
}

// registerAfterHours declares --after-hours-start/--after-hours-end.
func registerAfterHours(fs *flag.FlagSet, start, end *int) {
	fs.IntVar(start, "after-hours-start", logAfterHoursDefault("NETOPS_AFTER_HOURS_START", pipeline.DefaultAfterHoursStart), "first hour (0-23) of the after-hours change window (env NETOPS_AFTER_HOURS_START)")
	fs.IntVar(end, "after-hours-end", logAfterHoursDefault("NETOPS_AFTER_HOURS_END", pipeline.DefaultAfterHoursEnd), "first hour (0-23) after which changes are no longer after-hours (env NETOPS_AFTER_HOURS_END)")
}

// ==============================================================================
// Shared connection settings
// ==============================================================================

// logConn is the connection flag group shared by every subcommand that
// connects to devices (collect, monitor, diagnose). The names, defaults and
// meanings follow the other netops commands (see commonFlags).
type logConn struct {
	inventory        string
	envFile          string
	connectTimeout   time.Duration
	commandTimeout   time.Duration
	knownHosts       string
	hostKeyPolicy    string
	legacyAlgorithms bool
	jump             bool
	jumpHost         string
}

func (c *logConn) register(fs *flag.FlagSet) {
	fs.StringVar(&c.inventory, "inventory", "inventory.csv", "inventory CSV: hostname,address,port,vendor,credential_group,jump_host")
	fs.StringVar(&c.envFile, "env-file", ".env", "credentials file (KEY=VALUE lines, NETOPS_* names); missing is fine")
	fs.DurationVar(&c.connectTimeout, "connect-timeout", 10*time.Second, "TCP connect + SSH handshake budget per device")
	fs.DurationVar(&c.commandTimeout, "command-timeout", 30*time.Second, "budget per SSH command or interactive session")
	fs.StringVar(&c.knownHosts, "known-hosts", "known_hosts", `OpenSSH-format known_hosts file for host key checks ("" = the user's ~/.ssh/known_hosts)`)
	fs.StringVar(&c.hostKeyPolicy, "host-key-policy", "update", "policy for host keys: 'strict' (reject unknown/changed), 'accept-new' (learn new), 'update' (learn new and replace changed keys) or 'insecure' (no verification; DANGEROUS)")
	fs.BoolVar(&c.legacyAlgorithms, "legacy-algorithms", true, "allow negotiation of legacy SSH algorithms as a fallback for older network gear")
	fs.BoolVar(&c.jump, "jump", true, "enable jump host / bastion routing (false = connect everything directly)")
	fs.StringVar(&c.jumpHost, "jump-host", "", "global default bastion host[:port] for devices not reachable directly")
}

// validate checks the values that have no sensible fallback.
func (c *logConn) validateConn() error {
	if c.connectTimeout <= 0 || c.commandTimeout <= 0 {
		return errors.New("--connect-timeout and --command-timeout must be positive")
	}
	if _, err := sshclient.ParsePolicy(c.hostKeyPolicy); err != nil {
		return fmt.Errorf("--host-key-policy: %w", err)
	}
	return nil
}

// logTransport is what a connecting subcommand needs to dial devices.
type logTransport struct {
	resolver *credentials.Resolver
	ssh      sshclient.ExecOptions
}

// transport loads the credentials (the .env file, the NETOPS_* environment and,
// on a terminal, prompts) and builds the SSH options, including the host key
// verifier. It never reads NETLOG_* variables.
func (c *logConn) transport(stdin *os.File, stderr io.Writer, log *logLogger) (*logTransport, error) {
	policy, err := sshclient.ParsePolicy(c.hostKeyPolicy)
	if err != nil {
		return nil, err
	}

	overrides := make(map[string]string)
	if c.jumpHost != "" {
		overrides["NETOPS_JUMP_HOST"] = c.jumpHost
	}
	dot, err := credentials.LoadDotEnv(c.envFile)
	if err != nil {
		return nil, fmt.Errorf("loading credentials: %w", err)
	}
	for _, w := range dot.Warnings {
		log.Warn("%s", w)
	}
	resolver := &credentials.Resolver{DotEnv: dot.Values, LookupEnv: os.LookupEnv, Overrides: overrides}
	if credentials.IsTerminal(stdin) {
		resolver.Prompter = &credentials.TerminalPrompter{In: stdin, Out: stderr}
	}

	knownHosts := c.knownHosts
	if knownHosts == "" {
		knownHosts = sshclient.DefaultKnownHostsFile()
	}
	hostKey, err := sshclient.NewHostKeyCallback(knownHosts, policy)
	if err != nil {
		return nil, fmt.Errorf("loading known_hosts %q: %w", knownHosts, err)
	}
	if policy == sshclient.PolicyInsecure {
		log.Warn("host key verification disabled via --host-key-policy insecure; connections are vulnerable to MITM")
	}

	return &logTransport{
		resolver: resolver,
		ssh: sshclient.ExecOptions{
			ConnectTimeout:   c.connectTimeout,
			CommandTimeout:   c.commandTimeout,
			HostKeyCallback:  hostKey,
			LegacyAlgorithms: c.legacyAlgorithms,
		},
	}, nil
}

// resolveGroups resolves the credentials of every group the devices use, once and
// up front, so a missing credential is reported (and prompted for on a
// terminal) before polling starts instead of in the middle of it. A group that
// cannot be resolved is only a warning: its devices fail individually, the rest
// of the fleet is still polled.
func (t *logTransport) resolveGroups(devices []inventory.Device, log *logLogger) {
	seen := make(map[string]bool)
	for _, d := range devices {
		if seen[d.Group] {
			continue
		}
		seen[d.Group] = true
		if _, err := t.resolver.Resolve(d.Group); err != nil {
			log.Warn("%v (devices in group %q will fail to authenticate)", err, d.Group)
		}
	}
}

// ==============================================================================
// Logging
// ==============================================================================

// logLogger writes timestamped lines to stderr, which is where cron and systemd
// expect a tool's diagnostics ("netops log collect >> netops.log 2>&1"). It
// deliberately does not use internal/logging: that package creates one
// backup_run_*.log file per process, which would mean one file per cron run
// here, and its summary code is tied to backup results.
type logLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *logLogger) emit(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %-5s %s\n", time.Now().Format(time.RFC3339), level, cleanLogText(fmt.Sprintf(format, args...)))
}

// cleanLogText neutralises control characters in a log message. Messages embed
// text taken from device logs, which is untrusted: a crafted line must not be
// able to forge extra log lines (CR/LF) or drive the terminal (ESC).
func cleanLogText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return '?'
		}
		return r
	}, s)
}

func (l *logLogger) Info(format string, args ...any)  { l.emit("INFO", format, args...) }
func (l *logLogger) Warn(format string, args ...any)  { l.emit("WARN", format, args...) }
func (l *logLogger) Error(format string, args ...any) { l.emit("ERROR", format, args...) }

// logColorEnabled reports whether w is an interactive terminal that should get
// ANSI colour.
func logColorEnabled(w io.Writer, noColor bool) bool {
	return !noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && isTerminalWriter(w)
}

// initTip is appended to errors caused by a missing inventory file.
const logInitTip = "\nTip: Run 'netops init' to create sample inventory.csv, commands.txt and .env templates.\n\n"

// logMissingFile reports whether err is a missing-file error.
func logMissingFile(file string, err error) bool {
	if _, statErr := os.Stat(file); os.IsNotExist(statErr) {
		return true
	}
	return err != nil && strings.Contains(err.Error(), "no such file")
}

// ==============================================================================
// File name:     log_top_cmd.go
// Description:   "netops log top" (the live terminal dashboard) and the
//                dashboard mode of "netops log monitor --tui".
// License:       MIT
// ==============================================================================

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"netops/internal/credentials"
	"netops/internal/inventory"
	"netops/internal/log/store"
	"netops/internal/log/tui"
	"netops/internal/task"
)

const logTopUsageText = `Usage: netops log top [flags]

A live terminal dashboard over the stored data: a banner with the event counters
(FAULT, CONFIG, AUTH, SECURITY, SYSTEM; last 24h), devices monitored and
collection health; a scrolling event feed; unresolved outages and flapping
links; and the status of every device with its last poll time.

Keys:  q or Ctrl+C  quit     c  cycle the category filter     p  pause/resume the feed

It only reads the data directory, so it can run next to "netops log monitor",
"collect" and "listen". Use "netops log monitor --tui" to poll and watch in one
terminal.
`

var logTopFlagGroups = []flagGroup{
	{"Data", []string{"data-dir", "inventory", "stale-after", "silent-after"}},
	{"Display", []string{"refresh", "no-color"}},
}

// logMinRefresh is the fastest redraw rate the dashboard accepts.
const logMinRefresh = 100 * time.Millisecond

func runLogTop(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := newLogFlagSet("top", stderr, logTopUsageText, logTopFlagGroups)
	var (
		dataDir     = fs.String("data-dir", "data", "base directory of logs/ and state files")
		refresh     = fs.Duration("refresh", time.Second, "redraw interval (minimum 100ms)")
		invPath     = fs.String("inventory", "inventory.csv", "inventory CSV, so devices that were never polled are listed too (optional)")
		staleAfter  = fs.Duration("stale-after", store.DefaultStaleAfter, "show a device as STALE when nothing has tried to poll it for this long")
		silentAfter = fs.Duration("silent-after", store.DefaultSilentAfter, "show a device as SILENT when it has produced no new log line for this long")
		noColor     = fs.Bool("no-color", false, "disable colours")
	)
	if code, ok := parseLogFlags(fs, args); !ok {
		return code
	}
	if code, ok := logNoArgs(fs, stderr, "top"); !ok {
		return code
	}
	if *refresh < logMinRefresh {
		return logFail(stderr, "top", "--refresh must be at least %s", logMinRefresh)
	}
	if *staleAfter <= 0 || *silentAfter <= 0 {
		return logFail(stderr, "top", "--stale-after and --silent-after must be positive")
	}
	out, ok := stdout.(*os.File)
	if !ok || !credentials.IsTerminal(stdin) || !credentials.IsTerminal(out) {
		fmt.Fprintln(stderr, "netops log top: needs an interactive terminal (stdin and stdout must both be a TTY); use 'netops log status' or 'netops log query' in scripts")
		return task.ExitFatal
	}

	var hosts []string
	if devices, _ := inventory.LoadLenient(*invPath); len(devices) > 0 {
		for _, d := range devices {
			hosts = append(hosts, d.Hostname)
		}
	}
	src := tui.NewFileSource(*dataDir, hosts, tui.SourceOptions{StaleAfter: *staleAfter, SilentAfter: *silentAfter})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := tui.Run(ctx, stdin, out, src, tui.RunOptions{Refresh: *refresh, Color: logColorEnabled(out, *noColor)}); err != nil {
		return logFail(stderr, "top", "%v", err)
	}
	return task.ExitOK
}

// runMonitorTUI is "netops log monitor --tui": the monitor loop runs in the
// background while the dashboard owns the terminal. Log lines go to a file
// because anything written to the terminal would corrupt the screen.
func runLogMonitorTUI(o logCollectOpts, stdin *os.File, stdout, stderr io.Writer) int {
	out, ok := stdout.(*os.File)
	if !ok || !credentials.IsTerminal(stdin) || !credentials.IsTerminal(out) {
		fmt.Fprintln(stderr, "netops log monitor: --tui needs an interactive terminal (stdin and stdout must both be a TTY)")
		return task.ExitFatal
	}
	if err := os.MkdirAll(o.dataDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "netops log monitor: creating data directory: %v\n", err)
		return task.ExitFatal
	}
	logPath := filepath.Join(o.dataDir, "monitor.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "netops log monitor: opening %s: %v\n", logPath, err)
		return task.ExitFatal
	}
	defer logFile.Close()
	log := &logLogger{w: logFile}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := newLogApp(o, stdin, stderr, log)
	if err != nil {
		log.Error("%v", err)
		fmt.Fprintf(stderr, "netops log monitor: %v\n", err)
		return task.ExitFatal
	}
	defer a.close()

	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.monitorLoop(ctx, o, log)
	}()

	hosts := make([]string, len(a.devices))
	for i, d := range a.devices {
		hosts[i] = d.Hostname
	}
	src := tui.NewFileSource(o.dataDir, hosts, tui.SourceOptions{})
	runErr := tui.Run(ctx, stdin, out, src, tui.RunOptions{Refresh: time.Second, Color: logColorEnabled(out, o.noColor)})

	cancel()
	fmt.Fprintln(stderr, "netops log monitor: stopping (waiting for in-flight polls and triage)...")
	<-done
	if runErr != nil {
		fmt.Fprintf(stderr, "netops log monitor: %v\n", runErr)
		return task.ExitFatal
	}
	fmt.Fprintf(stderr, "netops log monitor: stopped; log: %s\n", logPath)
	return task.ExitOK
}

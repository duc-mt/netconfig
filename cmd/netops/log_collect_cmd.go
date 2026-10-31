// ==============================================================================
// File name:     log_collect_cmd.go
// Description:   "netops log collect" and "netops log monitor": poll every
//                device's log buffer over SSH, run the events through the
//                pipeline (parse, watermark, classify, store, detect) and
//                auto-triage anomalies with read-only diagnostics.
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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"netops/internal/inventory"
	"netops/internal/log/collector"
	"netops/internal/log/parser"
	"netops/internal/log/pipeline"
	"netops/internal/log/query"
	"netops/internal/log/report"
	"netops/internal/log/store"
	"netops/internal/log/triage"
	"netops/internal/notifier"
	"netops/internal/task"
)

// logCollectOpts is the command line of "netops log collect" and "netops log
// monitor": the connection flags every connecting command shares, plus those
// specific to polling.
type logCollectOpts struct {
	logConn

	dataDir         string
	concurrency     int
	interval        time.Duration
	retentionDays   int
	afterHoursStart int
	afterHoursEnd   int
	dryRun          bool
	noColor         bool
	noConfigDiff    bool
	noPeerTriage    bool
	tui             bool
}

// logCollectFlagGroups organises the help of collect and monitor. Every flag of
// either command appears in one group (a test enforces it).
var logCollectFlagGroups = []flagGroup{
	{"Devices", []string{"inventory", "concurrency", "interval", "dry-run", "tui"}},
	{"Storage", []string{"data-dir", "retention-days"}},
	{"Connection", []string{"connect-timeout", "command-timeout", "env-file", "host-key-policy", "known-hosts", "legacy-algorithms"}},
	{"Jump hosts", []string{"jump", "jump-host"}},
	{"Triage and classification", []string{"no-config-diff", "no-peer-triage", "after-hours-start", "after-hours-end"}},
	{"Output", []string{"no-color"}},
}

const logCollectUsageText = `Usage: netops log collect [flags]

Polls every device in the inventory once: reads its log buffer, stores the new
events under --data-dir, runs the anomaly detector and captures read-only
diagnostics (show/display commands only) for the incidents it finds. Exits when
the cycle is done; a cycle in which no device could be polled exits 1.
Use --dry-run to test connectivity, authentication and clock skew first.
`

const logMonitorUsageText = `Usage: netops log monitor [flags]

Runs "netops log collect" in a loop every --interval until SIGINT/SIGTERM, then
waits for in-flight polls and triage and exits 0. With --tui the live dashboard
("netops log top") is shown in the same terminal and log lines go to
<data-dir>/monitor.log.
`

// newLogCollectFlagSet declares the flags of collect (monitor=false) or monitor.
func newLogCollectFlagSet(o *logCollectOpts, stderr io.Writer, monitor bool) *flag.FlagSet {
	name, usage := "collect", logCollectUsageText
	if monitor {
		name, usage = "monitor", logMonitorUsageText
	}
	fs := newLogFlagSet(name, stderr, usage, logCollectFlagGroups)
	o.register(fs)
	fs.StringVar(&o.dataDir, "data-dir", "data", "base directory for logs/, incidents/ and state files")
	fs.IntVar(&o.concurrency, "concurrency", 10, "number of devices polled in parallel")
	fs.IntVar(&o.retentionDays, "retention-days", 0, "delete daily log files older than this many days (0 = keep everything)")
	registerAfterHours(fs, &o.afterHoursStart, &o.afterHoursEnd)
	fs.BoolVar(&o.noColor, "no-color", false, "disable coloured output")
	fs.BoolVar(&o.noConfigDiff, "no-config-diff", false, "do not open an SSH session to capture a configuration diff after a configuration change")
	fs.BoolVar(&o.noPeerTriage, "no-peer-triage", false, "do not triage the neighbour at the other end of a faulted link")
	if monitor {
		fs.DurationVar(&o.interval, "interval", collector.DefaultInterval, "polling interval; devices start staggered across the first part of it")
		fs.BoolVar(&o.tui, "tui", false, "show the live terminal dashboard (as 'netops log top') while monitoring; log lines go to <data-dir>/monitor.log")
	} else {
		fs.BoolVar(&o.dryRun, "dry-run", false, "test connectivity, authentication and clock skew without saving logs or running triage")
	}
	return fs
}

func (o *logCollectOpts) validate(monitor bool) error {
	switch {
	case o.concurrency < 1:
		return errors.New("--concurrency must be at least 1")
	case o.dataDir == "":
		return errors.New("--data-dir must not be empty")
	case o.retentionDays < 0:
		return errors.New("--retention-days must not be negative")
	case o.afterHoursStart < 0 || o.afterHoursStart > 23 || o.afterHoursEnd < 0 || o.afterHoursEnd > 23:
		return errors.New("--after-hours-start and --after-hours-end must be between 0 and 23")
	case monitor && o.interval < 10*time.Second:
		return errors.New("--interval must be at least 10s")
	}
	return o.validateConn()
}

// runLogCollect is "netops log collect" (monitor=false) and "netops log monitor".
func runLogCollect(args []string, stdin *os.File, stdout, stderr io.Writer, monitor bool) int {
	name := "collect"
	if monitor {
		name = "monitor"
	}
	var o logCollectOpts
	fs := newLogCollectFlagSet(&o, stderr, monitor)
	if code, ok := parseLogFlags(fs, args); !ok {
		return code
	}
	if code, ok := logNoArgs(fs, stderr, name); !ok {
		return code
	}
	if err := o.validate(monitor); err != nil {
		return logFail(stderr, name, "%v", err)
	}

	if monitor && o.tui {
		return runLogMonitorTUI(o, stdin, stdout, stderr)
	}

	log := &logLogger{w: stderr}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if o.dryRun {
		return runLogDryRun(ctx, o, stdin, stdout, stderr, log)
	}

	a, err := newLogApp(o, stdin, stderr, log)
	if err != nil {
		log.Error("%v", err)
		if logMissingFile(o.inventory, err) {
			fmt.Fprint(stderr, logInitTip)
		}
		return task.ExitFatal
	}
	defer a.close()

	if !monitor {
		st := a.cycle(ctx)
		a.engine.Wait()
		if ctx.Err() != nil {
			log.Warn("interrupted before the cycle finished")
			return task.ExitFatal
		}
		// Individual device failures are normal and exit 0, but a cycle in
		// which not one device could be polled (wrong credentials, network
		// down, empty vendor support) must not look like success to cron.
		if st.polled == 0 {
			log.Error("no device could be polled")
			return task.ExitFatal
		}
		return task.ExitOK
	}

	a.monitorLoop(ctx, o, log)
	return task.ExitOK
}

// newLogApp opens everything a collect/monitor run needs: inventory, credentials,
// the data directory and its lock, state, the collector, triage engine and
// Telegram notifier.
func newLogApp(o logCollectOpts, stdin *os.File, stderr io.Writer, log *logLogger) (*logApp, error) {
	devices, warns := inventory.LoadLenient(o.inventory)
	for _, w := range warns {
		if len(devices) == 0 {
			return nil, w
		}
		log.Warn("inventory: %v", w)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("inventory %q contains no devices (tip: run 'netops init' to create sample inventory.csv and .env templates)", o.inventory)
	}
	seen := make(map[string]bool, len(devices))
	for _, d := range devices {
		if seen[d.Hostname] {
			log.Warn("inventory: hostname %q appears more than once; watermarks and cooldowns are keyed by hostname, so use unique names", d.Hostname)
		}
		seen[d.Hostname] = true
	}

	tp, err := o.transport(stdin, stderr, log)
	if err != nil {
		return nil, err
	}
	tp.resolveGroups(devices, log)

	if err := os.MkdirAll(o.dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}
	// One collector per data directory: each run keeps its watermarks in
	// memory and rewrites the state file, so two overlapping runs (a slow
	// cron job still going when the next starts) would overwrite each other's
	// progress and store duplicates.
	release, err := lockLogDataDir(o.dataDir)
	if err != nil {
		return nil, err
	}
	state, err := store.LoadState(store.StatePath(o.dataDir))
	if err != nil {
		release()
		return nil, err
	}
	writer, err := store.NewJSONLWriter(o.dataDir)
	if err != nil {
		release()
		return nil, err
	}
	// Health is diagnostics only: a bad file is reported and replaced, and
	// never stops collection.
	health, err := store.LoadHealth(store.HealthPath(o.dataDir))
	if err != nil {
		log.Warn("%v", err)
	}

	interval := o.interval
	if interval <= 0 {
		interval = collector.DefaultInterval
	}
	coll := collector.New(collector.Config{
		Concurrency:     o.concurrency,
		Interval:        interval,
		SSH:             tp.ssh,
		CredStore:       tp.resolver,
		JumpEnabled:     o.jump,
		JumpDefaultHost: o.jumpHost,
		ClockParser:     pipeline.ParseDeviceClock,
		Logger:          log,
	})

	tgCfg := notifier.ConfigForLog(tp.resolver)
	tg := notifier.NewTelegramWithLogger(tgCfg, log)
	if tg != nil {
		log.Info("telegram alerts enabled (chat_id: %s)", tgCfg.ChatID)
	}

	var peerInventory []inventory.Device // nil disables topology-aware peer triage
	if !o.noPeerTriage {
		peerInventory = devices
	}
	var hook triage.Hook
	if tg != nil {
		hook = tg
	}
	engine, err := triage.New(triage.Config{
		DataDir:         o.dataDir,
		SSH:             tp.ssh,
		CredStore:       tp.resolver,
		JumpEnabled:     o.jump,
		JumpDefaultHost: o.jumpHost,
		Logger:          log,
		Hook:            hook,
		Inventory:       peerInventory,
	})
	if err != nil {
		if tg != nil {
			tg.Close()
		}
		_ = writer.Close()
		release()
		return nil, err
	}

	// Seed the anomaly windows from the last few minutes of stored events, so
	// a cron-driven "collect" (a new process every run) still sees flaps,
	// login bursts and config changes that straddle two runs.
	det := pipeline.NewDetector(pipeline.DetectorConfig{ConfigSignals: !o.noConfigDiff})
	if recent, err := query.LoadTail(o.dataDir, query.Filter{Since: time.Now().Add(-logPrimeWindow)}, logPrimeTailBytes); err != nil {
		log.Warn("priming anomaly detector from stored logs: %v", err)
	} else {
		det.Prime(recent)
	}

	counters, err := store.LoadCounters(store.CountersPath(o.dataDir))
	if err != nil {
		log.Warn("loading counters: %v", err)
	}

	return &logApp{
		opts:      o,
		log:       log,
		devices:   devices,
		collector: coll,
		marks:     pipeline.NewWatermarks(state),
		health:    health,
		classifier: pipeline.NewClassifierWithOptions(pipeline.ClassifierOptions{
			Location:        time.Local,
			AfterHoursStart: o.afterHoursStart,
			AfterHoursEnd:   o.afterHoursEnd,
		}),
		detector: det,
		writer:   writer,
		engine:   engine,
		telegram: tg,
		counters: counters,
		loc:      time.Local,
		warnedAt: make(map[string]time.Time),
		failing:  make(map[string]string),
		unlock:   release,
	}, nil
}

// monitorLoop polls on the configured interval until ctx is cancelled.
func (a *logApp) monitorLoop(ctx context.Context, o logCollectOpts, log *logLogger) {
	log.Info("netops log monitor started: %d device(s), interval %s", len(a.devices), o.interval)
	for ctx.Err() == nil {
		began := time.Now()
		_ = a.cycle(ctx)

		wait := o.interval - time.Since(began)
		if wait < 0 {
			log.Warn("cycle took %s, longer than the %s interval; starting the next one immediately (lower --concurrency pressure or raise --interval)",
				time.Since(began).Round(time.Second), o.interval)
			wait = 0
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	log.Info("shutting down: waiting for in-flight triage")
}

// logApp holds everything a collect/monitor run needs.
type logApp struct {
	opts    logCollectOpts
	log     *logLogger
	devices []inventory.Device

	collector  *collector.Collector
	marks      *pipeline.Watermarks
	health     *store.Health // per-device poll health, for "netops log status" and the report
	classifier *pipeline.Classifier
	detector   *pipeline.Detector
	writer     *store.JSONLWriter
	engine     *triage.Engine
	telegram   *notifier.TelegramNotifier
	counters   *store.FleetCounters

	loc *time.Location

	warnedMu sync.Mutex
	warnedAt map[string]time.Time

	// failing remembers each device's last poll error so a persistent
	// failure is logged once, and its recovery once, instead of every cycle.
	// Only the single result-processing goroutine touches it.
	failing map[string]string

	unlock func() // releases the data-directory lock
}

// How much stored history seeds the detector at startup: the longest window
// any rule uses is the 10-minute config correlation, plus margin.
const (
	logPrimeWindow    = 15 * time.Minute
	logPrimeTailBytes = 16 << 20 // read at most the last 16 MiB of each daily file
)

func (a *logApp) close() {
	if a.telegram != nil {
		a.telegram.Close()
	}
	a.engine.Close()
	if err := a.marks.Save(); err != nil {
		a.log.Warn("saving watermarks: %v", err)
	}
	if a.counters != nil {
		if err := store.SaveCounters(store.CountersPath(a.opts.dataDir), a.counters); err != nil {
			a.log.Warn("saving counters: %v", err)
		}
	}
	_ = a.writer.Close()
	a.unlock()
}

// errLogAlreadyRunning is returned when another netops log already holds the data
// directory's lock.
var errLogAlreadyRunning = errors.New("another netops log collect/monitor is already running on this data directory")

// warnEvery logs a warning for key at most once per `every` (once per run if
// every is zero), so a condition that persists across polls (unparseable
// log format, repeated gaps) does not repeat on every cycle.
func (a *logApp) warnEvery(key string, every time.Duration, format string, args ...any) {
	a.warnedMu.Lock()
	last, seen := a.warnedAt[key]
	due := !seen || (every > 0 && time.Since(last) >= every)
	if due {
		a.warnedAt[key] = time.Now()
	}
	a.warnedMu.Unlock()
	if due {
		a.log.Warn(format, args...)
	}
}

// logMaxPlausibleSkew is the largest clock error that is still believable as a
// real clock error plus a time-zone difference (zones span at most 14 hours).
// A measured skew beyond it points at a mis-set device clock or a clock
// reading that was misparsed.
const logMaxPlausibleSkew = 24 * time.Hour

type logCycleStats struct {
	polled, failed, entries, signals int
}

// cycle polls every device once and runs each result through the pipeline.
func (a *logApp) cycle(ctx context.Context) logCycleStats {
	began := time.Now()
	if a.opts.retentionDays > 0 {
		if n, err := store.Prune(a.opts.dataDir, a.opts.retentionDays, began); err != nil {
			a.log.Warn("retention: %v", err)
		} else if n > 0 {
			a.log.Info("retention: removed %d log file(s) older than %d days", n, a.opts.retentionDays)
		}
	}

	var st logCycleStats
	for res := range a.collector.Run(ctx, a.devices) {
		a.safeProcess(ctx, res, &st)
	}
	if err := a.marks.Save(); err != nil {
		a.log.Warn("saving watermarks: %v", err)
	}
	if err := a.health.Save(); err != nil {
		a.log.Warn("saving collection health: %v", err)
	}
	a.log.Info("cycle complete: %d/%d device(s) polled (%d failed), %d new log entr%s, %d triage signal(s), %s",
		st.polled, len(a.devices), st.failed, st.entries, logPlural(st.entries, "y", "ies"), st.signals,
		time.Since(began).Round(100*time.Millisecond))
	return st
}

// safeProcess isolates one device's result: a bug triggered by one odd log
// buffer must cost that device's poll, not the whole monitor.
func (a *logApp) safeProcess(ctx context.Context, r collector.Result, st *logCycleStats) {
	defer func() {
		if p := recover(); p != nil {
			st.failed++
			a.health.Failed(r.Device.Hostname, time.Now(), fmt.Sprintf("internal error: %v", p), false)
			a.log.Error("%s: internal error while processing the poll result: %v", r.Device.Hostname, p)
		}
	}()
	a.process(ctx, r, st)
}

func logPlural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// process runs one device's poll result through the pipeline. Results arrive
// one at a time on a single goroutine, so the pipeline stages need no locking.
func (a *logApp) process(ctx context.Context, r collector.Result, st *logCycleStats) {
	host := r.Device.Hostname

	if r.Err != nil {
		st.failed++
		a.health.Failed(host, time.Now(), r.Err.Error(), errors.Is(r.Err, collector.ErrUnsupportedVendor))
		// Log a failure when it first appears or changes, not every cycle.
		if msg := r.Err.Error(); a.failing[host] != msg {
			a.failing[host] = msg
			if errors.Is(r.Err, collector.ErrUnsupportedVendor) {
				a.log.Warn("%s: %v (device skipped)", host, r.Err)
			} else {
				a.log.Warn("%s: poll failed: %v", host, r.Err)
				if a.telegram != nil {
					a.telegram.SendDeviceHealth(host, false, msg)
				}
			}
		}
		return
	}
	st.polled++
	a.health.Succeeded(host, time.Now())
	if _, was := a.failing[host]; was {
		delete(a.failing, host)
		a.log.Info("%s: poll recovered", host)
		if a.telegram != nil {
			a.telegram.SendDeviceHealth(host, true, "")
		}
	}

	// Stage 2 (parse). Stage 1 (watermark) needs entries to compare, so
	// parsing comes first; the watermark then discards everything seen before.
	parsed := parser.Parse(r.VendorKey, r.Raw, r.Device, parser.Options{Ref: r.FetchedAt, Location: a.loc})
	if len(parsed) == 0 {
		if n := logNonEmptyLines(r.Raw); n >= 5 {
			a.health.SetUnparseable(host, time.Now(), true)
			a.warnEvery("noparse:"+host, 0, "%s: %d lines of log output but none could be parsed as %s; check the device's log timestamp format (Cisco/Ruijie need 'service timestamps log datetime')", host, n, r.VendorKey)
		}
		return
	}
	a.health.SetUnparseable(host, time.Now(), false)

	// A line cannot be dated after "now" on the device. Such lines come from
	// a clock that was stepped forward and back; keeping them would drag the
	// watermark into the future and hide every genuine later line. The
	// device's "now" is the fetch time plus the measured skew (zero if the
	// skew is unknown, which widens the tolerance accordingly).
	deviceNow := r.FetchedAt
	if r.SkewOK {
		deviceNow = deviceNow.Add(time.Duration(r.SkewMs) * time.Millisecond)
	}
	var dropped int
	if parsed, dropped = pipeline.DropFuture(parsed, deviceNow, pipeline.FutureTolerance(r.VendorKey, r.SkewOK)); dropped > 0 {
		a.warnEvery("future:"+host, time.Hour, "%s: ignored %d log line(s) dated in the future (device clock stepped?)", host, dropped)
	}
	if r.SkewOK && (time.Duration(r.SkewMs)*time.Millisecond > logMaxPlausibleSkew || time.Duration(r.SkewMs)*time.Millisecond < -logMaxPlausibleSkew) {
		a.warnEvery("skew:"+host, 0, "%s: device clock differs from this host by %s, more than any time-zone difference explains; its timestamps are being corrected by that amount, so check the device's clock and timezone settings", host, (time.Duration(r.SkewMs) * time.Millisecond).Round(time.Minute))
	}

	if a.marks.PossibleGap(host, parsed) {
		a.warnEvery("gap:"+host, time.Hour, "%s: every line in the fetched log buffer is newer than the last poll, so events in between were probably missed; the device logs faster than it is polled for its buffer size (poll more often or enlarge the device's log buffer)", host)
	}

	fresh := a.marks.Filter(host, parsed)
	if len(fresh) == 0 {
		return
	}
	pipeline.Normalize(fresh, r.SkewMs, r.SkewOK)
	a.classifier.ClassifyAll(fresh)

	// Advance the watermark over the full batch (including own-session lines)
	// before suppressing them.  This ensures suppressed entries are never
	// re-presented on the next poll, while also never hitting disk.
	a.marks.Advance(host, fresh)
	if err := a.marks.Save(); err != nil {
		a.log.Warn("%s: saving watermark: %v", host, err)
	}

	// Drop PAM / systemd session-tracking lines generated by our own SSH
	// polling sessions; they carry no diagnostic value.
	fresh = pipeline.SuppressOwn(fresh)
	if len(fresh) == 0 {
		return
	}

	// Store entries; a failed write leaves the watermark already advanced, so
	// the batch is lost rather than retried.  Acceptable: these lines would
	// reappear on the next poll only if the device still has them in its
	// buffer, which is the normal retry path for transient write errors.
	if err := a.writer.Append(fresh); err != nil {
		a.log.Error("%s: storing %d entries: %v", host, len(fresh), err)
		return
	}
	st.entries += len(fresh)
	a.health.NewLogs(host, time.Now())

	// Stage 4: anomaly detection runs after the commit, so a retried batch
	// cannot double-count toward a flap or brute-force threshold.
	var signals []pipeline.TriageSignal
	for _, e := range fresh {
		signals = append(signals, a.detector.Observe(e)...)
	}
	var derived []collector.LogEntry
	for _, s := range signals {
		if s.Derived {
			derived = append(derived, s.Entry)
		}
	}
	if err := a.writer.Append(derived); err != nil {
		a.log.Warn("%s: storing derived events: %v", host, err)
	}

	for _, s := range signals {
		st.signals++
		a.log.Info("%s: %s detected (%s): %s", host, s.Entry.Event, s.Playbook, s.Entry.Summary)
		a.engine.Handle(ctx, s, r.Device)
	}
}

func logNonEmptyLines(s string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// ==============================================================================
// dry run
// ==============================================================================

type logDryResult struct {
	dev      inventory.Device
	vendor   string
	success  bool
	duration time.Duration
	skewMs   int64
	skewOK   bool
	bytes    int
	err      error
}

func runLogDryRun(ctx context.Context, o logCollectOpts, stdin *os.File, stdout, stderr io.Writer, log *logLogger) int {
	devices, warns := inventory.LoadLenient(o.inventory)
	for _, w := range warns {
		log.Warn("inventory: %v", w)
	}
	if len(devices) == 0 {
		log.Error("inventory %q contains no devices", o.inventory)
		if logMissingFile(o.inventory, nil) {
			fmt.Fprint(stderr, logInitTip)
		}
		return task.ExitFatal
	}

	tp, err := o.transport(stdin, stderr, log)
	if err != nil {
		log.Error("%v", err)
		return task.ExitFatal
	}
	tp.resolveGroups(devices, log)

	coll := collector.New(collector.Config{
		SSH:               tp.ssh,
		CredStore:         tp.resolver,
		JumpEnabled:       o.jump,
		JumpDefaultHost:   o.jumpHost,
		Concurrency:       o.concurrency,
		ClockParser:       pipeline.ParseDeviceClock,
		WarnOnSkewFailure: true,
		Logger:            log,
	})

	log.Info("dry-run: probing %d device(s) with concurrency %d...", len(devices), o.concurrency)
	began := time.Now()

	results := make([]logDryResult, 0, len(devices))
	for res := range coll.Run(ctx, devices) {
		dr := logDryResult{
			dev:      res.Device,
			vendor:   res.VendorKey,
			success:  res.Err == nil,
			duration: res.Duration,
			skewMs:   res.SkewMs,
			skewOK:   res.SkewOK,
			bytes:    len(res.Raw),
			err:      res.Err,
		}
		results = append(results, dr)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].dev.Hostname < results[j].dev.Hostname
	})

	useColor := logColorEnabled(stdout, o.noColor)
	printLogDryRunTable(stdout, results, useColor)

	succeeded := 0
	for _, r := range results {
		if r.success {
			succeeded++
		}
	}

	log.Info("dry-run complete: %d/%d device(s) connected successfully in %s (0 logs written, 0 watermarks saved)",
		succeeded, len(devices), time.Since(began).Round(10*time.Millisecond))

	if succeeded == 0 {
		return task.ExitFatal
	}
	return task.ExitOK
}

func printLogDryRunTable(w io.Writer, results []logDryResult, useColor bool) {
	if len(results) == 0 {
		return
	}

	cols := []report.Column{
		{Title: "DEVICE", Limit: 64, Right: false},
		{Title: "ADDRESS", Limit: 24, Right: false},
		{Title: "VENDOR", Limit: 16, Right: false},
		{Title: "STATUS", Limit: 12, Right: false},
		{Title: "DURATION", Limit: 12, Right: true},
		{Title: "SKEW", Limit: 10, Right: true},
		{Title: "NOTES", Limit: 60, Right: false},
	}

	rows := make([][]string, len(results))
	for i, r := range results {
		addr := r.dev.Address
		if r.dev.Port != 0 && r.dev.Port != 22 {
			addr = fmt.Sprintf("%s:%d", r.dev.Address, r.dev.Port)
		}

		status := "✔ OK"
		notes := "Connected"
		if r.bytes > 0 {
			notes = fmt.Sprintf("Connected (buffer: %d bytes)", r.bytes)
		}
		if r.dev.JumpHost != "" {
			notes += " via " + r.dev.JumpHost
		}
		if !r.success {
			status = "✖ FAIL"
			notes = r.err.Error()
		}

		skewStr := "-"
		if r.skewOK {
			skewStr = fmt.Sprintf("%+dms", r.skewMs)
		}
		durStr := r.duration.Round(time.Millisecond).String()

		rows[i] = []string{r.dev.Hostname, addr, r.vendor, status, durStr, skewStr, notes}
	}

	st := query.Style{Color: useColor}
	_ = report.WriteBoxTable(w, st, cols, rows, func(rowIdx int, cellText string) string {
		if !results[rowIdx].success {
			return st.Red(cellText)
		}
		if strings.Contains(cellText, "OK") {
			return st.Green(cellText)
		}
		return cellText
	})
	fmt.Fprintln(w)
}

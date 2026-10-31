// ==============================================================================
// File name:     log_query_cmd.go
// Description:   The read-only reporting subcommands of "netops log": query,
//                timeline, incidents, report and status. They read the data
//                directory only and can run next to a monitor or listener.
// License:       MIT
// ==============================================================================

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"netops/internal/inventory"
	"netops/internal/log/collector"
	"netops/internal/log/query"
	"netops/internal/log/report"
	"netops/internal/log/store"
	"netops/internal/task"
)

const (
	logQueryUsageText = `Usage: netops log query [flags]

Searches the stored events (newest first). --limit takes comma-separated
hostname globs, as in the other netops commands.
`
	logTimelineUsageText = `Usage: netops log timeline [flags]

A cross-device chronological stream of the stored events in a time window, with
changes and faults on other devices annotated as likely causes. The window
defaults to the last hour. --limit narrows the stream, and so the cause
correlation, to the matching devices.
`
	logIncidentsUsageText = `Usage: netops log incidents [flags]

Lists the auto-triage incident reports captured by collect and monitor, or shows
one in full with --id (an ID prefix is enough). Reports are read-only
diagnostics: only show/display commands are ever sent to a device.
`
	logReportUsageText = `Usage: netops log report [flags]

A digest over the stored data: noisy devices, change accountability, the
security watchlist, week-over-week trends, MTTR and collection health.
`
	logStatusUsageText = `Usage: netops log status [flags]

Per-device collection health: which devices could not be polled and since when,
which are reachable but silent, and which nothing has tried to poll. With --fail
it exits 1 when any device is not OK, for cron and monitoring.
`
)

var (
	logQueryFlagGroups = []flagGroup{
		{"Filters", []string{"limit", "user", "category", "severity", "event", "since"}},
		{"Output", []string{"format", "data-dir", "no-color"}},
	}
	logTimelineFlagGroups = []flagGroup{
		{"Window", []string{"from", "to", "limit", "all"}},
		{"Output", []string{"data-dir", "no-color"}},
	}
	logIncidentsFlagGroups = []flagGroup{
		{"Selection", []string{"id", "since"}},
		{"Output", []string{"format", "data-dir", "no-color"}},
	}
	logReportFlagGroups = []flagGroup{
		{"Window", []string{"since", "top", "compare"}},
		{"Output", []string{"format", "data-dir", "no-color"}},
	}
	logStatusFlagGroups = []flagGroup{
		{"Devices", []string{"inventory", "stale-after", "silent-after", "fail"}},
		{"Output", []string{"format", "data-dir", "no-color"}},
	}
)

// logFilterEntries keeps the entries whose hostname matches.
func logFilterEntries(entries []collector.LogEntry, match func(string) bool) []collector.LogEntry {
	kept := entries[:0]
	for _, e := range entries {
		if match(e.Hostname) {
			kept = append(kept, e)
		}
	}
	return kept
}

var (
	logValidCategories = []string{"CONFIG", "AUTH", "FAULT", "SECURITY", "SYSTEM"}
	logValidSeverities = []string{"INFO", "WARNING", "ERROR", "CRITICAL"}
)

func logOneOf(v string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(v, a) {
			return true
		}
	}
	return false
}

func runLogQuery(args []string, stdout, stderr io.Writer) int {
	fs := newLogFlagSet("query", stderr, logQueryUsageText, logQueryFlagGroups)
	var limit string
	registerLimit(fs, &limit)
	var (
		user     = fs.String("user", "", "filter by user")
		category = fs.String("category", "", "CONFIG | AUTH | FAULT | SECURITY | SYSTEM")
		severity = fs.String("severity", "", "INFO | WARNING | ERROR | CRITICAL")
		event    = fs.String("event", "", "filter by event type (substring)")
		since    = fs.String("since", "24h", "time window: 30m, 2h, 24h, 7d, or today")
		format   = logFormatFlag(fs, "table")
		dataDir  = fs.String("data-dir", "data", "netops log data directory")
		noColor  = fs.Bool("no-color", false, "disable coloured output")
	)
	if code, ok := parseLogFlags(fs, args); !ok {
		return code
	}
	if code, ok := logNoArgs(fs, stderr, "query"); !ok {
		return code
	}
	if *category != "" && !logOneOf(*category, logValidCategories) {
		return logFail(stderr, "query", "--category must be one of %s", strings.Join(logValidCategories, ", "))
	}
	if *severity != "" && !logOneOf(*severity, logValidSeverities) {
		return logFail(stderr, "query", "--severity must be one of %s", strings.Join(logValidSeverities, ", "))
	}
	if !validLogFormat(*format) {
		return logFail(stderr, "query", "--format must be table or json")
	}
	matchHost, err := logLimitFilter(limit)
	if err != nil {
		return logFail(stderr, "query", "%v", err)
	}
	from, err := query.ParseSince(*since, time.Now())
	if err != nil {
		return logFail(stderr, "query", "%v", err)
	}

	entries, err := query.Load(*dataDir, query.Filter{
		User: *user, Category: *category, Severity: *severity, Event: *event,
		Since: from, Until: time.Now(),
	})
	if err != nil {
		return logFail(stderr, "query", "%v", err)
	}
	entries = logFilterEntries(entries, matchHost)
	query.SortNewestFirst(entries)

	if *format == "json" {
		err = query.WriteJSON(stdout, entries)
	} else {
		err = query.WriteTable(stdout, entries, query.Style{Color: logColorEnabled(stdout, *noColor)})
	}
	if err != nil {
		return logFail(stderr, "query", "%v", err)
	}
	return task.ExitOK
}

// ==============================================================================
// timeline
// ==============================================================================

func runLogTimeline(args []string, stdout, stderr io.Writer) int {
	fs := newLogFlagSet("timeline", stderr, logTimelineUsageText, logTimelineFlagGroups)
	var limit string
	registerLimit(fs, &limit)
	var (
		fromS   = fs.String("from", "", `window start: "2006-01-02 15:04:05" (local) or RFC 3339 (default: one hour ago)`)
		toS     = fs.String("to", "", "window end, same formats (default: now)")
		dataDir = fs.String("data-dir", "data", "netops log data directory")
		all     = fs.Bool("all", false, "include unclassified (UNKNOWN) events")
		noColor = fs.Bool("no-color", false, "disable coloured output")
	)
	if code, ok := parseLogFlags(fs, args); !ok {
		return code
	}
	if code, ok := logNoArgs(fs, stderr, "timeline"); !ok {
		return code
	}

	matchHost, err := logLimitFilter(limit)
	if err != nil {
		return logFail(stderr, "timeline", "%v", err)
	}
	now := time.Now()
	from, to := now.Add(-time.Hour), now
	if *fromS != "" {
		if from, err = query.ParseTime(*fromS, time.Local); err != nil {
			return logFail(stderr, "timeline", "--from: %v", err)
		}
	}
	if *toS != "" {
		if to, err = query.ParseTime(*toS, time.Local); err != nil {
			return logFail(stderr, "timeline", "--to: %v", err)
		}
	}
	if to.Before(from) {
		return logFail(stderr, "timeline", "--to is before --from")
	}

	// Load a correlation window of history before --from so a fault at the
	// very start of the window can still be tied to the change that preceded it.
	entries, err := query.Load(*dataDir, query.Filter{Since: from.Add(-query.CorrelationWindow), Until: to})
	if err != nil {
		return logFail(stderr, "timeline", "%v", err)
	}
	entries = logFilterEntries(entries, matchHost)
	rows := query.BuildTimeline(entries, query.TimelineOptions{From: from, IncludeUnknown: *all})
	if err := query.WriteTimeline(stdout, rows, query.Style{Color: logColorEnabled(stdout, *noColor)}); err != nil {
		return logFail(stderr, "timeline", "%v", err)
	}
	return task.ExitOK
}

// ==============================================================================
// incidents
// ==============================================================================

func runLogIncidents(args []string, stdout, stderr io.Writer) int {
	fs := newLogFlagSet("incidents", stderr, logIncidentsUsageText, logIncidentsFlagGroups)
	var (
		since   = fs.String("since", "24h", "list incidents from this window: 30m, 2h, 24h, 7d, or today")
		id      = fs.String("id", "", "show one full incident report by ID prefix")
		format  = logFormatFlag(fs, "table")
		dataDir = fs.String("data-dir", "data", "netops log data directory")
		noColor = fs.Bool("no-color", false, "disable coloured output")
	)
	if code, ok := parseLogFlags(fs, args); !ok {
		return code
	}
	if code, ok := logNoArgs(fs, stderr, "incidents"); !ok {
		return code
	}
	if !validLogFormat(*format) {
		return logFail(stderr, "incidents", "--format must be table or json")
	}
	dir := store.IncidentsDir(*dataDir)

	if *id != "" {
		report, err := store.FindIncident(dir, *id)
		if err != nil {
			return logFail(stderr, "incidents", "%v", err)
		}
		if *format == "json" {
			err = query.WriteIncidentJSON(stdout, report)
		} else {
			err = query.WriteIncidentDetail(stdout, report, query.Style{Color: logColorEnabled(stdout, *noColor)})
		}
		if err != nil {
			return logFail(stderr, "incidents", "%v", err)
		}
		return task.ExitOK
	}

	from, err := query.ParseSince(*since, time.Now())
	if err != nil {
		return logFail(stderr, "incidents", "%v", err)
	}
	reports, err := store.ListIncidents(dir, from)
	if err != nil {
		return logFail(stderr, "incidents", "%v", err)
	}
	if *format == "json" {
		if reports == nil {
			reports = []collector.IncidentReport{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(reports)
	} else {
		err = query.WriteIncidentList(stdout, reports, query.Style{Color: logColorEnabled(stdout, *noColor)})
	}
	if err != nil {
		return logFail(stderr, "incidents", "%v", err)
	}
	return task.ExitOK
}

// ==============================================================================
// report
// ==============================================================================

func runLogReport(args []string, stdout, stderr io.Writer) int {
	fs := newLogFlagSet("report", stderr, logReportUsageText, logReportFlagGroups)
	var (
		since   = fs.String("since", "7d", "time window: 30m, 2h, 24h, 7d, or today")
		top     = fs.Int("top", report.DefaultTop, "rows shown in the noisy-device and watchlist rankings")
		compare = fs.Bool("compare", false, "force the week-over-week delta on or off (default: on only when --since is exactly 7d)")
		format  = logFormatFlag(fs, "table")
		dataDir = fs.String("data-dir", "data", "netops log data directory")
		noColor = fs.Bool("no-color", false, "disable coloured output")
	)
	if code, ok := parseLogFlags(fs, args); !ok {
		return code
	}
	if code, ok := logNoArgs(fs, stderr, "report"); !ok {
		return code
	}
	if !validLogFormat(*format) {
		return logFail(stderr, "report", "--format must be table or json")
	}
	if *top < 1 {
		return logFail(stderr, "report", "--top must be at least 1")
	}
	now := time.Now()
	from, err := query.ParseSince(*since, now)
	if err != nil {
		return logFail(stderr, "report", "%v", err)
	}

	// The delta compares the window with the equal-length one before it. It
	// defaults to on for exactly one week; an explicit --compare either way wins.
	window := now.Sub(from)
	doCompare := window == report.Week
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "compare" {
			doCompare = *compare
		}
	})
	if window <= 0 {
		doCompare = false
	}

	// Load back to the start of the previous window when it is needed.
	loadFrom := from
	if doCompare {
		loadFrom = from.Add(-window)
	}
	// Collection health is what netops log last saw of each device, not a
	// property of the window. A bad health file is worth a warning only.
	health, err := store.LoadHealth(store.HealthPath(*dataDir))
	if err != nil {
		fmt.Fprintf(stderr, "netops log report: warning: %v\n", err)
	}

	// Load interface counters snapshot if available
	var ifaceDeltas []collector.InterfaceDelta
	fc, err := store.LoadCounters(store.CountersPath(*dataDir))
	if err == nil && fc != nil && len(fc.Devices) > 0 {
		for dev, ifaces := range fc.Devices {
			for name, cnt := range ifaces {
				ifaceDeltas = append(ifaceDeltas, collector.InterfaceDelta{
					Device:       dev,
					Interface:    name,
					DurationSec:  float64(time.Since(cnt.Timestamp).Seconds()),
					InBps:        0,
					OutBps:       0,
					InErrorDiff:  cnt.InErrors,
					OutErrorDiff: cnt.OutErrors,
					InDropDiff:   cnt.InDiscards,
					OutDropDiff:  cnt.OutDiscards,
				})
			}
		}
		sort.Slice(ifaceDeltas, func(i, j int) bool {
			totI := ifaceDeltas[i].InDropDiff + ifaceDeltas[i].OutDropDiff + ifaceDeltas[i].InErrorDiff
			totJ := ifaceDeltas[j].InDropDiff + ifaceDeltas[j].OutDropDiff + ifaceDeltas[j].InErrorDiff
			if totI != totJ {
				return totI > totJ
			}
			return ifaceDeltas[i].Device < ifaceDeltas[j].Device
		})
		if len(ifaceDeltas) > *top {
			ifaceDeltas = ifaceDeltas[:*top]
		}
	}

	// Stream the logs into the report: memory stays proportional to the
	// number of devices and sources, not to the volume of history.
	b := report.NewBuilder(report.Options{
		Since: from, Until: now, Top: *top, Compare: doCompare,
		Label:           strings.ToLower(strings.TrimSpace(*since)),
		Devices:         report.DeviceStatuses(health.All(), nil, now, store.DefaultStaleAfter, store.DefaultSilentAfter),
		InterfaceDeltas: ifaceDeltas,
	})
	if err := query.Scan(*dataDir, query.Filter{Since: loadFrom, Until: now}, b.AddEntry); err != nil {
		return logFail(stderr, "report", "%v", err)
	}
	incidents, err := store.ListIncidents(store.IncidentsDir(*dataDir), from)
	if err != nil {
		return logFail(stderr, "report", "%v", err)
	}
	for _, inc := range incidents {
		b.AddIncident(inc)
	}
	rep := b.Build()
	if *format == "json" {
		err = report.WriteJSON(stdout, rep)
	} else {
		err = report.WriteTable(stdout, rep, query.Style{Color: logColorEnabled(stdout, *noColor)})
	}
	if err != nil {
		return logFail(stderr, "report", "%v", err)
	}
	return task.ExitOK
}

// ==============================================================================
// status
// ==============================================================================

func runLogStatus(args []string, stdout, stderr io.Writer) int {
	fs := newLogFlagSet("status", stderr, logStatusUsageText, logStatusFlagGroups)
	var (
		invPath     = fs.String("inventory", "inventory.csv", "path to the device inventory CSV (devices in it that were never polled are listed)")
		dataDir     = fs.String("data-dir", "data", "netops log data directory")
		staleAfter  = fs.Duration("stale-after", store.DefaultStaleAfter, "report a device as STALE when nothing has tried to poll it for this long")
		silentAfter = fs.Duration("silent-after", store.DefaultSilentAfter, "report a device as SILENT when it is reachable but has produced no new log line for this long")
		format      = logFormatFlag(fs, "table")
		failOnBad   = fs.Bool("fail", false, "exit 1 when any device is not OK (for cron and monitoring)")
		noColor     = fs.Bool("no-color", false, "disable coloured output")
	)
	if code, ok := parseLogFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 0 {
		return logFail(stderr, "status", "unexpected argument %q", fs.Arg(0))
	}
	if !validLogFormat(*format) {
		return logFail(stderr, "status", "--format must be table or json")
	}
	if *staleAfter <= 0 || *silentAfter <= 0 {
		return logFail(stderr, "status", "--stale-after and --silent-after must be positive")
	}

	health, err := store.LoadHealth(store.HealthPath(*dataDir))
	if err != nil {
		fmt.Fprintf(stderr, "netops log status: warning: %v\n", err)
	}

	// The inventory adds the devices that were never polled. Without it the
	// command still reports everything netops log has recorded.
	var hostnames []string
	devices, warns := inventory.LoadLenient(*invPath)
	if len(devices) == 0 && len(warns) > 0 {
		fmt.Fprintf(stderr, "netops log status: inventory not read (%v); listing recorded devices only\n", warns[0])
	}
	for _, d := range devices {
		hostnames = append(hostnames, d.Hostname)
	}

	rows := report.DeviceStatuses(health.All(), hostnames, time.Now(), *staleAfter, *silentAfter)
	if *format == "json" {
		err = report.WriteDeviceStatusJSON(stdout, rows)
	} else {
		err = report.WriteDeviceStatus(stdout, rows, query.Style{Color: logColorEnabled(stdout, *noColor)})
	}
	if err != nil {
		return logFail(stderr, "status", "%v", err)
	}
	if *failOnBad {
		for _, r := range rows {
			if r.Status != string(store.StatusOK) {
				return task.ExitFatal
			}
		}
	}
	return task.ExitOK
}

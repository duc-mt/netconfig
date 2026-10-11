// ==============================================================================
// Package main implements Implementation and logic for summary..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run summary.go [options]
// Notes:         Go package implementation
// ==============================================================================
package task

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Summary aggregates the results of a run.
type Summary struct {
	Results   []Result
	Succeeded int
	Failed    int
	Skipped   int
	// ByCategory lists, per failure/skip category, the affected hosts.
	ByCategory map[Category][]string
}

// Summarize counts outcomes and groups hosts by failure/skip category.
func Summarize(results []Result) Summary {
	s := Summary{Results: results, ByCategory: make(map[Category][]string)}
	for _, r := range results {
		switch r.Status {
		case StatusSucceeded:
			s.Succeeded++
		case StatusFailed:
			s.Failed++
		case StatusSkipped:
			s.Skipped++
		}
		if r.Status != StatusSucceeded && r.Category != "" {
			s.ByCategory[r.Category] = append(s.ByCategory[r.Category], r.Device.Hostname)
		}
	}
	return s
}

// ExitCode is ExitOK only when every selected device succeeded; any failure or
// skipped device yields ExitPartial.
func ExitCode(results []Result) int {
	for _, r := range results {
		if r.Status != StatusSucceeded {
			return ExitPartial
		}
	}
	return ExitOK
}

const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiBold   = "\x1b[1m"
)

// RenderOptions controls how Render formats the summary table.
type RenderOptions struct {
	Color  bool // colorize the STATUS column and the totals line
	DryRun bool // note in the title that nothing was committed or saved

	// Width is the terminal width to fit the table into. 0 (or negative)
	// means "no limit": natural column widths, nothing dropped or
	// shrunk. That's what the log file gets, since a file isn't
	// constrained to a fixed-width screen the way a console is.
	Width int
}

// displayOrder returns result indices with FAILED first, then SKIPPED, then
// SUCCEEDED -- the order an operator actually needs after a run, since the
// devices needing attention should be the first thing seen, not scattered
// through a wall of successes. Each group keeps its original (inventory)
// order.
func displayOrder(results []Result) []int {
	order := make([]int, len(results))
	for i := range order {
		order[i] = i
	}
	rank := func(s Status) int {
		switch s {
		case StatusFailed:
			return 0
		case StatusSkipped:
			return 1
		case StatusSucceeded:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		return rank(results[order[i]].Status) < rank(results[order[j]].Status)
	})
	return order
}

// appliedCell renders the APPLIED column: how many of a device's commands
// were actually sent and accepted, out of how many it was given. "-" for a
// device that was never run (skipped, or zero commands applied to it).
func appliedCell(r Result) string {
	if r.CommandsTotal == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d", r.CommandsApplied, r.CommandsTotal)
}

// backupCell renders the BACKUP column: whether a pre-change snapshot was
// taken, and if a rollback was attempted, its outcome.
func backupCell(r Result) string {
	if r.BackupPath == "" {
		return "-"
	}
	if s := r.Rollback.String(); s != "" {
		return s
	}
	return "SAVED"
}

// anyBackupActivity reports whether any result has a backup path, so the
// BACKUP column can be omitted entirely on a run that didn't use -backup
// instead of printing a column of dashes.
func anyBackupActivity(results []Result) bool {
	for _, r := range results {
		if r.BackupPath != "" {
			return true
		}
	}
	return false
}

// diffCell renders the DIFF column: how many configuration lines were
// added/removed by the change (see Options.ShowDiff), e.g. "+3/-1". "-"
// for a device with nothing to show (not used, or no textual difference).
func diffCell(r Result) string {
	if r.DiffAdded == 0 && r.DiffRemoved == 0 {
		return "-"
	}
	return fmt.Sprintf("+%d/-%d", r.DiffAdded, r.DiffRemoved)
}

// anyDiffActivity reports whether any result recorded a diff, so the DIFF
// column can be omitted entirely on a run that didn't use -show-diff.
func anyDiffActivity(results []Result) bool {
	for _, r := range results {
		if r.DiffAdded != 0 || r.DiffRemoved != 0 {
			return true
		}
	}
	return false
}

// Render formats the summary as a table plus per-category breakdowns. Rows
// are shown FAILED first, then SKIPPED, then SUCCEEDED (see displayOrder).
//
// When opts.Width is set and the table doesn't fit, less critical columns
// -- VENDOR, TIME, ADDRESS, then BACKUP and DIFF if present -- are dropped
// in that order before the DETAIL column is truncated further to make up
// the rest. With opts.Width <= 0 nothing is dropped or shrunk.
func (s Summary) Render(opts RenderOptions) string {
	var b strings.Builder

	title := "netconfig run summary"
	if opts.DryRun {
		title += " (DRY-RUN: nothing was committed or saved)"
	}
	if opts.Color {
		title = ansiBold + title + ansiReset
	}
	b.WriteString(title + "\n")

	order := displayOrder(s.Results)
	showBackup := anyBackupActivity(s.Results)
	showDiff := anyDiffActivity(s.Results)
	n := len(order)

	type column struct {
		header     string
		cells      []string
		alignRight bool
	}

	statusOf := make([]Status, n)
	hostCol := make([]string, n)
	addressCol := make([]string, n)
	vendorCol := make([]string, n)
	statusCol := make([]string, n)
	appliedCol := make([]string, n)
	backupCol := make([]string, n)
	diffCol := make([]string, n)
	reasonCol := make([]string, n)
	timeCol := make([]string, n)
	detailCol := make([]string, n)

	for i, ri := range order {
		r := s.Results[ri]
		statusOf[i] = r.Status
		hostCol[i] = r.Device.Hostname
		addressCol[i] = r.Device.Endpoint()
		vendorCol[i] = r.Device.Vendor
		statusCol[i] = statusBadge(r.Status)
		appliedCol[i] = appliedCell(r)
		backupCol[i] = backupCell(r)
		diffCol[i] = diffCell(r)
		if r.Category != "" {
			reasonCol[i] = string(r.Category)
		} else {
			reasonCol[i] = "-"
		}
		timeCol[i] = formatDuration(r.Duration)
		detailCol[i] = truncate(r.Detail, 90)
	}

	cols := []column{
		{"HOST", hostCol, false},
		{"ADDRESS", addressCol, false},
		{"VENDOR", vendorCol, false},
		{"STATUS", statusCol, false},
		{"APPLIED", appliedCol, true},
	}
	if showBackup {
		cols = append(cols, column{"BACKUP", backupCol, false})
	}
	if showDiff {
		cols = append(cols, column{"DIFF", diffCol, true})
	}
	cols = append(cols,
		column{"REASON", reasonCol, false},
		column{"TIME", timeCol, true},
		column{"DETAIL", detailCol, false},
	)

	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = utf8.RuneCountInString(c.header)
		for _, cell := range c.cells {
			if w := utf8.RuneCountInString(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}

	visible := make([]bool, len(cols))
	for i := range visible {
		visible[i] = true
	}

	colIndex := func(header string) int {
		for i, c := range cols {
			if c.header == header {
				return i
			}
		}
		return -1
	}
	totalWidth := func() int {
		t, count := 0, 0
		for i, v := range visible {
			if v {
				t += widths[i]
				count++
			}
		}
		if count > 0 {
			t += 3*count + 1
		}
		return t
	}

	if opts.Width > 0 {
		// Drop least-critical columns first, in this priority order, until
		// the table fits or there's nothing left to drop.
		for _, header := range []string{"APPLIED", "VENDOR", "TIME", "ADDRESS", "BACKUP", "DIFF"} {
			if totalWidth() <= opts.Width {
				break
			}
			if idx := colIndex(header); idx >= 0 {
				visible[idx] = false
			}
		}
		// Still too wide: shrink DETAIL (the one flexible column) to
		// whatever's left, rather than dropping a column an operator
		// actually needs.
		if totalWidth() > opts.Width {
			if idx := colIndex("DETAIL"); idx >= 0 {
				fixed := totalWidth() - widths[idx]
				budget := opts.Width - fixed
				const minDetail = 15
				if budget < minDetail {
					budget = minDetail
				}
				if budget < widths[idx] {
					widths[idx] = budget
					for i, cell := range cols[idx].cells {
						cols[idx].cells[i] = truncate(cell, budget)
					}
				}
			}
		}
	}

	writeBorder := func(left, mid, right string) {
		b.WriteString(left)
		first := true
		for i, v := range visible {
			if !v {
				continue
			}
			if !first {
				b.WriteString(mid)
			}
			first = false
			b.WriteString(strings.Repeat("─", widths[i]+2))
		}
		b.WriteString(right + "\n")
	}

	writeHeader := func() {
		writeBorder("╭", "┬", "╮")
		b.WriteString("│")
		for i, c := range cols {
			if !visible[i] {
				continue
			}
			b.WriteString(" ")
			pad := strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c.header))
			if c.alignRight {
				b.WriteString(pad + c.header)
			} else {
				b.WriteString(c.header + pad)
			}
			b.WriteString(" │")
		}
		b.WriteByte('\n')
		writeBorder("├", "┼", "┤")
	}

	writeData := func(rowIdx int) {
		st := statusOf[rowIdx]
		b.WriteString("│")
		for i, c := range cols {
			if !visible[i] {
				continue
			}
			cell := c.cells[rowIdx]
			b.WriteString(" ")
			pad := strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell))
			var content string
			if c.alignRight {
				content = pad + cell
			} else {
				content = cell + pad
			}
			if opts.Color && c.header == "STATUS" {
				b.WriteString(statusColor(st) + content + ansiReset)
			} else {
				b.WriteString(content)
			}
			b.WriteString(" │")
		}
		b.WriteByte('\n')
	}

	writeHeader()
	for i := 0; i < n; i++ {
		writeData(i)
	}
	if n > 0 {
		writeBorder("╰", "┴", "╯")
	}

	colorize := func(c, text string) string {
		if !opts.Color {
			return text
		}
		return c + text + ansiReset
	}
	fmt.Fprintf(&b, "\n  %s  │  %s  │  %s  │  (total %d)\n",
		colorize(ansiGreen, fmt.Sprintf("✔ Succeeded: %d", s.Succeeded)),
		colorize(ansiRed, fmt.Sprintf("✖ Failed: %d", s.Failed)),
		colorize(ansiYellow, fmt.Sprintf("⊘ Skipped: %d", s.Skipped)),
		len(s.Results))

	s.writeCategories(&b, "Failure reasons", StatusFailed)
	s.writeCategories(&b, "Skipped reasons", StatusSkipped)
	return b.String()
}

// writeCategories lists category counts for devices with the given status.
func (s Summary) writeCategories(b *strings.Builder, title string, status Status) {
	hostsBy := make(map[Category][]string)
	for _, r := range s.Results {
		if r.Status == status && r.Category != "" {
			hostsBy[r.Category] = append(hostsBy[r.Category], r.Device.Hostname)
		}
	}
	if len(hostsBy) == 0 {
		return
	}
	cats := make([]string, 0, len(hostsBy))
	for c := range hostsBy {
		cats = append(cats, string(c))
	}
	sort.Strings(cats)

	fmt.Fprintf(b, "\n%s:\n", title)
	for _, c := range cats {
		hosts := hostsBy[Category(c)]
		shown := hosts
		more := ""
		if len(shown) > 8 {
			shown = shown[:8]
			more = fmt.Sprintf(" ... +%d more", len(hosts)-8)
		}
		fmt.Fprintf(b, "  %-20s %3d  %s%s\n", c, len(hosts), strings.Join(shown, ", "), more)
	}
}

func statusBadge(s Status) string {
	switch s {
	case StatusSucceeded:
		return "✔ SUCCEEDED"
	case StatusFailed:
		return "✖ FAILED"
	case StatusSkipped:
		return "⊘ SKIPPED"
	}
	return s.String()
}

func statusColor(s Status) string {
	switch s {
	case StatusSucceeded:
		return ansiGreen
	case StatusFailed:
		return ansiRed
	}
	return ansiYellow
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.Round(100 * time.Millisecond).String()
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 3 {
		return string(r[:n])
	}
	return string(r[:n-3]) + "..."
}

// safeHostFilename sanitizes a hostname for use in a generated file name,
// matching how the runner names -output-dir files (see unsafeFileChars in
// runner.go) so report links line up with what's actually on disk.
func safeHostFilename(host string) string {
	var b strings.Builder
	for _, r := range host {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// JSONDeviceResult is the JSON representation of one device's run outcome.
type JSONDeviceResult struct {
	Hostname        string `json:"hostname"`
	Address         string `json:"address"`
	Vendor          string `json:"vendor"`
	Status          string `json:"status"`
	Category        string `json:"category,omitempty"`
	Detail          string `json:"detail,omitempty"`
	DurationMs      int64  `json:"duration_ms"`
	CommandsApplied int    `json:"commands_applied"`
	CommandsTotal   int    `json:"commands_total"`
	BackupPath      string `json:"backup_path,omitempty"`
	Rollback        string `json:"rollback,omitempty"`
	DiffAdded       int    `json:"diff_added,omitempty"`
	DiffRemoved     int    `json:"diff_removed,omitempty"`
	OutputFile      string `json:"output_file,omitempty"`
}

// JSONReport is the top-level structure written to the JSON report file.
type JSONReport struct {
	GeneratedAt string             `json:"generated_at"`
	Succeeded   int                `json:"succeeded"`
	Failed      int                `json:"failed"`
	Skipped     int                `json:"skipped"`
	Total       int                `json:"total"`
	Devices     []JSONDeviceResult `json:"devices"`
}

// WriteJSONReport marshals the run results to a JSON file at path.
// outputDir is used to annotate each result with its output file path (if any).
func WriteJSONReport(path string, results []Result, outputDir string) error {
	sum := Summarize(results)
	devices := make([]JSONDeviceResult, 0, len(results))
	for _, r := range results {
		jr := JSONDeviceResult{
			Hostname:        r.Device.Hostname,
			Address:         r.Device.Endpoint(),
			Vendor:          r.Device.Vendor,
			Status:          r.Status.String(),
			Category:        string(r.Category),
			Detail:          r.Detail,
			DurationMs:      r.Duration.Milliseconds(),
			CommandsApplied: r.CommandsApplied,
			CommandsTotal:   r.CommandsTotal,
			BackupPath:      r.BackupPath,
			Rollback:        r.Rollback.String(),
			DiffAdded:       r.DiffAdded,
			DiffRemoved:     r.DiffRemoved,
		}
		if outputDir != "" && r.Status == StatusSucceeded {
			jr.OutputFile = outputDir + "/" + safeHostFilename(r.Device.Hostname) + ".txt"
		}
		devices = append(devices, jr)
	}
	report := JSONReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Succeeded:   sum.Succeeded,
		Failed:      sum.Failed,
		Skipped:     sum.Skipped,
		Total:       len(results),
		Devices:     devices,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON report: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write JSON report %s: %w", path, err)
	}
	return nil
}

// csvHeader lists the CSV report's columns, in order. Kept in one place so
// WriteCSVReport's header and row-building can't drift apart.
var csvHeader = []string{
	"hostname", "address", "vendor", "status", "category", "detail",
	"duration_ms", "commands_applied", "commands_total", "backup_path",
	"rollback", "diff_added", "diff_removed", "output_file",
}

// WriteCSVReport writes the run results to a CSV file at path, with the
// same fields as the JSON report (see JSONDeviceResult) so an operator can
// pick whichever format their tooling (or spreadsheet) prefers. outputDir
// is used the same way as in WriteJSONReport.
func WriteCSVReport(path string, results []Result, outputDir string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create CSV report %s: %w", path, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write(csvHeader); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}

	for _, r := range results {
		outputFile := ""
		if outputDir != "" && r.Status == StatusSucceeded {
			outputFile = outputDir + "/" + safeHostFilename(r.Device.Hostname) + ".txt"
		}
		row := []string{
			r.Device.Hostname,
			r.Device.Endpoint(),
			r.Device.Vendor,
			r.Status.String(),
			string(r.Category),
			r.Detail,
			strconv.FormatInt(r.Duration.Milliseconds(), 10),
			strconv.Itoa(r.CommandsApplied),
			strconv.Itoa(r.CommandsTotal),
			r.BackupPath,
			r.Rollback.String(),
			strconv.Itoa(r.DiffAdded),
			strconv.Itoa(r.DiffRemoved),
			outputFile,
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("write CSV row for %s: %w", r.Device.Hostname, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("flush CSV report %s: %w", path, err)
	}
	return nil
}

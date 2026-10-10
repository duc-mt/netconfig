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
	"encoding/json"
	"fmt"
	"os"
	"sort"
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

// Render formats the summary as a table plus per-category breakdowns. With
// color false the output is plain text (used for the log file).
func (s Summary) Render(color, dryRun bool) string {
	var b strings.Builder

	title := "netconfig run summary"
	if dryRun {
		title += " (DRY-RUN: nothing was committed or saved)"
	}
	if color {
		title = ansiBold + title + ansiReset
	}
	b.WriteString(title + "\n")

	headers := []string{"HOST", "ADDRESS", "VENDOR", "STATUS", "REASON", "TIME", "DETAIL"}
	rows := make([][]string, 0, len(s.Results))
	for _, r := range s.Results {
		reason := "-"
		if r.Category != "" {
			reason = string(r.Category)
		}
		rows = append(rows, []string{
			r.Device.Hostname,
			r.Device.Endpoint(),
			r.Device.Vendor,
			r.Status.String(),
			reason,
			formatDuration(r.Duration),
			truncate(r.Detail, 90),
		})
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}

	writeRow := func(cells []string, status *Status) {
		last := len(cells) - 1
		for i, cell := range cells {
			if i == last {
				b.WriteString(cell)
				break
			}
			padded := cell + strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell))
			if color && status != nil && i == 3 {
				padded = statusColor(*status) + padded + ansiReset
			}
			b.WriteString(padded)
			b.WriteString("  ")
		}
		b.WriteByte('\n')
	}
	writeRow(headers, nil)
	for i, row := range rows {
		st := s.Results[i].Status
		writeRow(row, &st)
	}

	colorize := func(c, text string) string {
		if !color {
			return text
		}
		return c + text + ansiReset
	}
	fmt.Fprintf(&b, "\n%s   %s   %s   (total %d)\n",
		colorize(ansiGreen, fmt.Sprintf("Succeeded: %d", s.Succeeded)),
		colorize(ansiRed, fmt.Sprintf("Failed: %d", s.Failed)),
		colorize(ansiYellow, fmt.Sprintf("Skipped: %d", s.Skipped)),
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
	return string(r[:n-3]) + "..."
}

// JSONDeviceResult is the JSON representation of one device's run outcome.
type JSONDeviceResult struct {
	Hostname   string `json:"hostname"`
	Address    string `json:"address"`
	Vendor     string `json:"vendor"`
	Status     string `json:"status"`
	Category   string `json:"category,omitempty"`
	Detail     string `json:"detail,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	BackupPath string `json:"backup_path,omitempty"`
	OutputFile string `json:"output_file,omitempty"`
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
	safeHost := func(host string) string {
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
	devices := make([]JSONDeviceResult, 0, len(results))
	for _, r := range results {
		jr := JSONDeviceResult{
			Hostname:   r.Device.Hostname,
			Address:    r.Device.Endpoint(),
			Vendor:     r.Device.Vendor,
			Status:     r.Status.String(),
			Category:   string(r.Category),
			Detail:     r.Detail,
			DurationMs: r.Duration.Milliseconds(),
			BackupPath: r.BackupPath,
		}
		if outputDir != "" && r.Status == StatusSucceeded {
			jr.OutputFile = outputDir + "/" + safeHost(r.Device.Hostname) + ".txt"
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

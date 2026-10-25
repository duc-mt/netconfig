// Package report renders a colorized "Result Table" summary of a backup
// run to the terminal. It is independent of the structured run log the
// logging package writes to disk -- that log is for grepping and
// machine parsing, this table is for a human glancing at a terminal.
//
// Like the rest of netops, this package adds no third-party
// dependency: it reuses golang.org/x/term (already vendored for SSH host
// key handling) only to detect whether stdout is a real terminal, and
// draws the table itself with box-drawing characters. That keeps the
// project's "vendor everything, build with no internet access" promise
// intact instead of pulling in a table-rendering library just for this.
//
// Nothing here panics. A result that can't be formatted (e.g. a
// corrupt negative duration) degrades to a placeholder cell and a
// warning on stderr instead of aborting the table, matching the rest of
// netops's "one bad entry never stops the run" philosophy. The
// top-level PrintSummaryTable additionally recovers from anything
// unforeseen in rendering itself, so a bug here can never crash the
// main goroutine after a backup run has already done its work.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// BackupResult is one row of the result table: the outcome of backing up
// a single device, in the shape a renderer needs. It is intentionally
// decoupled from backup.Result so this package stays usable on its own
// (e.g. for a dry-run report, or replaying a saved run) -- see
// FromResults in adapter.go for converting a real run's output into this
// shape.
type BackupResult struct {
	HostnameIP string  // hostname and/or address, however the caller wants it labeled
	Platform   string  // vendor/platform key, e.g. "cisco_ios", "juniper_junos"
	Status     string  // free-form, e.g. "SUCCESS", "AUTH FAILED", "TIMEOUT" -- matched case-insensitively for color
	FileSize   int64   // bytes written; use -1 when no size applies (e.g. a failed or skipped-unchanged backup)
	Duration   float64 // elapsed time in seconds
	Diff       string  // configuration change diff count e.g. "+3/-1", or "-"
	Error      error   // nil on success

	// Risk is the highest risk level detected in the diff: "", "INFO",
	// "WARNING" or "CRITICAL".
	Risk string

	// RiskBadge is the short tag shown next to the diff counts, e.g.
	// "CRITICAL: ACL" or "ROUTING"; empty when no risk was detected.
	RiskBadge string

	// RiskDetails lists the notable (WARNING / CRITICAL) findings as
	// display lines, for the HTML and Markdown reports.
	RiskDetails []string

	// DiffLines holds the raw "+"/"-" diff lines of a changed device.
	DiffLines []string

	// ComplianceChecked is true when a golden baseline applied to the
	// device; Drifts then lists the deviations (empty means compliant).
	ComplianceChecked bool
	Drifts            []string

	// Warnings lists non-fatal analysis problems recorded for the device.
	Warnings []string

	// Hostname, Address, and Checksum for audit and machine-readable reports.
	Hostname string
	Address  string
	Checksum string
}

// Well-known status labels. Callers aren't required to use these exact
// strings -- colorForStatus matches case-insensitively by substring so
// any reasonably-named status still gets colored sensibly -- but using
// them keeps output consistent across the codebase.
const (
	StatusSuccess    = "SUCCESS"
	StatusDryRun     = "SUCCESS (dry-run)"
	StatusUnchanged  = "UNCHANGED"
	StatusAuthFailed = "AUTH FAILED"
	StatusTimeout    = "TIMEOUT"
	StatusFailed     = "FAILED"
)

// ANSI color codes. Kept minimal on purpose: just enough to distinguish
// success from the two failure classes the spec calls out.
const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"

	ansiBoldRed = "\033[1;31m" // CRITICAL risk
)

// rowOptions selects the optional table columns.
type rowOptions struct {
	diff       bool // DIFF column: at least one device recorded a diff
	compliance bool // COMPLIANCE column: at least one device was checked against a golden baseline
}

// tableColumns returns the headers for the selected optional columns. The
// first five columns and the trailing ERROR column are always present, so
// the cell indexes of HOSTNAME/IP .. DURATION never move.
func tableColumns(o rowOptions) []string {
	cols := []string{"HOSTNAME/IP", "PLATFORM", "STATUS", "FILE SIZE", "DURATION"}
	if o.diff {
		cols = append(cols, "DIFF")
	}
	if o.compliance {
		cols = append(cols, "COMPLIANCE")
	}
	return append(cols, "ERROR")
}

// defaultMaxErrorColumnWidth is the baseline error column width when stdout is
// not a terminal or when terminal width cannot be determined.
const defaultMaxErrorColumnWidth = 100

// minErrorColumnWidth is the floor for the error column so that error messages
// always have at least a readable amount of room when constrained by terminal width.
const minErrorColumnWidth = 30

// FormatFileSize renders a byte count as a human-readable size
// (B/KB/MB/...). It returns an error instead of panicking on a size that
// can never be valid, so a single bad value degrades only its own row.
// FileSize == -1 means "not applicable" and renders as "-" with no error.
func FormatFileSize(bytes int64) (string, error) {
	if bytes == -1 {
		return "-", nil
	}
	if bytes < 0 {
		return "", fmt.Errorf("invalid file size: %d bytes", bytes)
	}

	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes), nil
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp]), nil
}

// FormatDuration renders an elapsed time in seconds as a short, fixed
// string. It returns an error instead of panicking on a negative value,
// which can only indicate a bug upstream (e.g. a bad time subtraction).
func FormatDuration(seconds float64) (string, error) {
	if seconds < 0 {
		return "", fmt.Errorf("invalid duration: %.3f seconds", seconds)
	}
	if seconds < 60 {
		return fmt.Sprintf("%.2fs", seconds), nil
	}
	minutes := int(seconds) / 60
	rem := seconds - float64(minutes*60)
	return fmt.Sprintf("%dm%04.1fs", minutes, rem), nil
}

// formatError renders the Error field for display: "-" when nil, and the
// message formatted as a single line. If maxWidth > 0, it truncates with "…"
// when exceeding maxWidth.
func formatError(err error, maxWidth ...int) string {
	if err == nil {
		return "-"
	}
	limit := defaultMaxErrorColumnWidth
	if len(maxWidth) > 0 && maxWidth[0] > 0 {
		limit = maxWidth[0]
	}
	msg := strings.ReplaceAll(err.Error(), "\n", " ")
	if utf8.RuneCountInString(msg) <= limit {
		return msg
	}
	runes := []rune(msg)
	return string(runes[:limit-1]) + "…"
}

// colorForStatus maps a status string to an ANSI color code: SUCCESS /
// UNCHANGED-like statuses are green, AUTH FAILED and other failures are
// red, TIMEOUT is yellow. Matching is case-insensitive and by substring
// so callers aren't tied to the exact Status* constants. An unrecognized
// status renders uncolored rather than defaulting to an alarming color.
func colorForStatus(status string) string {
	s := strings.ToUpper(status)
	switch {
	case strings.Contains(s, "SUCCESS"), strings.Contains(s, "UNCHANGED"), strings.Contains(s, "SAVED"), strings.Contains(s, "OK"):
		return ansiGreen
	case strings.Contains(s, "TIMEOUT"):
		return ansiYellow
	case strings.Contains(s, "AUTH"), strings.Contains(s, "FAIL"), strings.Contains(s, "ERROR"):
		return ansiRed
	default:
		return ""
	}
}

// tableRow holds one row's plain-text cells (no ANSI codes -- used for
// column-width math) plus the color to apply to the STATUS cell.
type tableRow struct {
	cells       []string
	statusColor string
	cellColors  map[int]string // optional color per cell index (DIFF risk, COMPLIANCE)
}

func statusWithIcon(status string) string {
	s := strings.ToUpper(status)
	switch {
	case strings.Contains(s, "SUCCESS"), strings.Contains(s, "UNCHANGED"), strings.Contains(s, "SAVED"), strings.Contains(s, "OK"):
		return "✔ " + status
	case strings.Contains(s, "TIMEOUT"):
		return "⏱ " + status
	case strings.Contains(s, "AUTH"), strings.Contains(s, "FAIL"), strings.Contains(s, "ERROR"):
		return "✖ " + status
	default:
		return status
	}
}

// buildRow formats one BackupResult into display cells. showDiff[0]
// switches the DIFF column on. See buildRowOpts for the full option set.
func buildRow(r BackupResult, showDiff ...bool) (tableRow, []string) {
	var o rowOptions
	if len(showDiff) > 0 {
		o.diff = showDiff[0]
	}
	return buildRowOpts(r, o)
}

// buildRowOpts formats one BackupResult into display cells. It never
// panics: a formatting failure is recorded as a warning and the cell falls
// back to "N/A", so one malformed result can't stop the rest of the table
// from rendering.
func buildRowOpts(r BackupResult, o rowOptions) (tableRow, []string) {
	var warnings []string
	row := tableRow{statusColor: colorForStatus(r.Status), cellColors: make(map[int]string)}

	hostCell := orDash(r.HostnameIP)
	platformCell := orDash(r.Platform)
	statusCell := statusWithIcon(orDash(r.Status))

	size, err := FormatFileSize(r.FileSize)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s: file size: %v", orDash(r.HostnameIP), err))
		size = "N/A"
	}

	dur, err := FormatDuration(r.Duration)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s: duration: %v", orDash(r.HostnameIP), err))
		dur = "N/A"
	}

	cells := []string{hostCell, platformCell, statusCell, size, dur}

	if o.diff {
		diffCell := orDash(r.Diff)
		if r.RiskBadge != "" {
			if diffCell == "-" {
				diffCell = "[" + r.RiskBadge + "]"
			} else {
				diffCell += " [" + r.RiskBadge + "]"
			}
			if c := colorForRisk(r.Risk); c != "" {
				row.cellColors[len(cells)] = c
			}
		}
		cells = append(cells, diffCell)
	}

	if o.compliance {
		cells = append(cells, complianceCell(r))
		if r.ComplianceChecked {
			if len(r.Drifts) == 0 {
				row.cellColors[len(cells)-1] = ansiGreen
			} else {
				row.cellColors[len(cells)-1] = ansiRed
			}
		}
	}

	cells = append(cells, formatError(r.Error))
	row.cells = cells

	return row, warnings
}

// colorForRisk maps a risk level to the color of its DIFF-column badge.
// INFO and unknown levels stay uncolored.
func colorForRisk(risk string) string {
	switch strings.ToUpper(risk) {
	case "CRITICAL":
		return ansiBoldRed
	case "WARNING":
		return ansiYellow
	default:
		return ""
	}
}

// complianceLabel renders "COMPLIANT", "1 DRIFT" or "N DRIFTS"; empty when
// the device was not checked against a baseline.
func complianceLabel(r BackupResult) string {
	switch {
	case !r.ComplianceChecked:
		return ""
	case len(r.Drifts) == 0:
		return "COMPLIANT"
	case len(r.Drifts) == 1:
		return "1 DRIFT"
	default:
		return fmt.Sprintf("%d DRIFTS", len(r.Drifts))
	}
}

// complianceCell renders the COMPLIANCE table cell.
func complianceCell(r BackupResult) string {
	label := complianceLabel(r)
	switch {
	case label == "":
		return "-"
	case r.ComplianceChecked && len(r.Drifts) == 0:
		return "✔ " + label
	default:
		return "✖ " + label
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// PrintSummaryTable renders results as a colorized table on stdout.
// Color is used only when stdout is a real terminal and NO_COLOR isn't
// set, so piping the output to a file or another program yields plain,
// diff-friendly text.
//
// This function never panics: per-row formatting problems are reported
// to stderr as warnings (see buildRow) and a recover() guards against
// anything unforeseen in the rendering itself, printing a one-line
// warning instead of taking down the caller's main goroutine.
func PrintSummaryTable(results []BackupResult, totalRuntime ...time.Duration) {
	colorize := os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(os.Stdout.Fd()))
	fprintSummaryTable(os.Stdout, os.Stderr, results, colorize, totalRuntime...)
}

// terminalWidth inspects w and returns the visible terminal columns, or 0 if
// w is not a terminal or the size cannot be determined.
func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return 0
	}
	width, _, err := term.GetSize(int(f.Fd()))
	if err != nil || width <= 0 {
		return 0
	}
	return width
}

// FprintSummaryTable renders the result table to out; warnings about a
// rendering problem go to warn. PrintSummaryTable is this with os.Stdout and
// os.Stderr; the explicit writers let a caller (and its tests) choose.
func FprintSummaryTable(out, warn io.Writer, results []BackupResult, colorize bool, totalRuntime ...time.Duration) {
	fprintSummaryTable(out, warn, results, colorize, totalRuntime...)
}

// fprintSummaryTable does the real work against explicit writers so it
// can be exercised by tests without touching the process's real
// stdout/stderr.
func fprintSummaryTable(out, warn io.Writer, results []BackupResult, colorize bool, totalRuntime ...time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(warn, "report: recovered while rendering result table: %v\n", r)
		}
	}()

	var opts rowOptions
	for _, r := range results {
		if r.Diff != "" && r.Diff != "-" {
			opts.diff = true
		}
		if r.ComplianceChecked {
			opts.compliance = true
		}
	}

	cols := tableColumns(opts)

	rows := make([]tableRow, 0, len(results))
	for _, r := range results {
		row, warnings := buildRowOpts(r, opts)
		rows = append(rows, row)
		for _, w := range warnings {
			fmt.Fprintf(warn, "report: %s\n", w)
		}
	}

	widths := columnWidths(cols, rows)

	// Adjust flexible columns (specifically ERROR, the trailing column) to fit
	// terminal width if stdout is an interactive terminal.
	if tw := terminalWidth(out); tw > 0 && len(cols) > 0 {
		lastIdx := len(cols) - 1
		if cols[lastIdx] == "ERROR" {
			// Calculate width used by all fixed columns plus borders and 2-space padding per column.
			// Format: "│ col1 │ col2 │ ... │"
			// Total width = sum(widths[0..lastIdx-1]) + 3 * len(cols) + 1 + widths[lastIdx]
			fixedWidth := 1 // leading "│"
			for i := 0; i < lastIdx; i++ {
				fixedWidth += widths[i] + 3 // " " + cell + " │"
			}
			fixedWidth += 3 // for ERROR column overhead: " " + ERROR + " │"

			budget := tw - fixedWidth
			if budget < minErrorColumnWidth {
				budget = minErrorColumnWidth
			}

			// If the error column natural width exceeds budget, or budget allows showing more,
			// resize the ERROR column to fit the terminal neatly.
			if budget < widths[lastIdx] {
				widths[lastIdx] = budget
				// Truncate error cells to budget
				for rowIdx := range rows {
					if lastIdx < len(rows[rowIdx].cells) {
						errCell := rows[rowIdx].cells[lastIdx]
						if utf8.RuneCountInString(errCell) > budget {
							runes := []rune(errCell)
							if budget > 1 {
								rows[rowIdx].cells[lastIdx] = string(runes[:budget-1]) + "…"
							} else {
								rows[rowIdx].cells[lastIdx] = string(runes[:budget])
							}
						}
					}
				}
			}
		}
	}

	writeBorder(out, widths, "╭", "┬", "╮")
	writeHeader(out, cols, widths)
	writeBorder(out, widths, "├", "┼", "┤")
	for _, row := range rows {
		writeRow(out, cols, widths, row, colorize)
	}
	writeBorder(out, widths, "╰", "┴", "╯")

	if len(results) > 0 {
		var succeeded, failed int
		var sumDur float64
		for _, r := range results {
			s := strings.ToUpper(r.Status)
			switch {
			case strings.Contains(s, "SUCCESS"), strings.Contains(s, "UNCHANGED"), strings.Contains(s, "SAVED"), strings.Contains(s, "OK"):
				succeeded++
			default:
				failed++
			}
			if r.Duration > 0 {
				sumDur += r.Duration
			}
		}
		green := func(s string) string {
			if colorize {
				return ansiGreen + s + ansiReset
			}
			return s
		}
		red := func(s string) string {
			if colorize {
				return ansiRed + s + ansiReset
			}
			return s
		}

		var durSec float64
		if len(totalRuntime) > 0 && totalRuntime[0] > 0 {
			durSec = totalRuntime[0].Seconds()
		} else {
			durSec = sumDur
		}
		durStr, err := FormatDuration(durSec)
		if err != nil {
			durStr = "-"
		}

		fmt.Fprintf(out, "\n  %s  │  %s  │  Total Runtime: %s  │  (total %d)\n",
			green(fmt.Sprintf("✔ Succeeded: %d", succeeded)),
			red(fmt.Sprintf("✖ Failed: %d", failed)),
			durStr,
			len(results))

		if line, color := riskSummaryLine(results); line != "" {
			fmt.Fprintf(out, "  %s\n", paint(colorize, color, line))
		}
		if opts.compliance {
			checked, compliant := complianceCounts(results)
			rate := 100 * float64(compliant) / float64(checked)
			color := ansiGreen
			if compliant < checked {
				color = ansiRed
			}
			line := fmt.Sprintf("Compliance: %d/%d compliant (%.0f%%)", compliant, checked, rate)
			fmt.Fprintf(out, "  %s\n", paint(colorize, color, line))
		}
	}
}

// paint wraps s in an ANSI color when colorize is set and color is non-empty.
func paint(colorize bool, color, s string) string {
	if !colorize || color == "" {
		return s
	}
	return color + s + ansiReset
}

// complianceCounts returns how many results were checked against a golden
// baseline and how many of those had no drift.
func complianceCounts(results []BackupResult) (checked, compliant int) {
	for _, r := range results {
		if !r.ComplianceChecked {
			continue
		}
		checked++
		if len(r.Drifts) == 0 {
			compliant++
		}
	}
	return checked, compliant
}

// riskSummaryLine counts devices by highest risk level. It returns an empty
// line when no device carries a risk; the color is red when any device is
// CRITICAL, yellow otherwise.
func riskSummaryLine(results []BackupResult) (line, color string) {
	var critical, warning, info int
	for _, r := range results {
		switch strings.ToUpper(r.Risk) {
		case "CRITICAL":
			critical++
		case "WARNING":
			warning++
		case "INFO":
			info++
		}
	}
	if critical+warning+info == 0 {
		return "", ""
	}
	switch {
	case critical > 0:
		color = ansiBoldRed
	case warning > 0:
		color = ansiYellow
	}
	return fmt.Sprintf("⚠ Risk: %d critical │ %d warning │ %d info", critical, warning, info), color
}

func columnWidths(cols []string, rows []tableRow) []int {
	widths := make([]int, len(cols))
	for i, h := range cols {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		for i, cell := range row.cells {
			if i < len(widths) {
				if n := utf8.RuneCountInString(cell); n > widths[i] {
					widths[i] = n
				}
			}
		}
	}
	return widths
}

func writeBorder(w io.Writer, widths []int, left, mid, right string) {
	fmt.Fprint(w, left)
	for i, width := range widths {
		fmt.Fprint(w, strings.Repeat("─", width+2))
		if i < len(widths)-1 {
			fmt.Fprint(w, mid)
		}
	}
	fmt.Fprintln(w, right)
}

func writeHeader(w io.Writer, cols []string, widths []int) {
	fmt.Fprint(w, "│")
	for i, h := range cols {
		alignRight := (h == "FILE SIZE" || h == "DURATION" || h == "DIFF")
		fmt.Fprintf(w, " %s │", padCell(h, widths[i], alignRight))
	}
	fmt.Fprintln(w)
}

func writeRow(w io.Writer, cols []string, widths []int, row tableRow, colorize bool) {
	fmt.Fprint(w, "│")
	for i, cell := range row.cells {
		if i >= len(cols) || i >= len(widths) {
			break
		}
		h := cols[i]
		alignRight := (h == "FILE SIZE" || h == "DURATION" || h == "DIFF")
		text := padCell(cell, widths[i], alignRight)
		if colorize {
			if i == 2 && row.statusColor != "" {
				text = row.statusColor + text + ansiReset
			} else if c := row.cellColors[i]; c != "" {
				text = c + text + ansiReset
			}
		}
		fmt.Fprintf(w, " %s │", text)
	}
	fmt.Fprintln(w)
}

func padCell(s string, width int, alignRight bool) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	pad := strings.Repeat(" ", width-n)
	if alignRight {
		return pad + s
	}
	return s + pad
}

// MockResults returns illustrative sample data covering success,
// unchanged, auth-failure and timeout cases, for demos and tests. See
// cmd/resultdemo for a runnable example.
func MockResults() []BackupResult {
	return []BackupResult{
		{
			HostnameIP: "core-sw01 (10.0.1.1)",
			Platform:   "cisco_ios",
			Status:     StatusSuccess,
			FileSize:   45896,
			Duration:   3.42,
			Diff:       "+3/-1",
		},
		{
			HostnameIP: "edge-rtr02 (10.0.2.5)",
			Platform:   "juniper_junos",
			Status:     StatusUnchanged,
			FileSize:   -1,
			Duration:   2.10,
		},
		{
			HostnameIP: "fw-dc01 (10.0.3.10)",
			Platform:   "fortinet_fortios",
			Status:     StatusAuthFailed,
			FileSize:   -1,
			Duration:   1.05,
			Error:      fmt.Errorf("ssh: unable to authenticate, attempted methods [password], no supported methods remain"),
		},
		{
			HostnameIP: "sw-branch09 (10.0.9.2)",
			Platform:   "arista_eos",
			Status:     StatusTimeout,
			FileSize:   -1,
			Duration:   30.00,
			Error:      fmt.Errorf("command timed out after 30s"),
		},
		{
			HostnameIP: "sw-branch14 (10.0.14.3)",
			Platform:   "cisco_ios",
			Status:     StatusFailed,
			FileSize:   -1,
			Duration:   0.87,
			Error:      fmt.Errorf("no route to host"),
		},
	}
}

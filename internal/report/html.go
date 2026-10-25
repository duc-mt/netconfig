// ==============================================================================
// Package report implements the standalone HTML run report.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package report

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxReportDiffLines caps how many diff lines one device contributes to an
// HTML or Markdown report; the complete diff always stays in the .diff file
// next to the backup.
const maxReportDiffLines = 2000

// RunInfo describes the backup run a report is generated for.
type RunInfo struct {
	RunName     string    // run directory name, e.g. "backup-2026-10-12-0757"
	GeneratedAt time.Time // when the report was produced
}

// Totals are the headline numbers of a run.
type Totals struct {
	Total      int // devices in the run
	Succeeded  int // devices backed up (including unchanged ones)
	Unchanged  int // succeeded with no meaningful change
	Changed    int // succeeded with a configuration diff
	Failed     int // devices that could not be backed up
	Checked    int // devices checked against a golden baseline
	Compliant  int // checked devices without drift
	Critical   int // devices whose highest risk is CRITICAL
	Warning    int // devices whose highest risk is WARNING
	InfoRisk   int // devices whose highest risk is INFO
	WithDrifts int // checked devices that drifted
}

// ComplianceRate returns the share of checked devices that are compliant,
// in percent. ok is false when no device was checked.
func (t Totals) ComplianceRate() (rate float64, ok bool) {
	if t.Checked == 0 {
		return 0, false
	}
	return 100 * float64(t.Compliant) / float64(t.Checked), true
}

// isOKStatus mirrors the table's notion of a successful row.
func isOKStatus(status string) bool {
	s := strings.ToUpper(status)
	return strings.Contains(s, "SUCCESS") || strings.Contains(s, "UNCHANGED") ||
		strings.Contains(s, "SAVED") || strings.Contains(s, "OK")
}

func isUnchanged(r BackupResult) bool {
	return strings.Contains(strings.ToUpper(r.Status), "UNCHANGED")
}

// isChanged reports whether the device's configuration differs from the
// previous backup.
func isChanged(r BackupResult) bool {
	return len(r.DiffLines) > 0 || (r.Diff != "" && r.Diff != "-")
}

// Summarize computes the headline numbers for a set of results.
func Summarize(results []BackupResult) Totals {
	var t Totals
	for _, r := range results {
		t.Total++
		if isOKStatus(r.Status) {
			t.Succeeded++
			switch {
			case isUnchanged(r):
				t.Unchanged++
			case isChanged(r):
				t.Changed++
			}
		} else {
			t.Failed++
		}
		if r.ComplianceChecked {
			t.Checked++
			if len(r.Drifts) == 0 {
				t.Compliant++
			} else {
				t.WithDrifts++
			}
		}
		switch strings.ToUpper(r.Risk) {
		case "CRITICAL":
			t.Critical++
		case "WARNING":
			t.Warning++
		case "INFO":
			t.InfoRisk++
		}
	}
	return t
}

// ExpandPath substitutes run placeholders in a report path so each run can
// get its own file, e.g. "backups/{run}/report.html". Supported:
// {run} (run directory name), {timestamp} (20061002-150405) and {date}
// (2006-10-02). The "<run>" / "<timestamp>" / "<date>" spellings work too.
func ExpandPath(pattern string, info RunInfo) string {
	at := info.GeneratedAt
	if at.IsZero() {
		at = time.Now()
	}
	ts := at.Format("20060102-150405")
	date := at.Format("2006-01-02")
	return strings.NewReplacer(
		"{run}", info.RunName, "<run>", info.RunName,
		"{timestamp}", ts, "<timestamp>", ts,
		"{date}", date, "<date>", date,
	).Replace(pattern)
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory followed by a rename, so a crash never leaves a half-written
// report behind. Parent directories are created as needed.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating report dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".netops-report-*")
	if err != nil {
		return fmt.Errorf("creating temp report file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing report: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("closing report: %w", err)
	}
	_ = os.Chmod(tmpName, 0o640)
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replacing report: %w", err)
	}
	return nil
}

// safeSection runs one device's rendering, converting a panic into a
// placeholder plus a warning so one malformed result cannot lose the whole
// report.
func safeSection(host string, warnings *[]string, render func() string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			*warnings = append(*warnings, fmt.Sprintf("report: %s: rendering failed: %v", host, r))
			out = ""
		}
	}()
	return render()
}

// statusClass maps a status onto a CSS badge class.
func statusClass(status string) string {
	switch colorForStatus(status) {
	case ansiGreen:
		return "ok"
	case ansiYellow:
		return "warn"
	case ansiRed:
		return "bad"
	default:
		return "muted"
	}
}

// riskClass maps a risk level onto a CSS badge class.
func riskClass(risk string) string {
	switch strings.ToUpper(risk) {
	case "CRITICAL":
		return "crit"
	case "WARNING":
		return "warn"
	case "INFO":
		return "info"
	default:
		return "muted"
	}
}

// capDiff returns at most maxReportDiffLines diff lines and the number of
// lines that were cut off.
func capDiff(lines []string) (shown []string, hidden int) {
	if len(lines) <= maxReportDiffLines {
		return lines, 0
	}
	return lines[:maxReportDiffLines], len(lines) - maxReportDiffLines
}

const htmlStyle = `
:root{--bg:#f5f6f8;--fg:#1c2330;--muted:#667085;--card:#ffffff;--line:#e3e6ec;--ok:#157f3b;--okbg:#e3f6ea;--bad:#b42318;--badbg:#fde8e6;--warn:#9a6700;--warnbg:#fff3d1;--info:#175cd3;--infobg:#e4eefc;--add:#157f3b;--addbg:#e6f7ec;--del:#b42318;--delbg:#fdecea;--code:#f0f2f6}
@media (prefers-color-scheme:dark){:root{--bg:#0f1420;--fg:#e6e9f0;--muted:#98a2b3;--card:#171e2e;--line:#2a3347;--ok:#5fd18a;--okbg:#12301f;--bad:#ff8a80;--badbg:#3a1714;--warn:#f5c451;--warnbg:#3a2e0d;--info:#7cb2ff;--infobg:#13284a;--add:#5fd18a;--addbg:#10281a;--del:#ff8a80;--delbg:#331513;--code:#0c111c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:32px 0 12px}
.sub{color:var(--muted);margin:0 0 20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:28px;font-weight:700;line-height:1.1}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card.ok .n{color:var(--ok)}.card.bad .n{color:var(--bad)}.card.warn .n{color:var(--warn)}.card.info .n{color:var(--info)}
.tablewrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
td.wrap{white-space:normal;max-width:420px;overflow-wrap:anywhere}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right}
.badge{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.badge.ok{color:var(--ok);background:var(--okbg)}.badge.bad,.badge.crit{color:var(--bad);background:var(--badbg)}
.badge.warn{color:var(--warn);background:var(--warnbg)}.badge.info{color:var(--info);background:var(--infobg)}
.badge.muted{color:var(--muted);background:var(--code)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:0 0 10px}
summary{cursor:pointer;padding:10px 14px;font-weight:600}
summary .meta{color:var(--muted);font-weight:400;margin-left:8px}
.body{padding:0 14px 14px}
ul.findings{margin:6px 0 12px;padding-left:20px}
pre.diff{margin:0;padding:10px 12px;background:var(--code);border-radius:8px;overflow-x:auto;font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre.diff span{display:block;white-space:pre}
pre.diff .add{color:var(--add);background:var(--addbg)}pre.diff .del{color:var(--del);background:var(--delbg)}
.note{color:var(--muted);font-size:12px;margin:6px 0 0}
footer{margin-top:32px;color:var(--muted);font-size:12px}
@media (max-width:600px){main{padding:16px 10px 32px}.card .n{font-size:24px}}
`

func htmlCard(class, label, value string) string {
	return `<div class="card ` + class + `"><div class="n">` + html.EscapeString(value) + `</div><div class="l">` + html.EscapeString(label) + `</div></div>`
}

func htmlBadge(class, text string) string {
	return `<span class="badge ` + class + `">` + html.EscapeString(text) + `</span>`
}

// RenderHTML builds the complete, self-contained HTML report (inline CSS,
// no scripts, no external resources). It never fails: a device whose
// section cannot be rendered is replaced by a placeholder and reported in
// the returned warnings.
func RenderHTML(info RunInfo, results []BackupResult) (page string, warnings []string) {
	t := Summarize(results)
	esc := html.EscapeString

	generated := info.GeneratedAt
	if generated.IsZero() {
		generated = time.Now()
	}

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<meta name=\"color-scheme\" content=\"light dark\">\n")
	b.WriteString("<title>netops backup report")
	if info.RunName != "" {
		b.WriteString(" - " + esc(info.RunName))
	}
	b.WriteString("</title>\n<style>" + htmlStyle + "</style>\n</head>\n<body>\n<main>\n")

	b.WriteString("<h1>Network configuration backup report</h1>\n")
	b.WriteString("<p class=\"sub\">")
	if info.RunName != "" {
		b.WriteString("Run <strong>" + esc(info.RunName) + "</strong> &middot; ")
	}
	b.WriteString("generated " + esc(generated.Format("2006-01-02 15:04:05 MST")) + "</p>\n")

	// ---- summary cards ----
	b.WriteString("<div class=\"cards\">\n")
	b.WriteString(htmlCard("", "Total devices", fmt.Sprint(t.Total)) + "\n")
	b.WriteString(htmlCard("ok", "Succeeded", fmt.Sprint(t.Succeeded)) + "\n")
	b.WriteString(htmlCard("", "Unchanged", fmt.Sprint(t.Unchanged)) + "\n")
	changedClass := ""
	if t.Changed > 0 {
		changedClass = "info"
	}
	b.WriteString(htmlCard(changedClass, "Changed", fmt.Sprint(t.Changed)) + "\n")
	failedClass := ""
	if t.Failed > 0 {
		failedClass = "bad"
	}
	b.WriteString(htmlCard(failedClass, "Failed", fmt.Sprint(t.Failed)) + "\n")
	if rate, ok := t.ComplianceRate(); ok {
		class := "ok"
		if t.Compliant < t.Checked {
			class = "warn"
		}
		b.WriteString(htmlCard(class, "Compliance rate", fmt.Sprintf("%.0f%%", rate)) + "\n")
	} else {
		b.WriteString(htmlCard("", "Compliance rate", "n/a") + "\n")
	}
	if t.Critical+t.Warning > 0 {
		class := "warn"
		if t.Critical > 0 {
			class = "bad"
		}
		b.WriteString(htmlCard(class, "Risky changes", fmt.Sprintf("%d crit / %d warn", t.Critical, t.Warning)) + "\n")
	}
	b.WriteString("</div>\n")

	// ---- result table ----
	b.WriteString("<h2>Results</h2>\n<div class=\"tablewrap\"><table>\n<thead><tr>")
	for _, h := range []string{"Device", "Platform", "Status", "Risk", "Diff", "Compliance", "Size", "Duration", "Error"} {
		class := ""
		if h == "Size" || h == "Duration" || h == "Diff" {
			class = ` class="num"`
		}
		b.WriteString("<th" + class + ">" + h + "</th>")
	}
	b.WriteString("</tr></thead>\n<tbody>\n")
	if len(results) == 0 {
		b.WriteString("<tr><td colspan=\"9\">No devices in this run.</td></tr>\n")
	}
	for _, r := range results {
		row := safeSection(r.HostnameIP, &warnings, func() string { return htmlRow(r) })
		if row == "" {
			row = "<tr><td colspan=\"9\">" + esc(orDash(r.HostnameIP)) + ": row could not be rendered</td></tr>"
		}
		b.WriteString(row + "\n")
	}
	b.WriteString("</tbody></table></div>\n")

	// ---- changed devices: collapsible diffs ----
	changedCount := 0
	for _, r := range results {
		if isChanged(r) {
			changedCount++
		}
	}
	if changedCount > 0 {
		b.WriteString("<h2>Configuration changes</h2>\n")
		for _, r := range results {
			if !isChanged(r) {
				continue
			}
			sec := safeSection(r.HostnameIP, &warnings, func() string { return htmlChange(r) })
			if sec == "" {
				sec = "<details><summary>" + esc(orDash(r.HostnameIP)) + " <span class=\"meta\">diff could not be rendered</span></summary></details>"
			}
			b.WriteString(sec + "\n")
		}
	}

	// ---- compliance drift ----
	if t.WithDrifts > 0 {
		b.WriteString("<h2>Compliance drift</h2>\n")
		for _, r := range results {
			if !r.ComplianceChecked || len(r.Drifts) == 0 {
				continue
			}
			sec := safeSection(r.HostnameIP, &warnings, func() string { return htmlDrift(r) })
			if sec == "" {
				sec = "<details><summary>" + esc(orDash(r.HostnameIP)) + " <span class=\"meta\">drift could not be rendered</span></summary></details>"
			}
			b.WriteString(sec + "\n")
		}
	}

	// ---- warnings ----
	var notes []string
	for _, r := range results {
		for _, w := range r.Warnings {
			notes = append(notes, orDash(r.HostnameIP)+": "+w)
		}
	}
	if len(notes) > 0 {
		b.WriteString("<h2>Warnings</h2>\n<ul class=\"findings\">\n")
		for _, n := range notes {
			b.WriteString("<li>" + esc(n) + "</li>\n")
		}
		b.WriteString("</ul>\n")
	}

	b.WriteString("<footer>Generated by netops backup. This file is self-contained: it needs no network access.</footer>\n")
	b.WriteString("</main>\n</body>\n</html>\n")
	return b.String(), warnings
}

// fullError renders an error for a report cell without the truncation the
// terminal table applies ("-" when there is none).
func fullError(err error) string {
	if err == nil {
		return "-"
	}
	return strings.ReplaceAll(err.Error(), "\n", " ")
}

// htmlRow renders one result-table row.
func htmlRow(r BackupResult) string {
	esc := html.EscapeString
	size, err := FormatFileSize(r.FileSize)
	if err != nil {
		size = "N/A"
	}
	dur, err := FormatDuration(r.Duration)
	if err != nil {
		dur = "N/A"
	}

	riskCell := "-"
	if r.RiskBadge != "" {
		riskCell = htmlBadge(riskClass(r.Risk), r.RiskBadge)
	}
	diffCell := esc(orDash(r.Diff))

	complianceHTML := "-"
	if label := complianceLabel(r); label != "" {
		if len(r.Drifts) == 0 {
			complianceHTML = htmlBadge("ok", "✔ "+label)
		} else {
			complianceHTML = htmlBadge("bad", "✖ "+label)
		}
	}

	var b strings.Builder
	b.WriteString("<tr>")
	b.WriteString("<td>" + esc(orDash(r.HostnameIP)) + "</td>")
	b.WriteString("<td>" + esc(orDash(r.Platform)) + "</td>")
	b.WriteString("<td>" + htmlBadge(statusClass(r.Status), orDash(r.Status)) + "</td>")
	b.WriteString("<td>" + riskCell + "</td>")
	b.WriteString("<td class=\"num\">" + diffCell + "</td>")
	b.WriteString("<td>" + complianceHTML + "</td>")
	b.WriteString("<td class=\"num\">" + esc(size) + "</td>")
	b.WriteString("<td class=\"num\">" + esc(dur) + "</td>")
	b.WriteString("<td class=\"wrap\">" + esc(fullError(r.Error)) + "</td>")
	b.WriteString("</tr>")
	return b.String()
}

// htmlChange renders one device's collapsible diff section.
func htmlChange(r BackupResult) string {
	esc := html.EscapeString
	var b strings.Builder

	open := ""
	if strings.ToUpper(r.Risk) == "CRITICAL" {
		open = " open"
	}
	b.WriteString("<details" + open + "><summary>" + esc(orDash(r.HostnameIP)))
	b.WriteString(" <span class=\"meta\">" + esc(orDash(r.Diff)) + "</span> ")
	if r.RiskBadge != "" {
		b.WriteString(htmlBadge(riskClass(r.Risk), r.RiskBadge))
	}
	b.WriteString("</summary>\n<div class=\"body\">\n")

	if len(r.RiskDetails) > 0 {
		b.WriteString("<ul class=\"findings\">\n")
		for _, d := range r.RiskDetails {
			b.WriteString("<li>" + esc(d) + "</li>\n")
		}
		b.WriteString("</ul>\n")
	}

	shown, hidden := capDiff(r.DiffLines)
	if len(shown) == 0 {
		b.WriteString("<p class=\"note\">Only the change counts are available for this device.</p>\n")
	} else {
		b.WriteString("<pre class=\"diff\">")
		for _, line := range shown {
			class := ""
			switch {
			case strings.HasPrefix(line, "+"):
				class = ` class="add"`
			case strings.HasPrefix(line, "-"):
				class = ` class="del"`
			}
			b.WriteString("<span" + class + ">" + esc(line) + "</span>")
		}
		b.WriteString("</pre>\n")
		if hidden > 0 {
			b.WriteString(fmt.Sprintf("<p class=\"note\">%d more line(s) not shown; see the .diff file next to the backup.</p>\n", hidden))
		}
	}
	b.WriteString("</div></details>")
	return b.String()
}

// htmlDrift renders one device's compliance-drift section.
func htmlDrift(r BackupResult) string {
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString("<details><summary>" + esc(orDash(r.HostnameIP)) + " <span class=\"meta\">" + esc(complianceLabel(r)) + "</span></summary>\n")
	b.WriteString("<div class=\"body\"><ul class=\"findings\">\n")
	for _, d := range r.Drifts {
		b.WriteString("<li>" + esc(d) + "</li>\n")
	}
	b.WriteString("</ul></div></details>")
	return b.String()
}

// WriteHTML renders the report and writes it to path (see ExpandPath for
// run placeholders). It returns the rendering warnings alongside any write
// error so the caller can log them.
func WriteHTML(path string, info RunInfo, results []BackupResult) (warnings []string, err error) {
	page, warnings := RenderHTML(info, results)
	if err := writeFileAtomic(path, []byte(page)); err != nil {
		return warnings, err
	}
	return warnings, nil
}

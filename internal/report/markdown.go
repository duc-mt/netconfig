// ==============================================================================
// Package report implements the Markdown changelog report.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package report

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// changelogMarker separates the file header from the run sections. New
	// runs are inserted right after it, so the newest run is on top.
	changelogMarker = "<!-- netbackup:changelog -->"

	changelogHeader = "# Network Configuration Changelog\n\n" + changelogMarker + "\n\n"
)

// mdCell makes text safe for a GitHub-flavored Markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

// mdFence returns a code fence longer than any backtick run inside body, so
// configuration text (banners can contain backticks) cannot close it early.
func mdFence(body string) string {
	longest, run := 0, 0
	for _, r := range body {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := 3
	if longest >= n {
		n = longest + 1
	}
	return strings.Repeat("`", n)
}

// RenderMarkdown builds one run's section of the changelog: a summary
// table, a per-device result table and, for every changed device, its risk
// findings and a fenced "diff" block. It never fails; a device section that
// cannot be rendered is skipped and reported in the returned warnings.
func RenderMarkdown(info RunInfo, results []BackupResult) (section string, warnings []string) {
	t := Summarize(results)
	generated := info.GeneratedAt
	if generated.IsZero() {
		generated = time.Now()
	}

	var b strings.Builder
	b.WriteString("## " + generated.Format("2006-01-02 15:04:05"))
	if info.RunName != "" {
		b.WriteString(" - `" + strings.ReplaceAll(info.RunName, "`", "") + "`")
	}
	b.WriteString("\n\n")

	rate := "n/a"
	if r, ok := t.ComplianceRate(); ok {
		rate = fmt.Sprintf("%.0f%%", r)
	}
	b.WriteString("| Devices | Succeeded | Unchanged | Changed | Failed | Compliance |\n")
	b.WriteString("|--------:|----------:|----------:|--------:|-------:|-----------:|\n")
	b.WriteString(fmt.Sprintf("| %d | %d | %d | %d | %d | %s |\n\n", t.Total, t.Succeeded, t.Unchanged, t.Changed, t.Failed, rate))

	if t.Critical+t.Warning > 0 {
		b.WriteString(fmt.Sprintf("> **Risk:** %d device(s) with CRITICAL changes, %d with WARNING changes.\n\n", t.Critical, t.Warning))
	}

	b.WriteString("### Results\n\n")
	if len(results) == 0 {
		b.WriteString("_No devices in this run._\n\n")
	} else {
		b.WriteString("| Device | Platform | Status | Diff | Risk | Compliance |\n")
		b.WriteString("|--------|----------|--------|-----:|------|------------|\n")
		for _, r := range results {
			row := safeSection(r.HostnameIP, &warnings, func() string { return mdRow(r) })
			if row == "" {
				row = "| " + mdCell(orDash(r.HostnameIP)) + " | - | row could not be rendered | - | - | - |\n"
			}
			b.WriteString(row)
		}
		b.WriteString("\n")
	}

	changed := false
	for _, r := range results {
		if isChanged(r) {
			changed = true
			break
		}
	}
	if changed {
		b.WriteString("### Changes\n\n")
		for _, r := range results {
			if !isChanged(r) {
				continue
			}
			sec := safeSection(r.HostnameIP, &warnings, func() string { return mdChange(r) })
			if sec == "" {
				sec = "#### " + mdCell(orDash(r.HostnameIP)) + "\n\n_diff could not be rendered_\n\n"
			}
			b.WriteString(sec)
		}
	}

	drifted := false
	for _, r := range results {
		if r.ComplianceChecked && len(r.Drifts) > 0 {
			drifted = true
			break
		}
	}
	if drifted {
		b.WriteString("### Compliance drift\n\n")
		for _, r := range results {
			if !r.ComplianceChecked || len(r.Drifts) == 0 {
				continue
			}
			sec := safeSection(r.HostnameIP, &warnings, func() string { return mdDrift(r) })
			if sec == "" {
				sec = "#### " + mdCell(orDash(r.HostnameIP)) + "\n\n_drift could not be rendered_\n\n"
			}
			b.WriteString(sec)
		}
	}

	var notes []string
	for _, r := range results {
		for _, w := range r.Warnings {
			notes = append(notes, "- **"+mdCell(orDash(r.HostnameIP))+":** "+mdCell(w)+"\n")
		}
	}
	if len(notes) > 0 {
		b.WriteString("### Warnings\n\n")
		for _, n := range notes {
			b.WriteString(n)
		}
		b.WriteString("\n")
	}

	return b.String(), warnings
}

// mdRow renders one device's row of the result table.
func mdRow(r BackupResult) string {
	risk := "-"
	if r.RiskBadge != "" {
		risk = r.RiskBadge
	}
	comp := "-"
	if label := complianceLabel(r); label != "" {
		if len(r.Drifts) == 0 {
			comp = "✔ " + label
		} else {
			comp = "✖ " + label
		}
	}
	return "| " + mdCell(orDash(r.HostnameIP)) +
		" | " + mdCell(orDash(r.Platform)) +
		" | " + mdCell(orDash(r.Status)) +
		" | " + mdCell(orDash(r.Diff)) +
		" | " + mdCell(risk) +
		" | " + mdCell(comp) + " |\n"
}

// mdChange renders one changed device: heading, risk findings, diff block.
func mdChange(r BackupResult) string {
	var b strings.Builder
	b.WriteString("#### " + mdCell(orDash(r.HostnameIP)) + " (" + mdCell(orDash(r.Diff)) + ")")
	if r.RiskBadge != "" {
		b.WriteString(" - " + mdCell(r.RiskBadge))
	}
	b.WriteString("\n\n")

	if len(r.RiskDetails) > 0 {
		for _, d := range r.RiskDetails {
			b.WriteString("- " + strings.ReplaceAll(d, "\n", " ") + "\n")
		}
		b.WriteString("\n")
	}

	shown, hidden := capDiff(r.DiffLines)
	if len(shown) == 0 {
		b.WriteString("_Only the change counts are available for this device._\n\n")
		return b.String()
	}
	body := strings.Join(shown, "\n")
	fence := mdFence(body)
	b.WriteString(fence + "diff\n" + body + "\n" + fence + "\n\n")
	if hidden > 0 {
		b.WriteString(fmt.Sprintf("_%d more line(s) not shown; see the .diff file next to the backup._\n\n", hidden))
	}
	return b.String()
}

// mdDrift renders one device's compliance drifts.
func mdDrift(r BackupResult) string {
	var b strings.Builder
	b.WriteString("#### " + mdCell(orDash(r.HostnameIP)) + " (" + mdCell(complianceLabel(r)) + ")\n\n")
	for _, d := range r.Drifts {
		b.WriteString("- " + strings.ReplaceAll(d, "\n", " ") + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

// composeChangelog merges a new run section into an existing changelog
// file. A file created by netbackup carries a marker line and new runs are
// inserted right below it (newest first). A non-empty file without the
// marker is never overwritten: the section is appended instead.
func composeChangelog(existing, section string) string {
	if strings.TrimSpace(existing) == "" {
		return changelogHeader + section
	}
	if idx := strings.Index(existing, changelogMarker); idx >= 0 {
		head := existing[:idx+len(changelogMarker)]
		tail := strings.TrimLeft(existing[idx+len(changelogMarker):], "\r\n")
		out := head + "\n\n" + section
		if tail != "" {
			out += "\n---\n\n" + tail
		}
		return out
	}
	return strings.TrimRight(existing, "\r\n") + "\n\n---\n\n" + section
}

// WriteMarkdown writes the run's Markdown report to path (see ExpandPath
// for run placeholders). When the file already exists it is treated as a
// running changelog: the new run is inserted at the top and earlier runs
// are kept. Use a "{run}" or "{timestamp}" placeholder for one file per
// run instead. The returned warnings come from rendering.
func WriteMarkdown(path string, info RunInfo, results []BackupResult) (warnings []string, err error) {
	section, warnings := RenderMarkdown(info, results)

	existing := ""
	data, rerr := os.ReadFile(path)
	switch {
	case rerr == nil:
		existing = string(data)
	case os.IsNotExist(rerr):
		// First run: start a new changelog.
	default:
		// Unreadable but present: refuse to overwrite what we cannot read.
		return warnings, fmt.Errorf("reading existing changelog: %w", rerr)
	}

	if err := writeFileAtomic(path, []byte(composeChangelog(existing, section))); err != nil {
		return warnings, err
	}
	return warnings, nil
}

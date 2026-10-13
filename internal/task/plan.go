package task

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"netconfig/internal/vendor"
)

// PlanRow is one device's line of the -plan impact matrix.
type PlanRow struct {
	Host     string
	Vendor   string
	Commands int
	Risk     string // LOW, MEDIUM, HIGH, CRITICAL, or UNKNOWN when the lint failed
	Level    RiskLevel
	Impact   string // impacted subsystems, e.g. "BGP / Interface"
	Safety   vendor.RollbackSafety
	Findings []Finding // MEDIUM and above
}

// PlanRenderOptions tunes RenderPlan.
type PlanRenderOptions struct {
	Color         bool
	DryRun        bool
	CommitConfirm int // minutes; > 0 adds per-device rollback hazard lines
}

// maxImpactNames bounds the IMPACT cell; the rest is summarised as "+N".
const maxImpactNames = 4

// BuildPlanRows turns jobs and their lint reports (index-aligned) into matrix
// rows. Skipped devices are left out: nothing will happen to them.
func BuildPlanRows(jobs []Job, reports []LintReport) []PlanRow {
	var rows []PlanRow
	for i, j := range jobs {
		if j.Skip != "" {
			continue
		}
		row := PlanRow{Host: j.Device.Hostname, Vendor: j.Device.Vendor, Commands: len(j.Commands), Risk: "LOW"}
		if j.Profile != nil {
			row.Safety = j.Profile.Safety()
		}
		if i < len(reports) {
			rep := reports[i]
			switch {
			case rep.Err != nil:
				row.Risk = "UNKNOWN"
			default:
				row.Level, row.Risk = rep.Level, rep.Level.String()
				for _, f := range rep.Findings {
					if f.Level >= RiskMedium {
						row.Findings = append(row.Findings, f)
					}
				}
			}
			names := rep.Subsystems
			if len(names) > maxImpactNames {
				names = append(append([]string{}, names[:maxImpactNames]...), fmt.Sprintf("+%d", len(rep.Subsystems)-maxImpactNames))
			}
			row.Impact = strings.Join(names, " / ")
		}
		if row.Impact == "" {
			row.Impact = "-"
		}
		rows = append(rows, row)
	}
	return rows
}

// RenderPlan draws the impact matrix, the findings behind each risk level and
// the rollback safety legend. It is what -plan shows before asking to proceed.
func RenderPlan(rows []PlanRow, opts PlanRenderOptions) string {
	var b strings.Builder
	title := "netconfig change plan"
	if opts.DryRun {
		title += " (DRY-RUN: nothing will be committed or saved)"
	}
	if opts.Color {
		title = ansiBold + title + ansiReset
	}
	b.WriteString(title + "\n")

	headers := []string{"HOST", "VENDOR", "CMDS", "RISK", "IMPACT", "ROLLBACK"}
	body := make([][]string, len(rows))
	for i, r := range rows {
		body[i] = []string{r.Host, r.Vendor, fmt.Sprint(r.Commands), r.Risk, r.Impact, r.Safety.Label()}
	}
	b.WriteString(renderTable(headers, body, map[int]bool{2: true}, func(col int, row int, padded string) string {
		if !opts.Color || col != 3 {
			return padded
		}
		return riskColor(rows[row].Level, rows[row].Risk) + padded + ansiReset
	}))

	for _, r := range rows {
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "  %-8s %s [%s] command %d %q: %s\n", f.Level, r.Host, f.Rule, f.Index, f.Command, f.Message)
		}
	}
	if opts.CommitConfirm > 0 {
		for _, r := range rows {
			if r.Safety != vendor.RollbackSafe {
				fmt.Fprintf(&b, "  ROLLBACK %s: %s - %s\n", r.Host, r.Safety, r.Safety.Hazard())
			}
		}
	}
	b.WriteString("Rollback: SAFE = native hitless auto-rollback; REBOOT ONLY = revert needs a reload (-allow-reboot-rollback); " +
		"UNSAFE = no on-box watchdog, OOB/console access is needed if connectivity is lost.\n")
	return b.String()
}

func riskColor(l RiskLevel, risk string) string {
	switch {
	case risk == "UNKNOWN" || l == RiskMedium:
		return ansiYellow
	case l >= RiskHigh:
		return ansiRed
	}
	return ansiGreen
}

// renderTable draws a rounded-border table. alignRight marks right-aligned
// columns; decorate may wrap an already padded cell (e.g. in colour).
func renderTable(headers []string, rows [][]string, alignRight map[int]bool, decorate func(col, row int, padded string) string) string {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if w := utf8.RuneCountInString(c); w > widths[i] {
				widths[i] = w
			}
		}
	}
	pad := func(s string, i int) string {
		gap := strings.Repeat(" ", widths[i]-utf8.RuneCountInString(s))
		if alignRight[i] {
			return gap + s
		}
		return s + gap
	}
	rule := func(l, m, r string) string {
		parts := make([]string, len(widths))
		for i, w := range widths {
			parts[i] = strings.Repeat("─", w+2)
		}
		return l + strings.Join(parts, m) + r + "\n"
	}
	var b strings.Builder
	b.WriteString(rule("╭", "┬", "╮"))
	cells := make([]string, len(headers))
	for i, h := range headers {
		cells[i] = " " + pad(h, i) + " "
	}
	b.WriteString("│" + strings.Join(cells, "│") + "│\n")
	b.WriteString(rule("├", "┼", "┤"))
	for ri, r := range rows {
		for i, c := range r {
			p := pad(c, i)
			if decorate != nil {
				p = decorate(i, ri, p)
			}
			cells[i] = " " + p + " "
		}
		b.WriteString("│" + strings.Join(cells, "│") + "│\n")
	}
	b.WriteString(rule("╰", "┴", "╯"))
	return b.String()
}

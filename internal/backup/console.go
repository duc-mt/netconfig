// ==============================================================================
// File name:     console.go
// Description:   Console and log rendering of a backup run.
// License:       MIT
// ==============================================================================
package backup

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"netconfig/internal/errcat"
	"netconfig/internal/logging"
)

const (
	// maxAlertFindings caps how many classified lines the run summary lists
	// per device in the risk alerts block (the full diff is in the log).
	maxAlertFindings = 8

	// maxLoggedDrifts caps how many compliance drifts are listed per device.
	maxLoggedDrifts = 10
)

// Console renders a backup run for people. It writes through netconfig's
// logger, so every line also reaches the log file, plain and with registered
// secrets masked.
type Console struct {
	Log *logging.Logger
}

// DiffLines logs diff lines, additions green and removals red on a colour
// console. A line the risk classifier recognises as CRITICAL or WARNING is
// logged at WARN level and tagged with a "<== CRITICAL: ACL" style marker, so
// security-relevant changes stand out inside a long diff.
func (c Console) DiffLines(host, prefix string, lines []string) {
	for _, raw := range lines {
		level, text := logging.LevelInfo, raw
		if mark := riskMarker(raw); mark != "" {
			level, text = logging.LevelWarn, raw+mark
		}
		c.Log.DiffBlock(level, host, prefix, text)
	}
}

// riskMarker returns the inline marker for a diff line, or "" when the line is
// not CRITICAL or WARNING.
func riskMarker(rawLine string) string {
	f, ok := ClassifyLine(rawLine)
	if !ok {
		return ""
	}
	switch f.Level {
	case RiskCritical:
		return "  <== CRITICAL: " + f.Category
	case RiskWarning:
		return "  <== WARNING: " + f.Category
	}
	return ""
}

// Progress logs real-time status as each device completes during a run.
func (c Console) Progress(completed, total int, r Result) {
	if r.Success {
		if r.DryRun {
			c.Log.Infof("", "[%d/%d] OK      %-20s (%s) [DRY-RUN] [%s]", completed, total, r.Device.Hostname, r.Device.Address, r.Duration.Round(time.Millisecond))
			return
		}
		c.Log.Infof("", "[%d/%d] OK      %-20s (%s) [%s] -> %s [%s]", completed, total, r.Device.Hostname, r.Device.Address, outcome(r), r.OutputPath, r.Duration.Round(time.Millisecond))
		return
	}
	c.Log.Errorf("", "[%d/%d] FAILED  %-20s (%s) category=%s detail=%v [%s]", completed, total, r.Device.Hostname, r.Device.Address, r.Category, r.Err, r.Duration.Round(time.Millisecond))
}

// outcome describes a successful, non-dry-run result: "SAVED (+3/-1) RISK=...".
func outcome(r Result) string {
	status := "SAVED"
	if r.Unchanged {
		status = "UNCHANGED"
		if r.VolatileOnly {
			status = "UNCHANGED (volatile lines only)"
		}
	} else if r.HasDiff || r.DiffAdded > 0 || r.DiffRemoved > 0 {
		status = fmt.Sprintf("SAVED (+%d/-%d)", r.DiffAdded, r.DiffRemoved)
	}
	if r.Risk.Level != RiskNone {
		status += " RISK=" + riskLabel(r.Risk)
	}
	return status
}

// Summary prints a per-device outcome line for every result plus roll-up
// counts by failure category, and returns the number of failures so the
// caller can set a meaningful process exit code.
//
// Beyond the outcome lines it also reports, when present: per-device
// warnings (a skipped or failed analysis step), golden-config compliance
// drifts, and a "Risk alerts" block listing the security- and
// routing-relevant changes of the run.
func (c Console) Summary(results []Result, totalRuntime ...time.Duration) int {
	failures := 0
	byCategory := make(map[errcat.Category]int)

	c.Log.Infof("", "---- Backup run summary ----")
	for _, r := range results {
		if r.Success {
			if r.DryRun {
				c.Log.Infof("", "OK      %-20s (%s) [DRY-RUN] [%s]", r.Device.Hostname, r.Device.Address, r.Duration.Round(time.Millisecond))
			} else {
				c.Log.Infof("", "OK      %-20s (%s) [%s] -> %s [%s]", r.Device.Hostname, r.Device.Address, outcome(r), r.OutputPath, r.Duration.Round(time.Millisecond))
			}
			c.deviceNotes(r)
			continue
		}
		failures++
		byCategory[r.Category]++
		c.Log.Errorf("", "FAILED  %-20s (%s) category=%s detail=%v [%s]", r.Device.Hostname, r.Device.Address, r.Category, r.Err, r.Duration.Round(time.Millisecond))
		c.deviceNotes(r)
	}

	var totalDur time.Duration
	if len(totalRuntime) > 0 && totalRuntime[0] > 0 {
		totalDur = totalRuntime[0]
	} else {
		for _, r := range results {
			totalDur += r.Duration
		}
	}

	c.Log.Infof("", "---- Totals ----")
	c.Log.Infof("", "Devices: %d total, %d succeeded, %d failed", len(results), len(results)-failures, failures)
	if totalDur > 0 {
		c.Log.Infof("", "Total runtime: %s", totalDur.Round(time.Millisecond))
	}
	if failures > 0 {
		cats := make([]string, 0, len(byCategory))
		for cat := range byCategory {
			cats = append(cats, string(cat))
		}
		sort.Strings(cats)
		for _, cat := range cats {
			c.Log.Infof("", "  %-35s %d", cat, byCategory[errcat.Category(cat)])
		}
	}

	c.riskAlerts(results)
	c.complianceTotals(results)
	return failures
}

// riskLabel renders an assessment for the run log, e.g. "CRITICAL(ACL,SSH)".
func riskLabel(a RiskAssessment) string {
	if len(a.Categories) == 0 {
		return a.Level.String()
	}
	return a.Level.String() + "(" + strings.Join(a.Categories, ",") + ")"
}

// deviceNotes logs a device's analysis warnings and compliance drifts.
func (c Console) deviceNotes(r Result) {
	for _, w := range r.Warnings {
		c.Log.Warnf("", "WARN    %-20s %s", r.Device.Hostname, w)
	}
	drifts := r.Compliance.Drifts
	if !r.Compliance.Checked || len(drifts) == 0 {
		return
	}
	c.Log.Warnf("", "DRIFT   %-20s %s (%d of %d baseline rule(s) failed)", r.Device.Hostname, r.Compliance.Summary(), len(drifts), r.Compliance.Rules)
	for i, d := range drifts {
		if i >= maxLoggedDrifts {
			c.Log.Warnf("", "DRIFT   %-20s   ... and %d more", r.Device.Hostname, len(drifts)-maxLoggedDrifts)
			break
		}
		c.Log.Warnf("", "DRIFT   %-20s   %s", r.Device.Hostname, d.String())
	}
}

// riskAlerts logs a prominent block for every device whose changes were
// classified WARNING or CRITICAL, plus a one-line count of devices per
// highest risk level. It prints nothing when no device carries a risk.
func (c Console) riskAlerts(results []Result) {
	var critical, warning, info int
	for _, r := range results {
		switch r.Risk.Level {
		case RiskCritical:
			critical++
		case RiskWarning:
			warning++
		case RiskInfo:
			info++
		}
	}
	if critical+warning+info == 0 {
		return
	}

	if critical+warning > 0 {
		c.Log.Warnf("", "---- Risk alerts ----")
		for _, r := range results {
			if r.Risk.Level != RiskCritical && r.Risk.Level != RiskWarning {
				continue
			}
			c.Log.Warnf("", "RISK    %-20s %s (+%d/-%d)", r.Device.Hostname, riskLabel(r.Risk), r.DiffAdded, r.DiffRemoved)

			shown := 0
			notable := r.Risk.Count(RiskCritical) + r.Risk.Count(RiskWarning)
			for _, f := range r.Risk.Findings {
				if f.Level != RiskCritical && f.Level != RiskWarning {
					continue
				}
				if shown == maxAlertFindings {
					c.Log.Warnf("", "          ... and %d more notable line(s)", notable-shown)
					break
				}
				c.Log.Warnf("", "          %-8s %-11s %s", f.Level, f.Category, f.Line)
				shown++
			}
		}
	}
	c.Log.Infof("", "Risk: %d critical, %d warning, %d info (devices by highest risk level)", critical, warning, info)
}

// complianceTotals logs how many checked devices match their golden
// baseline. It prints nothing when no device was checked.
func (c Console) complianceTotals(results []Result) {
	checked, compliant := 0, 0
	for _, r := range results {
		if !r.Compliance.Checked {
			continue
		}
		checked++
		if r.Compliance.Compliant() {
			compliant++
		}
	}
	if checked == 0 {
		return
	}
	c.Log.Infof("", "Compliance: %d of %d checked device(s) match the golden baseline (%.0f%%)", compliant, checked, 100*float64(compliant)/float64(checked))
}

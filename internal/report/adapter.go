package report

import (
	"fmt"
	"os"

	"netops/internal/backup"
	"netops/internal/errcat"
)

// FromResults adapts backup.RunAll's output into the shape
// PrintSummaryTable expects, so a real run and the mock data in
// MockResults go through the exact same renderer.
//
// File size is read with os.Stat on each result's OutputPath; a result
// with no output file (a failed backup, or an unchanged one that was
// skipped rather than saved) gets FileSize -1, which FormatFileSize
// renders as "-" rather than treating as an error. A stat failure is
// likewise treated as "no size available" rather than propagated -- the
// table is a best-effort summary, not the place to surface a stat error
// for a backup that otherwise already succeeded.
func FromResults(results []backup.Result) []BackupResult {
	out := make([]BackupResult, 0, len(results))
	for _, r := range results {
		out = append(out, fromResult(r))
	}
	return out
}

func fromResult(r backup.Result) BackupResult {
	diff := "-"
	if r.HasDiff || r.DiffAdded > 0 || r.DiffRemoved > 0 {
		diff = fmt.Sprintf("+%d/-%d", r.DiffAdded, r.DiffRemoved)
	}
	out := BackupResult{
		HostnameIP: hostnameIP(r),
		Platform:   orDash(r.Device.Vendor),
		Status:     statusFor(r),
		FileSize:   fileSizeFor(r),
		Duration:   r.Duration.Seconds(),
		Diff:       diff,
		Error:      r.Err,

		RiskBadge:         r.Risk.Badge(),
		RiskDetails:       riskDetails(r.Risk),
		DiffLines:         r.DiffLines,
		ComplianceChecked: r.Compliance.Checked,
		Drifts:            r.Compliance.DriftMessages(),
		Warnings:          r.Warnings,

		Hostname: r.Device.Hostname,
		Address:  r.Device.Address,
		Checksum: r.Checksum,
	}
	if r.Risk.Level != backup.RiskNone {
		out.Risk = r.Risk.Level.String()
	}
	return out
}

// riskDetails renders the notable (WARNING and CRITICAL) findings of an
// assessment as display lines such as "CRITICAL ACL: +access-list 10 ...".
// INFO findings are omitted: they are cosmetic and would only add noise.
func riskDetails(a backup.RiskAssessment) []string {
	var out []string
	for _, f := range a.Findings {
		if f.Level != backup.RiskCritical && f.Level != backup.RiskWarning {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s: %s", f.Level, f.Category, f.Line))
	}
	return out
}

func hostnameIP(r backup.Result) string {
	switch {
	case r.Device.Hostname != "" && r.Device.Address != "":
		return r.Device.Hostname + " (" + r.Device.Address + ")"
	case r.Device.Hostname != "":
		return r.Device.Hostname
	default:
		return r.Device.Address
	}
}

func statusFor(r backup.Result) string {
	switch {
	case r.DryRun && r.Success:
		return StatusDryRun
	case r.Success && r.Unchanged:
		return StatusUnchanged
	case r.Success:
		return StatusSuccess
	default:
		return categoryLabel(r.Category)
	}
}

// categoryLabel maps the backup package's failure categories onto the
// table's status vocabulary. Categories not called out explicitly by the
// spec (session errors, local I/O errors, unknown) fall back to the
// generic FAILED label, which still colors red.
func categoryLabel(c errcat.Category) string {
	switch c {
	case errcat.CategoryAuthFailed:
		return StatusAuthFailed
	case errcat.CategoryTimeout, errcat.CategoryUnreachable, errcat.CategoryConnectFailed:
		return StatusTimeout
	case errcat.CategoryTruncatedOutput:
		return "TRUNCATED"
	default:
		return StatusFailed
	}
}

func fileSizeFor(r backup.Result) int64 {
	if r.OutputPath == "" {
		return -1
	}
	info, err := os.Stat(r.OutputPath)
	if err != nil {
		return -1
	}
	return info.Size()
}

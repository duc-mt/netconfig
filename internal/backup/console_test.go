// ==============================================================================
// File name:     console_test.go
// Description:   Tests for the backup run's console and log rendering.
// License:       MIT
// ==============================================================================
package backup

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"netconfig/internal/compliance"
	"netconfig/internal/errcat"
	"netconfig/internal/inventory"
	"netconfig/internal/logging"
)

// newConsole returns a Console writing plain text to a captured console and to
// a log file in a temp directory.
func newConsole(t *testing.T, color bool) (Console, *strings.Builder, func() string) {
	t.Helper()
	dir := t.TempDir()
	var out strings.Builder
	log, err := logging.New(logging.Options{Dir: dir, Console: &out, Color: color})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return Console{Log: log}, &out, func() string {
		data, err := os.ReadFile(log.Path())
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
}

func lineWith(t *testing.T, text, needle string) string {
	t.Helper()
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	t.Fatalf("no line containing %q in:\n%s", needle, text)
	return ""
}

func okResult(host, addr string) Result {
	return Result{
		Device:     inventory.Device{Hostname: host, Address: addr},
		Success:    true,
		OutputPath: "backups/run/cisco_ios/" + host + ".cfg",
		Duration:   1500 * time.Millisecond,
	}
}

func TestProgressLines(t *testing.T) {
	saved := okResult("sw1", "10.0.0.1")
	changed := okResult("sw2", "10.0.0.2")
	changed.HasDiff, changed.DiffAdded, changed.DiffRemoved = true, 3, 1
	unchanged := okResult("sw3", "10.0.0.3")
	unchanged.Unchanged = true
	volatileOnly := okResult("sw4", "10.0.0.4")
	volatileOnly.Unchanged, volatileOnly.VolatileOnly = true, true
	risky := okResult("sw5", "10.0.0.5")
	risky.Risk = RiskAssessment{Level: RiskCritical, Categories: []string{"ACL", "SSH"}}
	dry := okResult("sw6", "10.0.0.6")
	dry.DryRun = true
	failed := Result{
		Device:   inventory.Device{Hostname: "sw7", Address: "10.0.0.7"},
		Category: errcat.CategoryAuthFailed,
		Err:      errors.New("unable to authenticate"),
		Duration: time.Second,
	}

	tests := []struct {
		completed int
		res       Result
		want      string
	}{
		{1, saved, "[1/7] OK      sw1                  (10.0.0.1) [SAVED] -> backups/run/cisco_ios/sw1.cfg [1.5s]"},
		{2, changed, "[2/7] OK      sw2                  (10.0.0.2) [SAVED (+3/-1)] -> backups/run/cisco_ios/sw2.cfg [1.5s]"},
		{3, unchanged, "[3/7] OK      sw3                  (10.0.0.3) [UNCHANGED] ->"},
		{4, volatileOnly, "[UNCHANGED (volatile lines only)]"},
		{5, risky, "[SAVED RISK=CRITICAL(ACL,SSH)]"},
		{6, dry, "[6/7] OK      sw6                  (10.0.0.6) [DRY-RUN] [1.5s]"},
		{7, failed, "[7/7] FAILED  sw7                  (10.0.0.7) category=AUTHENTICATION_FAILED detail=unable to authenticate [1s]"},
	}
	for _, tt := range tests {
		c, out, _ := newConsole(t, false)
		c.Progress(tt.completed, 7, tt.res)
		if !strings.Contains(out.String(), tt.want) {
			t.Errorf("progress for %s:\n got  %q\n want it to contain %q", tt.res.Device.Hostname, out.String(), tt.want)
		}
	}

	// failures are ERROR, everything else INFO
	c, out, _ := newConsole(t, false)
	c.Progress(1, 1, failed)
	c.Progress(1, 1, saved)
	if l := lineWith(t, out.String(), "FAILED"); !strings.Contains(l, "ERROR") {
		t.Errorf("failure not logged as ERROR: %q", l)
	}
	if l := lineWith(t, out.String(), "OK      sw1"); !strings.Contains(l, "INFO") {
		t.Errorf("success not logged as INFO: %q", l)
	}
}

func TestDiffLinesMarkRiskyLines(t *testing.T) {
	c, out, file := newConsole(t, false)
	c.DiffLines("sw1", "  ", []string{
		"+hostname sw1-new",
		"+access-list 101 permit ip any any",
		"-snmp-server community public RO",
		"+interface Gi0/1",
	})
	got := out.String()

	if l := lineWith(t, got, "hostname sw1-new"); strings.Contains(l, "<==") || !strings.Contains(l, "INFO") {
		t.Errorf("a cosmetic change must stay INFO and unmarked: %q", l)
	}
	acl := lineWith(t, got, "access-list 101")
	if !strings.Contains(acl, "<== CRITICAL: ACL") || !strings.Contains(acl, "WARN") {
		t.Errorf("an ACL change must be flagged CRITICAL at WARN level: %q", acl)
	}
	if snmp := lineWith(t, got, "snmp-server community"); !strings.Contains(snmp, "<== CRITICAL: SNMP") {
		t.Errorf("an SNMP change must be flagged: %q", snmp)
	}
	if !strings.Contains(acl, "[sw1]") || !strings.Contains(acl, "  +access-list") {
		t.Errorf("host tag and prefix missing: %q", acl)
	}
	// the log file carries the same plain text
	if l := lineWith(t, file(), "access-list 101"); !strings.Contains(l, "<== CRITICAL: ACL") || strings.Contains(l, "\x1b[") {
		t.Errorf("log file line: %q", l)
	}

	// nothing to log, nothing logged
	c2, out2, _ := newConsole(t, false)
	c2.DiffLines("sw1", "  ", nil)
	if out2.String() != "" {
		t.Errorf("empty diff produced output: %q", out2.String())
	}
}

func TestDiffLinesColorTheChangeNotTheLog(t *testing.T) {
	c, out, file := newConsole(t, true)
	c.DiffLines("sw1", "", []string{"+ntp server 10.0.0.9", "-ntp server 10.0.0.8", " unchanged context"})
	if !strings.Contains(out.String(), "\x1b[32m+ntp server") || !strings.Contains(out.String(), "\x1b[31m-ntp server") {
		t.Errorf("additions must be green and removals red on a colour console: %q", out.String())
	}
	if strings.Contains(file(), "\x1b[") {
		t.Error("the log file must never contain colour codes")
	}
}

func TestSummaryCountsAndGroupsFailures(t *testing.T) {
	c, out, _ := newConsole(t, false)
	fail := func(host string, cat errcat.Category) Result {
		return Result{Device: inventory.Device{Hostname: host, Address: "10.0.0.9"}, Category: cat, Err: errors.New("boom"), Duration: time.Second}
	}
	results := []Result{
		okResult("a", "10.0.0.1"),
		fail("b", errcat.CategoryUnreachable),
		fail("c", errcat.CategoryAuthFailed),
		fail("d", errcat.CategoryUnreachable),
	}
	if n := c.Summary(results, 42*time.Second); n != 3 {
		t.Errorf("Summary returned %d failures, want 3", n)
	}
	got := out.String()
	for _, want := range []string{
		"---- Backup run summary ----",
		"OK      a ",
		"FAILED  b ",
		"---- Totals ----",
		"Devices: 4 total, 1 succeeded, 3 failed",
		"Total runtime: 42s",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary is missing %q:\n%s", want, got)
		}
	}
	// roll-up by category, sorted by name (only the block after the totals)
	rollup := got[strings.Index(got, "---- Totals ----"):]
	auth := strings.Index(rollup, "AUTHENTICATION_FAILED")
	unreach := strings.Index(rollup, "CONNECTION_TIMEOUT_OR_UNREACHABLE")
	if auth < 0 || unreach < 0 || auth > unreach {
		t.Errorf("failure categories missing or not sorted:\n%s", rollup)
	}
	if l := lineWith(t, rollup, "CONNECTION_TIMEOUT_OR_UNREACHABLE  "); !strings.HasSuffix(strings.TrimSpace(l), "2") {
		t.Errorf("unreachable count should be 2: %q", l)
	}
}

func TestSummaryRuntimeFallsBackToTheSumOfDurations(t *testing.T) {
	c, out, _ := newConsole(t, false)
	a, b := okResult("a", "10.0.0.1"), okResult("b", "10.0.0.2")
	c.Summary([]Result{a, b})
	if !strings.Contains(out.String(), "Total runtime: 3s") {
		t.Errorf("want the summed 3s runtime:\n%s", out.String())
	}
}

func TestSummaryReportsRiskComplianceAndWarnings(t *testing.T) {
	crit := okResult("fw1", "10.0.0.1")
	crit.DiffAdded, crit.DiffRemoved = 2, 1
	crit.Risk = RiskAssessment{
		Level: RiskCritical, Categories: []string{"ACL"},
		Findings: []RiskFinding{
			{Level: RiskCritical, Category: "ACL", Line: "+access-list 101 permit ip any any"},
			{Level: RiskInfo, Category: "NTP", Line: "+ntp server 10.0.0.9"},
		},
	}
	warn := okResult("sw2", "10.0.0.2")
	warn.Risk = RiskAssessment{Level: RiskWarning, Categories: []string{"VLAN"},
		Findings: []RiskFinding{{Level: RiskWarning, Category: "VLAN", Line: "+vlan 30"}}}
	info := okResult("sw3", "10.0.0.3")
	info.Risk = RiskAssessment{Level: RiskInfo, Categories: []string{"NTP"}}
	drifted := okResult("sw4", "10.0.0.4")
	drifted.Compliance = compliance.Report{Checked: true, Rules: 4,
		Drifts: []compliance.Drift{{Kind: compliance.KindMissing, Rule: "service password-encryption"}}}
	clean := okResult("sw5", "10.0.0.5")
	clean.Compliance = compliance.Report{Checked: true, Rules: 4}
	warned := okResult("sw6", "10.0.0.6")
	warned.Warnings = []string{"diff skipped: configuration too large"}

	c, out, file := newConsole(t, false)
	c.Summary([]Result{crit, warn, info, drifted, clean, warned})
	got := out.String()

	for _, want := range []string{
		"[SAVED (+2/-1) RISK=CRITICAL(ACL)]",
		"---- Risk alerts ----",
		"RISK    fw1                  CRITICAL(ACL) (+2/-1)",
		"CRITICAL ACL         +access-list 101 permit ip any any",
		"RISK    sw2                  WARNING(VLAN)",
		"Risk: 1 critical, 1 warning, 1 info (devices by highest risk level)",
		"DRIFT   sw4 ",
		"(1 of 4 baseline rule(s) failed)",
		"service password-encryption",
		"Compliance: 1 of 2 checked device(s) match the golden baseline (50%)",
		"WARN    sw6                  diff skipped: configuration too large",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "+ntp server 10.0.0.9") {
		t.Error("INFO-level findings must not be listed in the risk alerts block")
	}
	if !strings.Contains(file(), "---- Risk alerts ----") {
		t.Error("the log file must get the summary too")
	}
}

func TestSummaryStaysQuietWithoutRiskOrCompliance(t *testing.T) {
	c, out, _ := newConsole(t, false)
	c.Summary([]Result{okResult("a", "10.0.0.1")})
	for _, banned := range []string{"Risk alerts", "Risk:", "Compliance:", "DRIFT", "WARN"} {
		if strings.Contains(out.String(), banned) {
			t.Errorf("unexpected %q in:\n%s", banned, out.String())
		}
	}
}

func TestSummaryCapsAlertFindingsAndDrifts(t *testing.T) {
	r := okResult("fw1", "10.0.0.1")
	r.Risk.Level = RiskCritical
	for i := 0; i < 12; i++ {
		r.Risk.Findings = append(r.Risk.Findings, RiskFinding{Level: RiskCritical, Category: "ACL", Line: fmt.Sprintf("+access-list %d permit any", i)})
	}
	r.Compliance.Checked, r.Compliance.Rules = true, 30
	for i := 0; i < 15; i++ {
		r.Compliance.Drifts = append(r.Compliance.Drifts, compliance.Drift{Kind: compliance.KindMissing, Rule: fmt.Sprintf("rule %02d", i)})
	}

	c, out, _ := newConsole(t, false)
	c.Summary([]Result{r})
	got := out.String()
	if !strings.Contains(got, "... and 4 more notable line(s)") {
		t.Errorf("12 findings with a cap of 8 should leave 4 more:\n%s", got)
	}
	if strings.Contains(got, "access-list 8 ") || !strings.Contains(got, "access-list 7 ") {
		t.Errorf("exactly the first 8 findings must be listed:\n%s", got)
	}
	if !strings.Contains(got, "... and 5 more") {
		t.Errorf("15 drifts with a cap of 10 should leave 5 more:\n%s", got)
	}
}

// Secrets the logger was told about must be masked in everything the console
// prints, including a failure detail that happens to quote one.
func TestConsoleMasksRegisteredSecrets(t *testing.T) {
	c, out, file := newConsole(t, false)
	c.Log.AddSecret("hunter2-secret")
	c.Progress(1, 1, Result{
		Device:   inventory.Device{Hostname: "sw1", Address: "10.0.0.1"},
		Category: errcat.CategoryAuthFailed,
		Err:      errors.New("login failed for password hunter2-secret"),
	})
	if strings.Contains(out.String(), "hunter2-secret") || strings.Contains(file(), "hunter2-secret") {
		t.Errorf("a registered secret leaked:\n%s\n%s", out.String(), file())
	}
}

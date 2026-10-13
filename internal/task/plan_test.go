package task

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"netconfig/internal/inventory"
	"netconfig/internal/vendor"
)

func planJob(t *testing.T, vendorName, host string, cmds ...string) Job {
	t.Helper()
	prof, ok := vendor.Lookup(vendorName)
	if !ok {
		t.Fatalf("vendor %q", vendorName)
	}
	return Job{
		Device:   inventory.Device{Hostname: host, Address: "10.0.0.1", Port: 22, Vendor: vendorName},
		Profile:  prof,
		Commands: cmds,
	}
}

func TestBuildPlanRows(t *testing.T) {
	jobs := []Job{
		planJob(t, "junos", "r1", "set system host-name r1"),
		planJob(t, "cisco", "sw1", "no ip route 0.0.0.0 0.0.0.0", "interface Gi0/1", "shutdown"),
		{Device: inventory.Device{Hostname: "gone"}, Skip: CatUnsupportedVendor},
		planJob(t, "huawei", "fw1", "sysname x"),
	}
	reports := make([]LintReport, len(jobs))
	for i, j := range jobs {
		if j.Skip == "" {
			reports[i] = LintJob(j, "svc", false)
		}
	}
	reports[3] = LintReport{Err: errors.New("lint exploded")} // an analysis failure on one device

	rows := BuildPlanRows(jobs, reports)
	if len(rows) != 3 {
		t.Fatalf("skipped devices must not appear: %+v", rows)
	}
	byHost := map[string]PlanRow{}
	for _, r := range rows {
		byHost[r.Host] = r
	}
	r1, sw1, fw1 := byHost["r1"], byHost["sw1"], byHost["fw1"]

	if r1.Risk != "LOW" || r1.Commands != 1 || r1.Impact != "System" || r1.Safety != vendor.RollbackSafe {
		t.Fatalf("r1 = %+v", r1)
	}
	if sw1.Risk != "CRITICAL" || sw1.Commands != 3 || sw1.Safety != vendor.RollbackRebootOnly {
		t.Fatalf("sw1 = %+v", sw1)
	}
	if sw1.Impact != "Routing / Interface" {
		t.Fatalf("impact = %q, want the subsystems joined by ' / '", sw1.Impact)
	}
	if len(sw1.Findings) != 2 {
		t.Fatalf("MEDIUM+ findings are carried for display: %+v", sw1.Findings)
	}
	if fw1.Risk != "UNKNOWN" || fw1.Safety != vendor.RollbackClientOnly {
		t.Fatalf("a failed analysis is shown as UNKNOWN, never as LOW: %+v", fw1)
	}
}

func TestBuildPlanRowsCapsLongImpactLists(t *testing.T) {
	job := planJob(t, "cisco", "sw1",
		"router bgp 65000", "exit", "router ospf 1", "exit", "interface Gi0/1", "exit",
		"vlan 10", "exit", "aaa new-model", "ntp server 10.0.0.9")
	rows := BuildPlanRows([]Job{job}, []LintReport{LintJob(job, "", false)})
	// Six subsystems are touched; four are named and the rest summarised.
	if want := "BGP / OSPF / Interface / VLAN/L2 / +2"; rows[0].Impact != want {
		t.Fatalf("impact = %q, want %q", rows[0].Impact, want)
	}
}

func TestBuildPlanRowsWithoutReport(t *testing.T) {
	rows := BuildPlanRows([]Job{planJob(t, "junos", "r1", "set system host-name r1")}, nil)
	if len(rows) != 1 || rows[0].Risk != "LOW" || rows[0].Impact != "-" {
		t.Fatalf("%+v", rows)
	}
}

func TestRenderPlan(t *testing.T) {
	jobs := []Job{
		planJob(t, "junos", "r1", "set system host-name r1"),
		planJob(t, "cisco", "sw1", "no ip route 0.0.0.0 0.0.0.0"),
		planJob(t, "huawei", "fw1", "sysname x"),
	}
	reports := make([]LintReport, len(jobs))
	for i, j := range jobs {
		reports[i] = LintJob(j, "svc", false)
	}
	out := RenderPlan(BuildPlanRows(jobs, reports), PlanRenderOptions{CommitConfirm: 5})

	for _, want := range []string{
		"netconfig change plan",
		"HOST", "VENDOR", "CMDS", "RISK", "IMPACT", "ROLLBACK",
		"r1", "junos", "LOW", "SAFE",
		"sw1", "CRITICAL", "REBOOT ONLY",
		"fw1", "UNSAFE",
		"default-route-removed", // the finding behind a CRITICAL
		"ROLLBACK sw1: REBOOT REQUIRED",
		"ROLLBACK fw1: UNSAFE / OOB REQUIRED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ROLLBACK r1:") {
		t.Errorf("a SAFE device needs no hazard line:\n%s", out)
	}
	if strings.Contains(out, "DRY-RUN") {
		t.Error("not a dry run")
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("no colour requested")
	}

	// Without -commit-confirm the per-device hazard lines are not repeated;
	// the rating column and the legend still show it.
	if out := RenderPlan(BuildPlanRows(jobs, reports), PlanRenderOptions{}); strings.Contains(out, "ROLLBACK sw1:") || !strings.Contains(out, "REBOOT ONLY") {
		t.Errorf("hazard lines only accompany -commit-confirm:\n%s", out)
	}
}

func TestRenderPlanTableIsRectangular(t *testing.T) {
	jobs := []Job{planJob(t, "junos", "r1", "set system host-name r1"), planJob(t, "cisco", "a-much-longer-hostname", "ntp server 10.0.0.9")}
	reports := []LintReport{LintJob(jobs[0], "", false), LintJob(jobs[1], "", false)}
	out := RenderPlan(BuildPlanRows(jobs, reports), PlanRenderOptions{})
	var width int
	for _, line := range strings.Split(out, "\n") {
		if !strings.ContainsAny(line, "│╭├╰") {
			continue
		}
		if w := utf8.RuneCountInString(line); width == 0 {
			width = w
		} else if w != width {
			t.Fatalf("ragged table row (%d != %d): %q\n%s", w, width, line, out)
		}
	}
	if width == 0 {
		t.Fatalf("no table drawn:\n%s", out)
	}
	if !strings.Contains(out, "│    1 │") {
		t.Fatalf("CMDS must be right-aligned:\n%s", out)
	}
}

func TestRenderPlanDryRunAndColor(t *testing.T) {
	jobs := []Job{planJob(t, "cisco", "sw1", "no ip route 0.0.0.0 0.0.0.0"), planJob(t, "junos", "r1", "set system host-name r1")}
	reports := []LintReport{LintJob(jobs[0], "", false), LintJob(jobs[1], "", false)}
	out := RenderPlan(BuildPlanRows(jobs, reports), PlanRenderOptions{DryRun: true, Color: true})
	if !strings.Contains(out, "DRY-RUN") {
		t.Fatalf("a combined -plan -dry-run says so:\n%s", out)
	}
	if !strings.Contains(out, ansiRed+"CRITICAL"+ansiReset) || !strings.Contains(out, ansiGreen+"LOW     "+ansiReset) {
		t.Fatalf("risk cells are coloured (padding inside the colour):\n%q", out)
	}
	// Colour must not change the geometry of the table.
	plain := RenderPlan(BuildPlanRows(jobs, reports), PlanRenderOptions{DryRun: true})
	strip := func(s string) string {
		for _, c := range []string{ansiRed, ansiGreen, ansiYellow, ansiBold, ansiReset} {
			s = strings.ReplaceAll(s, c, "")
		}
		return s
	}
	if strip(out) != plain {
		t.Fatalf("coloured and plain output differ beyond escape codes")
	}
}

func TestRenderPlanEmpty(t *testing.T) {
	out := RenderPlan(nil, PlanRenderOptions{})
	if !strings.Contains(out, "HOST") {
		t.Fatalf("an empty plan still renders its header:\n%s", out)
	}
}

func TestRiskColors(t *testing.T) {
	cases := []struct {
		level RiskLevel
		risk  string
		want  string
	}{
		{RiskLow, "LOW", ansiGreen},
		{RiskMedium, "MEDIUM", ansiYellow},
		{RiskHigh, "HIGH", ansiRed},
		{RiskCritical, "CRITICAL", ansiRed},
		{RiskLow, "UNKNOWN", ansiYellow}, // a failed analysis must not look green
	}
	for _, tc := range cases {
		if got := riskColor(tc.level, tc.risk); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.risk, got, tc.want)
		}
	}
}

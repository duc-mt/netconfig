// ==============================================================================
// Package report implements tests for the HTML and Markdown reports.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package report

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/internal/backup"
	"netops/internal/compliance"
	"netops/internal/inventory"
)

var reportTime = time.Date(2026, time.October, 12, 8, 13, 22, 0, time.UTC)

func testInfo() RunInfo {
	return RunInfo{RunName: "backup-2026-10-12-0813", GeneratedAt: reportTime}
}

// sampleResults covers every state a report has to render: a changed
// device with a critical risk, an unchanged one, a compliant one, one with
// drift, a first-time backup and a failure.
func sampleResults() []BackupResult {
	return []BackupResult{
		{
			HostnameIP: "sw1 (10.0.0.1)", Platform: "cisco_ios", Status: "SUCCESS", FileSize: 2048, Duration: 1.2,
			Diff: "+2/-1", Risk: "CRITICAL", RiskBadge: "CRITICAL: ACL",
			RiskDetails: []string{"CRITICAL ACL: +ip access-list extended MGMT"},
			DiffLines:   []string{"-ntp server 1.1.1.1", "+ip access-list extended MGMT", "+ permit ip any any"},
		},
		{
			HostnameIP: "sw2 (10.0.0.2)", Platform: "cisco_ios", Status: "UNCHANGED", FileSize: 1024, Duration: 0.8, Diff: "-",
			ComplianceChecked: true,
		},
		{
			HostnameIP: "gw3 (10.0.0.3)", Platform: "vyos", Status: "SUCCESS", FileSize: 4096, Duration: 2.5, Diff: "+1/-0",
			Risk: "WARNING", RiskBadge: "ROUTING",
			DiffLines:         []string{"+set protocols static route 10.1.0.0/16 next-hop 10.0.0.254"},
			ComplianceChecked: true,
			Drifts:            []string{`missing: "set service ntp server time1.vyos.net"`, `forbidden: "set service telnet" is present`},
		},
		{
			HostnameIP: "gw4 (10.0.0.4)", Platform: "vyos", Status: "SUCCESS", FileSize: 512, Duration: 0.5, Diff: "-",
		},
		{
			HostnameIP: "sw5 (10.0.0.5)", Platform: "cisco_ios", Status: "TIMEOUT", Duration: 30, Diff: "-",
			Error: errors.New("dial tcp 10.0.0.5:22: i/o timeout"),
		},
	}
}

func TestSummarize(t *testing.T) {
	got := Summarize(sampleResults())
	want := Totals{
		Total: 5, Succeeded: 4, Unchanged: 1, Changed: 2, Failed: 1,
		Checked: 2, Compliant: 1, WithDrifts: 1,
		Critical: 1, Warning: 1,
	}
	if got != want {
		t.Errorf("Summarize =\n %+v\nwant\n %+v", got, want)
	}

	rate, ok := got.ComplianceRate()
	if !ok || rate != 50 {
		t.Errorf("ComplianceRate = %v, %v, want 50, true", rate, ok)
	}
	if _, ok := (Totals{}).ComplianceRate(); ok {
		t.Error("ComplianceRate must report ok=false when nothing was checked")
	}
	if got := Summarize(nil); got != (Totals{}) {
		t.Errorf("Summarize(nil) = %+v, want zero", got)
	}
}

func TestExpandPath(t *testing.T) {
	info := testInfo()
	tests := []struct{ in, want string }{
		{"reports/run-latest.html", "reports/run-latest.html"},
		{"backups/{run}/report.html", "backups/backup-2026-10-12-0813/report.html"},
		{"backups/<run>/report.html", "backups/backup-2026-10-12-0813/report.html"},
		{"reports/{timestamp}.md", "reports/20261012-081322.md"},
		{"reports/<timestamp>.md", "reports/20261012-081322.md"},
		{"reports/{date}/{run}.html", "reports/2026-10-12/backup-2026-10-12-0813.html"},
		{"reports/CHANGELOG-{date}.md", "reports/CHANGELOG-2026-10-12.md"},
		{"no placeholders {unknown} ok", "no placeholders {unknown} ok"},
	}
	for _, tt := range tests {
		if got := ExpandPath(tt.in, info); got != tt.want {
			t.Errorf("ExpandPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRenderHTMLStructure(t *testing.T) {
	page, warnings := RenderHTML(testInfo(), sampleResults())
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	for _, want := range []string{
		"<!DOCTYPE html>",
		"prefers-color-scheme:dark",
		"<meta name=\"viewport\"",
		"backup-2026-10-12-0813",
		// summary cards
		">Total devices<", ">Succeeded<", ">Unchanged<", ">Changed<", ">Failed<", ">Compliance rate<",
		`<div class="n">5</div>`,
		`<div class="n">50%</div>`,
		// table rows with badges
		"sw1 (10.0.0.1)",
		`<span class="badge crit">CRITICAL: ACL</span>`,
		`<span class="badge warn">ROUTING</span>`,
		`<span class="badge ok">✔ COMPLIANT</span>`,
		`<span class="badge bad">✖ 2 DRIFTS</span>`,
		`<span class="badge warn">TIMEOUT</span>`,
		"dial tcp 10.0.0.5:22: i/o timeout",
		// collapsible diffs with colored lines
		"<details open><summary>sw1 (10.0.0.1)",
		`<span class="add">+ip access-list extended MGMT</span>`,
		`<span class="del">-ntp server 1.1.1.1</span>`,
		"CRITICAL ACL: +ip access-list extended MGMT",
		// drift section
		"Compliance drift",
		"set service telnet",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}

	// Only the critical device opens by default; the warning one is collapsed.
	if !strings.Contains(page, "<details><summary>gw3 (10.0.0.3)") {
		t.Error("the non-critical changed device should be collapsed by default")
	}
}

func TestRenderHTMLIsSelfContained(t *testing.T) {
	page, _ := RenderHTML(testInfo(), sampleResults())
	for _, forbidden := range []string{"http://", "https://", "<script", "<link", "@import", "src="} {
		if strings.Contains(page, forbidden) {
			t.Errorf("a self-contained report must not contain %q", forbidden)
		}
	}
}

func TestRenderHTMLEscapesContent(t *testing.T) {
	results := []BackupResult{{
		HostnameIP: `<img src=x onerror=alert(1)> (10.0.0.1)`,
		Platform:   "vyos",
		Status:     "SUCCESS",
		Diff:       "+1/-1",
		DiffLines:  []string{`-set system login user x authentication encrypted-password "<REDACTED>"`, `+<script>alert("x")</script>`},
		Error:      errors.New(`bad <b>error</b> & more`),
	}}
	page, _ := RenderHTML(testInfo(), results)

	for _, raw := range []string{"<img src=x", "<script>alert", "<REDACTED>", "<b>error</b>"} {
		if strings.Contains(page, raw) {
			t.Errorf("unescaped content %q leaked into the HTML", raw)
		}
	}
	for _, escaped := range []string{"&lt;img src=x", "&lt;REDACTED&gt;", "&lt;script&gt;alert", "&amp; more"} {
		if !strings.Contains(page, escaped) {
			t.Errorf("expected escaped content %q in the HTML", escaped)
		}
	}
}

func TestRenderHTMLEmptyAndMinimal(t *testing.T) {
	page, warnings := RenderHTML(RunInfo{}, nil)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	for _, want := range []string{"No devices in this run.", ">Compliance rate<", ">n/a<", "</html>"} {
		if !strings.Contains(page, want) {
			t.Errorf("empty report missing %q", want)
		}
	}
	if strings.Contains(page, "Configuration changes") || strings.Contains(page, "Compliance drift") {
		t.Error("an empty report must not render change or drift sections")
	}
}

func TestRenderHTMLCapsHugeDiffs(t *testing.T) {
	lines := make([]string, maxReportDiffLines+5)
	for i := range lines {
		lines[i] = "+line"
	}
	page, _ := RenderHTML(testInfo(), []BackupResult{{
		HostnameIP: "big (1.1.1.1)", Platform: "vyos", Status: "SUCCESS", Diff: "+2005/-0", DiffLines: lines,
	}})
	if got := strings.Count(page, `<span class="add">+line</span>`); got != maxReportDiffLines {
		t.Errorf("rendered %d diff lines, want the cap of %d", got, maxReportDiffLines)
	}
	if !strings.Contains(page, "5 more line(s) not shown") {
		t.Error("expected a note about the truncated lines")
	}
}

func TestRenderHTMLChangeWithoutDiffLines(t *testing.T) {
	page, _ := RenderHTML(testInfo(), []BackupResult{{
		HostnameIP: "gw (1.1.1.1)", Platform: "vyos", Status: "SUCCESS", Diff: "+1/-0",
	}})
	if !strings.Contains(page, "Only the change counts are available") {
		t.Error("a changed device without diff lines should say so")
	}
}

func TestRenderHTMLShowsWarnings(t *testing.T) {
	page, _ := RenderHTML(testInfo(), []BackupResult{{
		HostnameIP: "gw (1.1.1.1)", Platform: "vyos", Status: "SUCCESS", Diff: "-",
		Warnings: []string{"change detection failed: boom"},
	}})
	if !strings.Contains(page, "<h2>Warnings</h2>") || !strings.Contains(page, "gw (1.1.1.1): change detection failed: boom") {
		t.Error("device warnings should be listed in the report")
	}
}

func TestSafeSectionRecoversFromPanic(t *testing.T) {
	var warnings []string
	got := safeSection("sw1", &warnings, func() string { panic("boom") })
	if got != "" {
		t.Errorf("safeSection returned %q after a panic, want empty", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "sw1") || !strings.Contains(warnings[0], "boom") {
		t.Errorf("warnings = %v, want one naming the device and the panic", warnings)
	}
	if got := safeSection("sw1", &warnings, func() string { return "ok" }); got != "ok" {
		t.Errorf("safeSection = %q, want the render output", got)
	}
}

func TestWriteHTMLCreatesDirectoriesAndOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports", "nested", "run-latest.html")

	if _, err := WriteHTML(path, testInfo(), sampleResults()); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(first), "<!DOCTYPE html>") {
		t.Fatalf("report not written correctly (err=%v)", err)
	}

	if _, err := WriteHTML(path, testInfo(), nil); err != nil {
		t.Fatalf("second WriteHTML: %v", err)
	}
	second, _ := os.ReadFile(path)
	if strings.Contains(string(second), "sw1 (10.0.0.1)") {
		t.Error("the HTML report is a per-run snapshot and must be overwritten, not appended")
	}

	// No temp files may be left behind.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("expected only the report file, found %d entries", len(entries))
	}
}

func TestWriteHTMLUnwritablePathReturnsError(t *testing.T) {
	// A regular file where a directory is needed makes MkdirAll fail.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteHTML(filepath.Join(blocker, "sub", "r.html"), testInfo(), nil); err == nil {
		t.Error("expected an error when the report directory cannot be created")
	}
}

func TestRenderMarkdownStructure(t *testing.T) {
	section, warnings := RenderMarkdown(testInfo(), sampleResults())
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	for _, want := range []string{
		"## 2026-10-12 08:13:22 - `backup-2026-10-12-0813`",
		"| Devices | Succeeded | Unchanged | Changed | Failed | Compliance |",
		"| 5 | 4 | 1 | 2 | 1 | 50% |",
		"**Risk:** 1 device(s) with CRITICAL changes, 1 with WARNING changes.",
		"| Device | Platform | Status | Diff | Risk | Compliance |",
		"| sw1 (10.0.0.1) | cisco_ios | SUCCESS | +2/-1 | CRITICAL: ACL | - |",
		"| sw2 (10.0.0.2) | cisco_ios | UNCHANGED | - | - | ✔ COMPLIANT |",
		"| gw3 (10.0.0.3) | vyos | SUCCESS | +1/-0 | ROUTING | ✖ 2 DRIFTS |",
		"#### sw1 (10.0.0.1) (+2/-1) - CRITICAL: ACL",
		"- CRITICAL ACL: +ip access-list extended MGMT",
		"```diff\n-ntp server 1.1.1.1\n+ip access-list extended MGMT\n+ permit ip any any\n```",
		"### Compliance drift",
		"#### gw3 (10.0.0.3) (2 DRIFTS)",
		`- missing: "set service ntp server time1.vyos.net"`,
	} {
		if !strings.Contains(section, want) {
			t.Errorf("Markdown section missing %q\n---\n%s", want, section)
		}
	}
	if strings.Contains(section, "#### sw2") {
		t.Error("an unchanged, compliant device must not get a change or drift section")
	}
}

func TestRenderMarkdownEscapesTablesAndFences(t *testing.T) {
	results := []BackupResult{{
		HostnameIP: "a|b (1.1.1.1)", Platform: "vyos", Status: "SUCCESS", Diff: "+1/-0",
		DiffLines: []string{"+banner motd ``` tricky ```` fence"},
	}}
	section, _ := RenderMarkdown(testInfo(), results)

	if !strings.Contains(section, `| a\|b (1.1.1.1) |`) {
		t.Errorf("pipes inside table cells must be escaped:\n%s", section)
	}
	// The body holds a run of four backticks, so the fence needs five.
	if !strings.Contains(section, "`````diff\n+banner motd") || !strings.Contains(section, "\n`````\n") {
		t.Errorf("the code fence must be longer than any backtick run in the body:\n%s", section)
	}
}

func TestMdFence(t *testing.T) {
	tests := []struct{ body, want string }{
		{"", "```"},
		{"no ticks", "```"},
		{"a ` b", "```"},
		{"two `` ticks", "```"},
		{"three ``` run", "````"},
		{"four ```` run", "`````"},
	}
	for _, tt := range tests {
		if got := mdFence(tt.body); got != tt.want {
			t.Errorf("mdFence(%q) = %q, want %q", tt.body, got, tt.want)
		}
	}
}

func TestMdCell(t *testing.T) {
	if got := mdCell("a|b\nc\r"); got != `a\|b c ` {
		t.Errorf("mdCell = %q, want %q", got, `a\|b c `)
	}
}

func TestRenderMarkdownEmptyRun(t *testing.T) {
	section, _ := RenderMarkdown(testInfo(), nil)
	for _, want := range []string{"| 0 | 0 | 0 | 0 | 0 | n/a |", "_No devices in this run._"} {
		if !strings.Contains(section, want) {
			t.Errorf("empty run section missing %q", want)
		}
	}
}

func TestRenderMarkdownCapsHugeDiffs(t *testing.T) {
	lines := make([]string, maxReportDiffLines+3)
	for i := range lines {
		lines[i] = "+x"
	}
	section, _ := RenderMarkdown(testInfo(), []BackupResult{{
		HostnameIP: "big", Platform: "vyos", Status: "SUCCESS", Diff: "+2003/-0", DiffLines: lines,
	}})
	if got := strings.Count(section, "\n+x\n") + strings.Count(section, "diff\n+x\n"); got < 1 {
		t.Fatal("diff body not rendered")
	}
	if !strings.Contains(section, "3 more line(s) not shown") {
		t.Error("expected a note about the truncated lines")
	}
}

func TestComposeChangelog(t *testing.T) {
	run1 := "## run 1\n\nbody 1\n"
	run2 := "## run 2\n\nbody 2\n"

	fresh := composeChangelog("", run1)
	if !strings.HasPrefix(fresh, "# Network Configuration Changelog\n") || !strings.Contains(fresh, changelogMarker) || !strings.HasSuffix(fresh, run1) {
		t.Errorf("fresh changelog malformed:\n%s", fresh)
	}

	// A second run goes on top, the first is kept below a separator.
	both := composeChangelog(fresh, run2)
	i2, i1 := strings.Index(both, "## run 2"), strings.Index(both, "## run 1")
	if i2 < 0 || i1 < 0 || i2 > i1 {
		t.Errorf("newest run must come first:\n%s", both)
	}
	if strings.Count(both, "# Network Configuration Changelog") != 1 || strings.Count(both, changelogMarker) != 1 {
		t.Errorf("the header and marker must appear exactly once:\n%s", both)
	}
	if !strings.Contains(both, "\n---\n") {
		t.Errorf("runs should be separated by a rule:\n%s", both)
	}

	// A foreign, non-empty file is never overwritten.
	foreign := composeChangelog("# My own notes\n\nkeep me\n", run1)
	if !strings.HasPrefix(foreign, "# My own notes") || !strings.Contains(foreign, "keep me") || !strings.HasSuffix(foreign, run1) {
		t.Errorf("a file without the marker must be preserved and appended to:\n%s", foreign)
	}

	// Whitespace-only existing content counts as empty.
	if got := composeChangelog("  \n\n", run1); !strings.HasPrefix(got, "# Network Configuration Changelog") {
		t.Errorf("whitespace-only file should be treated as new:\n%s", got)
	}
}

func TestWriteMarkdownAccumulatesNewestFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports", "CHANGELOG.md")

	first := RunInfo{RunName: "backup-run-one", GeneratedAt: reportTime}
	second := RunInfo{RunName: "backup-run-two", GeneratedAt: reportTime.Add(time.Hour)}

	if _, err := WriteMarkdown(path, first, sampleResults()); err != nil {
		t.Fatalf("first WriteMarkdown: %v", err)
	}
	if _, err := WriteMarkdown(path, second, nil); err != nil {
		t.Fatalf("second WriteMarkdown: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	i2, i1 := strings.Index(text, "backup-run-two"), strings.Index(text, "backup-run-one")
	if i2 < 0 || i1 < 0 || i2 > i1 {
		t.Errorf("expected run two above run one:\n%s", text)
	}
	if !strings.Contains(text, "sw1 (10.0.0.1)") {
		t.Error("the first run's details must survive the second write")
	}
}

func TestWriteMarkdownReadErrorDoesNotOverwrite(t *testing.T) {
	// A directory at the report path: ReadFile fails with a non-"not exist" error.
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteMarkdown(path, testInfo(), nil); err == nil {
		t.Error("expected an error instead of overwriting something unreadable")
	}
}

func TestBuildRowShowsRiskBadgeInDiffColumn(t *testing.T) {
	r := sampleResults()[0]

	row, _ := buildRowOpts(r, rowOptions{diff: true})
	if got := row.cells[5]; got != "+2/-1 [CRITICAL: ACL]" {
		t.Errorf("DIFF cell = %q, want %q", got, "+2/-1 [CRITICAL: ACL]")
	}
	if row.cellColors[5] != ansiBoldRed {
		t.Errorf("critical badge color = %q, want bold red", row.cellColors[5])
	}

	warn := sampleResults()[2]
	row, _ = buildRowOpts(warn, rowOptions{diff: true})
	if got := row.cells[5]; got != "+1/-0 [ROUTING]" {
		t.Errorf("DIFF cell = %q, want %q", got, "+1/-0 [ROUTING]")
	}
	if row.cellColors[5] != ansiYellow {
		t.Errorf("warning badge color = %q, want yellow", row.cellColors[5])
	}

	// The legacy entry point keeps working and the DIFF column stays opt-in.
	legacy, _ := buildRow(r)
	if len(legacy.cells) != 6 {
		t.Errorf("buildRow without showDiff has %d cells, want 6", len(legacy.cells))
	}
}

func TestBuildRowComplianceColumn(t *testing.T) {
	opts := rowOptions{compliance: true}
	results := sampleResults()

	tests := []struct {
		idx   int
		want  string
		color string
	}{
		{1, "✔ COMPLIANT", ansiGreen},
		{2, "✖ 2 DRIFTS", ansiRed},
		{3, "-", ""},
	}
	for _, tt := range tests {
		row, _ := buildRowOpts(results[tt.idx], opts)
		// cells: host, platform, status, size, duration, compliance, error;
		// result 3 (gw4) was never checked against a baseline.
		if got := row.cells[5]; got != tt.want {
			t.Errorf("result %d: COMPLIANCE cell = %q, want %q", tt.idx, got, tt.want)
		}
		if got := row.cellColors[5]; got != tt.color {
			t.Errorf("result %d: COMPLIANCE color = %q, want %q", tt.idx, got, tt.color)
		}
	}
}

func TestTableColumns(t *testing.T) {
	tests := []struct {
		opts rowOptions
		want string
	}{
		{rowOptions{}, "HOSTNAME/IP,PLATFORM,STATUS,FILE SIZE,DURATION,ERROR"},
		{rowOptions{diff: true}, "HOSTNAME/IP,PLATFORM,STATUS,FILE SIZE,DURATION,DIFF,ERROR"},
		{rowOptions{compliance: true}, "HOSTNAME/IP,PLATFORM,STATUS,FILE SIZE,DURATION,COMPLIANCE,ERROR"},
		{rowOptions{diff: true, compliance: true}, "HOSTNAME/IP,PLATFORM,STATUS,FILE SIZE,DURATION,DIFF,COMPLIANCE,ERROR"},
	}
	for _, tt := range tests {
		if got := strings.Join(tableColumns(tt.opts), ","); got != tt.want {
			t.Errorf("tableColumns(%+v) = %q, want %q", tt.opts, got, tt.want)
		}
	}
}

func TestSummaryTableWithRiskAndCompliance(t *testing.T) {
	var out, warn strings.Builder
	fprintSummaryTable(&out, &warn, sampleResults(), false)
	text := out.String()

	for _, want := range []string{
		"DIFF", "COMPLIANCE",
		"+2/-1 [CRITICAL: ACL]",
		"+1/-0 [ROUTING]",
		"✔ COMPLIANT", "✖ 2 DRIFTS",
		"Risk: 1 critical │ 1 warning │ 0 info",
		"Compliance: 1/2 compliant (50%)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("table output missing %q:\n%s", want, text)
		}
	}
	if warn.Len() != 0 {
		t.Errorf("unexpected table warnings: %s", warn.String())
	}
}

func TestSummaryTableWithoutExtrasKeepsLegacyLayout(t *testing.T) {
	var out, warn strings.Builder
	fprintSummaryTable(&out, &warn, []BackupResult{
		{HostnameIP: "sw1", Platform: "cisco_ios", Status: "SUCCESS", FileSize: 100, Duration: 1, Diff: "-"},
	}, false)
	text := out.String()
	for _, unwanted := range []string{"DIFF", "COMPLIANCE", "Risk:", "Compliance:"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("a plain run must not show %q:\n%s", unwanted, text)
		}
	}
}

func TestSummaryTableColorsBadges(t *testing.T) {
	var out, warn strings.Builder
	fprintSummaryTable(&out, &warn, sampleResults(), true)
	text := out.String()
	if !strings.Contains(text, ansiBoldRed) || !strings.Contains(text, ansiYellow) {
		t.Errorf("expected risk colors in the colorized table: %q", text)
	}
}

func TestRiskSummaryLine(t *testing.T) {
	if line, _ := riskSummaryLine([]BackupResult{{Risk: ""}}); line != "" {
		t.Errorf("no risk: line = %q, want empty", line)
	}
	if line, color := riskSummaryLine([]BackupResult{{Risk: "WARNING"}, {Risk: "info"}}); color != ansiYellow || !strings.Contains(line, "0 critical │ 1 warning │ 1 info") {
		t.Errorf("warning-only: line=%q color=%q", line, color)
	}
	if _, color := riskSummaryLine([]BackupResult{{Risk: "CRITICAL"}}); color != ansiBoldRed {
		t.Errorf("critical color = %q, want bold red", color)
	}
}

func TestFromResultsCarriesRiskComplianceAndDiff(t *testing.T) {
	dev := inventory.Device{Hostname: "sw1", Address: "10.0.0.1", Vendor: "cisco_ios"}
	rows := FromResults([]backup.Result{{
		Device:      dev,
		Success:     true,
		HasDiff:     true,
		DiffAdded:   2,
		DiffRemoved: 1,
		DiffLines:   []string{"+ip access-list extended MGMT", "+ permit ip any any", "-ntp server 1.1.1.1"},
		Risk:        backup.AssessRisk([]string{"+ip access-list extended MGMT", "+ permit ip any any", "-ntp server 1.1.1.1"}),
		Compliance: compliance.Report{
			Checked: true,
			Rules:   1,
			Drifts:  []compliance.Drift{{Kind: compliance.KindMissing, Rule: "logging host 10.9.9.9"}},
		},
		Warnings: []string{"w1"},
	}})
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]

	if r.Diff != "+2/-1" {
		t.Errorf("Diff = %q, want +2/-1", r.Diff)
	}
	if r.Risk != "CRITICAL" || r.RiskBadge != "CRITICAL: ACL" {
		t.Errorf("Risk=%q RiskBadge=%q, want CRITICAL / %q", r.Risk, r.RiskBadge, "CRITICAL: ACL")
	}
	if len(r.RiskDetails) != 2 || !strings.HasPrefix(r.RiskDetails[0], "CRITICAL ACL: ") {
		t.Errorf("RiskDetails = %q, want the 2 critical findings only (INFO omitted)", r.RiskDetails)
	}
	if len(r.DiffLines) != 3 {
		t.Errorf("DiffLines = %q, want all 3 lines", r.DiffLines)
	}
	if !r.ComplianceChecked || len(r.Drifts) != 1 || !strings.Contains(r.Drifts[0], "logging host 10.9.9.9") {
		t.Errorf("compliance not carried over: checked=%v drifts=%q", r.ComplianceChecked, r.Drifts)
	}
	if len(r.Warnings) != 1 || r.Warnings[0] != "w1" {
		t.Errorf("Warnings = %q, want [w1]", r.Warnings)
	}
}

func TestFromResultsWithoutRiskLeavesFieldsEmpty(t *testing.T) {
	rows := FromResults([]backup.Result{{
		Device:  inventory.Device{Hostname: "gw1", Address: "10.0.0.2", Vendor: "vyos"},
		Success: true,
	}})
	r := rows[0]
	if r.Risk != "" || r.RiskBadge != "" || len(r.RiskDetails) != 0 || r.ComplianceChecked || len(r.Drifts) != 0 {
		t.Errorf("a result with no risk or compliance data must leave those fields empty: %+v", r)
	}
}

func TestFromResultsDryRun(t *testing.T) {
	rows := FromResults([]backup.Result{{
		Device:   inventory.Device{Hostname: "gw1", Address: "10.0.0.2", Vendor: "vyos"},
		Success:  true,
		DryRun:   true,
		Duration: 45 * time.Millisecond,
	}})
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.Status != StatusDryRun {
		t.Errorf("Status = %q, want %q", r.Status, StatusDryRun)
	}
	if r.FileSize != -1 {
		t.Errorf("FileSize = %d, want -1", r.FileSize)
	}
	if r.Diff != "-" {
		t.Errorf("Diff = %q, want -", r.Diff)
	}
}

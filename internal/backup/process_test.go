// ==============================================================================
// Package backup implements tests for the post-fetch processing pipeline.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package backup

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/internal/compliance"
	"netops/internal/inventory"
	"netops/internal/vendor"
)

const (
	stampOld = "! Last configuration change at 10:00:00 UTC Mon Oct 12 2026 by admin\n"
	stampNew = "! Last configuration change at 11:30:00 UTC Mon Oct 12 2026 by admin\n"
)

func testDevice(t *testing.T, vendorName, hostname string) (inventory.Device, *vendor.Profile) {
	t.Helper()
	profile, ok := vendor.Lookup(vendorName)
	if !ok {
		t.Fatalf("vendor.Lookup(%q): unknown vendor", vendorName)
	}
	return inventory.Device{Hostname: hostname, Address: "10.0.0.1", Port: 22, Vendor: profile.Name}, profile
}

// seedBackup writes a pre-existing backup of dev in an earlier run directory.
func seedBackup(t *testing.T, outDir, runName string, dev inventory.Device, profile *vendor.Profile, content string) string {
	t.Helper()
	spec := archiveFor(profile)
	dir := filepath.Join(outDir, runName, spec.Dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, sanitize(dev.Hostname)+spec.Ext)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

func TestDefaultRunName(t *testing.T) {
	got := DefaultRunName(time.Date(2026, time.October, 12, 7, 57, 33, 0, time.UTC))
	if got != "backup-2026-10-12-0757" {
		t.Errorf("DefaultRunName = %q, want %q", got, "backup-2026-10-12-0757")
	}
}

func TestProcessConfigVolatileOnlyChangeIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "cisco_ios", "sw1")
	body := "hostname sw1\nntp server 10.0.0.1\n"
	prev := seedBackup(t, dir, "backup-2026-10-12-0000", dev, profile, stampOld+body)

	cfg := Config{OutputDir: dir, RunName: "backup-2026-10-13-0000", IgnoreVolatile: true}
	got := processConfig(dev, profile, stampNew+body, cfg, Result{Device: dev})

	if !got.Success {
		t.Fatalf("expected success, got err=%v", got.Err)
	}
	if !got.Unchanged || !got.VolatileOnly {
		t.Errorf("Unchanged=%v VolatileOnly=%v, want both true", got.Unchanged, got.VolatileOnly)
	}
	if got.HasDiff || len(got.DiffLines) != 0 {
		t.Errorf("a volatile-only change must not produce a diff, got %v", got.DiffLines)
	}
	if got.Risk.Level != RiskNone {
		t.Errorf("Risk.Level = %s, want NONE", got.Risk.Level)
	}
	if got.OutputPath != prev {
		t.Errorf("OutputPath = %q, want the previous backup %q", got.OutputPath, prev)
	}
	if _, err := os.Stat(filepath.Join(dir, cfg.RunName)); !os.IsNotExist(err) {
		t.Errorf("no new run directory should be written for an unchanged device (stat err=%v)", err)
	}
}

func TestProcessConfigVolatileOnlyWithSaveUnchangedKeepsRawText(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "cisco_ios", "sw1")
	body := "hostname sw1\nntp server 10.0.0.1\n"
	seedBackup(t, dir, "backup-2026-10-12-0000", dev, profile, stampOld+body)

	cfg := Config{OutputDir: dir, RunName: "backup-2026-10-13-0000", IgnoreVolatile: true, SaveUnchanged: true}
	after := stampNew + body
	got := processConfig(dev, profile, after, cfg, Result{Device: dev})

	if !got.Success || !got.Unchanged || !got.VolatileOnly {
		t.Fatalf("Success=%v Unchanged=%v VolatileOnly=%v err=%v", got.Success, got.Unchanged, got.VolatileOnly, got.Err)
	}
	if saved := readFile(t, got.OutputPath); saved != after {
		t.Errorf("the saved file must be the original text, volatile lines included:\n got: %q\nwant: %q", saved, after)
	}
}

func TestProcessConfigRealChangeAmongVolatileNoise(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "cisco_ios", "sw1")
	before := stampOld + "hostname sw1\nsnmp-server community old RO\n"
	after := stampNew + "hostname sw1\nsnmp-server community new RO\n"
	seedBackup(t, dir, "backup-2026-10-12-0000", dev, profile, before)

	var onDiffCalls int
	var onDiffLines []string
	cfg := Config{
		OutputDir:      dir,
		RunName:        "backup-2026-10-13-0000",
		IgnoreVolatile: true,
		OnDiff: func(_ inventory.Device, lines []string, _, _ int) {
			onDiffCalls++
			onDiffLines = lines
		},
	}
	got := processConfig(dev, profile, after, cfg, Result{Device: dev})

	if !got.Success || got.Unchanged {
		t.Fatalf("Success=%v Unchanged=%v err=%v, want a successful changed backup", got.Success, got.Unchanged, got.Err)
	}
	wantDiff := []string{"-snmp-server community old RO", "+snmp-server community new RO"}
	if !reflect.DeepEqual(got.DiffLines, wantDiff) {
		t.Errorf("DiffLines = %q, want %q (volatile stamp must not appear)", got.DiffLines, wantDiff)
	}
	if !got.HasDiff || got.DiffAdded != 1 || got.DiffRemoved != 1 {
		t.Errorf("HasDiff=%v +%d/-%d, want true +1/-1", got.HasDiff, got.DiffAdded, got.DiffRemoved)
	}
	if onDiffCalls != 1 || !reflect.DeepEqual(onDiffLines, wantDiff) {
		t.Errorf("OnDiff calls=%d lines=%q, want 1 call with the filtered diff", onDiffCalls, onDiffLines)
	}

	// Risk is classified on the filtered diff.
	if got.Risk.Level != RiskCritical || got.Risk.Badge() != "CRITICAL: SNMP" {
		t.Errorf("Risk = %s / %q, want CRITICAL / %q", got.Risk.Level, got.Risk.Badge(), "CRITICAL: SNMP")
	}

	// The backup on disk is the untouched text; the .diff file is the filtered diff.
	if saved := readFile(t, got.OutputPath); saved != after {
		t.Errorf("saved file differs from the fetched configuration:\n got: %q\nwant: %q", saved, after)
	}
	if got.DiffPath == "" {
		t.Fatal("expected a .diff file")
	}
	if d := readFile(t, got.DiffPath); strings.Contains(d, "Last configuration change") {
		t.Errorf("the .diff file contains volatile noise: %q", d)
	}
}

func TestProcessConfigWithoutIgnoreVolatileKeepsLegacyBehavior(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "cisco_ios", "sw1")
	body := "hostname sw1\n"
	seedBackup(t, dir, "backup-2026-10-12-0000", dev, profile, stampOld+body)

	cfg := Config{OutputDir: dir, RunName: "backup-2026-10-13-0000"} // IgnoreVolatile off
	got := processConfig(dev, profile, stampNew+body, cfg, Result{Device: dev})

	if !got.Success || got.Unchanged || got.VolatileOnly {
		t.Fatalf("Success=%v Unchanged=%v VolatileOnly=%v, want a changed backup", got.Success, got.Unchanged, got.VolatileOnly)
	}
	if !got.HasDiff || got.DiffAdded != 1 || got.DiffRemoved != 1 {
		t.Errorf("the clock stamp must count as a change when filtering is off: HasDiff=%v +%d/-%d", got.HasDiff, got.DiffAdded, got.DiffRemoved)
	}
	if got.Risk.Level != RiskNone {
		t.Errorf("a clock stamp is not a risk, got %s", got.Risk.Level)
	}
}

func TestProcessConfigFirstBackupAndIdenticalBackup(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "vyos", "gw1")
	content := "set system host-name 'gw1'\n"

	cfg := Config{OutputDir: dir, RunName: "backup-2026-10-12-0000", IgnoreVolatile: true}
	first := processConfig(dev, profile, content, cfg, Result{Device: dev})
	if !first.Success || first.Unchanged || first.HasDiff {
		t.Fatalf("first backup: Success=%v Unchanged=%v HasDiff=%v err=%v", first.Success, first.Unchanged, first.HasDiff, first.Err)
	}
	if got := readFile(t, first.OutputPath); got != content {
		t.Errorf("saved content = %q, want %q", got, content)
	}

	cfg.RunName = "backup-2026-10-13-0000"
	second := processConfig(dev, profile, content, cfg, Result{Device: dev})
	if !second.Success || !second.Unchanged || second.VolatileOnly {
		t.Errorf("identical backup: Success=%v Unchanged=%v VolatileOnly=%v, want unchanged and not volatile-only", second.Success, second.Unchanged, second.VolatileOnly)
	}
	if second.OutputPath != first.OutputPath {
		t.Errorf("OutputPath = %q, want %q", second.OutputPath, first.OutputPath)
	}
}

func TestProcessConfigCompliance(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "cisco_ios", "sw1")

	baseline := compliance.New()
	for _, line := range []string{"ntp server 10.0.0.1", "logging host 10.9.9.9", "not: ip http server"} {
		rule, err := compliance.ParseRule(line)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", line, err)
		}
		if err := baseline.Add("cisco", rule); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	cfg := Config{OutputDir: dir, RunName: "backup-2026-10-12-0000", Baseline: baseline}
	got := processConfig(dev, profile, "hostname sw1\nntp server 10.0.0.1\nip http server\n", cfg, Result{Device: dev})

	if !got.Success {
		t.Fatalf("expected success, got %v", got.Err)
	}
	if !got.Compliance.Checked || got.Compliance.Rules != 3 {
		t.Fatalf("Compliance = %+v, want checked with 3 rules", got.Compliance)
	}
	if len(got.Compliance.Drifts) != 2 {
		t.Errorf("drifts = %v, want the missing syslog host and the forbidden http server", got.Compliance.DriftMessages())
	}
	if got.Compliance.Summary() != "2 DRIFTS" {
		t.Errorf("Summary = %q, want %q", got.Compliance.Summary(), "2 DRIFTS")
	}
}

func TestProcessConfigWithoutBaselineLeavesComplianceUnchecked(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "vyos", "gw1")
	cfg := Config{OutputDir: dir, RunName: "backup-2026-10-12-0000"}
	got := processConfig(dev, profile, "set system host-name 'gw1'\n", cfg, Result{Device: dev})
	if got.Compliance.Checked {
		t.Errorf("no baseline configured, yet Compliance = %+v", got.Compliance)
	}
}

func TestProcessConfigOversizedDiffDegradesToWarning(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "vyos", "gw1")

	// a configuration replaced wholesale: far more changed lines than the diff
	// is willing to look for (a large file with few changes is diffed fine)
	var b, c strings.Builder
	for i := 0; i < 2500; i++ {
		b.WriteString("set line " + strconv.Itoa(i) + "\n")
		c.WriteString("set other " + strconv.Itoa(i) + "\n")
	}
	before, after := b.String(), c.String()
	seedBackup(t, dir, "backup-2026-10-12-0000", dev, profile, before)

	cfg := Config{OutputDir: dir, RunName: "backup-2026-10-13-0000", IgnoreVolatile: true}
	got := processConfig(dev, profile, after, cfg, Result{Device: dev})

	if !got.Success {
		t.Fatalf("an undiffable configuration must still be backed up, got %v", got.Err)
	}
	if got.HasDiff || got.Unchanged {
		t.Errorf("HasDiff=%v Unchanged=%v, want a changed backup without a diff", got.HasDiff, got.Unchanged)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "too large") {
		t.Errorf("Warnings = %q, want one 'too large' warning", got.Warnings)
	}
	if saved := readFile(t, got.OutputPath); saved != after {
		t.Error("the new configuration was not saved")
	}
}

func TestCompareConfigsRecoversFromFilterPanic(t *testing.T) {
	// A rule without a compiled pattern makes Apply dereference nil.
	broken := &VolatileFilter{rules: []volatileRule{{name: "broken"}}}
	cfg := Config{IgnoreVolatile: true, VolatileFilter: broken}

	lines, added, removed, ok, warn := compareConfigs(cfg, "cisco_ios", "a\n", "b\n")
	if ok || len(lines) != 0 || added != 0 || removed != 0 {
		t.Errorf("after a panic compareConfigs must report no diff, got lines=%v +%d/-%d ok=%v", lines, added, removed, ok)
	}
	if !strings.Contains(warn, "change detection failed") {
		t.Errorf("warn = %q, want it to mention the failure", warn)
	}
}

func TestProcessConfigSurvivesBrokenFilter(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "cisco_ios", "sw1")
	seedBackup(t, dir, "backup-2026-10-12-0000", dev, profile, "hostname sw1\n")

	cfg := Config{
		OutputDir:      dir,
		RunName:        "backup-2026-10-13-0000",
		IgnoreVolatile: true,
		VolatileFilter: &VolatileFilter{rules: []volatileRule{{name: "broken"}}},
	}
	got := processConfig(dev, profile, "hostname sw2\n", cfg, Result{Device: dev})

	if !got.Success {
		t.Fatalf("a broken filter must not fail the backup, got %v", got.Err)
	}
	if len(got.Warnings) == 0 || !strings.Contains(got.Warnings[0], "change detection failed") {
		t.Errorf("Warnings = %q, want a 'change detection failed' warning", got.Warnings)
	}
	if saved := readFile(t, got.OutputPath); saved != "hostname sw2\n" {
		t.Errorf("saved = %q, want the fetched configuration", saved)
	}
}

func TestCompareConfigsAppliesVendorScopedFilter(t *testing.T) {
	cfg := Config{IgnoreVolatile: true}
	lines, _, _, ok, warn := compareConfigs(cfg, "juniper_junos",
		"## Last changed: 2026-10-12 10:00:00 UTC\nset system host-name r1\n",
		"## Last changed: 2026-10-12 11:00:00 UTC\nset system host-name r1\n")
	if !ok || warn != "" || len(lines) != 0 {
		t.Errorf("Junos timestamp should be ignored: lines=%v ok=%v warn=%q", lines, ok, warn)
	}

	// The same comment on a Cisco device is not recognised as volatile.
	lines, _, _, ok, _ = compareConfigs(cfg, "cisco_ios",
		"## Last changed: 2026-10-12 10:00:00 UTC\n",
		"## Last changed: 2026-10-12 11:00:00 UTC\n")
	if !ok || len(lines) != 2 {
		t.Errorf("a Junos comment must still diff on Cisco, got lines=%v ok=%v", lines, ok)
	}
}

func TestCheckComplianceNilBaseline(t *testing.T) {
	rep, warn := checkCompliance(nil, "vyos", "anything")
	if rep.Checked || warn != "" {
		t.Errorf("nil baseline: Checked=%v warn=%q, want unchecked and silent", rep.Checked, warn)
	}
}

func TestAssessRiskSafe(t *testing.T) {
	a, warn := assessRiskSafe([]string{"+ip access-list extended MGMT"})
	if warn != "" || a.Level != RiskCritical {
		t.Errorf("assessRiskSafe: level=%s warn=%q, want CRITICAL and no warning", a.Level, warn)
	}
}

func TestProcessConfigStripsTerminalBannersByDefault(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "ruijie", "sw-ruijie")
	raw := strings.Join([]string{
		"Building configuration...",
		"Current configuration: 7675 bytes",
		"",
		"version CS83_RGOS 12.6(3)B0703, Release(12161105)",
		"hostname DCTTN_TTN_NET_Pro_5F-SW.02-CAM_189.88_U44",
		"!",
	}, "\n")
	wantClean := strings.Join([]string{
		"version CS83_RGOS 12.6(3)B0703, Release(12161105)",
		"hostname DCTTN_TTN_NET_Pro_5F-SW.02-CAM_189.88_U44",
		"!",
	}, "\n")

	cfg := Config{OutputDir: dir, RunName: "run1"}
	res := processConfig(dev, profile, raw, cfg, Result{Device: dev})
	if !res.Success {
		t.Fatalf("processConfig failed: %v", res.Err)
	}
	saved, err := os.ReadFile(res.OutputPath)
	if err != nil {
		t.Fatalf("reading saved file: %v", err)
	}
	if string(saved) != wantClean {
		t.Errorf("saved file content mismatch:\n got: %q\nwant: %q", string(saved), wantClean)
	}
}

func TestProcessConfigKeepTerminalBanners(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "cisco", "sw-cisco")
	raw := strings.Join([]string{
		"Building configuration...",
		"",
		"Current configuration : 5123 bytes",
		"!",
		"version 15.2",
		"hostname sw1",
	}, "\n")

	cfg := Config{OutputDir: dir, RunName: "run1", KeepTerminalBanners: true}
	res := processConfig(dev, profile, raw, cfg, Result{Device: dev})
	if !res.Success {
		t.Fatalf("processConfig failed: %v", res.Err)
	}
	saved, err := os.ReadFile(res.OutputPath)
	if err != nil {
		t.Fatalf("reading saved file: %v", err)
	}
	if string(saved) != raw {
		t.Errorf("saved file when KeepTerminalBanners=true mismatch:\n got: %q\nwant: %q", string(saved), raw)
	}
}

func TestProcessConfigCheckPointSanitization(t *testing.T) {
	dir := t.TempDir()
	dev, profile := testDevice(t, "checkpoint", "cp-gw")
	raw := strings.Join([]string{
		`set hostname "cp-gw"`,
		`set threat-prevention zero-phishing user-check ask-subject "Are you sure?" ask-body "Line 1`,
		"",
		`Line 2" ask-activity-text "Ignore"`,
	}, "\n")

	wantClean := strings.Join([]string{
		"# Enable continue on failure so harmless conflicts or duplicate objects do not halt restore",
		"set clienv on-failure continue",
		`set hostname "cp-gw"`,
		`set threat-prevention zero-phishing user-check ask-subject "Are you sure?" ask-body "Line 1 Line 2" ask-activity-text "Ignore"`,
	}, "\n")

	cfg := Config{OutputDir: dir, RunName: "run1"}
	res := processConfig(dev, profile, raw, cfg, Result{Device: dev})
	if !res.Success {
		t.Fatalf("processConfig failed: %v", res.Err)
	}
	saved, err := os.ReadFile(res.OutputPath)
	if err != nil {
		t.Fatalf("reading saved file: %v", err)
	}
	if string(saved) != wantClean {
		t.Errorf("saved file for checkpoint mismatch:\n got: %q\nwant: %q", string(saved), wantClean)
	}
}

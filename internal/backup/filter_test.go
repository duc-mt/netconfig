// ==============================================================================
// Package backup implements tests for the volatile-line filter.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package backup

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestBuiltinVolatilePatternsCompile(t *testing.T) {
	for _, spec := range builtinVolatileSpecs {
		if _, err := regexp.Compile(spec.pattern); err != nil {
			t.Errorf("built-in volatile rule %q does not compile: %v", spec.name, err)
		}
	}
	if got, want := DefaultVolatileFilter().Len(), len(builtinVolatileSpecs); got != want {
		t.Errorf("DefaultVolatileFilter has %d rules, want %d (a built-in pattern was skipped)", got, want)
	}
}

func TestVolatileFilterCisco(t *testing.T) {
	cfg := strings.Join([]string{
		"Building configuration...",
		"",
		"Current configuration : 5123 bytes",
		"!",
		"! Last configuration change at 12:00:00 UTC Mon Oct 12 2026 by admin",
		"! NVRAM config last updated at 12:01:00 UTC Mon Oct 12 2026 by admin",
		"! No configuration change since last restart",
		"! Time: Mon Oct 12 12:00:00 2026",
		"!",
		"version 15.2",
		"hostname core-sw01",
		"ntp clock-period 17179869",
		"ntp server 10.0.0.1",
		"end",
	}, "\n")

	f := DefaultVolatileFilter()
	for _, vendorName := range []string{"cisco_ios", "cisco", "ios_xe"} {
		got := f.Apply(vendorName, cfg)
		for _, noisy := range []string{
			"Building configuration", "Current configuration", "Last configuration change",
			"NVRAM config", "No configuration change", "! Time:", "ntp clock-period",
		} {
			if strings.Contains(got, noisy) {
				t.Errorf("vendor %q: volatile line %q survived:\n%s", vendorName, noisy, got)
			}
		}
		for _, real := range []string{"version 15.2", "hostname core-sw01", "ntp server 10.0.0.1", "end"} {
			if !strings.Contains(got, real) {
				t.Errorf("vendor %q: real line %q was removed:\n%s", vendorName, real, got)
			}
		}
	}
}

func TestVolatileFilterOtherVendors(t *testing.T) {
	f := DefaultVolatileFilter()
	tests := []struct {
		name   string
		vendor string
		config string
		want   string
	}{
		{
			name:   "arista time header",
			vendor: "arista",
			config: "! Time: Mon Oct 12 12:00:00 2026\nhostname a1",
			want:   "hostname a1",
		},
		{
			name:   "huawei update and save stamps",
			vendor: "huawei_vrp",
			config: "!Last configuration was updated at 2026-10-12 12:00:00+07:00 by admin\n!Last configuration was saved at 2026-10-12 12:00:00+07:00\nsysname r1",
			want:   "sysname r1",
		},
		{
			name:   "junos last changed, last commit and chassis prompt",
			vendor: "junos",
			config: "## Last changed: 2026-10-12 12:00:00 UTC\n## Last commit: 2026-10-12 12:00:00 UTC by admin\nset system host-name r1\n{master:0}",
			want:   "set system host-name r1",
		},
		{
			name:   "vyos version trailer",
			vendor: "vyos",
			config: "// Warning: Do not remove the following line.\n// vyos-config-version: \"bgp@5:x@1\"\n// Release version: 1.4-rolling-202610120317\nset system host-name 'vyos1'",
			want:   "set system host-name 'vyos1'",
		},
		{
			name:   "vyos old c-style trailer",
			vendor: "vyos",
			config: "/* Warning: Do not remove the following line. */\n/* === vyatta-config-version: \"x\" === */\n/* Release version: 1.3.0 */\nset service lldp",
			want:   "set service lldp",
		},
		{
			name:   "linux style dynamic comment banners",
			vendor: "vyos",
			config: "# Generated at 2026-10-12 12:00\n# uptime: 12 days\nset system host-name 'vyos1'",
			want:   "set system host-name 'vyos1'",
		},
		{
			name:   "checkpoint export stamp",
			vendor: "checkpoint_gaia",
			config: "# Exported by admin on Mon Oct 12 12:00:00 2026\nset hostname gw",
			want:   "set hostname gw",
		},
	}
	for _, tt := range tests {
		if got := f.Apply(tt.vendor, tt.config); got != tt.want {
			t.Errorf("%s: Apply = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestVolatileFilterIsVendorScoped(t *testing.T) {
	f := DefaultVolatileFilter()

	// A Junos comment must not be stripped from a Cisco device ...
	line := "## Last changed: 2026-10-12 12:00:00 UTC"
	if got := f.Apply("cisco_ios", line); got != line {
		t.Errorf("Junos rule leaked into cisco_ios: %q", got)
	}
	// ... nor a hash-comment banner outside the Linux-like platforms.
	if got := f.Apply("cisco_ios", "# uptime: 1"); got != "# uptime: 1" {
		t.Errorf("hash banner rule leaked into cisco_ios: %q", got)
	}
	// An unknown vendor only gets vendor-agnostic rules: none are built in.
	if got := f.Apply("no-such-vendor", "! Last configuration change at x"); got != "! Last configuration change at x" {
		t.Errorf("unknown vendor should keep every line, got %q", got)
	}
}

func TestVolatileFilterKeepsRealConfiguration(t *testing.T) {
	cfg := "hostname sw1\nntp server 1.1.1.1\nclock timezone UTC 0\ninterface Gi0/1\n description uplink\n shutdown"
	if got := DefaultVolatileFilter().Apply("cisco_ios", cfg); got != cfg {
		t.Errorf("real configuration was altered:\n got: %q\nwant: %q", got, cfg)
	}
}

func TestVolatileFilterTrimsCR(t *testing.T) {
	got := DefaultVolatileFilter().Apply("cisco_ios", "! Last configuration change at x\r\nhostname sw1\r\n")
	if got != "hostname sw1\n" {
		t.Errorf("Apply = %q, want %q", got, "hostname sw1\n")
	}
}

func TestVolatileFilterNilIsNoOp(t *testing.T) {
	var f *VolatileFilter
	cfg := "! Last configuration change at x\nhostname sw1"
	if got := f.Apply("cisco_ios", cfg); got != cfg {
		t.Errorf("nil filter changed the config: %q", got)
	}
	if f.IsVolatile("cisco_ios", "! Last configuration change at x") {
		t.Error("nil filter must not report volatile lines")
	}
	if f.Len() != 0 {
		t.Errorf("nil filter Len = %d, want 0", f.Len())
	}
}

func TestVolatileFilterIsVolatile(t *testing.T) {
	f := DefaultVolatileFilter()
	if !f.IsVolatile("cisco_ios", "! Last configuration change at 12:00\r") {
		t.Error("expected Cisco change stamp (with CR) to be volatile")
	}
	if f.IsVolatile("cisco_ios", "hostname sw1") {
		t.Error("hostname must not be volatile")
	}
}

func TestNewVolatileFilterCustomPatterns(t *testing.T) {
	base := DefaultVolatileFilter().Len()
	f, errs := NewVolatileFilter([]string{
		`^# build id \d+`,
		"   ",              // blank: ignored
		"# a comment line", // comment: ignored
		"(unclosed",        // invalid: reported, skipped
	})
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 pattern error, got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "(unclosed") {
		t.Errorf("error should name the bad pattern, got %v", errs[0])
	}
	if f.Len() != base+1 {
		t.Errorf("filter has %d rules, want %d (built-ins + 1 valid custom)", f.Len(), base+1)
	}

	// Custom patterns apply to every vendor, including unknown ones.
	for _, vendorName := range []string{"vyos", "cisco_ios", "no-such-vendor"} {
		if got := f.Apply(vendorName, "# build id 42\nreal line"); got != "real line" {
			t.Errorf("vendor %q: custom pattern not applied, got %q", vendorName, got)
		}
	}
	// Built-ins are still active next to the custom rule.
	if got := f.Apply("cisco_ios", "! Last configuration change at x\nreal line"); got != "real line" {
		t.Errorf("built-in rule lost after adding custom patterns: %q", got)
	}
}

func TestLoadVolatilePatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "volatile.txt")
	content := "# extra volatile lines\n\n^foo\n   ^bar   \n# trailing comment\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadVolatilePatterns(path)
	if err != nil {
		t.Fatalf("LoadVolatilePatterns: %v", err)
	}
	if want := []string{"^foo", "^bar"}; !reflect.DeepEqual(got, want) {
		t.Errorf("patterns = %q, want %q", got, want)
	}

	if _, err := LoadVolatilePatterns(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("expected an error for a missing patterns file")
	}
}

func TestVolatileFilterCiscoSBAndASA(t *testing.T) {
	cfg := strings.Join([]string{
		"Building configuration...",
		"",
		"Current configuration : 5123 bytes",
		"!",
		"! Last configuration change at 12:00:00 UTC Mon Oct 19 2026 by admin",
		"! NVRAM config last updated at 12:01:00 UTC Mon Oct 19 2026 by admin",
		"! No configuration change since last restart",
		"! Time: Mon Oct 19 12:00:00 2026",
		"!",
		": Saved",
		": Serial Number: 9A1B2C3D4E5",
		"hostname edge1",
		"ntp server 10.0.0.1",
		": end",
	}, "\n")

	f := DefaultVolatileFilter()
	for _, vendorName := range []string{"cisco_sb", "cisco_sg", "sg350", "cbs350", "ciscosb", "cisco_asa", "asa", "cisco_ftd", "ftd"} {
		got := f.Apply(vendorName, cfg)
		for _, noisy := range []string{
			"Building configuration", "Current configuration", "Last configuration change",
			"NVRAM config", "No configuration change", "! Time:",
		} {
			if strings.Contains(got, noisy) {
				t.Errorf("vendor %q: volatile line %q survived:\n%s", vendorName, noisy, got)
			}
		}
		for _, real := range []string{": Saved", ": Serial Number: 9A1B2C3D4E5", "hostname edge1", "ntp server 10.0.0.1", ": end"} {
			if !strings.Contains(got, real) {
				t.Errorf("vendor %q: real line %q was removed:\n%s", vendorName, real, got)
			}
		}
	}
}

func TestVolatileFilterMikroTik(t *testing.T) {
	f := DefaultVolatileFilter()
	body := "/interface bridge\nadd name=bridge1\n/ip address\nadd address=192.168.88.1/24 interface=bridge1 network=192.168.88.0\n/system identity\nset name=rtr1"
	tests := []struct {
		name   string
		vendor string
		config string
		want   string
	}{
		{
			name:   "RouterOS 6 header (mon/dd/yyyy)",
			vendor: "mikrotik",
			config: "# jan/02/1970 00:00:00 by RouterOS 6.49.10\n# software id = ABCD-1234\n#\n# model = RB4011iGS+\n# serial number = ABC123456789\n" + body,
			want:   "#\n# model = RB4011iGS+\n# serial number = ABC123456789\n" + body,
		},
		{
			name:   "RouterOS 7 header (ISO date)",
			vendor: "routeros",
			config: "# 2026-10-19 09:41:00 by RouterOS 7.16.1\n# software id = ABCD-1234\n#\n" + body,
			want:   "#\n" + body,
		},
		{
			name:   "CRLF line endings and alias",
			vendor: "ros",
			config: "# 2026-10-19 09:41:00 by RouterOS 7.16.1\r\n# software id = ABCD-1234\r\n" + body,
			want:   body,
		},
		{
			name:   "lookalike lines are kept",
			vendor: "mikrotik",
			config: "# managed by RouterOS team\n# software identifier is not a header\n/system script add name=s source=\"# software id check\"",
			want:   "# managed by RouterOS team\n# software identifier is not a header\n/system script add name=s source=\"# software id check\"",
		},
	}
	for _, tt := range tests {
		if got := f.Apply(tt.vendor, tt.config); got != tt.want {
			t.Errorf("%s: Apply = %q, want %q", tt.name, got, tt.want)
		}
	}

	if !f.IsVolatile("mikrotik", "# 2026-10-19 09:41:00 by RouterOS 7.16.1\r") {
		t.Error("expected RouterOS export header (with CR) to be volatile")
	}
	if f.IsVolatile("mikrotik", "/system identity") {
		t.Error("a RouterOS menu line must not be volatile")
	}
}

func TestVolatileFilterNewVendorsAreScoped(t *testing.T) {
	f := DefaultVolatileFilter()

	// RouterOS export headers must not be stripped from other platforms ...
	for _, line := range []string{"# 2026-10-19 09:41:00 by RouterOS 7.16.1", "# software id = ABCD-1234"} {
		for _, vendorName := range []string{"cisco_ios", "cisco_sb", "cisco_asa", "vyos"} {
			if got := f.Apply(vendorName, line); got != line {
				t.Errorf("MikroTik rule leaked into %s: %q", vendorName, got)
			}
		}
	}
	// ... and IOS-style "!" stamps do not apply to RouterOS, which has no such headers.
	stamp := "! Last configuration change at 12:00:00 UTC Mon Oct 19 2026"
	if got := f.Apply("mikrotik", stamp); got != stamp {
		t.Errorf("IOS rule leaked into mikrotik: %q", got)
	}
	// Junos and hash-banner rules stay away from the new Cisco platforms.
	for _, vendorName := range []string{"cisco_sb", "cisco_asa"} {
		for _, line := range []string{"## Last changed: 2026-10-19 12:00:00 UTC", "# uptime: 1"} {
			if got := f.Apply(vendorName, line); got != line {
				t.Errorf("rule leaked into %s: %q", vendorName, got)
			}
		}
	}
}

func TestVolatileFilterCiscoASAWrittenBy(t *testing.T) {
	cfg := strings.Join([]string{
		": Saved",
		":",
		": Written by enable_15 at 09:41:07.589 UTC Mon Oct 19 2026",
		"!",
		"ASA Version 9.12(4)",
		"hostname asa1",
		": end",
	}, "\n")
	want := strings.Join([]string{
		": Saved",
		":",
		"!",
		"ASA Version 9.12(4)",
		"hostname asa1",
		": end",
	}, "\n")

	f := DefaultVolatileFilter()
	for _, vendorName := range []string{"cisco_asa", "asa", "ftd"} {
		if got := f.Apply(vendorName, cfg); got != want {
			t.Errorf("vendor %q: Apply = %q, want %q", vendorName, got, want)
		}
	}
	// The stamp is ASA specific, and the other ": " header lines are static.
	for _, vendorName := range []string{"cisco_ios", "cisco_sb", "mikrotik"} {
		if got := f.Apply(vendorName, ": Written by admin at 09:41:07.589 UTC Mon Oct 19 2026"); got == "" {
			t.Errorf("ASA rule leaked into %s", vendorName)
		}
	}
	if f.IsVolatile("cisco_asa", ": Serial Number: 9A1B2C3D4E5") || f.IsVolatile("cisco_asa", ": Hardware:   ASA5516, 8192 MB RAM") {
		t.Error("static ASA header lines must not be volatile")
	}
}

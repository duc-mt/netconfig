// ==============================================================================
// Package compliance implements tests for golden-config drift detection.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package compliance

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mustRule(t *testing.T, line string) Rule {
	t.Helper()
	r, err := ParseRule(line)
	if err != nil {
		t.Fatalf("ParseRule(%q): %v", line, err)
	}
	return r
}

func mustBaseline(t *testing.T, section string, lines ...string) *Baseline {
	t.Helper()
	b := New()
	for _, l := range lines {
		if err := b.Add(section, mustRule(t, l)); err != nil {
			t.Fatalf("Add(%q): %v", section, err)
		}
	}
	return b
}

func TestParseRule(t *testing.T) {
	tests := []struct {
		line    string
		kind    ruleKind
		text    string
		display string
	}{
		{"set service ntp server time1.vyos.net", ruleRequire, "set service ntp server time1.vyos.net", "set service ntp server time1.vyos.net"},
		{"re: ^set system syslog host\\s+10\\.", ruleRequireRegex, "^set system syslog host\\s+10\\.", "re: ^set system syslog host\\s+10\\."},
		{"not: set service telnet", ruleForbid, "set service telnet", "not: set service telnet"},
		{"not-re: ^set service snmp community public", ruleForbidRegex, "^set service snmp community public", "not-re: ^set service snmp community public"},
		{"   padded line   ", ruleRequire, "padded line", "padded line"},
	}
	for _, tt := range tests {
		r, err := ParseRule(tt.line)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.line, err)
			continue
		}
		if r.kind != tt.kind || r.Text != tt.text || r.String() != tt.display {
			t.Errorf("ParseRule(%q) = kind %d text %q display %q, want kind %d text %q display %q",
				tt.line, r.kind, r.Text, r.String(), tt.kind, tt.text, tt.display)
		}
	}
}

func TestParseRuleErrors(t *testing.T) {
	for _, line := range []string{"", "   ", "re:", "re:   ", "re: (unclosed", "not:", "not-re:", "not-re: [a-"} {
		if _, err := ParseRule(line); err == nil {
			t.Errorf("ParseRule(%q): expected an error", line)
		}
	}
}

func TestParseRulesSectionsAndComments(t *testing.T) {
	text := strings.Join([]string{
		"# header comment",
		"! cisco style comment",
		"// slash comment",
		"",
		"banner motd authorized only",
		"[vyos]",
		"set service ntp server time1.vyos.net",
		"not: set service telnet",
		"[cisco]",
		"ntp server 10.0.0.1",
		"[common]",
		"service password-encryption",
	}, "\n")

	got, errs := ParseRules(text, "common")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if n := len(got["common"]); n != 2 {
		t.Errorf("common rules = %d, want 2 (before the first header and under [common])", n)
	}
	if n := len(got["vyos"]); n != 2 {
		t.Errorf("vyos rules = %d, want 2", n)
	}
	if n := len(got["cisco"]); n != 1 {
		t.Errorf("cisco rules = %d, want 1 ([cisco] must resolve to the cisco profile)", n)
	}
}

func TestParseRulesCollectsErrorsAndContinues(t *testing.T) {
	text := strings.Join([]string{
		"[vyos]",
		"re: (unclosed",
		"set service lldp",
		"[no-such-vendor]",
		"set should not be loaded",
		"[arista]",
		"hostname leaf1",
	}, "\n")

	got, errs := ParseRules(text, "common")
	if len(errs) != 2 {
		t.Fatalf("errors = %v, want 2 (bad regex + unknown section)", errs)
	}
	if !strings.Contains(errs[0].Error(), "line 2") || !strings.Contains(errs[1].Error(), "no-such-vendor") {
		t.Errorf("errors should carry their line/section context: %v", errs)
	}
	if len(got["vyos"]) != 1 || len(got["arista"]) != 1 {
		t.Errorf("good rules around the bad ones must survive: %v", got)
	}
	for key, rules := range got {
		for _, r := range rules {
			if strings.Contains(r.Text, "should not be loaded") {
				t.Errorf("rule from an unknown section leaked into %q", key)
			}
		}
	}
}

func TestParseRulesUnknownDefaultSection(t *testing.T) {
	got, errs := ParseRules("hostname x", "no-such-vendor")
	if len(errs) != 1 || len(got) != 0 {
		t.Errorf("got=%v errs=%v, want no rules and one error", got, errs)
	}
}

func TestCheckRequiredLines(t *testing.T) {
	b := mustBaseline(t, "vyos",
		"set service ntp server time1.vyos.net",
		"set system syslog host 10.9.9.9 facility all",
	)
	cfg := "set system host-name 'gw1'\nset service ntp server time1.vyos.net\n"

	rep := b.Check("vyos", cfg)
	if !rep.Checked || rep.Rules != 2 {
		t.Fatalf("Checked=%v Rules=%d, want checked with 2 rules", rep.Checked, rep.Rules)
	}
	if rep.Compliant() {
		t.Error("the syslog line is missing, the device must not be compliant")
	}
	if len(rep.Drifts) != 1 || rep.Drifts[0].Kind != KindMissing {
		t.Fatalf("Drifts = %+v, want exactly one MISSING", rep.Drifts)
	}
	if got := rep.Drifts[0].String(); !strings.Contains(got, "missing") || !strings.Contains(got, "10.9.9.9") {
		t.Errorf("drift message = %q", got)
	}
	if rep.Summary() != "1 DRIFT" {
		t.Errorf("Summary = %q, want %q", rep.Summary(), "1 DRIFT")
	}
}

func TestCheckCompliantDevice(t *testing.T) {
	b := mustBaseline(t, "vyos", "set service ntp server time1.vyos.net")
	rep := b.Check("vyos", "set service ntp server time1.vyos.net\n")
	if !rep.Compliant() || rep.Summary() != "COMPLIANT" || len(rep.DriftMessages()) != 0 {
		t.Errorf("report = %+v, want compliant", rep)
	}
}

func TestCheckExactMatchIgnoresQuotesWhitespaceAndIndent(t *testing.T) {
	b := mustBaseline(t, "vyos", "set system host-name gw1", "set service ssh port 22")
	cfg := "   set   system  host-name  'gw1'  \r\nset service ssh port \"22\"\n"
	if rep := b.Check("vyos", cfg); !rep.Compliant() {
		t.Errorf("quotes, indentation and repeated spaces must not matter: %v", rep.DriftMessages())
	}
}

func TestCheckMismatchReportsFoundValue(t *testing.T) {
	b := mustBaseline(t, "vyos", "set service ssh port 22")
	rep := b.Check("vyos", "set service ssh port '2222'\nset service ssh listen-address 10.0.0.1\n")

	if len(rep.Drifts) != 1 || rep.Drifts[0].Kind != KindMismatch {
		t.Fatalf("Drifts = %+v, want one MISMATCH", rep.Drifts)
	}
	if want := []string{"set service ssh port '2222'"}; !reflect.DeepEqual(rep.Drifts[0].Found, want) {
		t.Errorf("Found = %q, want %q", rep.Drifts[0].Found, want)
	}
	msg := rep.Drifts[0].String()
	if !strings.Contains(msg, "expected") || !strings.Contains(msg, "2222") {
		t.Errorf("message = %q, want expected and found values", msg)
	}
}

func TestCheckMismatchCapsFoundLines(t *testing.T) {
	b := mustBaseline(t, "vyos", "set service ntp server wanted.example.com")
	cfg := strings.Join([]string{
		"set service ntp server a.example.com",
		"set service ntp server b.example.com",
		"set service ntp server c.example.com",
		"set service ntp server d.example.com",
	}, "\n")
	rep := b.Check("vyos", cfg)
	if len(rep.Drifts) != 1 || len(rep.Drifts[0].Found) != maxFoundLines {
		t.Fatalf("Drifts = %+v, want one drift listing at most %d lines", rep.Drifts, maxFoundLines)
	}
}

func TestCheckSingleTokenRuleIsNeverAMismatch(t *testing.T) {
	b := mustBaseline(t, "vyos", "lldp")
	rep := b.Check("vyos", "lldpx\nset service lldp\n")
	if len(rep.Drifts) != 1 || rep.Drifts[0].Kind != KindMissing {
		t.Errorf("Drifts = %+v, want a plain MISSING", rep.Drifts)
	}
}

func TestCheckRegexRules(t *testing.T) {
	b := mustBaseline(t, "vyos",
		`re: ^set system syslog host\s+10\.`,
		`not-re: community\s+public\b`,
	)

	ok := b.Check("vyos", "set system syslog host 10.9.9.9 facility all\nset service snmp community private\n")
	if !ok.Compliant() {
		t.Errorf("expected compliance, got %v", ok.DriftMessages())
	}

	bad := b.Check("vyos", "set system syslog host 192.168.1.1\nset service snmp community public authorization ro\n")
	if len(bad.Drifts) != 2 {
		t.Fatalf("Drifts = %v, want a missing regex and a forbidden regex", bad.DriftMessages())
	}
	if bad.Drifts[0].Kind != KindMissing || !strings.HasPrefix(bad.Drifts[0].Rule, "re: ") {
		t.Errorf("first drift = %+v, want MISSING with its 're:' rule", bad.Drifts[0])
	}
	if bad.Drifts[1].Kind != KindForbidden || len(bad.Drifts[1].Found) != 1 {
		t.Errorf("second drift = %+v, want FORBIDDEN with the offending line", bad.Drifts[1])
	}
}

func TestCheckForbiddenExactLine(t *testing.T) {
	b := mustBaseline(t, "cisco_ios", "not: ip http server")
	rep := b.Check("cisco", "hostname sw1\nip http server\n")
	if len(rep.Drifts) != 1 || rep.Drifts[0].Kind != KindForbidden {
		t.Fatalf("Drifts = %+v, want one FORBIDDEN", rep.Drifts)
	}
	if !strings.Contains(rep.Drifts[0].String(), "forbidden") {
		t.Errorf("message = %q", rep.Drifts[0].String())
	}
	if clean := b.Check("cisco", "hostname sw1\nno ip http server\n"); !clean.Compliant() {
		t.Errorf("'no ip http server' is not the forbidden line, got %v", clean.DriftMessages())
	}
}

func TestCheckCommonRulesAndVendorScoping(t *testing.T) {
	b := New()
	if err := b.Add("common", mustRule(t, "service password-encryption")); err != nil {
		t.Fatal(err)
	}
	if err := b.Add("vyos", mustRule(t, "set service lldp")); err != nil {
		t.Fatal(err)
	}

	// vyos: common + vyos rules.
	if rep := b.Check("vyos", ""); rep.Rules != 2 || len(rep.Drifts) != 2 {
		t.Errorf("vyos: Rules=%d drifts=%d, want 2/2", rep.Rules, len(rep.Drifts))
	}
	// cisco: only the common rule applies.
	if rep := b.Check("cisco_ios", ""); rep.Rules != 1 || len(rep.Drifts) != 1 {
		t.Errorf("cisco: Rules=%d drifts=%d, want 1/1", rep.Rules, len(rep.Drifts))
	}
	// The vendor name may be an alias; an unknown vendor still gets common rules.
	if !b.Applies("junos") || !b.Applies("no-such-vendor") {
		t.Error("common rules must apply to every vendor, known or not")
	}
}

func TestCheckNoApplicableRulesIsUnchecked(t *testing.T) {
	b := mustBaseline(t, "vyos", "set service lldp")
	rep := b.Check("cisco_ios", "hostname sw1")
	if rep.Checked || rep.Compliant() || rep.Summary() != "" {
		t.Errorf("report = %+v, want unchecked", rep)
	}
	if b.Applies("cisco_ios") {
		t.Error("Applies must be false when no rule covers the vendor")
	}
}

func TestNilBaselineIsSafe(t *testing.T) {
	var b *Baseline
	if rep := b.Check("vyos", "anything"); rep.Checked {
		t.Errorf("nil baseline must check nothing, got %+v", rep)
	}
	if b.Len() != 0 || b.Applies("vyos") {
		t.Error("nil baseline must be empty")
	}
}

func TestBaselineAddUnknownSection(t *testing.T) {
	if err := New().Add("no-such-vendor", mustRule(t, "x")); err == nil {
		t.Error("expected an error for an unknown section")
	}
}

func TestDriftStringForms(t *testing.T) {
	tests := []struct {
		d    Drift
		want []string
	}{
		{Drift{Kind: KindMissing, Rule: "ntp server 1.1.1.1"}, []string{"missing", "ntp server 1.1.1.1"}},
		{Drift{Kind: KindMismatch, Rule: "a b", Found: []string{"a c"}}, []string{"mismatch", "expected", "a c"}},
		{Drift{Kind: KindForbidden, Rule: "not me", Found: []string{"not me"}}, []string{"forbidden", "not me"}},
	}
	for _, tt := range tests {
		got := tt.d.String()
		for _, w := range tt.want {
			if !strings.Contains(got, w) {
				t.Errorf("Drift(%s).String() = %q, missing %q", tt.d.Kind, got, w)
			}
		}
	}
}

func TestReportSummaryForms(t *testing.T) {
	tests := []struct {
		rep  Report
		want string
	}{
		{Report{}, ""},
		{Report{Checked: true}, "COMPLIANT"},
		{Report{Checked: true, Drifts: make([]Drift, 1)}, "1 DRIFT"},
		{Report{Checked: true, Drifts: make([]Drift, 3)}, "3 DRIFTS"},
	}
	for _, tt := range tests {
		if got := tt.rep.Summary(); got != tt.want {
			t.Errorf("Summary() = %q, want %q", got, tt.want)
		}
	}
}

func writeGolden(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadGoldenDirectory(t *testing.T) {
	dir := t.TempDir()
	writeGolden(t, dir, "vyos.golden", "# vyos baseline\nset service ntp server time1.vyos.net\nre: ^set system syslog host\n")
	writeGolden(t, dir, "cisco.golden", "ntp server 10.0.0.1\n")
	writeGolden(t, dir, "COMMON.golden", "service password-encryption\n")
	writeGolden(t, dir, "notes.txt", "ignored: wrong extension\n")
	writeGolden(t, dir, "bogus-vendor.golden", "x\n")
	if err := os.Mkdir(filepath.Join(dir, "sub.golden"), 0o750); err != nil {
		t.Fatal(err)
	}

	b, errs := Load(dir, "")
	if b == nil {
		t.Fatalf("expected a baseline, errors: %v", errs)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "bogus-vendor.golden") {
		t.Errorf("errors = %v, want exactly the unknown-vendor file", errs)
	}
	if b.Len() != 4 {
		t.Errorf("Len = %d, want 4 (2 vyos + 1 cisco_ios + 1 common)", b.Len())
	}
	if rep := b.Check("cisco_ios", "ntp server 10.0.0.1\nservice password-encryption\n"); !rep.Compliant() {
		t.Errorf("cisco.golden + COMMON.golden should apply to cisco_ios: %v", rep.DriftMessages())
	}
}

func TestLoadRulesFileAndMergeWithDirectory(t *testing.T) {
	dir := t.TempDir()
	writeGolden(t, dir, "vyos.golden", "set service lldp\n")
	rules := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(rules, []byte("banner motd hello\n[vyos]\nset service ntp server time1.vyos.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	b, errs := Load(dir, rules)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	rep := b.Check("vyos", "")
	if rep.Rules != 3 {
		t.Errorf("vyos rules = %d, want 3 (golden dir + common + [vyos] section)", rep.Rules)
	}
}

func TestLoadFailuresAreReportedNotFatal(t *testing.T) {
	b, errs := Load(filepath.Join(t.TempDir(), "missing-dir"), "")
	if b != nil || len(errs) != 1 {
		t.Errorf("missing dir: baseline=%v errs=%v, want nil baseline and one error", b, errs)
	}

	b, errs = Load("", filepath.Join(t.TempDir(), "missing.txt"))
	if b != nil || len(errs) != 1 {
		t.Errorf("missing rules file: baseline=%v errs=%v, want nil baseline and one error", b, errs)
	}

	// An empty directory yields no baseline and no error.
	b, errs = Load(t.TempDir(), "")
	if b != nil || len(errs) != 0 {
		t.Errorf("empty dir: baseline=%v errs=%v, want nil and no errors", b, errs)
	}

	// Nothing requested at all.
	if b, errs = Load("", ""); b != nil || len(errs) != 0 {
		t.Errorf("Load(\"\", \"\") = %v, %v, want nil, nil", b, errs)
	}
}

func TestLoadKeepsGoodRulesDespiteBadOnes(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.txt")
	content := "re: (unclosed\nset service lldp\n"
	if err := os.WriteFile(rules, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	b, errs := Load("", rules)
	if b == nil || b.Len() != 1 {
		t.Fatalf("baseline = %v, want the one good rule loaded", b)
	}
	if len(errs) != 1 {
		t.Errorf("errs = %v, want one error for the bad regex", errs)
	}
}

func hasDrift(rep Report, kind Kind, ruleContains string) bool {
	for _, d := range rep.Drifts {
		if d.Kind == kind && strings.Contains(d.Rule, ruleContains) {
			return true
		}
	}
	return false
}

func TestNewVendorSectionsResolve(t *testing.T) {
	text := strings.Join([]string{
		"[sg350]", "sntp server 10.0.0.1",
		"[asa]", "ssh version 2",
		"[ftd]", "ssh version 2",
		"[routeros]", "set telnet disabled=yes",
		"[h3c]", "sysname r1",
	}, "\n")

	sections, errs := ParseRules(text, "common")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	want := map[string]int{"cisco_sb": 1, "cisco_asa": 2, "mikrotik": 1, "huawei": 1}
	for key, n := range want {
		if got := len(sections[key]); got != n {
			t.Errorf("section %q has %d rules, want %d", key, got, n)
		}
	}
	if len(sections) != len(want) {
		t.Errorf("got %d sections, want %d: %v", len(sections), len(want), sections)
	}
}

func TestNewVendorGoldenFilesApplyByAlias(t *testing.T) {
	dir := t.TempDir()
	writeGolden(t, dir, "common.golden", "re: (?i)\\bbanner\\b\n")
	writeGolden(t, dir, "cisco.golden", "service password-encryption\n")
	writeGolden(t, dir, "asa.golden", "ssh version 2\n")
	writeGolden(t, dir, "sg350.golden", "sntp server 10.0.0.1\n")
	writeGolden(t, dir, "routeros.golden", "set telnet disabled=yes\n")
	writeGolden(t, dir, "huawei.golden", "sysname r1\n")

	b, errs := Load(dir, "")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	tests := []struct {
		vendor string
		config string
	}{
		{"cisco_asa", "banner login x\nssh version 2\n"},
		{"asa", "banner login x\nssh version 2\n"},
		{"cisco_ftd", "banner login x\nssh version 2\n"},
		{"cisco_sb", "banner login x\nsntp server 10.0.0.1\n"},
		{"cbs350", "banner login x\nsntp server 10.0.0.1\n"},
		{"sg300", "banner login x\nsntp server 10.0.0.1\n"},
		{"mikrotik", "banner x\nset telnet disabled=yes\n"},
		{"ros", "banner x\nset telnet disabled=yes\n"},
		{"h3c", "banner x\nsysname r1\n"},
		{"hp_comware", "banner x\nsysname r1\n"},
		// The IOS baseline still applies to IOS only.
		{"cisco", "banner login x\nservice password-encryption\n"},
	}
	for _, tt := range tests {
		// Every device gets common (1) plus exactly its own platform's rule (1):
		// cisco.golden is not inherited by Cisco SB / ASA, whose CLI differs from IOS.
		rep := b.Check(tt.vendor, tt.config)
		if !rep.Checked || rep.Rules != 2 {
			t.Errorf("%s: Checked=%v Rules=%d, want a checked report with 2 rules", tt.vendor, rep.Checked, rep.Rules)
		}
		if !rep.Compliant() {
			t.Errorf("%s: expected compliant, got %v", tt.vendor, rep.DriftMessages())
		}
	}

	// A missing platform rule is reported against the right section.
	if rep := b.Check("sg350", "banner login x\n"); !hasDrift(rep, KindMissing, "sntp server 10.0.0.1") {
		t.Errorf("sg350.golden rule not enforced on cisco_sb: %v", rep.DriftMessages())
	}
	if rep := b.Check("comware", "banner x\n"); !hasDrift(rep, KindMissing, "sysname r1") {
		t.Errorf("huawei.golden rule not enforced on an H3C/Comware device: %v", rep.DriftMessages())
	}
}

func TestShippedGoldenBaselinesCoverNewVendors(t *testing.T) {
	b, errs := Load("../../examples/golden", "")
	if len(errs) != 0 {
		t.Fatalf("shipped golden baselines have errors: %v", errs)
	}
	for _, key := range []string{"cisco", "vyos", "cisco_sb", "cisco_asa", "mikrotik"} {
		if !b.Applies(key) {
			t.Errorf("no shipped baseline applies to %q", key)
		}
	}

	good := map[string]string{
		"cisco_asa": strings.Join([]string{
			": Saved", "ASA Version 9.12(4)", "hostname asa1",
			"banner login Authorized access only",
			"ntp server 10.0.0.1 source inside",
			"logging host inside 10.0.0.9",
			"ssh version 2",
			"telnet timeout 5",
			": end",
		}, "\n"),
		"cisco_sb": strings.Join([]string{
			"config-file-header", "sw1", "CLI v1.0", "set system mode switch",
			"banner login", "hostname sw1",
			"sntp server 10.0.0.1",
			"logging host 10.0.0.9",
			"exit",
		}, "\n"),
		"mikrotik": strings.Join([]string{
			"/system identity", "set name=rtr1",
			"/system note", `set note="Authorized access only" show-at-login=yes`,
			"/system ntp client", "set enabled=yes",
			"/system logging", "add action=memory topics=info",
			"/ip service",
			`set telnet address="" disabled=yes port=23`,
			`set ftp address="" disabled=yes port=21`,
		}, "\n"),
	}
	for vendorKey, cfg := range good {
		if rep := b.Check(vendorKey, cfg); !rep.Compliant() {
			t.Errorf("%s: sample config should be compliant, got %v", vendorKey, rep.DriftMessages())
		}
	}

	// ASA: ssh version 2 missing and a telnet access line present.
	asaBad := strings.Replace(good["cisco_asa"], "ssh version 2\n", "telnet 10.0.0.0 255.255.255.0 inside\n", 1)
	rep := b.Check("asa", asaBad)
	if !hasDrift(rep, KindMissing, "ssh version 2") || !hasDrift(rep, KindForbidden, "telnet") {
		t.Errorf("asa: expected missing ssh version 2 + forbidden telnet, got %v", rep.DriftMessages())
	}
	if rep := b.Check("asa", strings.Replace(good["cisco_asa"], "telnet timeout 5", "telnet 2001:db8::/32 inside", 1)); !hasDrift(rep, KindForbidden, "telnet") {
		t.Errorf("asa: IPv6 telnet access line should be forbidden, got %v", rep.DriftMessages())
	}

	// Cisco SB: telnet server enabled and no SNTP server (SNTP must satisfy the common NTP rule).
	sbBad := strings.Replace(good["cisco_sb"], "sntp server 10.0.0.1\n", "ip telnet server\n", 1)
	rep = b.Check("sg350", sbBad)
	if !hasDrift(rep, KindForbidden, "ip telnet server") || !hasDrift(rep, KindMissing, "server") {
		t.Errorf("sg350: expected forbidden telnet server + missing sntp server, got %v", rep.DriftMessages())
	}

	// MikroTik: telnet service left enabled (verbose export form).
	mtBad := strings.Replace(good["mikrotik"], `set telnet address="" disabled=yes port=23`, `set telnet address="" disabled=no port=23`, 1)
	rep = b.Check("routeros", mtBad)
	if len(rep.Drifts) != 1 || !hasDrift(rep, KindMissing, "telnet") {
		t.Errorf("routeros: expected exactly the telnet drift, got %v", rep.DriftMessages())
	}
}

// An unsupported vendor baseline cannot apply. That
// must be reported, not silently ignored: otherwise a leftover invalid.golden
// would look like a passing check.
func TestUnsupportedVendorBaselineIsReported(t *testing.T) {
	_, errs := ParseRules("[nosuchvendor]\nset telnet disabled=yes\n", "common")
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "unknown vendor") {
		t.Errorf("section [nosuchvendor]: errors = %v, want one unknown-vendor error", errs)
	}

	dir := t.TempDir()
	writeGolden(t, dir, "common.golden", "re: (?i)\\bbanner\\b\n")
	writeGolden(t, dir, "nosuchvendor.golden", "set telnet disabled=yes\n")
	b, errs := Load(dir, "")
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "nosuchvendor.golden") {
		t.Errorf("nosuchvendor.golden: errors = %v, want one error naming the file", errs)
	}
	if b == nil || !b.Applies("cisco") {
		t.Error("the supported baselines must still load")
	}
}

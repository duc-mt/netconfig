// ==============================================================================
// File name:     audit_test.go
// Description:   Tests for rule evaluation and the rules file format.
// License:       MIT
// ==============================================================================
package audit

import (
	"bytes"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"netops/internal/vendor"
)

const ciscoGood = `hostname sw1
!
logging host 10.0.0.9
ntp server 10.0.0.1
snmp-server community Str0ng RO
tacacs-server host 10.0.0.5
!
line con 0
 exec-timeout 0 0
line vty 0 4
 exec-timeout 5 0
 transport input ssh
line vty 5 15
 exec-timeout 5 0
 transport input ssh
!
end
`

const ciscoBad = `hostname sw2
snmp-server community public RO
line con 0
 exec-timeout 5 0
 transport input ssh
line vty 0 4
 exec-timeout 0 0
 transport input all
line vty 5 15
 exec-timeout 5 0
 transport input ssh
end
`

func statuses(checks []Check) map[string]Status {
	m := map[string]Status{}
	for _, c := range checks {
		m[c.ID] = c.Status
	}
	return m
}

func TestDefaultsCompile(t *testing.T) {
	rules := Defaults()
	if len(rules) < 40 {
		t.Fatalf("only %d built-in rules", len(rules))
	}
	for _, r := range rules {
		if r.Remediation == "" || r.Title == "" {
			t.Errorf("rule %s/%v lacks a title or remediation", r.ID, r.Vendors)
		}
	}
}

func TestEvaluateCisco(t *testing.T) {
	rules := Defaults()
	for id, st := range statuses(Evaluate(vendor.Cisco, ciscoGood, rules)) {
		if st != Pass {
			t.Errorf("compliant config: %s = %s", id, st)
		}
	}
	got := statuses(Evaluate(vendor.Cisco, ciscoBad, rules))
	for _, id := range []string{"ntp", "syslog", "telnet", "snmp", "session-timeout", "aaa"} {
		if got[id] != Fail {
			t.Errorf("non-compliant config: %s = %s, want FAIL", id, got[id])
		}
	}
	// the console line's settings must not satisfy or break a vty rule
	checks := Evaluate(vendor.Cisco, ciscoBad, rules)
	for _, c := range checks {
		if c.ID == "telnet" && !strings.Contains(c.Evidence, "line vty 0 4") {
			t.Errorf("telnet evidence should name the failing block: %q", c.Evidence)
		}
		if c.Status == Fail && c.Remediation == "" {
			t.Errorf("%s fails without a remediation", c.ID)
		}
	}
}

func TestEveryVTYBlockMustComply(t *testing.T) {
	cfg := "line vty 0 4\n exec-timeout 5 0\n transport input ssh\nline vty 5 15\n exec-timeout 5 0\n transport input telnet\nend\n"
	if got := statuses(Evaluate(vendor.Cisco, cfg, Defaults()))["telnet"]; got != Fail {
		t.Errorf("one non-SSH vty block must fail the check, got %s", got)
	}
}

func TestExecTimeoutBoundaries(t *testing.T) {
	for line, want := range map[string]Status{
		"exec-timeout 5 0":  Pass,
		"exec-timeout 4 59": Pass,
		"exec-timeout 1 0":  Pass,
		"exec-timeout 0 30": Pass,
		"exec-timeout 6 0":  Fail,
		"exec-timeout 5 1":  Fail,
		"exec-timeout 0 0":  Fail, // never times out
		"exec-timeout 10 0": Fail,
	} {
		cfg := "line vty 0 4\n " + line + "\n transport input ssh\nend\n"
		if got := statuses(Evaluate(vendor.Cisco, cfg, Defaults()))["session-timeout"]; got != want {
			t.Errorf("%q: %s, want %s", line, got, want)
		}
	}
	if got := statuses(Evaluate(vendor.Cisco, "line vty 0 4\n transport input ssh\nend\n", Defaults()))["session-timeout"]; got != Fail {
		t.Errorf("no exec-timeout (IOS default 10 min) must fail, got %s", got)
	}
}

func TestEvaluateJunosSetForm(t *testing.T) {
	good := `set system host-name ex1
set system ntp server 10.0.0.1
set system syslog host 10.0.0.9 any notice
set system services ssh
set system login class ops idle-timeout 5
set system tacplus-server 10.0.0.5 secret "$9$x"
set snmp community Str0ng authorization read-only
`
	for id, st := range statuses(Evaluate(vendor.Junos, good, Defaults())) {
		if st != Pass {
			t.Errorf("junos compliant: %s = %s", id, st)
		}
	}
	bad := good + "set system services telnet\nset snmp community public authorization read-only\n"
	got := statuses(Evaluate(vendor.Junos, bad, Defaults()))
	if got["telnet"] != Fail || got["snmp"] != Fail || got["ntp"] != Pass {
		t.Errorf("junos non-compliant: %v", got)
	}
}

func TestEvaluateFortinetBlocks(t *testing.T) {
	good := `config system ntp
    set ntpsync enable
    set type custom
    config ntpserver
        edit 1
            set server "10.0.0.1"
        next
    end
end
config log syslogd setting
    set status enable
    set server "10.0.0.9"
end
config system global
    set admintimeout 5
    set admintelnet disable
end
config system snmp community
    edit 1
        set name "Str0ng"
    next
end
config user tacacs+
    edit "tac1"
        set server "10.0.0.5"
    next
end
`
	for id, st := range statuses(Evaluate(vendor.Fortinet, good, Defaults())) {
		if st != Pass {
			t.Errorf("fortinet compliant: %s = %s", id, st)
		}
	}
	bad := strings.Replace(good, `set name "Str0ng"`, `set name "public"`, 1)
	bad = strings.Replace(bad, "set admintelnet disable", "set admintelnet enable", 1)
	got := statuses(Evaluate(vendor.Fortinet, bad, Defaults()))
	if got["snmp"] != Fail || got["telnet"] != Fail {
		t.Errorf("fortinet non-compliant: %v", got)
	}
	// a syslogd block without a server must not pass
	noSrv := strings.Replace(good, "    set server \"10.0.0.9\"\n", "", 1)
	if st := statuses(Evaluate(vendor.Fortinet, noSrv, Defaults()))["syslog"]; st != Fail {
		t.Errorf("syslogd without a server: %s", st)
	}
}

func TestEvaluateHuawei(t *testing.T) {
	good := "sysname SW\n#\nntp-service unicast-server 10.0.0.1\n#\ninfo-center loghost 10.0.0.9\n#\nsnmp-agent community read cipher %^%#abc\n#\nhwtacacs-server template t1\n#\nuser-interface vty 0 4\n authentication-mode aaa\n idle-timeout 5 0\n protocol inbound ssh\n#\nreturn\n"
	for id, st := range statuses(Evaluate(vendor.Huawei, good, Defaults())) {
		if st != Pass {
			t.Errorf("huawei compliant: %s = %s", id, st)
		}
	}
	bad := strings.Replace(good, "protocol inbound ssh", "protocol inbound all", 1)
	bad = strings.Replace(bad, "snmp-agent community read cipher %^%#abc", "snmp-agent community read simple public", 1)
	got := statuses(Evaluate(vendor.Huawei, bad, Defaults()))
	if got["telnet"] != Fail || got["snmp"] != Fail {
		t.Errorf("huawei non-compliant: %v", got)
	}
}

func TestNotApplicablePlatforms(t *testing.T) {
	got := statuses(Evaluate(vendor.Sophos, "anything", Defaults()))
	for id, st := range got {
		if st != NA {
			t.Errorf("sophos %s = %s, want N/A (no rule covers it)", id, st)
		}
	}
	if got := statuses(Evaluate(vendor.PaloAlto, "anything", Defaults())); got["telnet"] != NA || got["ntp"] != Fail {
		t.Errorf("paloalto: %v", got)
	}
	s := Summarize(Evaluate(vendor.Cisco, ciscoBad, Defaults()))
	if s.Fail != 6 || s.Pass != 0 || s.NA != 0 {
		t.Errorf("summary = %+v", s)
	}
}

func TestEveryVendorEvaluates(t *testing.T) {
	for _, name := range vendor.Names() {
		checks := Evaluate(name, "", Defaults())
		if len(checks) != 6 {
			t.Errorf("%s: %d checks, want 6", name, len(checks))
		}
	}
}

func TestConfigCommand(t *testing.T) {
	j, _ := vendor.Lookup(vendor.Junos)
	if got := ConfigCommand(j); got != "show configuration | display set | no-more" {
		t.Errorf("junos config command = %q", got)
	}
	c, _ := vendor.Lookup(vendor.Cisco)
	if got := ConfigCommand(c); got != "show running-config" {
		t.Errorf("cisco config command = %q", got)
	}
}

func TestRulesRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRules(&buf, Defaults()); err != nil {
		t.Fatal(err)
	}
	back, err := ParseRules(&buf)
	if err != nil {
		t.Fatalf("defaults do not parse back: %v", err)
	}
	want := Defaults()
	if len(back) != len(want) {
		t.Fatalf("round trip: %d rules, want %d", len(back), len(want))
	}
	for i := range want {
		a, b := want[i], back[i]
		if a.ID != b.ID || a.Title != b.Title || a.Severity != b.Severity || a.Block != b.Block ||
			a.Require != b.Require || a.Forbid != b.Forbid || a.Remediation != b.Remediation ||
			!reflect.DeepEqual(a.Vendors, b.Vendors) {
			t.Errorf("rule %d differs after round trip:\n %+v\n %+v", i, a, b)
		}
	}
}

func TestParseRulesFile(t *testing.T) {
	src := "\ufeff# custom\nrules:\n" +
		"  - id: ntp   # trailing comment\n" +
		"    title: \"NTP \\\"primary\\\" set\"\n" +
		"    severity: HIGH\n" +
		"    vendors: [Cisco, \"junos\"]\n" +
		"    require: '^\\s*ntp server\\s+\\S+'   # regex in single quotes\n" +
		"    remediation: it's required\n" +
		"  -\n" +
		"    id: tn\n" +
		"    block: '^line vty'\n" +
		"    forbid: 'transport input (all|telnet)'\n" +
		"    remediation: 'don''t use telnet # really'\n"
	rules, err := ParseRules(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules", len(rules))
	}
	r := rules[0]
	if r.ID != "ntp" || r.Title != `NTP "primary" set` || r.Severity != SevHigh || r.Require != `^\s*ntp server\s+\S+` || r.Remediation != "it's required" {
		t.Errorf("rule 0 = %+v", r)
	}
	if !reflect.DeepEqual(r.Vendors, []string{vendor.Cisco, vendor.Junos}) {
		t.Errorf("vendors = %v (names must be canonicalised)", r.Vendors)
	}
	if rules[1].Remediation != "don't use telnet # really" || rules[1].Severity != SevMedium || rules[1].Title != "tn" {
		t.Errorf("rule 1 = %+v", rules[1])
	}
}

func TestParseRulesErrors(t *testing.T) {
	tests := []struct{ name, src, want string }{
		{"empty", "", "no rules"},
		{"no rules key", "foo:\n", "must start"},
		{"no items", "rules:\n", "no rules"},
		{"unknown key", "rules:\n  - id: a\n    requier: 'x'\n", "unknown or malformed key"},
		{"no pattern", "rules:\n  - id: a\n", "needs a require or a forbid"},
		{"bad regex", "rules:\n  - id: a\n    require: '('\n", "bad require pattern"},
		{"bad severity", "rules:\n  - id: a\n    severity: urgent\n    require: x\n", "severity"},
		{"bad vendor", "rules:\n  - id: a\n    vendors: [nokia]\n    require: x\n", "unknown vendor"},
		{"no id", "rules:\n  - require: x\n", "no id"},
		{"tab indent", "rules:\n  - id: a\n\trequire: x\n", "tabs"},
		{"stray line", "rules:\nrequire: x\n", "list item"},
		{"unterminated", "rules:\n  - id: a\n    require: 'abc\n", "unterminated"},
		{"bad escape", "rules:\n  - id: a\n    require: \"\\s+\"\n", "single quotes"},
		{"trailing text", "rules:\n  - id: a\n    require: 'x' y\n", "after the closing quote"},
		{"flow map", "rules:\n  - id: a\n    require: {x: 1}\n", "not supported"},
		{"vendors not list", "rules:\n  - id: a\n    vendors: cisco\n    require: x\n", "inline list"},
	}
	for _, tt := range tests {
		_, err := ParseRules(strings.NewReader(tt.src))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want it to contain %q", tt.name, err, tt.want)
		}
	}
	// errors carry the line number
	_, err := ParseRules(strings.NewReader("rules:\n  - id: a\n    bogus: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error should name line 3: %v", err)
	}
}

func TestCustomRulesOverrideDefaults(t *testing.T) {
	rules, err := ParseRules(strings.NewReader("rules:\n  - id: banner\n    title: Login banner\n    require: '^banner motd'\n    remediation: set a banner\n"))
	if err != nil {
		t.Fatal(err)
	}
	checks := Evaluate(vendor.Cisco, "hostname x\nbanner motd ^C hi ^C\n", rules)
	if len(checks) != 1 || checks[0].Status != Pass || checks[0].Evidence != "banner motd ^C hi ^C" {
		t.Errorf("checks = %+v", checks)
	}
	if got := Evaluate(vendor.Cisco, "hostname x\n", rules); got[0].Status != Fail {
		t.Errorf("missing banner should fail: %+v", got)
	}
}

func TestBlocksHelper(t *testing.T) {
	lines := splitLines("a\n x\n\n y\nb\n z\nline vty 0 4\n q\n")
	bodies, headers := blocks(lines, regexpMust(`^line vty`))
	if len(bodies) != 1 || headers[0] != "line vty 0 4" || len(bodies[0]) != 2 {
		t.Errorf("bodies=%v headers=%v", bodies, headers)
	}
}

func regexpMust(p string) *regexp.Regexp { return regexp.MustCompile(p) }

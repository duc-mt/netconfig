package task

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netconfig/internal/inventory"
	"netconfig/internal/vendor"
)

func TestParseVerifyRules(t *testing.T) {
	text := `
# BGP must come back
verify show ip bgp summary
  expect: "Established"
  not-contains: Idle
  regex: ^10\.0\.0\.2\s+4\s+65001
  retries: 5
  interval: 10s
  vendors: ios-xe, EOS
  hosts: Edge-*, core1

! reachability
VERIFY: ping 10.0.0.1 count 3
  expect: '0% packet loss'
`
	rules, err := ParseVerifyRules(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	r := rules[0]
	if r.Command != "show ip bgp summary" || r.Retries != 5 || r.Interval != 10*time.Second {
		t.Fatalf("rule 0 = %+v", r)
	}
	if strings.Join(r.Vendors, ",") != "cisco,arista" {
		t.Fatalf("vendors must be canonicalised, got %v", r.Vendors)
	}
	if strings.Join(r.Hosts, ",") != "edge-*,core1" {
		t.Fatalf("hosts = %v", r.Hosts)
	}
	want := []struct {
		kind MatchKind
		pat  string
	}{{MatchContains, "Established"}, {MatchNotContains, "Idle"}, {MatchRegex, `^10\.0\.0\.2\s+4\s+65001`}}
	if len(r.Conds) != len(want) {
		t.Fatalf("conds = %+v", r.Conds)
	}
	for i, w := range want {
		if r.Conds[i].Kind != w.kind || r.Conds[i].Pattern != w.pat {
			t.Errorf("cond %d = %+v, want %+v", i, r.Conds[i], w)
		}
	}
	if rules[1].Command != "ping 10.0.0.1 count 3" || rules[1].Conds[0].Pattern != "0% packet loss" {
		t.Fatalf("rule 1 = %+v", rules[1])
	}
	if rules[1].Retries != 0 || rules[1].Interval != 0 {
		t.Fatalf("no retries means no wait: %+v", rules[1])
	}
}

func TestParseVerifyRulesDefaultsAndUnits(t *testing.T) {
	rules, err := ParseVerifyRules("verify show x\n expect: y\n retries: 2\n")
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Interval != defaultVerifyInterval {
		t.Fatalf("retries without interval must default to %v, got %v", defaultVerifyInterval, rules[0].Interval)
	}
	rules, err = ParseVerifyRules("verify show x\n expect: y\n retries: 1\n interval: 7\n")
	if err != nil || rules[0].Interval != 7*time.Second {
		t.Fatalf("a bare number is seconds: %v %+v", err, rules)
	}
}

func TestParseVerifyRulesErrors(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"no condition", "verify show ip bgp summary\n", "no expect"},
		{"condition before header", "expect: x\n", `expected "verify <command>"`},
		{"stray text", "verify show x\n expect: y\n garbage\n", "key: value"},
		{"unknown key", "verify show x\n colour: red\n", `unknown key "colour"`},
		{"bad regex", "verify show x\n regex: (\n", "invalid regex"},
		{"retries too large", "verify show x\n expect: y\n retries: 999\n", "retries must be"},
		{"retries not a number", "verify show x\n expect: y\n retries: many\n", "retries must be"},
		{"bad interval", "verify show x\n expect: y\n interval: soon\n", "invalid interval"},
		{"negative interval", "verify show x\n expect: y\n interval: -5s\n", "negative"},
		{"unknown vendor", "verify show x\n expect: y\n vendors: nokia\n", `unknown vendor "nokia"`},
		{"bad glob", "verify show x\n expect: y\n hosts: [\n", "invalid host pattern"},
		{"reload", "verify reload\n expect: y\n", "not read-only"},
		{"configure", "verify configure terminal\n expect: y\n", "not read-only"},
		{"negation", "verify no shutdown\n expect: y\n", "not read-only"},
		{"commit", "verify commit\n expect: y\n", "not read-only"},
		{"clear", "verify clear counters\n expect: y\n", "not read-only"},
	}
	for _, tc := range cases {
		_, err := ParseVerifyRules(tc.text)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", tc.name, err, tc.want)
		}
	}
	if _, err := ParseVerifyRules("verify show x\n colour: red\n"); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("errors must carry the line number, got %v", err)
	}
	// vendor-native read-only verbs stay allowed
	if _, err := ParseVerifyRules("verify execute ping 10.0.0.1\n expect: ok\nverify request support information\n expect: x\n"); err != nil {
		t.Errorf("execute/request are legitimate read-only verbs: %v", err)
	}
}

func TestVerifyRuleEvaluate(t *testing.T) {
	rule := VerifyRule{Conds: mustConds(t, "expect: Established", "not-contains: Idle", `regex: (?i)peer\s+10\.0\.0\.2`)}
	if f := rule.Evaluate("Peer 10.0.0.2 Established"); len(f) != 0 {
		t.Fatalf("should pass: %v", f)
	}
	f := rule.Evaluate("peer 10.0.0.2 Idle")
	if len(f) != 2 || !strings.Contains(f[0], `"Established"`) || !strings.Contains(f[1], `"Idle"`) {
		t.Fatalf("both failing conditions must be reported: %v", f)
	}
	if f := rule.Evaluate("nothing here"); len(f) != 2 && len(f) != 3 {
		t.Fatalf("got %v", f)
	}
	if f := (VerifyRule{Conds: mustConds(t, "expect: established")}).Evaluate("Established"); len(f) != 1 {
		t.Fatal("contains is case-sensitive; use (?i) with regex for case-insensitive matching")
	}
	if f := (VerifyRule{Conds: []Condition{{Kind: MatchRegex, Pattern: "x"}}}).Evaluate("x"); len(f) != 1 {
		t.Fatal("a regex condition that was never compiled must fail closed, not pass")
	}
}

func mustConds(t *testing.T, lines ...string) []Condition {
	t.Helper()
	rules, err := ParseVerifyRules("verify show x\n" + strings.Join(lines, "\n") + "\n")
	if err != nil {
		t.Fatal(err)
	}
	return rules[0].Conds
}

func TestVerifyRuleAppliesTo(t *testing.T) {
	ios, _ := vendor.Lookup("ios")
	junos, _ := vendor.Lookup("junos")
	edge := inventory.Device{Hostname: "Edge-01"}
	core := inventory.Device{Hostname: "core1"}

	if !(VerifyRule{}).AppliesTo(core, ios) {
		t.Fatal("a rule without filters applies everywhere")
	}
	byVendor := VerifyRule{Vendors: []string{"junos"}}
	if byVendor.AppliesTo(core, ios) || !byVendor.AppliesTo(core, junos) {
		t.Fatal("vendor filter")
	}
	byHost := VerifyRule{Hosts: []string{"edge-*"}}
	if !byHost.AppliesTo(edge, ios) || byHost.AppliesTo(core, ios) {
		t.Fatal("host glob must match case-insensitively")
	}
	both := VerifyRule{Vendors: []string{"cisco"}, Hosts: []string{"edge-*"}}
	if !both.AppliesTo(edge, ios) || both.AppliesTo(edge, junos) || both.AppliesTo(core, ios) {
		t.Fatal("vendor and host filters combine with AND")
	}
	if byVendor.AppliesTo(core, nil) {
		t.Fatal("unknown profile never matches a vendor filter")
	}
}

func TestParseInlineVerify(t *testing.T) {
	text := `hostname lab1
!@verify show ip bgp summary
!@  expect: Established
interface Gi0/1
 description uplink
#@verify ping 10.0.0.1 count 3
#@  expect: 0% packet loss
! ordinary comment
`
	rules, err := ParseInlineVerify(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Command != "show ip bgp summary" || rules[1].Command != "ping 10.0.0.1 count 3" {
		t.Fatalf("rules = %+v", rules)
	}
	// The same file is a valid commands file: inline blocks are comments and
	// are never sent to a device.
	cmds := ParseCommands(text)
	for _, c := range cmds {
		if strings.Contains(c, "verify") || strings.Contains(c, "expect") {
			t.Fatalf("inline verify block leaked into the commands: %v", cmds)
		}
	}
	if len(cmds) != 3 {
		t.Fatalf("commands = %v", cmds)
	}
	// Errors point at the line in the original file.
	_, err = ParseInlineVerify("hostname x\n!@verify show y\n!@  colour: red\n")
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("err = %v, want a reference to line 3", err)
	}
	if rules, err := ParseInlineVerify("hostname x\n"); err != nil || rules != nil {
		t.Fatalf("no inline blocks: %v %v", rules, err)
	}
}

func TestReadVerifyFiles(t *testing.T) {
	dir := t.TempDir()
	vf := filepath.Join(dir, "verify.txt")
	if err := os.WriteFile(vf, []byte("verify show version\n expect: ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rules, err := ReadVerifyFile(vf); err != nil || len(rules) != 1 {
		t.Fatalf("ReadVerifyFile: %v %v", rules, err)
	}
	if _, err := ReadVerifyFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing -verify-file must be an error")
	}
	bad := filepath.Join(dir, "bad.txt")
	_ = os.WriteFile(bad, []byte("verify show version\n"), 0o600)
	if _, err := ReadVerifyFile(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Fatalf("errors must name the file: %v", err)
	}

	cf := filepath.Join(dir, "cmds.txt")
	_ = os.WriteFile(cf, []byte("hostname x\n!@verify show version\n!@ expect: ok\n"), 0o600)
	if rules, err := ReadInlineVerify(cf); err != nil || len(rules) != 1 {
		t.Fatalf("ReadInlineVerify: %v %v", rules, err)
	}
	if _, err := ReadInlineVerify(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file")
	}
	badInline := filepath.Join(dir, "badinline.txt")
	_ = os.WriteFile(badInline, []byte("hostname x\n!@verify show version\n"), 0o600) // no condition
	if _, err := ReadInlineVerify(badInline); err == nil || !strings.Contains(err.Error(), "inline verify") || !strings.Contains(err.Error(), badInline) {
		t.Fatalf("errors must name the file and say it is an inline block: %v", err)
	}
}

func TestCheckConfirmWindow(t *testing.T) {
	slow := []VerifyRule{{Retries: 10, Interval: 10 * time.Second}} // up to 100s of waiting
	if err := CheckConfirmWindow(slow, 0); err != nil {
		t.Fatalf("disabled commit-confirm is never too short: %v", err)
	}
	if err := CheckConfirmWindow(slow, 1); err == nil || !strings.Contains(err.Error(), "-commit-confirm 1") {
		t.Fatalf("1 minute cannot fit 100s of retries: %v", err)
	}
	if err := CheckConfirmWindow(slow, 3); err != nil {
		t.Fatalf("3 minutes fit 100s of retries plus the confirm margin: %v", err)
	}
	if err := CheckConfirmWindow(nil, 1); err != nil {
		t.Fatalf("no rules, 1 minute is fine: %v", err)
	}
	if got := VerifyBudget([]VerifyRule{{Retries: 2, Interval: time.Second}, {Retries: 3, Interval: 2 * time.Second}}); got != 8*time.Second {
		t.Fatalf("budget = %v", got)
	}
}

func TestExampleVerifyFileStaysValid(t *testing.T) {
	rules, err := ReadVerifyFile("../../examples/verify.example")
	if err != nil {
		t.Fatalf("the shipped example must parse: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(rules))
	}
	if rules[0].Retries != 6 || rules[0].Interval != 10*time.Second || strings.Join(rules[0].Vendors, ",") != "cisco,arista" {
		t.Fatalf("rule 0 = %+v", rules[0])
	}
}

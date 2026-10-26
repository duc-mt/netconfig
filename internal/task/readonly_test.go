// ==============================================================================
// File name:     readonly_test.go
// Description:   Tests for the read-only workflows: facts, find, audit, diff.
// License:       MIT
// ==============================================================================
package task

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/internal/audit"
	"netops/internal/vendor"
)

// scripted answers commands from a table; unknown commands answer with "".
func scripted(h *harness, answers map[string]string) {
	h.tr.devs = map[string]*viosDev{}
	h.tr.script = func(host, line string) string { return answers[host+"|"+line] }
}

// sampleSections splits a testdata/facts file into its per-command outputs.
func sampleSections(t *testing.T, vendorName string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "vendor", "testdata", "facts", vendorName+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	var cur string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "=== ") && strings.HasSuffix(l, " ===") {
			cur = strings.TrimSuffix(strings.TrimPrefix(l, "=== "), " ===")
			continue
		}
		out[cur] += l + "\n"
	}
	return out
}

// ---- facts ------------------------------------------------------------------

func TestFactsCollectedAcrossVendors(t *testing.T) {
	h, _ := newHarness(t, Options{})
	answers := map[string]string{}
	for host, v := range map[string]string{"zz-cisco": vendor.Cisco, "aa-junos": vendor.Junos, "mm-huawei": vendor.Huawei} {
		for cmd, out := range sampleSections(t, v) {
			answers[host+"|"+cmd] = out
		}
	}
	scripted(h, answers)

	sink := &FactsSink{}
	var jobs []Job
	for host, v := range map[string]string{"zz-cisco": vendor.Cisco, "aa-junos": vendor.Junos, "mm-huawei": vendor.Huawei} {
		jobs = append(jobs, h.jobs(v, FactsCapability, host)...)
	}
	h.r.Handler = sink.Handler()
	res := h.r.Run(context.Background(), jobs)
	if ExitCode(res) != ExitOK {
		t.Fatalf("results %+v", res)
	}
	rows := sink.Rows()
	if len(rows) != 3 || rows[0].Hostname != "aa-junos" || rows[1].Hostname != "mm-huawei" || rows[2].Hostname != "zz-cisco" {
		t.Fatalf("rows (should be sorted by hostname): %+v", rows)
	}
	if rows[0].Model != "ex4300-48t" || rows[0].Serial != "VK3718123456" || rows[0].Version != "21.4R3-S2.3" || rows[0].Vendor != "junos" {
		t.Errorf("junos row = %+v", rows[0])
	}
	if rows[2].Serial != "FCW2301A0AB" || rows[2].Model != "C9300-48P" || rows[2].IP == "" {
		t.Errorf("cisco row = %+v", rows[2])
	}
}

func TestFactsUnparseableOutputFailsLoudly(t *testing.T) {
	h, _ := newHarness(t, Options{})
	scripted(h, map[string]string{"sw1|show version": "% some unrelated banner\n"})
	sink := &FactsSink{}
	h.r.Handler = sink.Handler()
	res := h.r.Run(context.Background(), h.jobs(vendor.Cisco, FactsCapability, "sw1"))
	if res[0].Status != StatusFailed || res[0].Category != CatSyntaxError || len(sink.Rows()) != 0 {
		t.Errorf("an empty facts row must not be recorded as data: %+v rows=%v", res[0], sink.Rows())
	}
}

// ---- find -------------------------------------------------------------------

const (
	macTarget   = "aabb.ccdd.eeff"
	macCanon    = "aa:bb:cc:dd:ee:ff"
	trunkOutput = "Port        Mode             Encapsulation  Status        Native vlan\nGi1/0/48    on               802.1q         trunking      1\n"
)

func macTable(port string) string {
	return "Vlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n  30    " + macTarget + "    DYNAMIC     " + port + "\nAll    ffff.ffff.ffff    STATIC      CPU\n"
}

func TestFindMACClassifiesAccessAndUplinkPorts(t *testing.T) {
	h, _ := newHarness(t, Options{})
	scripted(h, map[string]string{
		"sw-access|show mac address-table address " + macTarget: macTable("Gi1/0/14"),
		"sw-dist|show mac address-table address " + macTarget:   macTable("Gi1/0/48"),
		"sw-core|show mac address-table address " + macTarget:   macTable("Po1"),
		"sw-empty|show mac address-table address " + macTarget:  "",
		"sw-access|show interfaces trunk":                       trunkOutput,
		"sw-dist|show interfaces trunk":                         trunkOutput,
		"sw-core|show interfaces trunk":                         trunkOutput,
	})
	sink := &FindSink{}
	h.r.Handler = sink.MACHandler(macCanon) // any notation is accepted
	res := h.r.Run(context.Background(), h.jobs(vendor.Cisco, LocatorCapability(true), "sw-access", "sw-dist", "sw-core", "sw-empty"))
	if ExitCode(res) != ExitOK {
		t.Fatalf("results %+v", res)
	}
	hits := sink.Hits()
	if len(hits) != 3 {
		t.Fatalf("hits = %+v (the CPU entry must be dropped)", hits)
	}
	if hits[0].Uplink || hits[0].Device.Hostname != "sw-access" || hits[0].Record.Interface != "Gi1/0/14" || hits[0].Record.VLAN != 30 {
		t.Errorf("first hit should be the access port: %+v", hits[0])
	}
	for _, uplink := range hits[1:] {
		if !uplink.Uplink {
			t.Errorf("%s %s should be an uplink: %+v", uplink.Device.Hostname, uplink.Record.Interface, uplink)
		}
	}
	whys := hits[1].Why + "," + hits[2].Why
	if !strings.Contains(whys, "trunk") || !strings.Contains(whys, "port-channel") {
		t.Errorf("uplink reasons = %q", whys)
	}
	for _, r := range res {
		if r.Device.Hostname == "sw-empty" && !strings.Contains(r.Detail, "not in the MAC table") {
			t.Errorf("sw-empty detail = %q", r.Detail)
		}
	}
}

func TestFindIPViaARPThenMAC(t *testing.T) {
	h, _ := newHarness(t, Options{})
	scripted(h, map[string]string{
		"gw|show ip arp 10.1.20.15": "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\nInternet  10.1.20.15              5   " + macTarget + "  ARPA   Vlan30\n",
	})
	sink := &FindSink{}
	h.r.Handler = sink.ARPHandler("10.1.20.15")
	res := h.r.Run(context.Background(), h.jobs(vendor.Cisco, LocatorCapability(false), "gw", "other"))
	if ExitCode(res) != ExitOK {
		t.Fatalf("results %+v", res)
	}
	arp := sink.ARP()
	if len(arp) != 1 || arp[0].Record.MAC != macCanon || arp[0].Record.VLAN != 30 || arp[0].Device.Hostname != "gw" {
		t.Errorf("arp = %+v", arp)
	}
}

func TestFindCapabilityDistinguishesMACAndARP(t *testing.T) {
	asa, _ := vendor.Lookup(vendor.CiscoASA)
	if ok, why := LocatorCapability(true)(asa); ok || !strings.Contains(why, "layer-3") {
		t.Errorf("ASA has no MAC table: ok=%t %q", ok, why)
	}
	if ok, _ := LocatorCapability(false)(asa); !ok {
		t.Error("ASA has an ARP table")
	}
	sophos, _ := vendor.Lookup(vendor.Sophos)
	if ok, _ := LocatorCapability(false)(sophos); ok {
		t.Error("sophos has no verified locator")
	}
}

func TestFindRejectsGarbageMACBeforeAnyCommand(t *testing.T) {
	h, _ := newHarness(t, Options{})
	scripted(h, nil)
	sink := &FindSink{}
	h.r.Handler = sink.MACHandler("not-a-mac")
	res := h.r.Run(context.Background(), h.jobs(vendor.Cisco, LocatorCapability(true), "sw1"))
	if res[0].Status != StatusFailed || len(h.tr.commands("sw1")) != 0 {
		t.Errorf("result = %+v, commands = %q", res[0], h.tr.commands("sw1"))
	}
}

// ---- audit ------------------------------------------------------------------

const auditCiscoGood = "hostname sw1\n!\nlogging host 10.0.0.9\nntp server 10.0.0.1\nsnmp-server community Str0ng RO\ntacacs-server host 10.0.0.5\nline vty 0 4\n exec-timeout 5 0\n transport input ssh\nend\n"

func TestAuditSink(t *testing.T) {
	h, _ := newHarness(t, Options{})
	scripted(h, map[string]string{
		"good|show running-config":      auditCiscoGood,
		"bad|show running-config":       "hostname sw2\n!\nsnmp-server community public RO\nline vty 0 4\n transport input all\nend\n",
		"truncated|show running-config": "hostname sw3\n!\nntp server 10.0.0.1\n",
		"broken|show running-config":    "% Invalid input detected at '^' marker.\n",
	})
	sink := NewAuditSink(audit.Defaults())
	h.r.Handler = sink.Handler()
	res := h.r.Run(context.Background(), h.jobs(vendor.Cisco, always, "good", "bad", "truncated", "broken"))

	byHost := map[string]Result{}
	for _, r := range res {
		byHost[r.Device.Hostname] = r
	}
	for _, name := range []string{"truncated", "broken"} {
		if byHost[name].Status != StatusFailed || byHost[name].Category != CatSyntaxError {
			t.Errorf("%s must fail instead of producing a verdict: %+v", name, byHost[name])
		}
	}
	rows := sink.Rows()
	if len(rows) != 2 || rows[0].Hostname != "bad" || rows[1].Hostname != "good" {
		t.Fatalf("rows = %+v", rows)
	}
	if s := audit.Summarize(rows[1].Checks); s.Fail != 0 || s.Pass != 6 {
		t.Errorf("good summary = %+v", s)
	}
	if s := audit.Summarize(rows[0].Checks); s.Fail != 6 {
		t.Errorf("bad summary = %+v", s)
	}
	if !strings.Contains(byHost["bad"].Detail, "6 failed") {
		t.Errorf("detail = %q", byHost["bad"].Detail)
	}
}

func TestAuditReadsJunosInSetForm(t *testing.T) {
	h, _ := newHarness(t, Options{})
	scripted(h, map[string]string{
		"jn1|show configuration | display set | no-more": "set system ntp server 10.0.0.1\nset system services telnet\n",
	})
	sink := NewAuditSink(audit.Defaults())
	h.r.Handler = sink.Handler()
	res := h.r.Run(context.Background(), h.jobs(vendor.Junos, always, "jn1"))
	if res[0].Status != StatusSucceeded {
		t.Fatalf("result = %+v", res[0])
	}
	got := map[string]audit.Status{}
	for _, c := range sink.Rows()[0].Checks {
		got[c.ID] = c.Status
	}
	if got["ntp"] != audit.Pass || got["telnet"] != audit.Fail {
		t.Errorf("checks = %v", got)
	}
}

func TestAuditDoesNotLeakSecretsInEvidence(t *testing.T) {
	rules := []audit.Rule{{ID: "x", Require: `^username `, Remediation: "r"}}
	if err := audit.Compile(rules); err != nil {
		t.Fatal(err)
	}
	h, _ := newHarness(t, Options{})
	scripted(h, map[string]string{"sw1|show running-config": "hostname a\n!\nusername bob privilege 15 secret 0 Sup3rSecret\nend\n"})
	sink := NewAuditSink(rules)
	h.r.Handler = sink.Handler()
	h.r.Run(context.Background(), h.jobs(vendor.Cisco, always, "sw1"))
	ev := sink.Rows()[0].Checks[0].Evidence
	if strings.Contains(ev, "Sup3rSecret") {
		t.Errorf("evidence leaks a secret: %q", ev)
	}
}

// ---- simulated diff ---------------------------------------------------------

const iosRunning = `Building configuration...

hostname sw1
!
interface GigabitEthernet1/0/14
 description old
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/15
 shutdown
!
ntp server 10.0.0.1
!
line vty 0 4
 exec-timeout 10 0
 transport input all
!
end
`

func TestSimulateDiffIOS(t *testing.T) {
	cmds := []string{
		"interface GigabitEthernet1/0/14", "description new", "switchport access vlan 30",
		"exit",
		"interface GigabitEthernet1/0/15", "no shutdown",
		"exit",
		"ntp server 10.0.0.2",
		"line vty 0 4", "transport input ssh", "exec-timeout 5 0",
	}
	lines, added, removed, ok := SimulateDiff(vendor.Cisco, iosRunning, cmds)
	if !ok {
		t.Fatal("cisco must be simulatable")
	}
	want := []string{
		" interface GigabitEthernet1/0/14",
		"-  description old",
		"-  switchport access vlan 10",
		"+  description new",
		"+  switchport access vlan 30",
		" interface GigabitEthernet1/0/15",
		"-  shutdown",
		" line vty 0 4",
		"-  exec-timeout 10 0",
		"-  transport input all",
		"+  transport input ssh",
		"+  exec-timeout 5 0",
		"+ntp server 10.0.0.2", // new lines land at the end: a device's canonical order is unknowable
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("diff:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if added != 5 || removed != 5 {
		t.Errorf("counts +%d -%d", added, removed)
	}
}

func TestSimulateDiffIsIdempotentAndHandlesRemovals(t *testing.T) {
	// re-applying what is already there predicts no change
	lines, _, _, _ := SimulateDiff(vendor.Cisco, iosRunning, []string{"ntp server 10.0.0.1", "interface GigabitEthernet1/0/14", "description old", "exit", "hostname sw1"})
	if len(lines) != 0 {
		t.Errorf("no-op commands produced a diff: %q", lines)
	}
	// "no" removes a whole block and a single line
	lines, added, removed, _ := SimulateDiff(vendor.Cisco, iosRunning, []string{"no interface GigabitEthernet1/0/15", "no ntp server 10.0.0.1"})
	if added != 0 || removed != 3 || lines[0] != "-interface GigabitEthernet1/0/15" {
		t.Errorf("removals: +%d -%d %q", added, removed, lines)
	}
	// a hostname change replaces rather than duplicates
	lines, _, _, _ = SimulateDiff(vendor.Cisco, iosRunning, []string{"hostname sw9"})
	if strings.Join(lines, "|") != "-hostname sw1|+hostname sw9" {
		t.Errorf("hostname diff = %q", lines)
	}
	// secondary addresses accumulate, a primary replaces
	run := "interface Vlan1\n ip address 10.0.0.1 255.255.255.0\n!\nend\n"
	lines, _, _, _ = SimulateDiff(vendor.Cisco, run, []string{"interface Vlan1", "ip address 10.0.1.1 255.255.255.0 secondary"})
	if strings.Join(lines, "|") != " interface Vlan1|+  ip address 10.0.1.1 255.255.255.0 secondary" {
		t.Errorf("secondary diff = %q", lines)
	}
}

func TestSimulateDiffHuawei(t *testing.T) {
	run := "sysname SW\n#\nvlan batch 10 20\n#\naaa\n local-user admin password irreversible-cipher $1c$x\n local-user admin service-type ssh\n#\nreturn\n"
	lines, _, _, ok := SimulateDiff(vendor.Huawei, run, []string{"vlan 30", "description Servers", "quit", "aaa", "undo local-user admin service-type", "local-user bob password irreversible-cipher x", "quit"})
	if !ok {
		t.Fatal("huawei must be simulatable")
	}
	want := []string{
		" aaa",
		"-  local-user admin service-type ssh",
		"+  local-user bob password irreversible-cipher x",
		"+vlan 30", "+  description Servers",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("diff:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestSimulateDiffFortinet(t *testing.T) {
	run := "config system admin\n    edit \"admin\"\n        set accprofile \"super_admin\"\n        set password ENC abc\n    next\nend\nconfig system global\n    set admintimeout 5\nend\n"
	lines, _, _, ok := SimulateDiff(vendor.Fortinet, run, []string{
		"config system admin", "edit bob", "set password S3cret", "set accprofile super_admin", "next", "delete admin", "end",
		"config system global", "set admintimeout 10", "end",
	})
	if !ok {
		t.Fatal("fortinet must be simulatable")
	}
	want := []string{
		" config system admin",
		"-  edit \"admin\"",
		"-    set accprofile \"super_admin\"",
		"-    set password ENC abc",
		"+  edit \"bob\"",
		"+    set password S3cret",
		"+    set accprofile super_admin",
		" config system global",
		"-  set admintimeout 5", // a single-valued set replaces, it does not duplicate
		"+  set admintimeout 10",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("diff:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestSimulationCapability(t *testing.T) {
	for name, want := range map[string]bool{
		vendor.Cisco: true, vendor.CiscoSB: true, vendor.CiscoASA: true, vendor.Ruijie: true, vendor.Aruba: true,
		vendor.Huawei: true, vendor.Fortinet: true,
		vendor.Junos: false, vendor.Arista: false, vendor.VyOS: false, // native candidate diff instead
		vendor.PaloAlto: false, vendor.CheckPoint: false, vendor.PfSense: false, vendor.Sophos: false,
	} {
		p, _ := vendor.Lookup(name)
		if got, _ := SimulationCapability(p); got != want {
			t.Errorf("%s: %t, want %t", name, got, want)
		}
	}
	if _, _, _, ok := SimulateDiff(vendor.Junos, "x", nil); ok {
		t.Error("junos must not be simulated")
	}
}

func TestDiffHandlerNeverEntersConfigModeAndRedactsSecrets(t *testing.T) {
	h, _ := newHarness(t, Options{})
	scripted(h, map[string]string{"sw1|show running-config": iosRunning})
	sink := &DiffSink{}
	h.r.Handler = sink.Handler([]string{"username bob privilege 15 secret 0 Sup3rSecret", "ntp server 10.0.0.2"})
	res := h.r.Run(context.Background(), h.jobs(vendor.Cisco, SimulationCapability, "sw1"))
	if res[0].Status != StatusSucceeded {
		t.Fatalf("result = %+v", res[0])
	}
	for _, c := range h.tr.commands("sw1") {
		if c == "configure terminal" || strings.HasPrefix(c, "username") || strings.HasPrefix(c, "ntp") {
			t.Errorf("a preview sent %q to the device", c)
		}
	}
	rows := sink.Rows()
	if len(rows) != 1 || rows[0].Added != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	all := strings.Join(rows[0].Lines, "\n") + h.logs.String()
	mustNotContain(t, all, "Sup3rSecret", "the diff preview")
	if !strings.Contains(all, "<redacted>") {
		t.Errorf("secret was neither shown nor masked: %s", all)
	}
}

func TestDiffHandlerRefusesTruncatedConfig(t *testing.T) {
	h, _ := newHarness(t, Options{})
	scripted(h, map[string]string{"sw1|show running-config": "hostname sw1\ninterface Gi1\n"})
	sink := &DiffSink{}
	h.r.Handler = sink.Handler([]string{"ntp server 10.0.0.2"})
	res := h.r.Run(context.Background(), h.jobs(vendor.Cisco, SimulationCapability, "sw1"))
	if res[0].Status != StatusFailed || len(sink.Rows()) != 0 {
		t.Errorf("a truncated config must not yield a prediction: %+v", res[0])
	}
}

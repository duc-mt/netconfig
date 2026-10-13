package task

import (
	"errors"
	"os"
	"strings"
	"testing"

	"netconfig/internal/inventory"
	"netconfig/internal/logging"
	"netconfig/internal/vendor"
)

// lintAs lints commands for a device at 10.0.0.1:22 that logs in as "svc".
func lintAs(vendorName string, cmds ...string) LintReport {
	return LintCommands(LintContext{
		Hostname: "sw1", Address: "10.0.0.1", Port: 22, Username: "svc", Vendor: vendorName,
	}, cmds)
}

func find(rep LintReport, rule string) (Finding, bool) {
	for _, f := range rep.Findings {
		if f.Rule == rule {
			return f, true
		}
	}
	return Finding{}, false
}

func TestLintRules(t *testing.T) {
	cases := []struct {
		name   string
		vendor string
		cmds   []string
		rule   string // "" = the commands must produce no finding at all
		level  RiskLevel
		kind   FindingKind
	}{
		// --- management address ---
		{"remove mgmt ip (cisco)", "cisco", []string{"interface Gi0/1", "no ip address 10.0.0.1 255.255.255.0"}, "mgmt-ip-removed", RiskCritical, KindLockout},
		{"remove mgmt ip (junos)", "junos", []string{"delete interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24"}, "mgmt-ip-removed", RiskCritical, KindLockout},
		{"remove mgmt ip (huawei)", "huawei", []string{"interface GE0/0/1", "undo ip address 10.0.0.1 24"}, "mgmt-ip-removed", RiskCritical, KindLockout},
		{"remove mgmt ip (vyos)", "vyos", []string{"delete interfaces ethernet eth0 address 10.0.0.1/24"}, "mgmt-ip-removed", RiskCritical, KindLockout},
		{"similar address is not the mgmt ip", "cisco", []string{"interface Gi0/1", "no ip address 10.0.0.10 255.255.255.0"}, "interface-address-removed", RiskHigh, KindLockout},
		{"remove any interface address", "cisco", []string{"interface Gi0/1", "no ip address"}, "interface-address-removed", RiskHigh, KindLockout},
		{"re-assert mgmt ip is harmless", "cisco", []string{"interface Gi0/1", "ip address 10.0.0.1 255.255.255.0"}, "", 0, ""},
		{"readdress interface", "cisco", []string{"interface Gi0/1", "ip address 10.9.9.9 255.255.255.0"}, "interface-readdressed", RiskMedium, KindLockout},
		{"readdress mgmt interface", "arista", []string{"interface Management1", "ip address 10.9.9.9/24"}, "mgmt-ip-changed", RiskCritical, KindLockout},
		{"junos address add does not replace", "junos", []string{"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.9/24"}, "", 0, ""},
		{"vrf move drops the address", "cisco", []string{"interface Gi0/1", "ip vrf forwarding BLUE"}, "interface-vrf-moved", RiskHigh, KindLockout},
		// --- default gateway ---
		{"remove default route (cisco)", "cisco", []string{"no ip route 0.0.0.0 0.0.0.0 10.0.0.254"}, "default-route-removed", RiskCritical, KindLockout},
		{"remove default route (junos)", "junos", []string{"delete routing-options static route 0.0.0.0/0"}, "default-route-removed", RiskCritical, KindLockout},
		{"remove default route (huawei)", "huawei", []string{"undo ip route-static 0.0.0.0 0.0.0.0"}, "default-route-removed", RiskCritical, KindLockout},
		{"remove default route (vyos)", "vyos", []string{"delete protocols static route 0.0.0.0/0"}, "default-route-removed", RiskCritical, KindLockout},
		{"remove default route (ipv6)", "cisco", []string{"no ipv6 route ::/0 2001:db8::1"}, "default-route-removed", RiskCritical, KindLockout},
		{"remove default gateway", "cisco", []string{"no ip default-gateway"}, "default-route-removed", RiskCritical, KindLockout},
		{"add default route", "cisco", []string{"ip route 0.0.0.0 0.0.0.0 10.0.0.253"}, "default-route-changed", RiskMedium, KindLockout},
		{"blackhole default route", "cisco", []string{"ip route 0.0.0.0 0.0.0.0 Null0"}, "default-route-blackholed", RiskHigh, KindLockout},
		{"replace default gateway", "cisco", []string{"ip default-gateway 10.1.1.1"}, "default-gateway-changed", RiskHigh, KindLockout},
		{"fortinet static route deleted", "fortinet", []string{"config router static", "delete 3", "end"}, "static-route-deleted", RiskHigh, KindLockout},
		{"ordinary static route", "cisco", []string{"ip route 10.1.0.0 255.255.0.0 10.0.0.254"}, "", 0, ""},
		{"remove ordinary static route", "cisco", []string{"no ip route 10.1.0.0 255.255.0.0 10.0.0.254"}, "", 0, ""},
		// --- SSH ---
		{"ssh port change (cisco)", "cisco", []string{"ip ssh port 2222 rotary 1"}, "ssh-port-changed", RiskCritical, KindLockout},
		{"ssh port change (junos)", "junos", []string{"set system services ssh port 2222"}, "ssh-port-changed", RiskCritical, KindLockout},
		{"ssh port change (vyos, quoted)", "vyos", []string{"set service ssh port '2222'"}, "ssh-port-changed", RiskCritical, KindLockout},
		{"ssh port change (huawei)", "huawei", []string{"ssh server port 2222"}, "ssh-port-changed", RiskCritical, KindLockout},
		{"ssh port change (fortinet)", "fortinet", []string{"config system global", "set admin-ssh-port 2222", "end"}, "ssh-port-changed", RiskCritical, KindLockout},
		{"ssh port unchanged", "cisco", []string{"ip ssh port 22 rotary 1"}, "", 0, ""},
		{"ssh port reset to default", "cisco", []string{"no ip ssh port"}, "", 0, ""},
		{"ssh disabled (junos)", "junos", []string{"delete system services ssh"}, "ssh-disabled", RiskCritical, KindLockout},
		{"ssh disabled (vyos)", "vyos", []string{"delete service ssh"}, "ssh-disabled", RiskCritical, KindLockout},
		{"ssh disabled (cisco)", "cisco", []string{"no ip ssh server enable"}, "ssh-disabled", RiskCritical, KindLockout},
		{"arista management ssh shutdown", "arista", []string{"management ssh", "shutdown"}, "ssh-disabled", RiskCritical, KindLockout},
		{"zeroize keys", "cisco", []string{"crypto key zeroize rsa"}, "ssh-keys-zeroized", RiskCritical, KindLockout},
		{"ssh ciphers (junos)", "junos", []string{"set system services ssh ciphers aes256-ctr"}, "ssh-algorithms-changed", RiskHigh, KindLockout},
		{"ssh ciphers (cisco)", "cisco", []string{"ip ssh server algorithm encryption aes256-ctr"}, "ssh-algorithms-changed", RiskHigh, KindLockout},
		{"vty without ssh", "cisco", []string{"line vty 0 4", "transport input telnet"}, "vty-ssh-disabled", RiskCritical, KindLockout},
		{"vty with ssh", "cisco", []string{"line vty 0 4", "transport input ssh"}, "", 0, ""},
		{"fortinet allowaccess without ssh", "fortinet", []string{"config system interface", "edit port1", "set allowaccess ping https", "next", "end"}, "ssh-access-removed", RiskCritical, KindLockout},
		{"fortinet allowaccess with ssh", "fortinet", []string{"config system interface", "edit port1", "set allowaccess ping https ssh", "next", "end"}, "", 0, ""},
		// --- AAA ---
		{"aaa without fallback", "cisco", []string{"aaa authentication login default group tacacs+"}, "aaa-no-fallback", RiskCritical, KindLockout},
		{"aaa with local fallback", "cisco", []string{"aaa authentication login default group tacacs+ local"}, "aaa-method-changed", RiskHigh, KindLockout},
		{"aaa new-model", "cisco", []string{"aaa new-model"}, "aaa-model-changed", RiskHigh, KindLockout},
		{"remove method list", "cisco", []string{"no aaa authentication login default"}, "aaa-method-removed", RiskHigh, KindLockout},
		{"junos auth order without password", "junos", []string{"set system authentication-order [ radius ]"}, "aaa-no-fallback", RiskCritical, KindLockout},
		{"junos auth order with password", "junos", []string{"set system authentication-order [ radius password ]"}, "aaa-order-changed", RiskHigh, KindLockout},
		{"remove login user", "cisco", []string{"no username svc"}, "mgmt-user-removed", RiskCritical, KindLockout},
		{"remove login user (junos)", "junos", []string{"delete system login user svc"}, "mgmt-user-removed", RiskCritical, KindLockout},
		{"remove another user", "cisco", []string{"no username bob"}, "user-removed", RiskMedium, KindImpact},
		{"change login user password", "cisco", []string{"username svc privilege 15 secret 0 hunter2"}, "mgmt-user-modified", RiskHigh, KindLockout},
		{"add another user", "cisco", []string{"username bob privilege 15 secret 0 pw"}, "", 0, ""},
		{"fortinet trusthost", "fortinet", []string{"config system admin", "edit svc", "set trusthost1 10.9.0.0 255.255.0.0", "next", "end"}, "admin-trusthost", RiskHigh, KindLockout},
		// --- vty ACL / auth ---
		{"vty acl applied", "cisco", []string{"line vty 0 4", "access-class MGMT in"}, "vty-acl-changed", RiskHigh, KindLockout},
		{"vty acl removed", "cisco", []string{"line vty 0 4", "no access-class MGMT in"}, "vty-acl-removed", RiskMedium, KindLockout},
		{"vty auth", "cisco", []string{"line vty 0 4", "login local"}, "vty-auth-changed", RiskHigh, KindLockout},
		{"huawei vty acl", "huawei", []string{"user-interface vty 0 4", "acl 2000 inbound"}, "vty-acl-changed", RiskHigh, KindLockout},
		{"junos RE filter", "junos", []string{"set interfaces lo0 unit 0 family inet filter input PROTECT-RE"}, "re-filter-applied", RiskHigh, KindLockout},
		{"ordinary acl on interface is not vty", "cisco", []string{"interface Gi0/1", "ip access-group EDGE in"}, "", 0, ""},
		// --- interfaces ---
		{"interface shutdown", "cisco", []string{"interface Gi0/1", "shutdown"}, "interface-shutdown", RiskHigh, KindLockout},
		{"mgmt interface shutdown", "arista", []string{"interface Management1", "shutdown"}, "mgmt-interface-shutdown", RiskCritical, KindLockout},
		{"interface no shutdown", "cisco", []string{"interface Gi0/1", "no shutdown"}, "", 0, ""},
		{"junos interface disable", "junos", []string{"set interfaces ge-0/0/1 disable"}, "interface-shutdown", RiskHigh, KindLockout},
		{"junos mgmt interface disable", "junos", []string{"set interfaces fxp0 disable"}, "mgmt-interface-shutdown", RiskCritical, KindLockout},
		{"fortinet mgmt interface down", "fortinet", []string{"config system interface", "edit mgmt", "set status down", "next", "end"}, "mgmt-interface-shutdown", RiskCritical, KindLockout},
		{"trunk list replaced", "cisco", []string{"interface Gi0/1", "switchport trunk allowed vlan 10,20"}, "trunk-vlan-list-replaced", RiskHigh, KindLockout},
		{"trunk list add", "cisco", []string{"interface Gi0/1", "switchport trunk allowed vlan add 30"}, "", 0, ""},
		{"shutdown after exit is not in an interface", "cisco", []string{"interface Gi0/1", "exit", "shutdown"}, "", 0, ""},
		// --- destructive ---
		{"no router bgp", "cisco", []string{"no router bgp 65000"}, "teardown-routing-process", RiskCritical, KindDestructive},
		{"no router ospf", "cisco", []string{"no router ospf 1"}, "teardown-routing-process", RiskCritical, KindDestructive},
		{"delete protocols bgp", "junos", []string{"delete protocols bgp"}, "teardown-routing-process", RiskCritical, KindDestructive},
		{"delete protocols bgp asn (vyos)", "vyos", []string{"delete protocols bgp 65000"}, "teardown-routing-process", RiskCritical, KindDestructive},
		{"delete part of bgp", "junos", []string{"delete protocols bgp group IBGP"}, "routing-config-removed", RiskMedium, KindImpact},
		{"delete bgp neighbor", "junos", []string{"delete protocols bgp group IBGP neighbor 10.1.1.1"}, "routing-neighbor-removed", RiskHigh, KindImpact},
		{"delete all interfaces", "junos", []string{"delete interfaces"}, "delete-all-interfaces", RiskCritical, KindDestructive},
		{"delete one interface (vyos)", "vyos", []string{"delete interfaces ethernet eth1"}, "delete-interface", RiskHigh, KindDestructive},
		{"delete one interface (junos)", "junos", []string{"delete interfaces ge-0/0/1"}, "delete-interface", RiskHigh, KindDestructive},
		{"delete mgmt interface", "junos", []string{"delete interfaces fxp0"}, "mgmt-interface-removed", RiskCritical, KindLockout},
		{"delete unit only", "junos", []string{"delete interfaces ge-0/0/1 unit 0 description"}, "", 0, ""},
		{"wipe config", "junos", []string{"delete"}, "wipe-configuration", RiskCritical, KindDestructive},
		{"no interface", "cisco", []string{"no interface Loopback1"}, "delete-interface", RiskHigh, KindDestructive},
		{"no mgmt interface", "arista", []string{"no interface Management1"}, "mgmt-interface-removed", RiskCritical, KindLockout},
		{"default interface", "cisco", []string{"default interface Gi0/1"}, "default-interface", RiskHigh, KindDestructive},
		{"default mgmt interface", "cisco", []string{"default interface mgmt0"}, "mgmt-interface-reset", RiskCritical, KindLockout},
		{"clear bgp all", "cisco", []string{"clear ip bgp *"}, "clear-bgp-all", RiskHigh, KindDestructive},
		{"clear bgp all (huawei)", "huawei", []string{"reset bgp all"}, "clear-bgp-all", RiskHigh, KindDestructive},
		{"clear bgp soft", "cisco", []string{"clear ip bgp * soft in"}, "bgp-soft-reset", RiskMedium, KindImpact},
		{"clear one bgp peer", "cisco", []string{"clear ip bgp 10.0.0.2"}, "", 0, ""},
		{"clear ospf", "cisco", []string{"clear ip ospf process"}, "clear-ospf", RiskHigh, KindDestructive},
		{"clear routes", "cisco", []string{"clear ip route *"}, "clear-routes", RiskMedium, KindImpact},
		{"reload now", "cisco", []string{"reload"}, "reload", RiskHigh, KindDestructive},
		{"reload scheduled", "cisco", []string{"reload in 5"}, "", 0, ""},
		{"reload cancel", "cisco", []string{"reload cancel"}, "", 0, ""},
		{"write erase", "cisco", []string{"write erase"}, "erase-configuration", RiskCritical, KindDestructive},
		{"load override", "junos", []string{"load override /var/tmp/x.conf"}, "erase-configuration", RiskCritical, KindDestructive},
		{"delete flash file", "cisco", []string{"delete flash:config.text"}, "delete-file", RiskHigh, KindDestructive},
		{"ip routing off", "cisco", []string{"no ip routing"}, "routing-disabled", RiskHigh, KindImpact},
		// --- contained impact ---
		{"bgp neighbor removed", "cisco", []string{"router bgp 65000", "no neighbor 10.1.1.1 remote-as 65001"}, "routing-neighbor-removed", RiskHigh, KindImpact},
		{"bgp neighbor shutdown", "cisco", []string{"router bgp 65000", "neighbor 10.1.1.1 shutdown"}, "routing-neighbor-shutdown", RiskHigh, KindImpact},
		{"network statement removed", "cisco", []string{"router ospf 1", "no network 10.0.0.0 0.0.0.255 area 0"}, "routing-config-removed", RiskMedium, KindImpact},
		{"passive-interface toggle is benign", "cisco", []string{"router ospf 1", "no passive-interface Gi0/1"}, "", 0, ""},
		{"router-id change", "cisco", []string{"router ospf 1", "router-id 1.1.1.1"}, "router-id-changed", RiskMedium, KindImpact},
		{"vlan removed", "cisco", []string{"no vlan 20"}, "vlan-removed", RiskMedium, KindImpact},
		{"stp mode", "cisco", []string{"spanning-tree mode rapid-pvst"}, "stp-mode-changed", RiskMedium, KindImpact},
		// --- read-only never triggers ---
		{"show with default route text", "cisco", []string{"show ip route 0.0.0.0"}, "", 0, ""},
		{"do show", "cisco", []string{"do show run | include no ip address"}, "", 0, ""},
		{"ping", "cisco", []string{"ping 10.0.0.1"}, "", 0, ""},
		{"harmless config", "cisco", []string{"hostname lab1", "ntp server 10.9.9.9"}, "", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := lintAs(tc.vendor, tc.cmds...)
			if rep.Err != nil {
				t.Fatalf("lint failed: %v", rep.Err)
			}
			if tc.rule == "" {
				if len(rep.Findings) != 0 {
					t.Fatalf("want no findings, got %+v", rep.Findings)
				}
				if rep.Level != RiskLow {
					t.Fatalf("clean report level = %v", rep.Level)
				}
				return
			}
			f, ok := find(rep, tc.rule)
			if !ok {
				t.Fatalf("rule %q not raised; findings: %+v", tc.rule, rep.Findings)
			}
			if f.Level != tc.level || f.Kind != tc.kind {
				t.Fatalf("rule %q = %v/%s, want %v/%s", tc.rule, f.Level, f.Kind, tc.level, tc.kind)
			}
		})
	}
}

func TestLintUsesConnectionParameters(t *testing.T) {
	t.Run("ssh port matches non-default session port", func(t *testing.T) {
		ctx := LintContext{Address: "10.0.0.1", Port: 2222, Vendor: "cisco"}
		if rep := LintCommands(ctx, []string{"ip ssh port 2222 rotary 1"}); len(rep.Findings) != 0 {
			t.Fatalf("moving SSH to the port already in use is not a lockout: %+v", rep.Findings)
		}
		rep := LintCommands(ctx, []string{"no ip ssh port"}) // falls back to 22
		if _, ok := find(rep, "ssh-port-changed"); !ok {
			t.Fatalf("resetting to 22 while connected on 2222 must be flagged: %+v", rep.Findings)
		}
	})
	t.Run("port 0 means 22", func(t *testing.T) {
		ctx := LintContext{Address: "10.0.0.1", Vendor: "cisco"}
		if rep := LintCommands(ctx, []string{"ip ssh port 22 rotary 1"}); len(rep.Findings) != 0 {
			t.Fatalf("unexpected findings: %+v", rep.Findings)
		}
	})
	t.Run("unknown username downgrades to HIGH", func(t *testing.T) {
		ctx := LintContext{Address: "10.0.0.1", Vendor: "cisco"}
		f, ok := find(LintCommands(ctx, []string{"no username svc"}), "user-removed")
		if !ok || f.Level != RiskHigh {
			t.Fatalf("got %+v ok=%v", f, ok)
		}
	})
	t.Run("hostname address", func(t *testing.T) {
		ctx := LintContext{Address: "SW1.lab.example", Vendor: "junos"}
		rep := LintCommands(ctx, []string{"delete interfaces ge-0/0/0 unit 0 family inet address sw1.lab.example"})
		if _, ok := find(rep, "mgmt-ip-removed"); !ok {
			t.Fatalf("a hostname mentioned literally must match case-insensitively: %+v", rep.Findings)
		}
	})
	t.Run("no address configured", func(t *testing.T) {
		rep := LintCommands(LintContext{Vendor: "cisco"}, []string{"interface Gi0/1", "no ip address 10.0.0.1 255.255.255.0"})
		f, ok := find(rep, "interface-address-removed")
		if !ok || f.Level != RiskHigh {
			t.Fatalf("got %+v", rep.Findings)
		}
	})
}

func TestLintOperationalModeOnlyChecksDestructive(t *testing.T) {
	ctx := LintContext{Address: "10.0.0.1", Port: 22, Vendor: "cisco", OpMode: true}
	rep := LintCommands(ctx, []string{"no ip route 0.0.0.0 0.0.0.0", "clear ip bgp *"})
	if _, ok := find(rep, "default-route-removed"); ok {
		t.Fatal("lockout rules must not run in operational mode")
	}
	if _, ok := find(rep, "clear-bgp-all"); !ok {
		t.Fatalf("destructive rules still apply in operational mode: %+v", rep.Findings)
	}
}

func TestLintReportAggregates(t *testing.T) {
	rep := lintAs("cisco",
		"hostname lab1",
		"interface Gi0/1",
		"shutdown", // HIGH
		"exit",
		"no ip route 0.0.0.0 0.0.0.0",         // CRITICAL
		"ip route 0.0.0.0 0.0.0.0 10.0.0.253", // MEDIUM
	)
	if rep.Level != RiskCritical {
		t.Fatalf("level = %v, want CRITICAL", rep.Level)
	}
	for i := 1; i < len(rep.Findings); i++ {
		if rep.Findings[i].Level > rep.Findings[i-1].Level {
			t.Fatalf("findings not sorted by severity: %+v", rep.Findings)
		}
	}
	if f, _ := find(rep, "default-route-removed"); f.Index != 5 {
		t.Fatalf("finding index = %d, want 5 (1-based position in the command list)", f.Index)
	}
}

func TestLintRedactsSecretsInFindings(t *testing.T) {
	rep := lintAs("cisco", "username svc privilege 15 secret 0 hunter2")
	f, ok := find(rep, "mgmt-user-modified")
	if !ok {
		t.Fatalf("not raised: %+v", rep.Findings)
	}
	if strings.Contains(f.Command, "hunter2") {
		t.Fatalf("secret leaked into a finding: %q", f.Command)
	}
}

func TestSafetyPolicy(t *testing.T) {
	lockout := Finding{Kind: KindLockout, Level: RiskCritical}
	softLockout := Finding{Kind: KindLockout, Level: RiskHigh}
	destructive := Finding{Kind: KindDestructive, Level: RiskHigh}
	impact := Finding{Kind: KindImpact, Level: RiskCritical}
	cases := []struct {
		name string
		p    SafetyPolicy
		f    Finding
		want bool
	}{
		{"strict blocks CRITICAL lockout", SafetyPolicy{Strict: true}, lockout, true},
		{"-force releases lockout", SafetyPolicy{Strict: true, Force: true}, lockout, false},
		{"-allow-dangerous does not release lockout", SafetyPolicy{Strict: true, AllowDangerous: true}, lockout, true},
		{"HIGH lockout only warns", SafetyPolicy{Strict: true}, softLockout, false},
		{"strict blocks destructive", SafetyPolicy{Strict: true}, destructive, true},
		{"-allow-dangerous releases destructive", SafetyPolicy{Strict: true, AllowDangerous: true}, destructive, false},
		{"-force does not release destructive", SafetyPolicy{Strict: true, Force: true}, destructive, true},
		{"impact never blocks", SafetyPolicy{Strict: true}, impact, false},
		{"non-strict never blocks lockout", SafetyPolicy{}, lockout, false},
		{"non-strict never blocks destructive", SafetyPolicy{}, destructive, false},
	}
	for _, tc := range cases {
		if got := tc.p.Blocks(tc.f); got != tc.want {
			t.Errorf("%s: Blocks = %v, want %v", tc.name, got, tc.want)
		}
	}
	rep := LintReport{Findings: []Finding{lockout, softLockout, destructive}}
	if n := len(rep.Blocking(SafetyPolicy{Strict: true})); n != 2 {
		t.Fatalf("Blocking = %d findings, want 2", n)
	}
}

func TestLintContainsPanicsToOneDevice(t *testing.T) {
	lintTestHook = func(c cmdInfo) {
		if strings.Contains(c.raw, "boom") {
			panic("rule bug")
		}
	}
	t.Cleanup(func() { lintTestHook = nil })

	bad := lintAs("cisco", "hostname ok", "boom")
	if bad.Err == nil || len(bad.Findings) != 0 {
		t.Fatalf("a panic must yield an empty report with Err set, got %+v", bad)
	}
	good := lintAs("cisco", "no ip route 0.0.0.0 0.0.0.0")
	if good.Err != nil || good.Level != RiskCritical {
		t.Fatalf("one device's failure must not affect the next analysis: %+v", good)
	}
}

func TestLintJobUsesProfileAndDevice(t *testing.T) {
	prof, _ := vendor.Lookup("junos")
	job := Job{
		Device:   inventory.Device{Hostname: "r1", Address: "10.0.0.1", Port: 2222},
		Profile:  prof,
		Commands: []string{"set system services ssh port 22"},
	}
	rep := LintJob(job, "svc", false)
	if _, ok := find(rep, "ssh-port-changed"); !ok {
		t.Fatalf("session port 2222 -> 22 must be flagged: %+v", rep.Findings)
	}
	// A job without a profile (skipped devices carry none) must not panic.
	if rep := LintJob(Job{Device: job.Device, Commands: []string{"hostname x"}}, "", false); rep.Err != nil {
		t.Fatalf("nil profile: %v", rep.Err)
	}
}

func TestSubsystems(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want []string
	}{
		{"bgp and interface", []string{"router bgp 65000", "neighbor 10.1.1.1 remote-as 65001", "exit", "interface Gi0/1", "description uplink"}, []string{"BGP", "Interface"}},
		{"static route", []string{"ip route 10.1.0.0 255.255.0.0 10.0.0.254"}, []string{"Routing"}},
		{"aaa and ssh", []string{"aaa new-model", "ip ssh version 2"}, []string{"AAA", "SSH/Mgmt"}},
		{"system", []string{"hostname lab1", "ntp server 10.9.9.9"}, []string{"System"}},
		{"junos bgp", []string{"set protocols bgp group IBGP neighbor 10.1.1.1"}, []string{"BGP"}},
		{"unclassified", []string{"foo bar"}, []string{"Other"}},
		{"read-only", []string{"show version", "ping 10.0.0.1"}, []string{"Read-only"}},
		{"read-only mixed with change", []string{"show version", "hostname x"}, []string{"System"}},
	}
	for _, tc := range cases {
		got := lintAs("cisco", tc.cmds...).Subsystems
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: subsystems = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRiskLevelString(t *testing.T) {
	for l, want := range map[RiskLevel]string{RiskLow: "LOW", RiskMedium: "MEDIUM", RiskHigh: "HIGH", RiskCritical: "CRITICAL"} {
		if l.String() != want {
			t.Errorf("%d = %q, want %q", l, l.String(), want)
		}
	}
}

func TestLintMessagesKeepTheOperatorsSpelling(t *testing.T) {
	cases := []struct {
		vendor string
		cmds   []string
		rule   string
		want   string
	}{
		{"huawei", []string{"interface GigabitEthernet0/0/1", "shutdown"}, "interface-shutdown", "GigabitEthernet0/0/1"},
		{"cisco", []string{"interface Management1", "shutdown"}, "mgmt-interface-shutdown", "Management1"},
		{"cisco", []string{"no interface Loopback1"}, "delete-interface", "Loopback1"},
		{"cisco", []string{"default interface GigabitEthernet1/0/5"}, "default-interface", "GigabitEthernet1/0/5"},
		{"fortinet", []string{"config system interface", "edit Port1", "set status down", "next", "end"}, "interface-shutdown", "Port1"},
	}
	for _, tc := range cases {
		f, ok := find(lintAs(tc.vendor, tc.cmds...), tc.rule)
		if !ok || !strings.Contains(f.Message, tc.want) {
			t.Errorf("%v: message %q should contain %q (ok=%v)", tc.cmds, f.Message, tc.want, ok)
		}
	}
}

func TestLintReportLogRoutesBySeverity(t *testing.T) {
	log, err := logging.New(logging.Options{Dir: t.TempDir(), Console: nil})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	rep := lintAs("cisco",
		"no ip route 0.0.0.0 0.0.0.0",         // CRITICAL
		"interface Gi0/1", "shutdown", "exit", // HIGH
		"spanning-tree mode rapid-pvst", // MEDIUM
	)
	rep.Log(log, "sw1")
	LintReport{Err: errors.New("lint exploded")}.Log(log, "sw2")
	LintReport{Findings: []Finding{{Level: RiskLow, Rule: "quiet", Message: "low findings are not logged"}}}.Log(log, "sw3")

	data, err := os.ReadFile(log.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"ERROR [sw1] LINT CRITICAL [default-route-removed] command 1",
		"WARN  [sw1] LINT HIGH [interface-shutdown] command 3",
		"WARN  [sw1] LINT MEDIUM [stp-mode-changed]",
		"[sw2] static safety lint failed (lint exploded); continuing without pre-flight analysis for this device",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("log lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "quiet") {
		t.Errorf("LOW findings stay out of the log:\n%s", text)
	}
}

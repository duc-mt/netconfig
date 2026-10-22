// ==============================================================================
// Package backup implements tests for the risk classifier.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package backup

import (
	"reflect"
	"regexp"
	"testing"
)

func TestBuiltinRiskPatternsCompile(t *testing.T) {
	for _, s := range builtinRiskSpecs {
		if _, err := regexp.Compile(s.pattern); err != nil {
			t.Errorf("risk rule %s/%q does not compile: %v", s.category, s.reason, err)
		}
	}
	if got, want := len(compiledRiskRules()), len(builtinRiskSpecs); got != want {
		t.Errorf("compiled %d risk rules, want %d (a pattern was skipped)", got, want)
	}
}

func TestRiskLevelString(t *testing.T) {
	tests := map[RiskLevel]string{
		RiskNone:     "NONE",
		RiskInfo:     "INFO",
		RiskWarning:  "WARNING",
		RiskCritical: "CRITICAL",
	}
	for level, want := range tests {
		if got := level.String(); got != want {
			t.Errorf("RiskLevel(%d).String() = %q, want %q", int(level), got, want)
		}
	}
	if !(RiskCritical > RiskWarning && RiskWarning > RiskInfo && RiskInfo > RiskNone) {
		t.Error("risk levels must be ordered NONE < INFO < WARNING < CRITICAL")
	}
}

func TestClassifyLine(t *testing.T) {
	tests := []struct {
		line     string
		level    RiskLevel
		category string
	}{
		// CRITICAL / SECURITY
		{"+aaa new-model", RiskCritical, "AAA"},
		{"+tacacs-server host 10.1.1.1 key 7 xxx", RiskCritical, "AAA"},
		{"-radius-server host 10.1.1.2", RiskCritical, "AAA"},
		{"+username admin privilege 15 secret 5 $1$abc", RiskCritical, "CREDENTIALS"},
		{`+set system login user bob authentication encrypted-password "<REDACTED>"`, RiskCritical, "CREDENTIALS"},
		{"+enable secret 5 $1$xyz", RiskCritical, "CREDENTIALS"},
		{"+snmp-server community public RO", RiskCritical, "SNMP"},
		{"+set service snmp community <REDACTED> authorization ro", RiskCritical, "SNMP"},
		{"+ip access-list extended MGMT", RiskCritical, "ACL"},
		{"+ permit tcp any any eq 22", RiskCritical, "ACL"},
		{"+10 deny ip any any", RiskCritical, "ACL"},
		{"+set firewall name WAN-IN rule 10 action 'accept'", RiskCritical, "FIREWALL"},
		{"-set firewall group network-group PRIVATE network '10.0.0.0/8'", RiskCritical, "FIREWALL"},
		{"+set service ssh port '2222'", RiskCritical, "SSH"},
		{"+ip ssh version 2", RiskCritical, "SSH"},

		// WARNING / ROUTING, VLAN, INTERFACE
		{"+router bgp 65001", RiskWarning, "ROUTING"},
		{"+ neighbor 10.0.0.2 remote-as 65002", RiskWarning, "ROUTING"},
		{"+set protocols bgp 65001 neighbor 10.0.0.2 remote-as 65002", RiskWarning, "ROUTING"},
		{"+router ospf 1", RiskWarning, "ROUTING"},
		{"+set protocols ospf area 0 network '10.1.1.0/24'", RiskWarning, "ROUTING"},
		{"+ip route 0.0.0.0 0.0.0.0 10.1.1.1", RiskWarning, "ROUTING"},
		{"+set protocols static route 0.0.0.0/0 next-hop 10.1.1.1", RiskWarning, "ROUTING"},
		{"+set protocols static table 100 route 0.0.0.0/0 next-hop 10.253.0.253", RiskWarning, "ROUTING"},
		{"+ip route 10.0.0.0 255.0.0.0 10.1.1.1", RiskWarning, "ROUTING"},
		{"-set protocols static route 10.250.0.0/28 next-hop 10.130.243.1", RiskWarning, "ROUTING"},
		{"+vlan 100", RiskWarning, "VLAN"},
		{"+switchport trunk allowed vlan 10,20", RiskWarning, "VLAN"},
		{"+set interfaces ethernet eth1 vif 100 address '10.1.1.1/24'", RiskWarning, "VLAN"},
		{"+ shutdown", RiskWarning, "INTERFACE"},
		{"-no shutdown", RiskWarning, "INTERFACE"},
		{"+set interfaces ethernet eth0 disable", RiskWarning, "INTERFACE"},
		{"+set interfaces ethernet eth1 vif 10 disable", RiskWarning, "INTERFACE"},

		// INFO
		{"+ntp server 10.0.0.1", RiskInfo, "NTP"},
		{"+set service ntp server time1.vyos.net", RiskInfo, "NTP"},
		{"+set system host-name 'NHG-GW-01'", RiskInfo, "HOSTNAME"},
		{"+hostname core-sw01", RiskInfo, "HOSTNAME"},
		{"+set system login banner post-login 'CMC-Cloud'", RiskInfo, "BANNER"},
		{"+banner motd ^C Authorized only ^C", RiskInfo, "BANNER"},

		// description / remark text never escalates, even if it mentions
		// something security- or routing-related
		{"+set interfaces ethernet eth0 description 'to radius server'", RiskInfo, "DESCRIPTION"},
		{"+ description Uplink to OSPF core", RiskInfo, "DESCRIPTION"},
		{"+access-list 10 remark allow mgmt", RiskInfo, "DESCRIPTION"},
	}

	for _, tt := range tests {
		got, ok := ClassifyLine(tt.line)
		if !ok {
			t.Errorf("ClassifyLine(%q): not classified, want %s/%s", tt.line, tt.level, tt.category)
			continue
		}
		if got.Level != tt.level || got.Category != tt.category {
			t.Errorf("ClassifyLine(%q) = %s/%s (%s), want %s/%s", tt.line, got.Level, got.Category, got.Reason, tt.level, tt.category)
		}
		if got.Line != tt.line {
			t.Errorf("ClassifyLine(%q): Line = %q, want the original line", tt.line, got.Line)
		}
		if got.Reason == "" {
			t.Errorf("ClassifyLine(%q): empty Reason", tt.line)
		}
	}
}

func TestClassifyLineIgnoresUnremarkableAndNonDiffLines(t *testing.T) {
	lines := []string{
		"+interface eth1 address 1.1.1.1",
		"+set high-availability vrrp group LAN vrid '10'",
		"+set interfaces ethernet eth0 offload gro",
		"+set system config-management commit-revisions '100'",
		"+set service lldp",
		"+set interfaces tunnel tun0 mtu '1476'",
		"+set policy route-map REDIST-STATIC rule 10 action 'permit'",
		"+ip prefix-list X permit 10.0.0.0/8",
		"+route-map X permit 10",
		"-set nat source rule 100 destination group network-group 'MGMT-HO'",
		" context line that mentions aaa and firewall", // context, not +/-
		"",
		"+",
		"+   ",
	}
	for _, l := range lines {
		if f, ok := ClassifyLine(l); ok {
			t.Errorf("ClassifyLine(%q) = %s/%s, want not classified", l, f.Level, f.Category)
		}
	}
}

func TestClassifyLineDefaultRouteIsPrecise(t *testing.T) {
	// 10.0.0.0/8 and 172.16.0.0/12 are ordinary static routes, not defaults.
	f, ok := ClassifyLine("+set protocols static route 10.0.0.0/8 next-hop 1.1.1.1")
	if !ok || f.Reason != "static route changed" {
		t.Errorf("10.0.0.0/8 should classify as a plain static route, got %+v ok=%v", f, ok)
	}
	f, ok = ClassifyLine("+set protocols static route 0.0.0.0/0 next-hop 1.1.1.1")
	if !ok || f.Reason != "default route changed" {
		t.Errorf("0.0.0.0/0 should classify as a default route, got %+v ok=%v", f, ok)
	}
}

func TestAssessRiskHighestLevelWins(t *testing.T) {
	lines := []string{
		"+ntp server 1.1.1.1",
		"-set protocols static route 10.0.0.0/8 next-hop 1.1.1.1",
		"+ip access-list extended MGMT",
		"+ permit ip any any",
		"+interface eth1 address 1.1.1.1", // unremarkable
	}
	a := AssessRisk(lines)

	if a.Level != RiskCritical {
		t.Fatalf("Level = %s, want CRITICAL", a.Level)
	}
	if want := []string{"ACL"}; !reflect.DeepEqual(a.Categories, want) {
		t.Errorf("Categories = %v, want %v (only categories at the highest level)", a.Categories, want)
	}
	if len(a.Findings) != 4 {
		t.Errorf("len(Findings) = %d, want 4 (the unremarkable line is not a finding)", len(a.Findings))
	}
	if a.Count(RiskCritical) != 2 || a.Count(RiskWarning) != 1 || a.Count(RiskInfo) != 1 {
		t.Errorf("counts critical/warning/info = %d/%d/%d, want 2/1/1",
			a.Count(RiskCritical), a.Count(RiskWarning), a.Count(RiskInfo))
	}
	if got := a.Badge(); got != "CRITICAL: ACL" {
		t.Errorf("Badge = %q, want %q", got, "CRITICAL: ACL")
	}
}

func TestAssessRiskBadges(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		level RiskLevel
		badge string
	}{
		{"warning shows its category only", []string{"+set protocols static route 10.0.0.0/8 next-hop 1.1.1.1"}, RiskWarning, "ROUTING"},
		{"warning with two categories", []string{"+router bgp 65001", "+vlan 10"}, RiskWarning, "ROUTING,VLAN"},
		{"info", []string{"+ntp server 1.1.1.1"}, RiskInfo, "INFO"},
		{"critical with many categories is abbreviated", []string{"+aaa new-model", "+ip access-list extended X", "+snmp-server community public RO"}, RiskCritical, "CRITICAL: AAA,ACL+1"},
		{"nothing recognised", []string{"+interface eth1 address 1.1.1.1"}, RiskNone, ""},
		{"empty diff", nil, RiskNone, ""},
	}
	for _, tt := range tests {
		a := AssessRisk(tt.lines)
		if a.Level != tt.level {
			t.Errorf("%s: Level = %s, want %s", tt.name, a.Level, tt.level)
		}
		if got := a.Badge(); got != tt.badge {
			t.Errorf("%s: Badge = %q, want %q", tt.name, got, tt.badge)
		}
	}
}

func TestAssessRiskAddedAndRemovedBothCount(t *testing.T) {
	a := AssessRisk([]string{"-snmp-server community old RO", "+snmp-server community new RO"})
	if a.Level != RiskCritical || a.Count(RiskCritical) != 2 {
		t.Errorf("both the removed and the added SNMP line must count, got level=%s critical=%d", a.Level, a.Count(RiskCritical))
	}
}

func TestRiskAssessmentBadgeWithoutCategories(t *testing.T) {
	// Defensive: a hand-built assessment with no categories still renders.
	if got := (RiskAssessment{Level: RiskCritical}).Badge(); got != "CRITICAL" {
		t.Errorf("Badge = %q, want CRITICAL", got)
	}
	if got := (RiskAssessment{Level: RiskWarning}).Badge(); got != "WARNING" {
		t.Errorf("Badge = %q, want WARNING", got)
	}
}

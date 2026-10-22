// ==============================================================================
// Package backup implements high-risk change classification for config diffs.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package backup

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// RiskLevel ranks how much attention a configuration change deserves. The
// zero value (RiskNone) means "nothing noteworthy was recognised"; levels
// are ordered so the highest level in a diff is simply the numeric maximum.
type RiskLevel int

const (
	RiskNone     RiskLevel = iota // no recognised pattern
	RiskInfo                      // cosmetic / housekeeping: NTP, description, hostname, banner
	RiskWarning                   // operational impact: routing, VLANs, interface state
	RiskCritical                  // security impact: AAA, credentials, SNMP, ACLs, firewall, SSH
)

// String returns the upper-case label used in logs and reports.
func (l RiskLevel) String() string {
	switch l {
	case RiskInfo:
		return "INFO"
	case RiskWarning:
		return "WARNING"
	case RiskCritical:
		return "CRITICAL"
	default:
		return "NONE"
	}
}

// RiskFinding is one classified diff line.
type RiskFinding struct {
	Level    RiskLevel
	Category string // short group name, e.g. "ACL", "AAA", "ROUTING"
	Reason   string // human-readable explanation
	Line     string // the diff line, including its leading "+" or "-"
}

// RiskAssessment is the outcome of classifying a whole diff.
type RiskAssessment struct {
	Level      RiskLevel     // highest level among the findings
	Categories []string      // distinct categories at that highest level, sorted
	Findings   []RiskFinding // every classified line, in diff order
}

// Count returns how many findings carry exactly the given level.
func (a RiskAssessment) Count(level RiskLevel) int {
	n := 0
	for _, f := range a.Findings {
		if f.Level == level {
			n++
		}
	}
	return n
}

// Badge renders the short tag shown next to the diff counts, e.g.
// "CRITICAL: ACL" or "ROUTING" (warnings show their category only) or
// "INFO". It is empty when nothing was recognised.
func (a RiskAssessment) Badge() string {
	if a.Level == RiskNone {
		return ""
	}
	label := ""
	if len(a.Categories) > 0 {
		shown := a.Categories
		if len(shown) > 2 {
			shown = shown[:2]
		}
		label = strings.Join(shown, ",")
		if extra := len(a.Categories) - len(shown); extra > 0 {
			label += fmt.Sprintf("+%d", extra)
		}
	}
	switch a.Level {
	case RiskCritical:
		if label == "" {
			return "CRITICAL"
		}
		return "CRITICAL: " + label
	case RiskWarning:
		if label == "" {
			return "WARNING"
		}
		return label
	default:
		return "INFO"
	}
}

// riskSpec is the declarative form of one classification rule. Patterns are
// RE2 and are matched against the lower-cased, trimmed diff line with its
// leading "+"/"-" removed, so they work on Cisco-style text ("ip route ...")
// as well as VyOS/Junos "set ..." command dumps.
type riskSpec struct {
	level    RiskLevel
	category string
	reason   string
	pattern  string
}

// builtinRiskSpecs is evaluated in order and the FIRST match wins for a
// line. The order matters:
//   - description/remark lines come first so that a free-text description
//     that happens to mention "radius" or "ospf" is not escalated;
//   - critical rules precede warnings, warnings precede info.
var builtinRiskSpecs = []riskSpec{
	{RiskInfo, "DESCRIPTION", "description or remark text changed",
		`\b(description|remark)\b`},

	// ---- CRITICAL / SECURITY -------------------------------------------
	{RiskCritical, "AAA", "AAA / TACACS+ / RADIUS configuration changed",
		`\b(aaa|tacacs|radius)\b`},
	{RiskCritical, "CREDENTIALS", "local user or credential configuration changed",
		`^(no\s+)?(username|local-user)\s+\S+|^(no\s+)?enable\s+(secret|password)\b|^(no\s+)?(password|secret)\s|^set\s+system\s+login\s+user\b|^set\s+system\s+root-authentication\b|\b(encrypted-password|plaintext-password)\b|\bpassword-encryption\b|^config\s+system\s+admin\b`},
	{RiskCritical, "SNMP", "SNMP community or credential configuration changed",
		`\bsnmp\b.*\b(community|usm-user|v3|trap-target)\b|\bsnmp-(server|agent)\s+(user|group|usm-user|host)\b|^set\s+community-name\b`},
	{RiskCritical, "ACL", "access control list changed",
		`\baccess-(list|group|class)\b|^\d+\s+(permit|deny)\b|^(permit|deny)\b|\bacl\b|\btraffic-filter\b|^rule\s+\d+\s+(permit|deny)\b`},
	{RiskCritical, "FIREWALL", "firewall rule or policy changed",
		`^(set\s+|config\s+)?(firewall|zone-policy)\b|^set\s+security\s+(policies|zones|policy|nat|screen)\b|^config\s+firewall\b|^set\s+(srcintf|dstintf|srcaddr|dstaddr)\b|^set\s+action\s+(accept|deny|ipsec)\b|^security-(policy|zone)\b|^set\s+(rulebase|zone)\b`},
	{RiskCritical, "SSH", "SSH service, port or cipher configuration changed",
		`\bssh\b.*\b(port|ciphers?|macs?|kex|key-exchange|host-key-algorithms|disable-password-authentication|listen-address)\b|^(no\s+)?ip\s+ssh\b|^set\s+system\s+services\s+ssh\b|^(no\s+)?ssh\s+(server|key-exchange|cipher)`},

	// ---- WARNING / OPERATIONAL ----------------------------------------
	{RiskWarning, "ROUTING", "default route changed",
		`(^|[^0-9.])0\.0\.0\.0/0([^0-9]|$)|(^|[^0-9a-f:])::/0([^0-9]|$)|\b0\.0\.0\.0\s+0\.0\.0\.0\b|\broute-static\s+0\.0\.0\.0\s+0(\.0\.0\.0)?\b|^ip\s+default-gateway\b|^set\s+system\s+gateway-address\b|\bdefault-information\s+originate\b`},
	{RiskWarning, "ROUTING", "BGP neighbor or AS configuration changed",
		`\bbgp\b|\bremote-as\b|\bpeer-as\b`},
	{RiskWarning, "ROUTING", "OSPF configuration changed",
		`\bospf(v3)?\b|^network\s+\S+\s+\S+\s+area\s+\S+|^area\s+\S+\s+(stub|nssa|virtual-link|range|authentication|default-cost)\b`},
	{RiskWarning, "ROUTING", "static route changed",
		`^(no\s+)?(ip|ipv6)\s+route\b|^(no\s+)?ip\s+route-static\b|^set\s+protocols\s+static\b|^set\s+routing-options\s+(static|rib)\b|^config\s+router\s+static\b|^static-route\b`},
	{RiskWarning, "INTERFACE", "interface shutdown / no shutdown",
		`^(no\s+|undo\s+)?shutdown$|^set\s+interfaces\s+.*\bdisable\b`},
	{RiskWarning, "VLAN", "VLAN configuration changed",
		`\bvlans?\d*\b|\bvif\s+\d+\b`},

	// ---- INFO ------------------------------------------------------------
	{RiskInfo, "NTP", "NTP / clock configuration changed",
		`\bntp\b|\bclock\s+timezone\b|\btime-zone\b|\btimezone\b|\bclock\s+summer-time\b`},
	{RiskInfo, "HOSTNAME", "hostname or domain name changed",
		`^(no\s+)?(hostname|sysname)\b|\bhost-name\b|\bdomain-name\b|^ip\s+domain[- ]name\b`},
	{RiskInfo, "BANNER", "login banner or MOTD changed",
		`\b(banner|motd)\b|^header\s+(login|shell)\b`},
}

type riskRule struct {
	level    RiskLevel
	category string
	reason   string
	re       *regexp.Regexp
}

var (
	riskRulesOnce sync.Once
	riskRules     []riskRule
)

// compiledRiskRules compiles the built-in rules once. A pattern that fails
// to compile is skipped rather than panicking, so a typo can never take the
// whole run down; TestBuiltinRiskPatternsCompile guards against that.
func compiledRiskRules() []riskRule {
	riskRulesOnce.Do(func() {
		for _, s := range builtinRiskSpecs {
			re, err := regexp.Compile(s.pattern)
			if err != nil {
				continue
			}
			riskRules = append(riskRules, riskRule{level: s.level, category: s.category, reason: s.reason, re: re})
		}
	})
	return riskRules
}

// ClassifyLine classifies a single diff line. Only added ("+") and removed
// ("-") lines are considered; context lines and anything else report false.
func ClassifyLine(line string) (RiskFinding, bool) {
	if line == "" || (line[0] != '+' && line[0] != '-') {
		return RiskFinding{}, false
	}
	text := strings.ToLower(strings.TrimSpace(line[1:]))
	if text == "" {
		return RiskFinding{}, false
	}
	for _, r := range compiledRiskRules() {
		if r.re.MatchString(text) {
			return RiskFinding{Level: r.level, Category: r.category, Reason: r.reason, Line: line}, true
		}
	}
	return RiskFinding{}, false
}

// AssessRisk classifies every line of a diff (as produced by diffConfig:
// each line prefixed with "+" or "-") and returns the aggregate assessment.
// Lines that match no rule are simply not reported.
func AssessRisk(lines []string) RiskAssessment {
	var a RiskAssessment
	for _, l := range lines {
		f, ok := ClassifyLine(l)
		if !ok {
			continue
		}
		a.Findings = append(a.Findings, f)
		if f.Level > a.Level {
			a.Level = f.Level
		}
	}

	seen := make(map[string]bool)
	for _, f := range a.Findings {
		if f.Level == a.Level && !seen[f.Category] {
			seen[f.Category] = true
			a.Categories = append(a.Categories, f.Category)
		}
	}
	sort.Strings(a.Categories)
	return a
}

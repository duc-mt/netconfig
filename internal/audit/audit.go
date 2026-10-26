// ==============================================================================
// File name:     audit.go
// Description:   Baseline security / compliance audit of running configurations.
// License:       MIT
// ==============================================================================

// Package audit evaluates a device's running configuration against a set of
// baseline rules (NTP, syslog, Telnet, SNMP, session timeout, AAA) without
// changing anything. Rules are plain regular expressions applied to the
// configuration text, optionally restricted to indented blocks such as
// "line vty". The same rules can be loaded from a small YAML file
// (see ParseRules) or taken from the built-in baseline (Defaults).
package audit

import (
	"fmt"
	"regexp"
	"strings"

	"netops/internal/vendor"
)

// Status is the outcome of one check on one device.
type Status string

// Check outcomes.
const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	NA   Status = "N/A" // no rule covers this platform: not evaluated
)

// Severity ranks a rule.
const (
	SevHigh   = "high"
	SevMedium = "medium"
	SevLow    = "low"
)

// Rule is one baseline requirement for the platforms listed in Vendors.
// Several rules may share an ID (the same requirement spelled differently per
// platform); on a given device the first rule whose Vendors cover it applies.
type Rule struct {
	ID          string
	Title       string
	Severity    string
	Vendors     []string // canonical vendor names; empty = every platform
	Block       string   // optional regexp selecting block header lines ("^line vty")
	Require     string   // regexp: a line (inside the block, if any) must match
	Forbid      string   // regexp: no line (inside the block, if any) may match
	Remediation string

	block, require, forbid *regexp.Regexp
}

// Check is the evaluation of one rule on one device.
type Check struct {
	ID          string
	Title       string
	Severity    string
	Status      Status
	Evidence    string // the line that decided it, or why it failed
	Remediation string
}

// Compile validates the rules and prepares their regular expressions.
func Compile(rules []Rule) error {
	for i := range rules {
		r := &rules[i]
		if r.ID == "" {
			return fmt.Errorf("rule %d has no id", i+1)
		}
		if r.Title == "" {
			r.Title = r.ID
		}
		switch r.Severity {
		case "":
			r.Severity = SevMedium
		case SevHigh, SevMedium, SevLow:
		default:
			return fmt.Errorf("rule %q: severity %q must be high, medium or low", r.ID, r.Severity)
		}
		if r.Require == "" && r.Forbid == "" {
			return fmt.Errorf("rule %q needs a require or a forbid pattern", r.ID)
		}
		var err error
		for _, c := range []struct {
			src string
			dst **regexp.Regexp
			nm  string
		}{{r.Block, &r.block, "block"}, {r.Require, &r.require, "require"}, {r.Forbid, &r.forbid, "forbid"}} {
			*c.dst = nil
			if c.src == "" {
				continue
			}
			if *c.dst, err = regexp.Compile(c.src); err != nil {
				return fmt.Errorf("rule %q: bad %s pattern: %w", r.ID, c.nm, err)
			}
		}
		for j, v := range r.Vendors {
			p, ok := vendor.Lookup(strings.TrimSpace(v))
			if !ok {
				return fmt.Errorf("rule %q: unknown vendor %q (supported: %s)", r.ID, v, strings.Join(vendor.Names(), ", "))
			}
			r.Vendors[j] = p.Name
		}
	}
	return nil
}

func (r Rule) covers(vendorName string) bool {
	if len(r.Vendors) == 0 {
		return true
	}
	for _, v := range r.Vendors {
		if v == vendorName {
			return true
		}
	}
	return false
}

// ConfigCommand is the command that prints the configuration in the form the
// rules are written against. Junos is read in "display set" form, whose
// one-line-per-statement shape the built-in rules rely on.
func ConfigCommand(p *vendor.Profile) string {
	if p.Name == vendor.Junos {
		return "show configuration | display set | no-more"
	}
	return p.BackupCommand
}

// Evaluate checks config (as printed by ConfigCommand) against rules. There is
// one Check per distinct rule ID, in the order the IDs first appear.
func Evaluate(vendorName, config string, rules []Rule) []Check {
	lines := splitLines(config)
	var order []string
	byID := map[string][]Rule{}
	for _, r := range rules {
		if _, seen := byID[r.ID]; !seen {
			order = append(order, r.ID)
		}
		byID[r.ID] = append(byID[r.ID], r)
	}
	checks := make([]Check, 0, len(order))
	for _, id := range order {
		group := byID[id]
		chosen := -1
		for i, r := range group {
			if r.covers(vendorName) {
				chosen = i
				break
			}
		}
		if chosen < 0 {
			g := group[0]
			checks = append(checks, Check{ID: id, Title: g.Title, Severity: g.Severity, Status: NA,
				Evidence: "no rule for " + vendorName})
			continue
		}
		checks = append(checks, evaluateRule(group[chosen], lines))
	}
	return checks
}

func evaluateRule(r Rule, lines []string) Check {
	c := Check{ID: r.ID, Title: r.Title, Severity: r.Severity, Remediation: r.Remediation}
	pass := func(ev string) Check { c.Status, c.Evidence = Pass, ev; return c }
	fail := func(ev string) Check { c.Status, c.Evidence = Fail, ev; return c }

	scopes := [][]string{lines}
	var headers []string
	if r.block != nil {
		scopes, headers = blocks(lines, r.block)
		if len(scopes) == 0 {
			if r.require != nil {
				return fail("no configuration block matches " + r.Block)
			}
			return pass("no " + r.Block + " block present")
		}
	}
	evidence := ""
	for i, body := range scopes {
		where := ""
		if headers != nil {
			where = fmt.Sprintf("in %q: ", headers[i])
		}
		if r.forbid != nil {
			if l, ok := firstMatch(body, r.forbid); ok {
				return fail(where + "found " + l)
			}
		}
		if r.require != nil {
			l, ok := firstMatch(body, r.require)
			if !ok {
				return fail(where + "no line matches " + r.Require)
			}
			if evidence == "" {
				evidence = l
			}
		}
	}
	if evidence == "" {
		evidence = "not present"
	}
	return pass(evidence)
}

func splitLines(config string) []string {
	var out []string
	for _, l := range strings.Split(config, "\n") {
		out = append(out, strings.TrimRight(l, "\r"))
	}
	return out
}

func firstMatch(lines []string, re *regexp.Regexp) (string, bool) {
	for _, l := range lines {
		if re.MatchString(l) {
			return strings.TrimSpace(l), true
		}
	}
	return "", false
}

// blocks returns the body of every block whose header line matches re, plus
// the headers. A block is the header followed by the lines indented deeper
// than it; it ends at the next line at column zero. Blank lines do not end it.
func blocks(lines []string, re *regexp.Regexp) (bodies [][]string, headers []string) {
	for i := 0; i < len(lines); i++ {
		if lines[i] == "" || lines[i][0] == ' ' || lines[i][0] == '\t' || !re.MatchString(lines[i]) {
			continue
		}
		var body []string
		j := i + 1
		for ; j < len(lines); j++ {
			if lines[j] != "" && lines[j][0] != ' ' && lines[j][0] != '\t' {
				break
			}
			body = append(body, lines[j])
		}
		bodies = append(bodies, body)
		headers = append(headers, strings.TrimSpace(lines[i]))
		i = j - 1
	}
	return bodies, headers
}

// Summary counts outcomes across checks.
type Summary struct{ Pass, Fail, NA int }

// Summarize tallies checks.
func Summarize(checks []Check) Summary {
	var s Summary
	for _, c := range checks {
		switch c.Status {
		case Pass:
			s.Pass++
		case Fail:
			s.Fail++
		default:
			s.NA++
		}
	}
	return s
}

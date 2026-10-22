// ==============================================================================
// Package compliance implements golden-config drift detection.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
// It checks device configurations against "golden" baselines: lists of
// lines every device of a platform must (or must not) carry, such as
// mandatory syslog and NTP servers, the standard login banner or password
// encryption.
//
// Baselines are plain text, one rule per line:
//
//	# comment                        ("!" and "//" also start a comment)
//	set service ntp server time1.vyos.net     required line (exact match)
//	re: ^set system syslog host\s+10\.         required: some line matches
//	not: set service telnet                    forbidden line (exact match)
//	not-re: ^set service snmp community public forbidden: no line matches
//
// Exact matching ignores indentation, runs of whitespace and quote
// characters, so "set system host-name 'sw1'" equals "set system host-name sw1".
// Checking is line based and context free: it does not understand
// configuration blocks, which keeps it vendor neutral.
//
// Baselines load from a directory of "<vendor>.golden" files (plus an
// optional "common.golden" that applies to every device) and/or from a
// single rules file whose "[vendor]" section headers pick the platform
// (lines before the first header are common rules).
package compliance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"netconfig/internal/vendor"
)

// commonSection holds the rules that apply to every vendor.
const commonSection = "common"

// maxFoundLines caps how many offending/near-miss lines one drift records.
const maxFoundLines = 3

// Kind classifies one compliance drift.
type Kind string

const (
	KindMissing   Kind = "MISSING"   // a required line is absent
	KindMismatch  Kind = "MISMATCH"  // a required line is absent but a line with the same key and a different value exists
	KindForbidden Kind = "FORBIDDEN" // a forbidden line is present
)

// Drift is one deviation from the golden baseline.
type Drift struct {
	Kind  Kind
	Rule  string   // the rule as written in the baseline
	Found []string // near-miss lines (mismatch) or offending lines (forbidden)
}

// String renders the drift as a one-line operator message.
func (d Drift) String() string {
	switch d.Kind {
	case KindMismatch:
		return fmt.Sprintf("mismatch: expected %q, found %s", d.Rule, quoteAll(d.Found))
	case KindForbidden:
		return fmt.Sprintf("forbidden: %q is present (%s)", d.Rule, quoteAll(d.Found))
	default:
		return fmt.Sprintf("missing: %q", d.Rule)
	}
}

func quoteAll(lines []string) string {
	q := make([]string, 0, len(lines))
	for _, l := range lines {
		q = append(q, fmt.Sprintf("%q", l))
	}
	return strings.Join(q, ", ")
}

// Report is the outcome of checking one device's configuration.
type Report struct {
	Checked bool    // false when no baseline applies to the device
	Rules   int     // number of rules evaluated
	Drifts  []Drift // deviations, in rule order
}

// Compliant reports whether a baseline applied and nothing drifted.
func (r Report) Compliant() bool { return r.Checked && len(r.Drifts) == 0 }

// Summary renders "COMPLIANT", "1 DRIFT" or "N DRIFTS"; empty when the
// device was not checked.
func (r Report) Summary() string {
	switch {
	case !r.Checked:
		return ""
	case len(r.Drifts) == 0:
		return "COMPLIANT"
	case len(r.Drifts) == 1:
		return "1 DRIFT"
	default:
		return fmt.Sprintf("%d DRIFTS", len(r.Drifts))
	}
}

// DriftMessages returns the drifts as display strings.
func (r Report) DriftMessages() []string {
	out := make([]string, 0, len(r.Drifts))
	for _, d := range r.Drifts {
		out = append(out, d.String())
	}
	return out
}

type ruleKind int

const (
	ruleRequire ruleKind = iota
	ruleRequireRegex
	ruleForbid
	ruleForbidRegex
)

// Rule is one baseline requirement.
type Rule struct {
	kind ruleKind
	Text string         // the line or pattern as written (without its prefix)
	norm string         // normalised form of Text, for the exact kinds
	re   *regexp.Regexp // compiled pattern, for the regex kinds
}

// String renders the rule the way it is written in a baseline file.
func (r Rule) String() string {
	switch r.kind {
	case ruleRequireRegex:
		return "re: " + r.Text
	case ruleForbid:
		return "not: " + r.Text
	case ruleForbidRegex:
		return "not-re: " + r.Text
	default:
		return r.Text
	}
}

// Baseline is a set of rules grouped by section: "common" or a canonical
// vendor key from the vendor package.
type Baseline struct {
	sections map[string][]Rule
}

// New returns an empty baseline.
func New() *Baseline {
	return &Baseline{sections: make(map[string][]Rule)}
}

// Add appends rules to a section. The section is a vendor name or alias
// ("cisco" resolves to "cisco_ios") or "common"/"all".
func (b *Baseline) Add(section string, rules ...Rule) error {
	key, err := sectionKey(section)
	if err != nil {
		return err
	}
	b.sections[key] = append(b.sections[key], rules...)
	return nil
}

// Len returns the total number of rules across all sections.
func (b *Baseline) Len() int {
	if b == nil {
		return 0
	}
	n := 0
	for _, rules := range b.sections {
		n += len(rules)
	}
	return n
}

// Applies reports whether at least one rule applies to the vendor.
func (b *Baseline) Applies(vendorName string) bool {
	return len(b.rulesFor(vendorName)) > 0
}

func (b *Baseline) rulesFor(vendorName string) []Rule {
	if b == nil {
		return nil
	}
	var rules []Rule
	rules = append(rules, b.sections[commonSection]...)
	if key, ok := canonicalKey(vendorName); ok {
		rules = append(rules, b.sections[key]...)
	}
	return rules
}

// sectionKey maps a section or file name onto its canonical key.
func sectionKey(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == commonSection || n == "all" {
		return commonSection, nil
	}
	if key, ok := canonicalKey(n); ok {
		return key, nil
	}
	return "", fmt.Errorf("unknown vendor %q", name)
}

// normalize makes an exact-match comparison insensitive to indentation,
// repeated whitespace and quote characters.
func normalize(s string) string {
	s = strings.NewReplacer("'", "", "\"", "").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

// cleanLines splits configuration text into trimmed, non-empty lines.
func cleanLines(config string) []string {
	var out []string
	for _, l := range strings.Split(config, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ParseRule parses one non-comment baseline line.
func ParseRule(line string) (Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Rule{}, errors.New("empty rule")
	}
	switch {
	case strings.HasPrefix(line, "not-re:"):
		return newRegexRule(ruleForbidRegex, strings.TrimSpace(strings.TrimPrefix(line, "not-re:")))
	case strings.HasPrefix(line, "re:"):
		return newRegexRule(ruleRequireRegex, strings.TrimSpace(strings.TrimPrefix(line, "re:")))
	case strings.HasPrefix(line, "not:"):
		text := strings.TrimSpace(strings.TrimPrefix(line, "not:"))
		if text == "" {
			return Rule{}, fmt.Errorf("empty rule after %q", "not:")
		}
		return Rule{kind: ruleForbid, Text: text, norm: normalize(text)}, nil
	default:
		return Rule{kind: ruleRequire, Text: line, norm: normalize(line)}, nil
	}
}

func newRegexRule(kind ruleKind, pattern string) (Rule, error) {
	if pattern == "" {
		return Rule{}, errors.New("empty regular expression")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("bad regular expression %q: %w", pattern, err)
	}
	return Rule{kind: kind, Text: pattern, re: re}, nil
}

func isCommentLine(line string) bool {
	return strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "//")
}

// ParseRules parses baseline text into rules grouped by canonical section.
// Lines before the first "[section]" header go to defaultSection. A bad
// line or an unknown section is reported in the error slice and skipped;
// parsing always continues so one typo cannot discard the whole baseline.
func ParseRules(text, defaultSection string) (map[string][]Rule, []error) {
	sections := make(map[string][]Rule)
	var errs []error

	current, err := sectionKey(defaultSection)
	if err != nil {
		return sections, []error{err}
	}
	skipping := false

	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || isCommentLine(line) {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			key, err := sectionKey(name)
			if err != nil {
				errs = append(errs, fmt.Errorf("line %d: section [%s]: %w", i+1, name, err))
				skipping = true
				continue
			}
			current = key
			skipping = false
			continue
		}
		if skipping {
			continue
		}
		rule, err := ParseRule(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", i+1, err))
			continue
		}
		sections[current] = append(sections[current], rule)
	}
	return sections, errs
}

// Load builds a baseline from a directory of "<vendor>.golden" files
// and/or a single rules file; either argument may be empty. Unreadable
// files, unknown vendors and malformed rules are returned as errors and
// skipped. The returned baseline is nil when no rule could be loaded.
func Load(goldenDir, rulesFile string) (*Baseline, []error) {
	b := New()
	var errs []error

	if goldenDir != "" {
		entries, err := os.ReadDir(goldenDir)
		if err != nil {
			errs = append(errs, fmt.Errorf("golden dir %q: %w", goldenDir, err))
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(name), ".golden") {
				continue
			}
			stem := name[:len(name)-len(".golden")]
			section, err := sectionKey(stem)
			if err != nil {
				errs = append(errs, fmt.Errorf("golden file %q: %w", name, err))
				continue
			}
			data, err := os.ReadFile(filepath.Join(goldenDir, name))
			if err != nil {
				errs = append(errs, fmt.Errorf("golden file %q: %w", name, err))
				continue
			}
			parsed, perrs := ParseRules(string(data), section)
			for _, pe := range perrs {
				errs = append(errs, fmt.Errorf("golden file %q: %w", name, pe))
			}
			b.merge(parsed)
		}
	}

	if rulesFile != "" {
		data, err := os.ReadFile(rulesFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("compliance rules %q: %w", rulesFile, err))
		} else {
			parsed, perrs := ParseRules(string(data), commonSection)
			for _, pe := range perrs {
				errs = append(errs, fmt.Errorf("compliance rules %q: %w", rulesFile, pe))
			}
			b.merge(parsed)
		}
	}

	if b.Len() == 0 {
		return nil, errs
	}
	return b, errs
}

func (b *Baseline) merge(sections map[string][]Rule) {
	for key, rules := range sections {
		b.sections[key] = append(b.sections[key], rules...)
	}
}

// Check evaluates the configuration against every rule that applies to the
// vendor (common rules first, then the vendor's own). When no rule applies
// the report has Checked == false. A nil baseline is valid and checks
// nothing.
func (b *Baseline) Check(vendorName, config string) Report {
	rules := b.rulesFor(vendorName)
	if len(rules) == 0 {
		return Report{}
	}

	lines := cleanLines(config)
	norms := make([]string, len(lines))
	present := make(map[string]bool, len(lines))
	for i, l := range lines {
		norms[i] = normalize(l)
		present[norms[i]] = true
	}

	rep := Report{Checked: true, Rules: len(rules)}
	for _, r := range rules {
		switch r.kind {
		case ruleRequire:
			if present[r.norm] {
				continue
			}
			if near := nearMisses(r.norm, lines, norms); len(near) > 0 {
				rep.Drifts = append(rep.Drifts, Drift{Kind: KindMismatch, Rule: r.Text, Found: near})
			} else {
				rep.Drifts = append(rep.Drifts, Drift{Kind: KindMissing, Rule: r.Text})
			}
		case ruleRequireRegex:
			if !anyMatch(r.re, lines) {
				rep.Drifts = append(rep.Drifts, Drift{Kind: KindMissing, Rule: r.String()})
			}
		case ruleForbid:
			if present[r.norm] {
				rep.Drifts = append(rep.Drifts, Drift{Kind: KindForbidden, Rule: r.Text, Found: []string{r.Text}})
			}
		case ruleForbidRegex:
			if hits := matches(r.re, lines); len(hits) > 0 {
				rep.Drifts = append(rep.Drifts, Drift{Kind: KindForbidden, Rule: r.String(), Found: hits})
			}
		}
	}
	return rep
}

func anyMatch(re *regexp.Regexp, lines []string) bool {
	for _, l := range lines {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

func matches(re *regexp.Regexp, lines []string) []string {
	var hits []string
	for _, l := range lines {
		if re.MatchString(l) {
			hits = append(hits, l)
			if len(hits) == maxFoundLines {
				break
			}
		}
	}
	return hits
}

// nearMisses finds configuration lines that share every token of the
// required line except the last one: same key, different value (for
// example "set service ssh port 22" required, "... port 2222" present).
func nearMisses(requiredNorm string, lines, norms []string) []string {
	tokens := strings.Fields(requiredNorm)
	if len(tokens) < 2 {
		return nil
	}
	prefix := strings.Join(tokens[:len(tokens)-1], " ") + " "

	var found []string
	for i, n := range norms {
		if n != requiredNorm && strings.HasPrefix(n, prefix) {
			found = append(found, lines[i])
			if len(found) == maxFoundLines {
				break
			}
		}
	}
	return found
}

// canonicalKey resolves a vendor name or alias ("cisco_ios", "ios", "cisco")
// to the canonical name of its netconfig vendor profile.
func canonicalKey(name string) (string, bool) {
	p, ok := vendor.Lookup(name)
	if !ok {
		return "", false
	}
	return p.Name, true
}

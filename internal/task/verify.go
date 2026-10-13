package task

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netconfig/internal/inventory"
	"netconfig/internal/vendor"
)

// MatchKind is how a verification condition inspects command output.
type MatchKind int

// Condition kinds.
const (
	MatchContains MatchKind = iota
	MatchNotContains
	MatchRegex
)

// Condition is one assertion on a check's output.
type Condition struct {
	Kind    MatchKind
	Pattern string
	re      *regexp.Regexp // MatchRegex only
}

// VerifyRule is one post-change health check: a read-only command and the
// conditions its output must satisfy.
type VerifyRule struct {
	Command  string
	Conds    []Condition
	Vendors  []string      // canonical vendor names; empty = every vendor
	Hosts    []string      // hostname globs; empty = every host
	Retries  int           // extra attempts while the conditions do not hold yet
	Interval time.Duration // wait between attempts
	Line     int           // source line, for messages
}

// defaultVerifyInterval is used when a rule retries without an interval.
const defaultVerifyInterval = 3 * time.Second

// maxVerifyRetries bounds retries so a typo cannot stall a device for hours.
const maxVerifyRetries = 30

// unsafeVerifyVerbs are first words that change state; verification commands
// must be read-only.
var unsafeVerifyVerbs = map[string]bool{
	"configure": true, "conf": true, "config": true, "reload": true, "reboot": true, "erase": true,
	"write": true, "copy": true, "delete": true, "no": true, "undo": true, "set": true, "unset": true,
	"commit": true, "clear": true, "reset": true, "shutdown": true, "format": true, "rollback": true,
}

// ParseVerifyRules parses the verification DSL:
//
//	verify show ip bgp summary
//	  expect: Established            # alias of contains
//	  not-contains: Idle
//	  regex: ^10\.0\.0\.2\s+4\s+65001
//	  retries: 5                     # optional: allow the network time to converge
//	  interval: 10s                  # optional: wait between attempts (default 3s)
//	  vendors: cisco, arista         # optional: only these platforms
//	  hosts: edge-*                  # optional: only these hostnames (globs)
//
// Blank lines and lines starting with '#' or '!' are ignored. Values may be
// wrapped in single or double quotes.
func ParseVerifyRules(text string) ([]VerifyRule, error) {
	var rules []VerifyRule
	var cur *VerifyRule
	flush := func() error {
		if cur == nil {
			return nil
		}
		if len(cur.Conds) == 0 {
			return fmt.Errorf("line %d: verify %q has no expect/contains/not-contains/regex condition", cur.Line, cur.Command)
		}
		if cur.Retries > 0 && cur.Interval == 0 {
			cur.Interval = defaultVerifyInterval
		}
		rules = append(rules, *cur)
		cur = nil
		return nil
	}
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		if m := reVerifyHeader.FindStringSubmatch(line); m != nil {
			if err := flush(); err != nil {
				return nil, err
			}
			cmd := strings.TrimSpace(m[1])
			if verb := strings.ToLower(strings.Fields(cmd + " ")[0]); unsafeVerifyVerbs[verb] {
				return nil, fmt.Errorf("line %d: verify command %q is not read-only (%q is not allowed)", n, cmd, verb)
			}
			cur = &VerifyRule{Command: cmd, Line: n}
			continue
		}
		if cur == nil {
			return nil, fmt.Errorf("line %d: expected \"verify <command>\", got %q", n, line)
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: expected \"key: value\", got %q", n, line)
		}
		key, val = strings.ToLower(strings.TrimSpace(key)), unquote(strings.TrimSpace(val))
		if err := cur.set(key, val); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return rules, nil
}

var reVerifyHeader = regexp.MustCompile(`(?i)^verify:?\s+(\S.*)$`)

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func (r *VerifyRule) set(key, val string) error {
	switch key {
	case "expect", "contains":
		r.Conds = append(r.Conds, Condition{Kind: MatchContains, Pattern: val})
	case "not-contains", "not_contains":
		r.Conds = append(r.Conds, Condition{Kind: MatchNotContains, Pattern: val})
	case "regex":
		re, err := regexp.Compile(val)
		if err != nil {
			return fmt.Errorf("invalid regex %q: %w", val, err)
		}
		r.Conds = append(r.Conds, Condition{Kind: MatchRegex, Pattern: val, re: re})
	case "retries":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > maxVerifyRetries {
			return fmt.Errorf("retries must be 0-%d, got %q", maxVerifyRetries, val)
		}
		r.Retries = n
	case "interval":
		d, err := time.ParseDuration(val)
		if err != nil {
			secs, serr := strconv.Atoi(val) // bare number = seconds
			if serr != nil {
				return fmt.Errorf("invalid interval %q (use e.g. 5s)", val)
			}
			d = time.Duration(secs) * time.Second
		}
		if d < 0 {
			return fmt.Errorf("interval must not be negative")
		}
		r.Interval = d
	case "vendors", "vendor":
		for _, v := range splitList(val) {
			p, ok := vendor.Lookup(v)
			if !ok {
				return fmt.Errorf("unknown vendor %q", v)
			}
			r.Vendors = append(r.Vendors, p.Name)
		}
	case "hosts", "host":
		for _, g := range splitList(val) {
			if _, err := path.Match(g, ""); err != nil {
				return fmt.Errorf("invalid host pattern %q: %w", g, err)
			}
			r.Hosts = append(r.Hosts, strings.ToLower(g))
		}
	default:
		return fmt.Errorf("unknown key %q (want expect, contains, not-contains, regex, retries, interval, vendors, hosts)", key)
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ReadVerifyFile loads rules from a -verify-file.
func ReadVerifyFile(file string) ([]VerifyRule, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read verify file: %w", err)
	}
	rules, err := ParseVerifyRules(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return rules, nil
}

// ParseInlineVerify extracts verification blocks embedded in a commands file
// or template as comment lines starting with "!@" or "#@". Such lines are
// comments to the commands parser, so they are never sent to a device:
//
//	!@verify show ip bgp summary
//	!@  expect: Established
func ParseInlineVerify(text string) ([]VerifyRule, error) {
	var b strings.Builder
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "!@") || strings.HasPrefix(line, "#@") {
			b.WriteString(line[2:])
		}
		b.WriteByte('\n') // keep line numbers aligned with the source file
	}
	return ParseVerifyRules(b.String())
}

// ReadInlineVerify loads inline verification blocks from a commands or
// template file.
func ReadInlineVerify(file string) ([]VerifyRule, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	rules, err := ParseInlineVerify(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: inline verify: %w", file, err)
	}
	return rules, nil
}

// AppliesTo reports whether the rule targets this device.
func (r VerifyRule) AppliesTo(d inventory.Device, p *vendor.Profile) bool {
	if len(r.Vendors) > 0 {
		ok := false
		for _, v := range r.Vendors {
			if p != nil && v == p.Name {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.Hosts) > 0 {
		ok := false
		for _, g := range r.Hosts {
			if m, _ := path.Match(g, strings.ToLower(d.Hostname)); m {
				ok = true
			}
		}
		return ok
	}
	return true
}

// Evaluate returns one message per failed condition; empty means the output
// satisfies the rule.
func (r VerifyRule) Evaluate(output string) []string {
	var fails []string
	for _, c := range r.Conds {
		switch c.Kind {
		case MatchContains:
			if !strings.Contains(output, c.Pattern) {
				fails = append(fails, fmt.Sprintf("expected output to contain %q", c.Pattern))
			}
		case MatchNotContains:
			if strings.Contains(output, c.Pattern) {
				fails = append(fails, fmt.Sprintf("output must not contain %q", c.Pattern))
			}
		case MatchRegex:
			if c.re == nil || !c.re.MatchString(output) {
				fails = append(fails, fmt.Sprintf("expected output to match /%s/", c.Pattern))
			}
		}
	}
	return fails
}

// CheckConfirmWindow reports an error when a commit-confirm window is too
// short for the verification retries to finish and still leave time to
// confirm: the device would roll back a change that was in fact fine.
func CheckConfirmWindow(rules []VerifyRule, minutes int) error {
	if minutes <= 0 {
		return nil
	}
	window := time.Duration(minutes) * time.Minute
	if need := VerifyBudget(rules) + confirmMargin; need >= window {
		return fmt.Errorf("-commit-confirm %d is too short: verification retries can take up to %s and %s must remain to confirm",
			minutes, VerifyBudget(rules).Round(time.Second), confirmMargin)
	}
	return nil
}

// VerifyBudget is the worst-case time spent waiting between retries for the
// rules of one device, used to check that a commit-confirm window is long
// enough for verification to finish before the device rolls back by itself.
func VerifyBudget(rules []VerifyRule) time.Duration {
	var total time.Duration
	for _, r := range rules {
		total += time.Duration(r.Retries) * r.Interval
	}
	return total
}

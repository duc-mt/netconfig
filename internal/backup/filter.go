// ==============================================================================
// Package backup implements the volatile-line filter used for semantic diffs.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package backup

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"netconfig/internal/vendor"
)

// Vendor families the built-in volatile rules are scoped to. Keys are the
// canonical vendor profile names (see canonicalKey).
var (
	// bangCommentVendors emit IOS-style "!" comment headers and share the
	// same auto-generated clock/size noise.
	bangCommentVendors = []string{"cisco", "cisco_sb", "cisco_asa", "arista", "huawei", "aruba", "ruijie"}

	// hashCommentVendors are Linux-like platforms whose dumps can carry
	// "# ..." banners with dates or uptime.
	hashCommentVendors = []string{"vyos", "pfsense", "checkpoint"}
)

// volatileSpec is the declarative form of one built-in rule. A nil vendors
// slice means "every vendor".
type volatileSpec struct {
	name    string
	vendors []string
	pattern string
}

// builtinVolatileSpecs lists the lines that change on every poll (or every
// commit) without the configuration itself having changed. Every pattern is
// matched against a single line and a match drops the whole line from the
// comparison. All patterns are RE2 and anchored on the comment syntax of the
// platform so they cannot swallow real configuration.
var builtinVolatileSpecs = []volatileSpec{
	// Cisco IOS / IOS-XE / Small Business / ASA, Arista EOS, Huawei VRP, Aruba, Ruijie.
	{"ios-last-change", bangCommentVendors, `(?i)^\s*!\s*last configuration change at\b`},
	{"ios-nvram-updated", bangCommentVendors, `(?i)^\s*!\s*nvram config last updated at\b`},
	{"ios-no-change-since-restart", bangCommentVendors, `(?i)^\s*!\s*no configuration change since last restart\b`},
	{"bang-time", bangCommentVendors, `(?i)^\s*!\s*time\s*:`},
	{"ios-config-size", bangCommentVendors, `(?i)^\s*current configuration\s*:\s*\d+\s*bytes\b`},
	{"ios-building-config", bangCommentVendors, `(?i)^\s*building configuration\.\.\.\s*$`},
	{"ntp-clock-period", bangCommentVendors, `(?i)^\s*ntp clock-period\s+\d+\s*$`},
	{"huawei-last-updated", []string{"huawei"}, `(?i)^\s*!\s*last configuration was (updated|saved) at\b`},

	// Cisco ASA: the ":" comment header carries the user and time of the
	// "show running-config" ("Written by enable_15 at 09:41:07.589 UTC ...").
	{"asa-written-by", []string{"cisco_asa"}, `(?i)^\s*:\s*written by\s+\S+\s+at\b`},

	// Juniper Junos.
	{"junos-last-changed", []string{"junos"}, `(?i)^\s*##\s*last changed\s*:`},
	{"junos-last-commit", []string{"junos"}, `(?i)^\s*##\s*last commit\s*:`},

	// VyOS (both the /* */ and the // flavours of the version trailer).
	{"vyos-c-comment-trailer", []string{"vyos"}, `(?i)^\s*/\*\s*(warning: do not remove|=== vyatta-config-version|release version)`},
	{"vyos-slash-trailer", []string{"vyos"}, `(?i)^\s*//\s*(warning:|vyos-config-version|release version)`},

	// Linux-like platforms: dynamic comment banners and uptime stamps.
	{"hash-banner", hashCommentVendors, `(?i)^\s*#\s*(generated|exported|created|last (login|updated|saved|modified|changed|commit)|date|timestamp|uptime)\b`},
}

type volatileRule struct {
	name    string
	vendors map[string]bool // nil means the rule applies to every vendor
	re      *regexp.Regexp
}

func (r volatileRule) appliesTo(vendorKey string) bool {
	if r.vendors == nil {
		return true
	}
	return r.vendors[vendorKey]
}

// VolatileFilter removes volatile lines (timestamps, clock stamps, size
// counters, uptime banners) from a configuration so that two dumps can be
// compared on their meaningful content only.
//
// A nil *VolatileFilter is valid and leaves configurations untouched, so
// callers never have to nil-check before using it.
type VolatileFilter struct {
	rules []volatileRule
}

// DefaultVolatileFilter returns a filter carrying only the built-in rules.
// A built-in pattern that fails to compile is skipped instead of panicking;
// TestBuiltinVolatilePatternsCompile guards against that ever happening.
func DefaultVolatileFilter() *VolatileFilter {
	f := &VolatileFilter{}
	for _, spec := range builtinVolatileSpecs {
		re, err := regexp.Compile(spec.pattern)
		if err != nil {
			continue
		}
		rule := volatileRule{name: spec.name, re: re}
		if spec.vendors != nil {
			rule.vendors = make(map[string]bool, len(spec.vendors))
			for _, v := range spec.vendors {
				rule.vendors[v] = true
			}
		}
		f.rules = append(f.rules, rule)
	}
	return f
}

var (
	sharedFilterOnce sync.Once
	sharedFilter     *VolatileFilter
)

// sharedDefaultFilter returns a process-wide filter with the built-in rules,
// built once. VolatileFilter is read-only after construction, so sharing it
// between the per-device goroutines is safe.
func sharedDefaultFilter() *VolatileFilter {
	sharedFilterOnce.Do(func() { sharedFilter = DefaultVolatileFilter() })
	return sharedFilter
}

// NewVolatileFilter returns the built-in rules plus user-supplied extra
// regular expressions (applied to every vendor). Blank entries and entries
// starting with "#" are ignored. A pattern that does not compile is skipped
// and reported in the returned error slice -- one bad pattern never disables
// the filter as a whole.
func NewVolatileFilter(extraPatterns []string) (*VolatileFilter, []error) {
	f := DefaultVolatileFilter()
	var errs []error
	for _, p := range extraPatterns {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("volatile pattern %q: %w", p, err))
			continue
		}
		f.rules = append(f.rules, volatileRule{name: "custom:" + p, re: re})
	}
	return f, errs
}

// LoadVolatilePatterns reads extra volatile-line regular expressions from a
// text file: one RE2 pattern per line, "#" starts a comment line.
func LoadVolatilePatterns(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var patterns []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return patterns, nil
}

// Len reports how many rules (built-in plus custom) the filter holds.
func (f *VolatileFilter) Len() int {
	if f == nil {
		return 0
	}
	return len(f.rules)
}

// activeRules returns the rules that apply to the given vendor name or alias.
// An unknown vendor still gets the vendor-agnostic (custom) rules.
func (f *VolatileFilter) activeRules(vendorName string) []volatileRule {
	key, _ := canonicalKey(vendorName)
	active := make([]volatileRule, 0, len(f.rules))
	for _, r := range f.rules {
		if r.appliesTo(key) {
			active = append(active, r)
		}
	}
	return active
}

func matchesAnyRule(rules []volatileRule, line string) bool {
	for _, r := range rules {
		if r.re.MatchString(line) {
			return true
		}
	}
	return false
}

// IsVolatile reports whether line would be dropped for the given vendor.
func (f *VolatileFilter) IsVolatile(vendorName, line string) bool {
	if f == nil || len(f.rules) == 0 {
		return false
	}
	return matchesAnyRule(f.activeRules(vendorName), strings.TrimRight(line, "\r"))
}

// Apply returns config with every volatile line removed (trailing "\r" is
// also trimmed from the surviving lines). The input is never modified, and
// the configuration saved to disk is never passed through here -- the
// filtered text exists only for before/after comparison.
func (f *VolatileFilter) Apply(vendorName, config string) string {
	if f == nil || len(f.rules) == 0 {
		return config
	}
	active := f.activeRules(vendorName)
	if len(active) == 0 {
		return config
	}
	lines := strings.Split(config, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if matchesAnyRule(active, line) {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
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

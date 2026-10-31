// ==============================================================================
// File name:     limit.go
// Description:   The -limit pattern syntax for callers that select hostnames
//                from something other than an inventory (stored log events).
// License:       MIT
// ==============================================================================

package inventory

import (
	"fmt"
	"path"
	"strings"
)

// ParseLimit splits a -limit value ("core-*,@dc1") into its patterns and checks
// their glob syntax, the same syntax Filter applies to an inventory. An empty
// value yields no patterns.
func ParseLimit(limit string) ([]string, error) {
	var pats []string
	for _, p := range strings.Split(limit, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := path.Match(strings.TrimPrefix(p, "@"), ""); err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		pats = append(pats, p)
	}
	return pats, nil
}

// MatchesAny reports whether d is selected by any of the patterns from
// ParseLimit; no patterns selects everything. Unlike Filter it does not fail
// when a pattern matches nothing, because it is applied to a stream of records
// rather than to the inventory a typo should be caught against.
func MatchesAny(d Device, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if matches(d, p) {
			return true
		}
	}
	return false
}

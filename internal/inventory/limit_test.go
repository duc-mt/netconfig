// ==============================================================================
// File name:     limit_test.go
// Description:   Tests for the shared -limit pattern helpers.
// License:       MIT
// ==============================================================================

package inventory

import (
	"slices"
	"testing"
)

func TestParseLimit(t *testing.T) {
	got, err := ParseLimit(" core-* , @dc1,,edge-1 ")
	if err != nil || !slices.Equal(got, []string{"core-*", "@dc1", "edge-1"}) {
		t.Fatalf("ParseLimit = %v, %v", got, err)
	}
	if got, err := ParseLimit(""); err != nil || len(got) != 0 {
		t.Errorf("an empty limit has no patterns, got %v, %v", got, err)
	}
	if _, err := ParseLimit("bad[glob"); err == nil {
		t.Error("a malformed glob must be an error")
	}
	if _, err := ParseLimit("@bad[glob"); err == nil {
		t.Error("a malformed group glob must be an error")
	}
}

// MatchesAny agrees with Filter: case-insensitive whole-name globs on the
// hostname, @glob on the credential group.
func TestMatchesAnyAgreesWithFilter(t *testing.T) {
	devs := []Device{
		{Hostname: "core-gw-1", Group: "dc1"},
		{Hostname: "Edge-1", Group: "dc2"},
		{Hostname: "dist-3", Group: "dc1"},
	}
	for _, limit := range []string{"", "core-*", "edge-?", "EDGE-1,dist-*", "@dc1", "core", "@dc*,edge-1", "nothing-*"} {
		pats, err := ParseLimit(limit)
		if err != nil {
			t.Fatal(err)
		}
		var viaMatch []string
		for _, d := range devs {
			if MatchesAny(d, pats) {
				viaMatch = append(viaMatch, d.Hostname)
			}
		}
		filtered, ferr := Filter(devs, pats)
		if ferr != nil {
			// Filter reports a pattern that matches nothing; MatchesAny just selects nothing.
			if len(viaMatch) != 0 && len(pats) == 1 {
				t.Errorf("limit %q: Filter failed (%v) but MatchesAny selected %v", limit, ferr, viaMatch)
			}
			continue
		}
		var viaFilter []string
		for _, d := range filtered {
			viaFilter = append(viaFilter, d.Hostname)
		}
		if !slices.Equal(viaMatch, viaFilter) {
			t.Errorf("limit %q: MatchesAny selects %v, Filter %v", limit, viaMatch, viaFilter)
		}
	}
	if !MatchesAny(Device{Hostname: "anything"}, nil) {
		t.Error("no patterns must select everything")
	}
	if MatchesAny(Device{Hostname: "core-gw-1"}, []string{"core"}) {
		t.Error("a bare word is a whole-name glob, not a substring")
	}
}

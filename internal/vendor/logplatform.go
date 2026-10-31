// ==============================================================================
// File name:     logplatform.go
// Description:   Platforms of "netops log". The log collector, parsers and
//                triage playbooks dispatch on the netops vendor names (cisco,
//                junos, fortinet, ...), so the inventory has one vendor
//                vocabulary; two log-only platforms are added.
// License:       MIT
// ==============================================================================

package vendor

import (
	"sort"
	"strings"
)

// Platforms that "netops log" can read but that have no configuration profile.
const (
	LogCumulus = "cumulus" // NVIDIA / Cumulus Linux
	LogGeneric = "generic" // anything that speaks RFC 3164/5424 syslog; selected when the inventory has no vendor
)

// LogPlatform resolves the vendor written in the inventory to the platform key
// the log packages dispatch on: the canonical netops vendor name (see
// Canonical, which accepts the same names and aliases as every other netops
// command), or one of the log-only platforms. ok is false for anything else.
func LogPlatform(name string) (key string, ok bool) {
	if canonical, found := Canonical(name); found {
		return canonical, true
	}
	switch n := strings.ToLower(strings.TrimSpace(name)); n {
	case LogCumulus, LogGeneric:
		return n, true
	}
	return "", false
}

// LogPlatforms returns every platform key "netops log" supports, sorted.
func LogPlatforms() []string {
	keys := append(Names(), LogCumulus, LogGeneric)
	sort.Strings(keys)
	return keys
}

// IsLogPlatform reports whether key is a platform key, exactly as returned by
// LogPlatform.
func IsLogPlatform(key string) bool {
	for _, k := range LogPlatforms() {
		if k == key {
			return true
		}
	}
	return false
}

// ==============================================================================
// File name:     types.go
// Description:   Data model of the CVE checker: severities, advisories, the
//                records kept in the offline cache and per-device results.
// License:       MIT
// ==============================================================================

// Package cve checks the software versions running on network devices against
// known vulnerabilities. Advisory data comes from NIST NVD, the Cisco PSIRT
// openVuln API and OSV.dev while online, and from a local gzip+JSON cache when
// the network is unreachable or -offline is requested.
//
// Matching is always done locally: sources return advisories together with
// the version ranges they affect, and Match evaluates a device's version
// against those ranges. That is what lets the offline cache answer for any
// version of a platform, not only for versions that were queried before.
//
// The package uses only the Go standard library and package vendor.
package cve

import (
	"strings"
	"time"
)

// Severity is a CVSS qualitative severity rating.
type Severity string

// Severity levels. SeverityUnknown means "not scored (yet)", which is common
// for freshly published CVEs that NVD has not analysed.
const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// Advisory source names as they appear in Advisory.Source.
const (
	SourceNVD   = "NVD"
	SourceCisco = "CISCO"
	SourceOSV   = "OSV"
	SourceCache = "CACHE"
)

// Advisory is one vulnerability that affects a device's software version.
//
// When several sources report the same CVE they are merged into one Advisory:
// Source lists every contributor joined with "+" (e.g. "NVD+CISCO"), CVSS is
// the highest score reported, and URL holds every distinct reference URL
// separated by single spaces.
type Advisory struct {
	ID          string    `json:"id"`           // e.g. "CVE-2023-20198"
	Source      string    `json:"source"`       // "NVD", "CISCO", "OSV", "CACHE" (or a "+" join)
	Title       string    `json:"title"`        // short headline
	Description string    `json:"description"`  // full text
	Severity    Severity  `json:"severity"`     // CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN
	CVSS        float64   `json:"cvss"`         // base score, 0 when not scored
	AffectedVer string    `json:"affected_ver"` // the version range that matched the device
	FixedVer    string    `json:"fixed_ver"`    // first fixed release for the device's train, if known
	Published   time.Time `json:"published"`
	URL         string    `json:"url"`
}

// DeviceCVEResult is the outcome of checking one device.
//
// A device with no Advisories and an empty Error was checked and nothing
// matched. A non-empty Error means the device could NOT be evaluated (no
// version, unsupported platform, no advisory data available): the absence of
// advisories then says nothing about whether it is vulnerable.
type DeviceCVEResult struct {
	Hostname   string     `json:"hostname"`
	IP         string     `json:"ip"`
	Vendor     string     `json:"vendor"`
	OS         string     `json:"os"`
	Version    string     `json:"version"`
	Advisories []Advisory `json:"advisories"`
	Error      string     `json:"error,omitempty"`
}

// Affect says which versions of one product a Record applies to. Exactly one
// shape is used: an exact Version, or a range built from the four bounds, or
// (no field set) every version of the product.
type Affect struct {
	Vendor         string `json:"vendor"`  // CPE vendor, e.g. "cisco"
	Product        string `json:"product"` // CPE product, e.g. "ios_xe"
	Version        string `json:"version,omitempty"`
	StartIncluding string `json:"start_including,omitempty"`
	StartExcluding string `json:"start_excluding,omitempty"`
	EndIncluding   string `json:"end_including,omitempty"`
	EndExcluding   string `json:"end_excluding,omitempty"`
	Fixed          string `json:"fixed,omitempty"` // first fixed release, when the source says
}

// Record is an advisory together with the versions it affects. Records are
// what sources return and what the offline cache stores; Match turns the
// records that apply to one device into Advisories.
type Record struct {
	Advisory
	Affects []Affect `json:"affects"`
}

// Rank orders severities: CRITICAL 4, HIGH 3, MEDIUM 2, LOW 1, anything else 0.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// Meets reports whether an advisory of severity s passes a minimum-severity
// filter. SeverityUnknown always passes: an advisory that has not been scored
// yet (typically a fresh disclosure) must not be hidden by a threshold it was
// never measured against.
func (s Severity) Meets(min Severity) bool {
	if s.Rank() == 0 {
		return true
	}
	return s.Rank() >= min.Rank()
}

// ParseSeverity understands the qualitative ratings used by NVD, Cisco and
// OSV ("MODERATE" is MEDIUM; "NONE" and "INFORMATIONAL" are LOW). Anything
// else, including "UNKNOWN", reports false.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical, true
	case "HIGH":
		return SeverityHigh, true
	case "MEDIUM", "MODERATE":
		return SeverityMedium, true
	case "LOW", "NONE", "INFORMATIONAL":
		return SeverityLow, true
	}
	return SeverityUnknown, false
}

// SeverityFromScore maps a CVSS base score to its qualitative rating
// (0.1-3.9 LOW, 4.0-6.9 MEDIUM, 7.0-8.9 HIGH, 9.0-10.0 CRITICAL).
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityUnknown
}

// Count returns how many of the result's advisories have severity s.
func (r DeviceCVEResult) Count(s Severity) int {
	n := 0
	for _, a := range r.Advisories {
		if a.Severity == s {
			n++
		}
	}
	return n
}

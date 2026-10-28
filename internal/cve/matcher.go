// ==============================================================================
// File name:     matcher.go
// Description:   Version comparison, platform to CPE product mapping and
//                matching of advisory records against a device's version.
// License:       MIT
// ==============================================================================

package cve

import (
	"fmt"
	"sort"
	"strings"

	"netops/internal/vendor"
)

// ---- version comparison ------------------------------------------------------

// token is one numeric or alphabetic run of a version string.
type token struct {
	num bool
	s   string // digits without leading zeros, or lower-case letters
}

// tokenize splits a version such as "15.2(4)M11", "20.4R3-S2.6", "v7.2.4",
// "17.06.01" or "10.2.3-h4" into alternating numeric and alphabetic runs.
// Separators ('.', '-', '(', ')', '_', ...) only delimit runs. A leading "v",
// anything after the first comma (FortiOS ",build1396,...") and anything after
// the first whitespace (RouterOS "7.11.2 (stable)") is dropped.
func tokenize(v string) []token {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	f := strings.Fields(v)
	if len(f) == 0 {
		return nil
	}
	v = f[0]
	if len(v) > 1 && v[0] == 'v' && isDigit(v[1]) {
		v = v[1:]
	}
	var out []token
	for i := 0; i < len(v); {
		switch c := v[i]; {
		case isDigit(c):
			j := i
			for j < len(v) && isDigit(v[j]) {
				j++
			}
			d := strings.TrimLeft(v[i:j], "0")
			if d == "" {
				d = "0"
			}
			out = append(out, token{num: true, s: d})
			i = j
		case c >= 'a' && c <= 'z':
			j := i
			for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
				j++
			}
			out = append(out, token{s: v[i:j]})
			i = j
		default:
			i++
		}
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// cmpToken orders two tokens: numbers compare numerically (without parsing, so
// there is no overflow), letters lexically, and a number sorts before letters.
func cmpToken(a, b token) int {
	switch {
	case a.num && b.num:
		if len(a.s) != len(b.s) {
			if len(a.s) < len(b.s) {
				return -1
			}
			return 1
		}
		return strings.Compare(a.s, b.s)
	case a.num:
		return -1
	case b.num:
		return 1
	}
	return strings.Compare(a.s, b.s)
}

// CompareVersions orders two version strings, returning -1, 0 or 1.
//
// The comparison is token-wise (see tokenize), so zero padding is irrelevant
// ("17.06.01" == "17.6.1"), a rebuild letter sorts after the plain release
// ("17.9.4a" > "17.9.4"), and a longer version is newer unless its extra part
// is only zeros ("17.6" == "17.6.0", "20.4R3-S1" > "20.4R3"). It is a generic
// comparison for network OS trains, not a per-vendor release-order oracle:
// letters that name a train (Cisco IOS "M" vs "S") compare lexically.
func CompareVersions(a, b string) int {
	ta, tb := tokenize(a), tokenize(b)
	n := min(len(ta), len(tb))
	for i := 0; i < n; i++ {
		if c := cmpToken(ta[i], tb[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(ta) > n:
		return tailSign(ta[n:])
	case len(tb) > n:
		return -tailSign(tb[n:])
	}
	return 0
}

// tailSign is 1 when the unmatched tail of the longer version adds anything
// beyond zeros, else 0.
func tailSign(rest []token) int {
	for _, t := range rest {
		if !t.num || t.s != "0" {
			return 1
		}
	}
	return 0
}

// ---- affected ranges -----------------------------------------------------------

// Contains reports whether version falls inside the versions a affects. An
// empty version is never contained: nothing can be said about it.
func (a Affect) Contains(version string) bool {
	if strings.TrimSpace(version) == "" {
		return false
	}
	if a.Version != "" {
		return CompareVersions(version, a.Version) == 0
	}
	switch {
	case a.StartIncluding != "" && CompareVersions(version, a.StartIncluding) < 0:
		return false
	case a.StartExcluding != "" && CompareVersions(version, a.StartExcluding) <= 0:
		return false
	case a.EndIncluding != "" && CompareVersions(version, a.EndIncluding) > 0:
		return false
	case a.EndExcluding != "" && CompareVersions(version, a.EndExcluding) >= 0:
		return false
	}
	return true
}

// String renders the affected versions for people: "17.6.1", ">=16.1.1, <17.9.4a"
// or "all versions".
func (a Affect) String() string {
	if a.Version != "" {
		return a.Version
	}
	var parts []string
	if a.StartIncluding != "" {
		parts = append(parts, ">="+a.StartIncluding)
	}
	if a.StartExcluding != "" {
		parts = append(parts, ">"+a.StartExcluding)
	}
	if a.EndIncluding != "" {
		parts = append(parts, "<="+a.EndIncluding)
	}
	if a.EndExcluding != "" {
		parts = append(parts, "<"+a.EndExcluding)
	}
	if len(parts) == 0 {
		return "all versions"
	}
	return strings.Join(parts, ", ")
}

// Match returns the advisories among recs that affect version of product p,
// most severe first. Each returned Advisory carries the range that matched
// (AffectedVer) and the fix for the device's release train (FixedVer), both
// taken from the matching Affect entries only.
func Match(recs []Record, p Product, version string) []Advisory {
	out := []Advisory{}
	for _, r := range recs {
		var ranges, fixed []string
		for _, a := range r.Affects {
			if a.Vendor != p.Vendor || a.Product != p.Name || !a.Contains(version) {
				continue
			}
			ranges = appendUnique(ranges, a.String())
			if a.Fixed != "" {
				fixed = appendUnique(fixed, a.Fixed)
			}
		}
		if len(ranges) == 0 {
			continue
		}
		adv := r.Advisory
		adv.AffectedVer = strings.Join(ranges, "; ")
		adv.FixedVer = strings.Join(fixed, ", ")
		if adv.Severity.Rank() == 0 && adv.CVSS > 0 {
			adv.Severity = SeverityFromScore(adv.CVSS)
		}
		if adv.Severity == "" {
			adv.Severity = SeverityUnknown
		}
		out = append(out, adv)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.CVSS != b.CVSS:
			return a.CVSS > b.CVSS
		case a.Severity.Rank() != b.Severity.Rank():
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.ID < b.ID
	})
	return out
}

func appendUnique(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}

// ---- platforms and CPE products ------------------------------------------------

// Product identifies a software product the way the NVD CPE dictionary does.
type Product struct {
	Part   string // CPE part: "o" operating system, "a" application
	Vendor string // CPE vendor
	Name   string // CPE product
	OS     string // operator-facing platform label, e.g. "cisco-ios-xe"
}

// Key identifies the product in the offline cache.
func (p Product) Key() string { return p.Part + ":" + p.Vendor + ":" + p.Name }

// CPE is the NVD match string selecting every version of the product.
func (p Product) CPE() string {
	return "cpe:2.3:" + p.Part + ":" + p.Vendor + ":" + p.Name + ":*:*:*:*:*:*:*:*"
}

// Platform is a device platform resolved to the product its CVEs are filed under.
type Platform struct {
	Vendor  string // netops canonical vendor name ("cisco", "junos", "fortinet", ...)
	Product Product
}

var (
	ciscoIOS   = Product{Part: "o", Vendor: "cisco", Name: "ios", OS: "cisco-ios"}
	ciscoIOSXE = Product{Part: "o", Vendor: "cisco", Name: "ios_xe", OS: "cisco-ios-xe"}
	ciscoASA   = Product{Part: "o", Vendor: "cisco", Name: "adaptive_security_appliance_software", OS: "cisco-asa"}
	ciscoFTD   = Product{Part: "o", Vendor: "cisco", Name: "firepower_threat_defense", OS: "cisco-ftd"}
)

// vendorProducts maps netops canonical vendor names to the CPE products their
// CVEs are published under. Platforms that are not listed (cisco_sb, huawei,
// aruba, ruijie) have no reliable CPE product and are reported as unsupported
// rather than guessed: a wrong mapping would produce a falsely clean result.
var vendorProducts = map[string][]Product{
	vendor.Cisco:      {ciscoIOSXE, ciscoIOS},
	vendor.CiscoASA:   {ciscoASA},
	vendor.Junos:      {{Part: "o", Vendor: "juniper", Name: "junos", OS: "junos"}},
	vendor.Fortinet:   {{Part: "o", Vendor: "fortinet", Name: "fortios", OS: "fortios"}},
	vendor.Arista:     {{Part: "o", Vendor: "arista", Name: "eos", OS: "eos"}},
	vendor.MikroTik:   {{Part: "o", Vendor: "mikrotik", Name: "routeros", OS: "routeros"}},
	vendor.PaloAlto:   {{Part: "o", Vendor: "paloaltonetworks", Name: "pan-os", OS: "pan-os"}},
	vendor.CheckPoint: {{Part: "o", Vendor: "checkpoint", Name: "gaia_os", OS: "gaia"}},
	vendor.VyOS:       {{Part: "o", Vendor: "vyos", Name: "vyos", OS: "vyos"}},
	vendor.PfSense:    {{Part: "a", Vendor: "netgate", Name: "pfsense", OS: "pfsense"}},
	vendor.Sophos:     {{Part: "o", Vendor: "sophos", Name: "sfos", OS: "sfos"}},
}

// osAliases name one specific product where the vendor alone is ambiguous.
var osAliases = map[string]Product{
	"ios": ciscoIOS, "cisco-ios": ciscoIOS,
	"ios-xe": ciscoIOSXE, "iosxe": ciscoIOSXE, "cisco-ios-xe": ciscoIOSXE,
	"asa": ciscoASA, "cisco-asa": ciscoASA,
	"ftd": ciscoFTD, "cisco-ftd": ciscoFTD,
}

func normalizeOSName(s string) string {
	return strings.NewReplacer("_", "-", " ", "-").Replace(strings.ToLower(strings.TrimSpace(s)))
}

// SupportedPlatforms lists the netops vendor names that map to a CVE product.
func SupportedPlatforms() []string {
	names := make([]string, 0, len(vendorProducts))
	for n := range vendorProducts {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Candidates returns every product osName may refer to: one for a specific
// name ("cisco-ios-xe", "fortios"), both IOS and IOS XE for a bare "cisco".
func Candidates(osName string) ([]Platform, error) {
	canon, ok := vendor.Canonical(osName)
	if !ok {
		return nil, fmt.Errorf("unknown OS/platform %q (supported: %s)", osName, strings.Join(SupportedPlatforms(), ", "))
	}
	if p, ok := osAliases[normalizeOSName(osName)]; ok {
		return []Platform{{Vendor: canon, Product: p}}, nil
	}
	prods := vendorProducts[canon]
	if len(prods) == 0 {
		return nil, fmt.Errorf("no CVE product mapping for platform %q (supported: %s)", osName, strings.Join(SupportedPlatforms(), ", "))
	}
	out := make([]Platform, len(prods))
	for i, p := range prods {
		out[i] = Platform{Vendor: canon, Product: p}
	}
	return out, nil
}

// Resolve picks the product for a device. A bare "cisco" (what the facts
// collector reports for both IOS and IOS XE) is decided by the version: classic
// IOS writes the maintenance release in parentheses ("15.2(7)E3"), IOS XE does
// not ("17.06.01", "16.12.4a").
func Resolve(osName, version string) (Platform, error) {
	cands, err := Candidates(osName)
	if err != nil {
		return Platform{}, err
	}
	if len(cands) == 1 {
		return cands[0], nil
	}
	for _, c := range cands { // only Cisco is ambiguous: [ios_xe, ios]
		isIOS := c.Product.Name == ciscoIOS.Name
		if isIOS == strings.Contains(version, "(") {
			return c, nil
		}
	}
	return cands[0], nil
}

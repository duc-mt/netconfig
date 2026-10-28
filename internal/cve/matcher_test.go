// ==============================================================================
// File name:     matcher_test.go
// Description:   Tests of version comparison, platform resolution and matching
//                across Cisco, Fortinet, Junos, RouterOS and others.
// License:       MIT
// ==============================================================================

package cve

import (
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		// numeric, not lexical
		{"minor 9 < 10", "17.9.4", "17.10.1", -1},
		{"patch 2 < 11", "15.2(4)M2", "15.2(4)M11", -1},
		{"equal", "17.6.1", "17.6.1", 0},

		// zero padding: IOS XE prints 17.06.01, NVD says 17.6.1
		{"ios-xe zero padding", "17.06.01", "17.6.1", 0},
		{"ios-xe zero padding newer", "17.06.02", "17.6.1", 1},

		// trailing zeros are irrelevant, other tails are newer
		{"trailing zero", "17.6", "17.6.0", 0},
		{"trailing zeros", "17.6", "17.6.0.0", 0},
		{"longer is newer", "17.6", "17.6.1", -1},

		// rebuild letters (IOS XE)
		{"rebuild letter newer", "17.9.4a", "17.9.4", 1},
		{"rebuild letter older than next", "17.9.4a", "17.9.5", -1},
		{"letter order", "16.12.4a", "16.12.4b", -1},

		// classic IOS: parentheses are separators
		{"ios parens equal", "15.2(7)E3", "15.2\\(7\\)e3", 0}, // NVD escapes and lower-cases
		{"ios maintenance", "15.2(4)M11", "15.2(7)E3", -1},
		{"asa parens vs dots", "9.16(2)", "9.16.2", 0},

		// FortiOS: leading v, trailing ",build..." noise
		{"fortios v prefix", "v7.2.4", "7.2.4", 0},
		{"fortios build suffix", "v7.2.4,build1396,230711 (GA)", "7.2.4", 0},
		{"fortios newer", "v7.2.5", "7.2.4", 1},

		// Junos
		{"junos service release", "20.4R3-S2", "20.4R3", 1},
		{"junos respin", "20.4R3-S2.6", "20.4R3-S2", 1},
		{"junos release", "21.2R3", "21.2R3-S5", -1},
		{"junos case", "20.4r3-s2", "20.4R3-S2", 0},

		// RouterOS: channel annotation is dropped
		{"routeros channel", "7.11.2 (stable)", "7.11.2", 0},
		{"routeros older", "6.49.8 (long-term)", "7.1", -1},

		// PAN-OS hotfix
		{"panos hotfix", "10.2.3-h4", "10.2.3", 1},
		{"panos hotfix order", "10.2.3-h4", "10.2.3-h10", -1},

		// Arista
		{"eos train letter", "4.28.3M", "4.28.3", 1},

		// numbers sort before letters at the same position
		{"number before letter", "1.0.1", "1.0.a", -1},
		{"letter after number", "1.0.a", "1.0.1", 1},

		// no overflow on long numbers
		{"huge numbers", "1.99999999999999999999999", "1.100000000000000000000000", -1},

		// degenerate input
		{"both empty", "", "", 0},
		{"empty is oldest", "", "1.0", -1},
		{"only separators", "...", "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CompareVersions(tc.a, tc.b); got != tc.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			if got := CompareVersions(tc.b, tc.a); got != -tc.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, got, -tc.want)
			}
		})
	}
}

func TestAffectContains(t *testing.T) {
	tests := []struct {
		name    string
		a       Affect
		version string
		want    bool
	}{
		{"exact hit", Affect{Version: "17.6.1"}, "17.06.01", true},
		{"exact miss", Affect{Version: "17.6.1"}, "17.6.2", false},
		{"unbounded matches all", Affect{}, "1.2.3", true},
		{"empty version never matches", Affect{}, "", false},
		{"blank version never matches", Affect{}, "  ", false},
		{"start including at bound", Affect{StartIncluding: "16.1.1"}, "16.1.1", true},
		{"start including below", Affect{StartIncluding: "16.1.1"}, "16.1.0", false},
		{"start excluding at bound", Affect{StartExcluding: "16.1.1"}, "16.1.1", false},
		{"start excluding above", Affect{StartExcluding: "16.1.1"}, "16.1.2", true},
		{"end including at bound", Affect{EndIncluding: "7.2.4"}, "v7.2.4", true},
		{"end including above", Affect{EndIncluding: "7.2.4"}, "v7.2.5", false},
		{"end excluding at bound", Affect{EndExcluding: "17.9.4a"}, "17.9.4a", false},
		{"end excluding below", Affect{EndExcluding: "17.9.4a"}, "17.9.4", true},
		{"inside window", Affect{StartIncluding: "7.0.0", EndIncluding: "7.0.11"}, "7.0.5", true},
		{"above window", Affect{StartIncluding: "7.0.0", EndIncluding: "7.0.11"}, "7.1.0", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Contains(tc.version); got != tc.want {
				t.Errorf("%+v.Contains(%q) = %v, want %v", tc.a, tc.version, got, tc.want)
			}
		})
	}
}

func TestAffectString(t *testing.T) {
	tests := []struct {
		a    Affect
		want string
	}{
		{Affect{Version: "17.6.1"}, "17.6.1"},
		{Affect{}, "all versions"},
		{Affect{StartIncluding: "16.1.1", EndExcluding: "17.9.4a"}, ">=16.1.1, <17.9.4a"},
		{Affect{StartExcluding: "6.0", EndIncluding: "6.49.7"}, ">6.0, <=6.49.7"},
	}
	for _, tc := range tests {
		if got := tc.a.String(); got != tc.want {
			t.Errorf("%+v.String() = %q, want %q", tc.a, got, tc.want)
		}
	}
}

func TestResolveAndCandidates(t *testing.T) {
	tests := []struct {
		name        string
		os, version string
		vendor      string
		product     string
		osLabel     string
	}{
		{"ios-xe alias", "cisco-ios-xe", "17.6.1", "cisco", "ios_xe", "cisco-ios-xe"},
		{"ios-xe underscore", "cisco_ios_xe", "17.6.1", "cisco", "ios_xe", "cisco-ios-xe"},
		{"iosxe", "IOSXE", "17.6.1", "cisco", "ios_xe", "cisco-ios-xe"},
		{"ios alias", "ios", "15.2(7)E3", "cisco", "ios", "cisco-ios"},
		{"bare cisco, xe version", "cisco", "17.06.01", "cisco", "ios_xe", "cisco-ios-xe"},
		{"bare cisco, xe letter", "cisco", "16.12.4a", "cisco", "ios_xe", "cisco-ios-xe"},
		{"bare cisco, ios version", "cisco", "15.2(4)E10", "cisco", "ios", "cisco-ios"},
		{"bare cisco, no version", "cisco", "", "cisco", "ios_xe", "cisco-ios-xe"},
		{"asa", "cisco_asa", "9.16(2)", "cisco_asa", "adaptive_security_appliance_software", "cisco-asa"},
		{"asa alias", "asa", "9.16.2", "cisco_asa", "adaptive_security_appliance_software", "cisco-asa"},
		{"ftd alias", "ftd", "7.2.4", "cisco_asa", "firepower_threat_defense", "cisco-ftd"},
		{"junos", "junos", "20.4R3-S2", "junos", "junos", "junos"},
		{"juniper alias", "Juniper", "20.4R3-S2", "junos", "junos", "junos"},
		{"fortios", "fortios", "v7.2.4", "fortinet", "fortios", "fortios"},
		{"fortigate alias", "fortigate", "7.2.4", "fortinet", "fortios", "fortios"},
		{"routeros", "routeros", "7.11.2", "mikrotik", "routeros", "routeros"},
		{"mikrotik", "mikrotik", "6.49.8", "mikrotik", "routeros", "routeros"},
		{"eos", "eos", "4.28.3M", "arista", "eos", "eos"},
		{"panos", "pan-os", "10.2.3-h4", "paloalto", "pan-os", "pan-os"},
		{"gaia", "checkpoint", "R81.10", "checkpoint", "gaia_os", "gaia"},
		{"vyos", "vyos", "1.3.4", "vyos", "vyos", "vyos"},
		{"pfsense", "pfsense", "2.7.0", "pfsense", "pfsense", "pfsense"},
		{"sophos", "sfos", "19.5.3", "sophos", "sfos", "sfos"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pl, err := Resolve(tc.os, tc.version)
			if err != nil {
				t.Fatalf("Resolve(%q, %q): %v", tc.os, tc.version, err)
			}
			if pl.Vendor != tc.vendor || pl.Product.Name != tc.product || pl.Product.OS != tc.osLabel {
				t.Errorf("Resolve(%q, %q) = vendor %q product %q os %q, want %q %q %q",
					tc.os, tc.version, pl.Vendor, pl.Product.Name, pl.Product.OS, tc.vendor, tc.product, tc.osLabel)
			}
		})
	}

	t.Run("bare cisco has two candidates", func(t *testing.T) {
		c, err := Candidates("cisco")
		if err != nil || len(c) != 2 {
			t.Fatalf("Candidates(cisco) = %v, %v; want IOS XE and IOS", c, err)
		}
		if c[0].Product.Name != "ios_xe" || c[1].Product.Name != "ios" {
			t.Errorf("candidates = %v", c)
		}
	})
}

func TestResolveErrors(t *testing.T) {
	tests := []struct {
		os      string
		wantSub string
	}{
		{"no-such-os", "unknown OS/platform"},
		{"", "unknown OS/platform"},
		{"cisco_sb", "no CVE product mapping"},
		{"huawei", "no CVE product mapping"},
		{"aruba", "no CVE product mapping"},
	}
	for _, tc := range tests {
		_, err := Resolve(tc.os, "1.0")
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("Resolve(%q) error = %v, want it to contain %q", tc.os, err, tc.wantSub)
			continue
		}
		if !strings.Contains(err.Error(), "supported:") {
			t.Errorf("Resolve(%q) error should list supported platforms: %v", tc.os, err)
		}
	}
	if _, err := Candidates("cisco_sb"); err == nil {
		t.Error("Candidates(cisco_sb) must fail")
	}
}

func TestSupportedPlatforms(t *testing.T) {
	got := strings.Join(SupportedPlatforms(), ",")
	for _, want := range []string{"cisco", "cisco_asa", "junos", "fortinet", "mikrotik", "paloalto"} {
		if !strings.Contains(got, want) {
			t.Errorf("SupportedPlatforms() = %s, missing %s", got, want)
		}
	}
	if strings.Contains(got, "cisco_sb") {
		t.Errorf("cisco_sb has no CPE mapping and must not be listed: %s", got)
	}
}

func TestProductKeyAndCPE(t *testing.T) {
	if got := ciscoIOSXE.Key(); got != "o:cisco:ios_xe" {
		t.Errorf("Key() = %q", got)
	}
	if got := ciscoIOSXE.CPE(); got != "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*" {
		t.Errorf("CPE() = %q", got)
	}
}

func rec(id string, cvss float64, sev Severity, affects ...Affect) Record {
	return Record{Advisory: Advisory{ID: id, Source: SourceNVD, CVSS: cvss, Severity: sev}, Affects: affects}
}

func TestMatchCiscoIOSXEPicksTheTrainsFix(t *testing.T) {
	// CVE-2023-20198 style data: one range per release train, each with its own fix.
	r := rec("CVE-2023-20198", 10.0, SeverityCritical,
		Affect{Vendor: "cisco", Product: "ios_xe", StartIncluding: "17.9.0", EndExcluding: "17.9.4a", Fixed: "17.9.4a"},
		Affect{Vendor: "cisco", Product: "ios_xe", StartIncluding: "17.6.0", EndExcluding: "17.6.6a", Fixed: "17.6.6a"},
		Affect{Vendor: "cisco", Product: "ios_xe", StartIncluding: "17.3.1", EndExcluding: "17.3.8a", Fixed: "17.3.8a"},
	)
	tests := []struct {
		version   string
		wantMatch bool
		wantFixed string
		wantRange string
	}{
		{"17.06.01", true, "17.6.6a", ">=17.6.0, <17.6.6a"}, // zero padded, 17.6 train
		{"17.6.5", true, "17.6.6a", ">=17.6.0, <17.6.6a"},
		{"17.6.6a", false, "", ""}, // the fix itself
		{"17.9.4", true, "17.9.4a", ">=17.9.0, <17.9.4a"},
		{"17.9.4a", false, "", ""},
		{"17.7.1", false, "", ""}, // a train the advisory does not list
		{"16.12.4", false, "", ""},
	}
	for _, tc := range tests {
		got := Match([]Record{r}, ciscoIOSXE, tc.version)
		if (len(got) == 1) != tc.wantMatch {
			t.Errorf("version %s: matched=%v, want %v (%v)", tc.version, len(got) == 1, tc.wantMatch, got)
			continue
		}
		if tc.wantMatch && (got[0].FixedVer != tc.wantFixed || got[0].AffectedVer != tc.wantRange) {
			t.Errorf("version %s: fixed %q range %q, want %q %q", tc.version, got[0].FixedVer, got[0].AffectedVer, tc.wantFixed, tc.wantRange)
		}
	}
}

func TestMatchCiscoClassicIOSExactEnumeration(t *testing.T) {
	// NVD lists classic IOS releases one by one.
	r := rec("CVE-2018-0171", 9.8, SeverityCritical,
		Affect{Vendor: "cisco", Product: "ios", Version: "15.2(7)e3"},
		Affect{Vendor: "cisco", Product: "ios", Version: "15.2(4)m11"},
	)
	if got := Match([]Record{r}, ciscoIOS, "15.2(7)E3"); len(got) != 1 {
		t.Errorf("15.2(7)E3 must match its exact CPE, got %v", got)
	}
	if got := Match([]Record{r}, ciscoIOS, "15.2(7)E4"); len(got) != 0 {
		t.Errorf("15.2(7)E4 is not listed, got %v", got)
	}
}

func TestMatchFortiOSEndIncluding(t *testing.T) {
	r := rec("CVE-2023-27997", 9.8, SeverityCritical,
		Affect{Vendor: "fortinet", Product: "fortios", StartIncluding: "7.2.0", EndIncluding: "7.2.4"},
		Affect{Vendor: "fortinet", Product: "fortios", StartIncluding: "7.0.0", EndIncluding: "7.0.11"},
		Affect{Vendor: "fortinet", Product: "fortios", StartIncluding: "6.4.0", EndIncluding: "6.4.12"},
	)
	fos := Product{Part: "o", Vendor: "fortinet", Name: "fortios", OS: "fortios"}
	for version, want := range map[string]bool{
		"v7.2.4": true, "v7.2.5": false, "v7.0.11": true, "v7.0.12": false,
		"v6.4.8,build1914,211119 (GA)": true, "v6.2.9": false, "v7.4.0": false,
	} {
		if got := len(Match([]Record{r}, fos, version)) == 1; got != want {
			t.Errorf("FortiOS %s: matched=%v, want %v", version, got, want)
		}
	}
	// no versionEndExcluding means no known fix: FixedVer stays empty
	if got := Match([]Record{r}, fos, "v7.2.4"); got[0].FixedVer != "" {
		t.Errorf("FixedVer = %q, want empty", got[0].FixedVer)
	}
}

func TestMatchJunosReleasesAndServiceReleases(t *testing.T) {
	junos := Product{Part: "o", Vendor: "juniper", Name: "junos", OS: "junos"}
	r := rec("CVE-2023-36845", 9.8, SeverityCritical,
		Affect{Vendor: "juniper", Product: "junos", StartIncluding: "21.2", EndExcluding: "21.2R3-S5", Fixed: "21.2R3-S5"},
		Affect{Vendor: "juniper", Product: "junos", Version: "20.4r3-s2"},
	)
	for version, want := range map[string]bool{
		"21.2R3":      true,  // older than the fix
		"21.2R3-S4":   true,  // older service release
		"21.2R3-S5":   false, // fixed
		"21.2R3-S6":   false,
		"21.2R1":      true,
		"22.1R1":      false,
		"20.4R3-S2":   true,  // exact CPE (release in the CPE update field)
		"20.4R3-S3":   false, // not enumerated
		"junk-string": false,
	} {
		if got := len(Match([]Record{r}, junos, version)) == 1; got != want {
			t.Errorf("Junos %s: matched=%v, want %v", version, got, want)
		}
	}
}

func TestMatchRouterOS(t *testing.T) {
	ros := Product{Part: "o", Vendor: "mikrotik", Name: "routeros", OS: "routeros"}
	r := rec("CVE-2023-30799", 9.1, SeverityCritical,
		Affect{Vendor: "mikrotik", Product: "routeros", StartIncluding: "6.0", EndExcluding: "6.49.7", Fixed: "6.49.7"},
		Affect{Vendor: "mikrotik", Product: "routeros", StartIncluding: "7.0", EndExcluding: "7.1", Fixed: "7.1"},
	)
	for version, want := range map[string]bool{
		"6.48.6 (long-term)": true, "6.49.7 (long-term)": false, "7.0.5 (stable)": true, "7.11.2 (stable)": false,
	} {
		if got := len(Match([]Record{r}, ros, version)) == 1; got != want {
			t.Errorf("RouterOS %s: matched=%v, want %v", version, got, want)
		}
	}
}

func TestMatchIgnoresOtherProducts(t *testing.T) {
	r := rec("CVE-X", 5.0, SeverityMedium, Affect{Vendor: "cisco", Product: "ios", Version: "15.2(7)e3"})
	if got := Match([]Record{r}, ciscoIOSXE, "15.2(7)E3"); len(got) != 0 {
		t.Errorf("an IOS advisory must not match an IOS XE device: %v", got)
	}
}

func TestMatchMergesRangesAndFixesOfOneRecord(t *testing.T) {
	// Two overlapping entries match: both ranges and both fixes are reported once each.
	r := rec("CVE-Y", 7.5, SeverityHigh,
		Affect{Vendor: "cisco", Product: "ios_xe", EndExcluding: "17.9.4a", Fixed: "17.9.4a"},
		Affect{Vendor: "cisco", Product: "ios_xe", StartIncluding: "17.0.0", EndExcluding: "17.9.4a", Fixed: "17.9.4a"},
		Affect{Vendor: "cisco", Product: "ios_xe", StartIncluding: "17.0.0", EndExcluding: "17.12.1", Fixed: "17.12.1"},
	)
	got := Match([]Record{r}, ciscoIOSXE, "17.6.1")
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if got[0].FixedVer != "17.9.4a, 17.12.1" {
		t.Errorf("FixedVer = %q", got[0].FixedVer)
	}
	if got[0].AffectedVer != "<17.9.4a; >=17.0.0, <17.9.4a; >=17.0.0, <17.12.1" {
		t.Errorf("AffectedVer = %q", got[0].AffectedVer)
	}
}

func TestMatchSortsBySeverityThenID(t *testing.T) {
	all := Affect{Vendor: "cisco", Product: "ios_xe"}
	recs := []Record{
		rec("CVE-2", 5.0, SeverityMedium, all),
		rec("CVE-9", 9.8, SeverityCritical, all),
		rec("CVE-1", 7.5, SeverityHigh, all),
		rec("CVE-0", 7.5, SeverityHigh, all),
		rec("CVE-U", 0, SeverityUnknown, all),
	}
	got := Match(recs, ciscoIOSXE, "17.6.1")
	var ids []string
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	if strings.Join(ids, ",") != "CVE-9,CVE-0,CVE-1,CVE-2,CVE-U" {
		t.Errorf("order = %v", ids)
	}
}

func TestMatchFillsInMissingSeverity(t *testing.T) {
	all := Affect{Vendor: "cisco", Product: "ios_xe"}
	got := Match([]Record{
		rec("CVE-A", 9.1, "", all),              // score but no rating
		rec("CVE-B", 0, "", all),                // neither
		rec("CVE-C", 5.0, SeverityUnknown, all), // unknown rating but a score
		rec("CVE-D", 3.1, SeverityMedium, all),  // a stated rating is kept
	}, ciscoIOSXE, "17.6.1")
	want := map[string]Severity{"CVE-A": SeverityCritical, "CVE-B": SeverityUnknown, "CVE-C": SeverityMedium, "CVE-D": SeverityMedium}
	for _, a := range got {
		if a.Severity != want[a.ID] {
			t.Errorf("%s severity = %q, want %q", a.ID, a.Severity, want[a.ID])
		}
	}
}

func TestMatchNoRecordsGivesEmptyNotNil(t *testing.T) {
	if got := Match(nil, ciscoIOSXE, "17.6.1"); got == nil || len(got) != 0 {
		t.Errorf("Match(nil) = %#v, want an empty non-nil slice (JSON [] not null)", got)
	}
}

func TestSeverityHelpers(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Severity
	}{
		{"critical", SeverityCritical}, {" High ", SeverityHigh}, {"MEDIUM", SeverityMedium}, {"moderate", SeverityMedium},
		{"low", SeverityLow}, {"NONE", SeverityLow}, {"Informational", SeverityLow},
	} {
		if got, ok := ParseSeverity(tc.in); !ok || got != tc.want {
			t.Errorf("ParseSeverity(%q) = %q, %v; want %q", tc.in, got, ok, tc.want)
		}
	}
	for _, in := range []string{"", "UNKNOWN", "bogus"} {
		if got, ok := ParseSeverity(in); ok || got != SeverityUnknown {
			t.Errorf("ParseSeverity(%q) = %q, %v; want UNKNOWN,false", in, got, ok)
		}
	}
	for score, want := range map[float64]Severity{
		0: SeverityUnknown, 0.1: SeverityLow, 3.9: SeverityLow, 4.0: SeverityMedium, 6.9: SeverityMedium,
		7.0: SeverityHigh, 8.9: SeverityHigh, 9.0: SeverityCritical, 10: SeverityCritical,
	} {
		if got := SeverityFromScore(score); got != want {
			t.Errorf("SeverityFromScore(%v) = %q, want %q", score, got, want)
		}
	}
	if SeverityUnknown.Rank() != 0 || Severity("weird").Rank() != 0 || SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Error("Rank ordering is wrong")
	}
	if !SeverityHigh.Meets(SeverityMedium) || SeverityLow.Meets(SeverityHigh) || !SeverityHigh.Meets(SeverityHigh) {
		t.Error("Meets threshold logic is wrong")
	}
	if !SeverityUnknown.Meets(SeverityCritical) {
		t.Error("an unscored advisory must never be hidden by a severity filter")
	}
}

func TestDeviceResultCount(t *testing.T) {
	r := DeviceCVEResult{Advisories: []Advisory{
		{Severity: SeverityHigh}, {Severity: SeverityHigh}, {Severity: SeverityCritical},
	}}
	if r.Count(SeverityHigh) != 2 || r.Count(SeverityCritical) != 1 || r.Count(SeverityLow) != 0 {
		t.Errorf("Count wrong: %d %d %d", r.Count(SeverityHigh), r.Count(SeverityCritical), r.Count(SeverityLow))
	}
}

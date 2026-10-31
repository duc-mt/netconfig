// ==============================================================================
// File name:     logplatform_test.go
// Description:   Tests for the "netops log" platform keys.
// License:       MIT
// ==============================================================================

package vendor

import (
	"slices"
	"testing"
)

func TestLogPlatformUsesTheNetopsVendorVocabulary(t *testing.T) {
	cases := map[string]string{
		"cisco": Cisco, "Cisco": Cisco, "IOS-XE": Cisco, "ios_xe": Cisco, " iosxe ": Cisco,
		"cisco_sb": CiscoSB, "SG350": CiscoSB, "cisco-asa": CiscoASA, "FTD": CiscoASA,
		"junos": Junos, "Juniper": Junos,
		"huawei": Huawei, "VRP": Huawei,
		"fortinet": Fortinet, "FortiGate": Fortinet, "fortios": Fortinet,
		"arista": Arista, "EOS": Arista,
		"vyos": VyOS, "ruijie": Ruijie, "aruba": Aruba, "checkpoint": CheckPoint, "gaia": CheckPoint,
		"paloalto": PaloAlto, "pfsense": PfSense, "sophos": Sophos, "mikrotik": MikroTik, "routeros": MikroTik,
		"cumulus": LogCumulus, "Cumulus": LogCumulus, "generic": LogGeneric, " GENERIC ": LogGeneric,
	}
	for in, want := range cases {
		if got, ok := LogPlatform(in); !ok || got != want {
			t.Errorf("LogPlatform(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "nokia", "cumulus-linux", "huawei_vrp_x"} {
		if got, ok := LogPlatform(in); ok {
			t.Errorf("LogPlatform(%q) = %q, want it rejected", in, got)
		}
	}
}

// Every vendor netops knows can be read by netops log, and each platform key
// resolves to itself.
func TestLogPlatformsCoverEveryVendor(t *testing.T) {
	keys := LogPlatforms()
	if !slices.IsSorted(keys) {
		t.Errorf("LogPlatforms is not sorted: %v", keys)
	}
	for _, name := range Names() {
		if !slices.Contains(keys, name) {
			t.Errorf("vendor %q is not a log platform", name)
		}
	}
	for _, k := range keys {
		if got, ok := LogPlatform(k); !ok || got != k {
			t.Errorf("LogPlatform(%q) = %q, %v; keys must resolve to themselves", k, got, ok)
		}
		if !IsLogPlatform(k) {
			t.Errorf("IsLogPlatform(%q) = false", k)
		}
	}
	if len(keys) != len(Names())+2 {
		t.Errorf("want the netops vendors plus cumulus and generic, got %v", keys)
	}
	if IsLogPlatform("Cisco") || IsLogPlatform("ios-xe") || IsLogPlatform("") {
		t.Error("IsLogPlatform only accepts exact platform keys")
	}
	keys[0] = "mutated"
	if LogPlatforms()[0] == "mutated" {
		t.Error("LogPlatforms must return a fresh slice")
	}
}

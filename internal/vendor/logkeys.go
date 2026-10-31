// ==============================================================================
// File name:     logkeys.go
// Description:   Canonical platform keys for "netops log": maps the vendor
//                names and aliases written in inventory.csv to the keys the
//                log collector, parsers and triage playbooks dispatch on.
// License:       MIT
// ==============================================================================

package vendor

import (
	"sort"
	"strings"
)

// logPlatformKeys lists every canonical log-platform key.
var logPlatformKeys = []string{
	"cisco_ios",
	"cisco_sb",
	"cisco_asa",
	"huawei_vrp",
	"juniper_junos",
	"aruba",
	"ruijie",
	"fortigate",
	"checkpoint_gaia",
	"pfsense",
	"vyos",
	"arista",
	"mikrotik",
	"cumulus",
	"paloalto",
	"sophos",
	"generic",
}

// Keys returns the canonical platform keys, sorted.
func Keys() []string {
	out := make([]string, len(logPlatformKeys))
	copy(out, logPlatformKeys)
	sort.Strings(out)
	return out
}

// IsKnown reports whether key is a canonical platform key.
func IsKnown(key string) bool {
	for _, k := range logPlatformKeys {
		if k == key {
			return true
		}
	}
	return false
}

// logPlatformAliases maps every accepted spelling (lower case, '-' and ' ' folded to '_')
// to its canonical key.
var logPlatformAliases = map[string]string{
	// Cisco
	"cisco":        "cisco_ios",
	"cisco_ios":    "cisco_ios",
	"cisco_ios_xe": "cisco_ios",
	"ios":          "cisco_ios",
	"ios_xe":       "cisco_ios",
	"iosxe":        "cisco_ios",

	// Cisco Small Business (SF/SG/CBS)
	"cisco_sb": "cisco_sb",
	"cisco_sf": "cisco_sb",
	"cisco_sg": "cisco_sb",
	"ciscosb":  "cisco_sb",
	"ciscosf":  "cisco_sb",
	"ciscosg":  "cisco_sb",
	"cbs":      "cisco_sb",
	"cbs350":   "cisco_sb",
	"sg300":    "cisco_sb",
	"sg350":    "cisco_sb",
	"sg500":    "cisco_sb",
	"sf300":    "cisco_sb",
	"sf500":    "cisco_sb",

	// Cisco ASA / Firepower FTD in ASA mode
	"cisco_asa": "cisco_asa",
	"asa":       "cisco_asa",
	"cisco_ftd": "cisco_asa",
	"ftd":       "cisco_asa",

	// Juniper
	"junos":         "juniper_junos",
	"juniper":       "juniper_junos",
	"juniper_junos": "juniper_junos",

	// Huawei
	"huawei":     "huawei_vrp",
	"vrp":        "huawei_vrp",
	"huawei_vrp": "huawei_vrp",
	"h3c":        "huawei_vrp", // H3C / HP Comware use the same CLI
	"comware":    "huawei_vrp",
	"hp_comware": "huawei_vrp",

	// Fortinet
	"fortinet":  "fortigate",
	"fortios":   "fortigate",
	"fortigate": "fortigate",

	// Arista
	"arista":     "arista",
	"eos":        "arista",
	"arista_eos": "arista",

	// MikroTik RouterOS
	"mikrotik": "mikrotik",
	"routeros": "mikrotik",
	"ros":      "mikrotik",

	// NVIDIA / Cumulus Linux
	"cumulus":        "cumulus",
	"cumulus_linux":  "cumulus",
	"nvidia_cumulus": "cumulus",
	"nvue":           "cumulus",

	// Aruba
	"aruba":    "aruba",
	"aruba_cx": "aruba",
	"aos_cx":   "aruba",
	"aos_s":    "aruba",

	// Ruijie
	"ruijie": "ruijie",
	"rgos":   "ruijie",

	// Check Point
	"checkpoint":      "checkpoint_gaia",
	"checkpoint_gaia": "checkpoint_gaia",
	"gaia":            "checkpoint_gaia",

	// pfSense
	"pfsense": "pfsense",

	// Palo Alto
	"paloalto": "paloalto",
	"panos":    "paloalto",
	"pan_os":   "paloalto",

	// Sophos
	"sophos":    "sophos",
	"sophos_xg": "sophos",
	"sfos":      "sophos",

	// VyOS
	"vyos": "vyos",

	// Generic
	"generic": "generic",
}

// CanonicalKey normalizes a vendor name or alias (handling case, '-', ' ')
// and returns its canonical key if known.
func CanonicalKey(name string) (string, bool) {
	norm := strings.ToLower(strings.TrimSpace(name))
	norm = strings.NewReplacer("-", "_", " ", "_").Replace(norm)
	if canonical, ok := logPlatformAliases[norm]; ok {
		return canonical, true
	}
	if IsKnown(norm) {
		return norm, true
	}
	return "", false
}

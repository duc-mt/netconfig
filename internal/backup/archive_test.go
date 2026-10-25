// ==============================================================================
// File name:     archive_test.go
// Description:   Tests that backups stay compatible with netbackup's layout.
// License:       MIT
// ==============================================================================
package backup

import (
	"slices"
	"testing"

	"netconfig/internal/vendor"
)

// netbackupLayout is where netbackup saved each platform: its own platform key
// as the directory, and the file extension. Existing backup trees depend on it
// (retention and "diff against the previous backup" look in these places).
var netbackupLayout = []struct{ key, ext string }{
	{"cisco_ios", ".cfg"}, {"cisco_sb", ".cfg"}, {"cisco_asa", ".cfg"},
	{"huawei_vrp", ".cfg"}, {"juniper_junos", ".set"}, {"fortigate", ".conf"},
	{"arista", ".cfg"}, {"vyos", ".config"}, {"ruijie", ".cfg"}, {"aruba", ".cfg"},
	{"checkpoint_gaia", ".cfg"}, {"paloalto", ".set"}, {"pfsense", ".xml"}, {"sophos", ".cfg"},
	{"mikrotik", ".rsc"},
}

func TestBackupsKeepNetbackupsDirectoriesAndExtensions(t *testing.T) {
	seen := map[string]bool{}
	for _, want := range netbackupLayout {
		// netbackup's key is a valid vendor name in an inventory...
		p, ok := vendor.Lookup(want.key)
		if !ok {
			t.Errorf("netbackup platform %q no longer resolves to a vendor", want.key)
			continue
		}
		// ...and its backups land where they always did
		spec := archiveFor(p)
		if spec.Dir != want.key || spec.Ext != want.ext {
			t.Errorf("%s: archived as %s/*%s, want %s/*%s", want.key, spec.Dir, spec.Ext, want.key, want.ext)
		}
		seen[p.Name] = true
	}
	// every netconfig vendor is covered by that table: none falls back to a
	// generated directory name by accident
	for _, name := range vendor.Names() {
		if !seen[name] {
			t.Errorf("vendor %q has no netbackup-compatible layout entry in this test", name)
		}
	}
}

func TestArchiveFallbackForAVendorWithoutAnEntry(t *testing.T) {
	p := &vendor.Profile{Name: "newvendor", BackupCommand: "show config"}
	spec := archiveFor(p)
	if spec.Dir != "newvendor" || spec.Ext != ".cfg" || spec.Command != "show config" {
		t.Errorf("fallback layout = %+v", spec)
	}
}

func TestArchiveCommandDefaultsToTheProfilesBackupCommand(t *testing.T) {
	for _, name := range vendor.Names() {
		p, _ := vendor.Lookup(name)
		spec := archiveFor(p)
		if name == vendor.Junos {
			if spec.Command == p.BackupCommand || spec.Command != "show configuration | display set" {
				t.Errorf("junos is archived as set commands, got %q", spec.Command)
			}
			continue
		}
		if spec.Command != p.BackupCommand {
			t.Errorf("%s: archive command %q differs from the profile's %q", name, spec.Command, p.BackupCommand)
		}
	}
}

func TestArchiveResolvesMultipleCommandsForSophos(t *testing.T) {
	p, _ := vendor.Lookup("sophos")
	spec := archiveFor(p)
	wantCmds := []string{
		"system diagnostics show version-info",
		"show network interfaces",
		"show network static-route",
		"system ha show details",
	}
	if !slices.Equal(spec.Commands, wantCmds) {
		t.Errorf("sophos archive commands = %v, want %v", spec.Commands, wantCmds)
	}
}

// Existing netbackup inventories keep working: every vendor spelling netbackup
// accepted still resolves, except the two platforms netconfig does not have.
func TestNetbackupVendorSpellingsStillResolve(t *testing.T) {
	spellings := map[string]string{
		"cisco_ios": "cisco", "ios": "cisco", "cisco_ios_xe": "cisco", "ios_xe": "cisco", "iosxe": "cisco",
		"cisco_sb": "cisco_sb", "cisco_sf": "cisco_sb", "cisco_sg": "cisco_sb", "ciscosb": "cisco_sb",
		"sg300": "cisco_sb", "sg350": "cisco_sb", "sg500": "cisco_sb", "sf300": "cisco_sb", "sf500": "cisco_sb",
		"cbs": "cisco_sb", "cbs350": "cisco_sb",
		"cisco_asa": "cisco_asa", "asa": "cisco_asa", "cisco_ftd": "cisco_asa", "ftd": "cisco_asa",
		"huawei_vrp": "huawei", "vrp": "huawei", "h3c": "huawei", "comware": "huawei", "hp_comware": "huawei",
		"juniper_junos": "junos", "juniper": "junos",
		"fortigate": "fortinet", "fortios": "fortinet",
		"arista_eos": "arista", "eos": "arista",
		"aruba_cx": "aruba", "aos_cx": "aruba", "aos_s": "aruba",
		"checkpoint_gaia": "checkpoint", "gaia": "checkpoint",
		"pan_os": "paloalto", "panos": "paloalto",
		"rgos": "ruijie", "sophos_xg": "sophos", "sfos": "sophos",
		"mikrotik": "mikrotik", "routeros": "mikrotik", "ros": "mikrotik",
	}
	for in, want := range spellings {
		if p, ok := vendor.Lookup(in); !ok || p.Name != want {
			t.Errorf("Lookup(%q) = %v, %v; want %s", in, p, ok, want)
		}
	}
	for _, unsupported := range []string{"generic"} {
		if _, ok := vendor.Lookup(unsupported); ok {
			t.Errorf("%q now resolves: update the migration notes and add its archive layout", unsupported)
		}
	}
	if !slices.Contains(vendor.Names(), "cisco_asa") {
		t.Error("sanity: cisco_asa missing")
	}
}

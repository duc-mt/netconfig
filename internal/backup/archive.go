// ==============================================================================
// File name:     archive.go
// Description:   How the backup subcommand lays out and names saved configurations.
// License:       MIT
// ==============================================================================
package backup

import (
	"netconfig/internal/vendor"
)

// archiveSpec describes how one platform's backups are stored on disk.
//
// netconfig names its vendors differently from the standalone netbackup tool
// ("cisco" / "junos" / "fortinet" versus "cisco_ios" / "juniper_junos" /
// "fortigate"). Backups keep netbackup's directory names and file extensions
// so that an existing backup tree, its retention rules and the "diff against
// the previous backup" check carry straight over to the merged binary.
type archiveSpec struct {
	Dir      string   // directory under <backup-dir>/<run>/
	Ext      string   // file extension, including the dot
	Command  string   // overrides the profile's BackupCommand when set
	Commands []string // overrides the profile's BackupCommands when set
}

// archiveSpecs is keyed by vendor profile name.
var archiveSpecs = map[string]archiveSpec{
	vendor.Cisco:      {Dir: "cisco_ios", Ext: ".cfg"},
	vendor.CiscoSB:    {Dir: "cisco_sb", Ext: ".cfg"},
	vendor.CiscoASA:   {Dir: "cisco_asa", Ext: ".cfg"},
	vendor.Huawei:     {Dir: "huawei_vrp", Ext: ".cfg"},
	vendor.Arista:     {Dir: "arista", Ext: ".cfg"},
	vendor.Aruba:      {Dir: "aruba", Ext: ".cfg"},
	vendor.Ruijie:     {Dir: "ruijie", Ext: ".cfg"},
	vendor.PaloAlto:   {Dir: "paloalto", Ext: ".set"},
	vendor.Sophos:     {Dir: "sophos", Ext: ".cfg"},
	vendor.Fortinet:   {Dir: "fortigate", Ext: ".conf"},
	vendor.CheckPoint: {Dir: "checkpoint_gaia", Ext: ".cfg"},
	vendor.PfSense:    {Dir: "pfsense", Ext: ".xml"},
	vendor.VyOS:       {Dir: "vyos", Ext: ".config"},
	vendor.MikroTik:   {Dir: "mikrotik", Ext: ".rsc"},
	// netbackup archives Junos as "set" commands (one statement per line),
	// which diff far better than the curly-brace form.
	vendor.Junos: {Dir: "juniper_junos", Ext: ".set", Command: "show configuration | display set"},
}

// archiveFor returns the storage layout for a profile. A vendor without an
// entry (one added later) is stored under its own name as ".cfg".
func archiveFor(p *vendor.Profile) archiveSpec {
	spec, ok := archiveSpecs[p.Name]
	if !ok {
		spec = archiveSpec{Dir: p.Name, Ext: ".cfg"}
	}
	if len(spec.Commands) == 0 && len(p.BackupCommands) > 0 {
		spec.Commands = p.BackupCommands
	}
	if spec.Command == "" {
		spec.Command = p.BackupCommand
	}
	return spec
}

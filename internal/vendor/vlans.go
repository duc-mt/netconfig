// ==============================================================================
// File name:     vlans.go
// Description:   VLANManager drivers.
// License:       MIT
// ==============================================================================
package vendor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// vlanDriver implements VLANManager from per-platform functions.
type vlanDriver struct {
	check  func(id int) string
	exists func(output string, id int) bool
	name   func(output string, id int) string
	create func(id int, name string) []string
	remove func(id int, name string) []string
}

func (d vlanDriver) CheckVLANCommand(id int) string { return d.check(id) }

func (d vlanDriver) VLANExists(output string, id int) bool { return d.exists(output, id) }

func (d vlanDriver) VLANName(output string, id int) string { return d.name(output, id) }

func (d vlanDriver) CreateVLANSteps(id int, name string) []Step { return body(d.create(id, name)...) }

func (d vlanDriver) DeleteVLANSteps(id int, name string) []Step {
	lines := d.remove(id, name)
	if len(lines) == 0 {
		return nil
	}
	return body(lines...)
}

// vlanRow matches the first table row that starts with the VLAN ID followed by
// a name and a status word: "10  Servers  active  Gi1/0/1", "10 VLAN0010 STATIC
// Gi0/1", "10 Servers up ok static 1/1/1". Wrapped port lists never start with
// the ID, and the "not found" messages start with a word, so they never match.
func vlanRow(id int) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\s*` + strconv.Itoa(id) + `\s+(\S+)\s+(\S+)`)
}

func rowExists(output string, id int) bool { return vlanRow(id).MatchString(output) }

func rowName(output string, id int) string {
	if m := vlanRow(id).FindStringSubmatch(output); m != nil {
		return m[1]
	}
	return ""
}

// numbered builds the "vlan <id>" / "name <name>" form shared by IOS-like CLIs.
func numbered(showCmd string) vlanDriver {
	return vlanDriver{
		check:  func(id int) string { return fmt.Sprintf("%s %d", showCmd, id) },
		exists: rowExists,
		name:   rowName,
		create: func(id int, name string) []string {
			lines := []string{fmt.Sprintf("vlan %d", id)}
			if name != "" {
				lines = append(lines, "name "+name)
			}
			return lines
		},
		remove: func(id int, _ string) []string { return []string{fmt.Sprintf("no vlan %d", id)} },
	}
}

// vlanDrivers maps a canonical vendor name to its driver.
//
// Only platforms with a global VLAN database have one. The firewalls (ASA,
// FortiGate, Check Point, Palo Alto, pfSense, Sophos) and VyOS model a VLAN as
// a sub-interface of a named parent port, which needs a parent the command
// line does not carry. Cisco SB (SF/SG/CBS) is left out because the VLAN and
// name syntax differs between firmware families.
var vlanDrivers = map[string]VLANManager{
	Cisco:  numbered("show vlan id"),
	Ruijie: numbered("show vlan id"),
	Arista: numbered("show vlan"),
	Aruba:  numbered("show vlan"),
	Huawei: vlanDriver{
		check: func(id int) string { return fmt.Sprintf("display vlan %d", id) },
		exists: func(output string, id int) bool {
			return huaweiVLAN(id).MatchString(output)
		},
		name: func(output string, id int) string {
			if m := huaweiVLAN(id).FindStringSubmatch(output); m != nil {
				return strings.TrimSpace(m[1])
			}
			return ""
		},
		create: func(id int, name string) []string {
			lines := []string{fmt.Sprintf("vlan %d", id)}
			if name != "" {
				lines = append(lines, "description "+name)
			}
			return append(lines, "quit")
		},
		remove: func(id int, _ string) []string { return []string{fmt.Sprintf("undo vlan %d", id)} },
	},
	Junos: vlanDriver{
		check: func(id int) string {
			return fmt.Sprintf("show configuration vlans | display set | match \"vlan-id %d$\"", id)
		},
		exists: func(output string, id int) bool { return junosVLAN(id).MatchString(output) },
		name: func(output string, id int) string {
			if m := junosVLAN(id).FindStringSubmatch(output); m != nil {
				return m[1]
			}
			return ""
		},
		create: func(id int, name string) []string {
			if name == "" {
				name = fmt.Sprintf("VLAN%d", id) // Junos requires a name
			}
			return []string{fmt.Sprintf("set vlans %s vlan-id %d", name, id)}
		},
		remove: func(_ int, name string) []string {
			if name == "" {
				return nil // deletion is by name: refuse rather than guess
			}
			return []string{"delete vlans " + name}
		},
	},
}

// huaweiVLAN matches the second table of "display vlan <id>":
//
//	VID  Status  Property  MAC-LRN Statistics Description
//	10   enable  default   enable  disable    Servers
func huaweiVLAN(id int) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\s*` + strconv.Itoa(id) + `\s+(?:enable|disable)\s+\S+\s+\S+\s+\S+\s+(.*)$`)
}

// junosVLAN matches "set vlans <name> vlan-id <id>".
func junosVLAN(id int) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\s*set vlans\s+["']?([^\s"']+)["']?\s+vlan-id\s+` + strconv.Itoa(id) + `\s*$`)
}

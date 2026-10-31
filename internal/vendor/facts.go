// ==============================================================================
// File name:     facts.go
// Description:   FactsCollector drivers (model, serial, version, uptime).
// License:       MIT
// ==============================================================================
package vendor

import (
	"regexp"
	"strings"
)

// factsDriver parses facts with an ordered list of regular expressions per
// field; the first expression that matches supplies capture group 1.
type factsDriver struct {
	commands string
	hostname []*regexp.Regexp
	model    []*regexp.Regexp
	serial   []*regexp.Regexp
	version  []*regexp.Regexp
	uptime   []*regexp.Regexp
}

func (d factsDriver) FactsCommand() string { return d.commands }

func (d factsDriver) ParseFacts(output string) DeviceFacts {
	output = strings.ReplaceAll(output, "\r", "")
	first := func(res []*regexp.Regexp) string {
		for _, re := range res {
			if m := re.FindStringSubmatch(output); m != nil {
				return strings.TrimSpace(m[1])
			}
		}
		return ""
	}
	return DeviceFacts{
		Hostname: first(d.hostname),
		Model:    first(d.model),
		Serial:   first(d.serial),
		Version:  first(d.version),
		Uptime:   first(d.uptime),
	}
}

// rx compiles a multi-line pattern.
func rx(p string) *regexp.Regexp { return regexp.MustCompile("(?m)" + p) }

// rxs compiles several patterns.
func rxs(ps ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(ps))
	for _, p := range ps {
		out = append(out, rx(p))
	}
	return out
}

// sec anchors a pattern to the output block of one command (see CombineOutputs).
func sec(cmd, pat string) string {
	return `^=== ` + regexp.QuoteMeta(cmd) + ` ===\n` + pat
}

// upUsers pulls "42 days, 1:23" out of a unix style "up 42 days, 1:23, 2 users".
const upUsers = `\bup\s+(.+?),\s+\d+\s+users?\b`

// factsDrivers covers every platform. The sample outputs the patterns were
// written against are in testdata/facts; real captures should be added there.
var factsDrivers = map[string]FactsCollector{
	Cisco: factsDriver{
		commands: "show version",
		hostname: rxs(`^(\S+)\s+uptime is\s`),
		model: rxs(
			`(?i)^model number\s*:\s*(\S+)`,
			`(?i)^cisco\s+(\S+)\s+\(.*?\)\s+processor`,
		),
		serial: rxs(
			`(?i)^system serial number\s*:\s*(\S+)`,
			`(?i)^processor board id\s+(\S+)`,
		),
		version: rxs(`^Cisco IOS(?: XE)? Software.*?Version\s+([^\s,]+)`),
		uptime:  rxs(`\suptime is\s+(.+?)\s*$`),
	},
	CiscoSB: factsDriver{
		commands: "show version\nshow system\nshow inventory",
		hostname: rxs(`(?i)^System Name:\s*(\S+)`),
		model:    rxs(`\bPID:\s*(\S+)`),
		serial:   rxs(`\bSN:\s*(\S+)`),
		version: rxs(
			`(?i)^SW version\s+(\S+)`,
			`(?i)^\s*Version:\s*(\S+)`,
		),
		uptime:   rxs(`(?i)^System Up Time\s*(?:\([^)]*\))?\s*:\s*(\S+)`),
	},
	CiscoASA: factsDriver{
		commands: "show version",
		hostname: rxs(`^(\S+)\s+up\s`),
		model:    rxs(`^Hardware:\s*([^,\s]+)`),
		serial:   rxs(`(?i)^Serial Number:\s*(\S+)`),
		version:  rxs(`^Cisco Adaptive Security Appliance Software Version\s+(\S+)`),
		uptime:   rxs(`^\S+\s+up\s+(.+?)\s*$`),
	},
	Junos: factsDriver{
		commands: "show version\nshow chassis hardware\nshow system uptime",
		hostname: rxs(`^Hostname:\s*(\S+)`),
		model: rxs(
			`^Model:\s*(\S+)`,
			`^Chassis\s+\S+\s+(\S+)\s*$`,
		),
		serial: rxs(`^Chassis\s+(\S+)`),
		version: rxs(
			`^Junos:\s*(\S+)`,
			`^JUNOS .*\[(\S+)\]`,
		),
		uptime: rxs(
			`^System booted:.*\((.+?) ago\)`,
			upUsers,
		),
	},
	Huawei: factsDriver{
		commands: "display version\ndisplay esn",
		model:    rxs(`^(?:HUAWEI|Huawei|Quidway|H3C)\s+(\S+)\s+.*?uptime is`),
		serial: rxs(
			`(?i)ESN of (?:device|slot \d+):\s*(\S+)`,
			`(?i)ESN of device:\s*(\S+)`,
			`BarCode=(\S+)`,
		),
		version: rxs(`^VRP \(R\) software, Version\s+(.+?)\s*$`),
		uptime:  rxs(`uptime is\s+(.+?)\s*$`),
	},
	Fortinet: factsDriver{
		commands: "get system status\nget system performance status",
		hostname: rxs(`^Hostname:\s*(\S+)`),
		model:    rxs(`^Version:\s*(\S+)\s+v`),
		serial:   rxs(`^Serial-Number:\s*(\S+)`),
		version:  rxs(`^Version:\s*\S+\s+(v[^,\s]+)`),
		uptime:   rxs(`^Uptime:\s*(.+?)\s*$`),
	},
	Arista: factsDriver{
		commands: "show version\nshow hostname",
		hostname: rxs(`^Hostname:\s*(\S+)`),
		model:    rxs(`^Arista\s+(\S+)`),
		serial:   rxs(`(?i)^Serial number:\s*(\S+)`),
		version:  rxs(`(?i)^Software image version:\s*(\S+)`),
		uptime:   rxs(`(?i)^Uptime:\s*(.+?)\s*$`),
	},
	VyOS: factsDriver{
		commands: "show version\nshow system uptime\nshow host name",
		hostname: rxs(sec("show host name", `(\S+)`)),
		model:    rxs(`^Hardware model:\s*(.+?)\s*$`),
		serial:   rxs(`^Hardware S/N:\s*(\S+)`),
		version:  rxs(`^Version:\s*(?:VyOS\s+)?(\S+)`),
		uptime:   rxs(upUsers),
	},
	Ruijie: factsDriver{
		commands: "show version",
		model:    rxs(`^System description\s*:.*\(([^)]+)\)`),
		serial:   rxs(`^System serial number\s*:\s*(\S+)`),
		version:  rxs(`^System software version\s*:\s*(.+?)\s*$`),
		uptime:   rxs(`^System uptime\s*:\s*(.+?)\s*$`),
	},
	// Aruba: AOS-CX and AOS-S / Provision (ProCurve).
	Aruba: factsDriver{
		commands: "show version\nshow system\nshow lldp info local-device",
		hostname: rxs(
			`^Hostname\s*:\s*(\S+)`,
			`(?i)^\s*System Name\s*:\s*(\S+)`,
		),
		model: rxs(
			`^Product Name\s*:\s*(.+?)\s*$`,
			`(?i)^\s*System Description\s*:\s*(.+?)\s*$`,
		),
		serial: rxs(
			`^Chassis Serial Nbr\s*:\s*(\S+)`,
			`(?i)Serial Number\s*:\s*(\S+)`,
		),
		version: rxs(
			`^Version\s*:\s*(\S+)`,
			`(?i)^\s*Software revision\s*:\s*(\S+)`,
			`(?i)^\s*Firmware release\s*:\s*(\S+)`,
			`\b(YA\.\d+\.\d+\.\d+)\b`,
		),
		uptime: rxs(
			`(?i)Up Time\s*:\s*([^\n\r]+?)(?:\s{2,}\S|\s*$)`,
		),
	},
	CheckPoint: factsDriver{
		commands: "show version all\nshow asset all\nshow uptime\nshow hostname\nshow software-version\nshow diag\nshow device-details\nuptime",
		hostname: rxs(
			sec("show hostname", `(\S+)`),
			`(?i)^\s*hostname:\s*(\S+)`,
		),
		model: rxs(
			`(?i)^Platform:\s*(.+?)\s*$`,
			`(?i)This is Check Point's\s+(\S+)`,
			`(?i)^\s*Unit model:\s*(.+?)\s*$`,
		),
		serial: rxs(
			`(?i)^Serial Number:\s*(\S+)`,
			`(?i)^\s*Serial [Nn]umber:\s*(\S+)`,
		),
		version: rxs(
			`^Product version\s+(.+?)\s*$`,
			`(?i)Appliance\s+(R\d+[^-\s]+(?:\s*-\s*Build\s*\d+)?)`,
			`(?i)Build\s+(\d+)`,
		),
		uptime: rxs(
			sec("show uptime", `\s*(?:\d+:\d+(?::\d+)?\s+)?up\s+(.+?)\s*$`),
			`\bup\s+(.+?),\s+\d+\s+users?\b`,
		),
	},
	PaloAlto: factsDriver{
		commands: "show system info",
		hostname: rxs(`^hostname:\s*(\S+)`),
		model:    rxs(`^model:\s*(\S+)`),
		serial:   rxs(`^serial:\s*(\S+)`),
		version:  rxs(`^sw-version:\s*(\S+)`),
		uptime:   rxs(`^uptime:\s*(.+?)\s*$`),
	},
	PfSense: factsDriver{
		commands: "cat /etc/version\nkenv smbios.system.product\nkenv smbios.system.serial\nuptime\nhostname",
		hostname: rxs(sec("hostname", `(\S+)`)),
		model:    rxs(sec("kenv smbios.system.product", `"?(.+?)"?\s*$`)),
		serial:   rxs(sec("kenv smbios.system.serial", `"?(.+?)"?\s*$`)),
		version:  rxs(sec("cat /etc/version", `(\S+)`)),
		uptime:   rxs(upUsers),
	},
	// Sophos: the SFOS device console. Field names are taken from the
	// version-info page; verify against a capture from your firmware.
	Sophos: factsDriver{
		commands: "system diagnostics show version-info",
		model:    rxs(`(?i)Appliance Model\s*:\s*(\S+)`),
		serial:   rxs(`(?i)Appliance Key\s*:\s*(\S+)`),
		version:  rxs(`(?i)Firmware Version\s*:\s*(.+?)\s*$`),
	},
}

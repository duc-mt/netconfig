// ==============================================================================
// File name:     locator.go
// Description:   NetworkLocator drivers: MAC address table and ARP lookups.
// License:       MIT
// ==============================================================================
package vendor

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Address fragments shared by the table parsers.
const (
	reMACDotted = `[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}`
	reMACColon  = `[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}`
	reMACHyphen = `[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}`
	reIPv4      = `\d{1,3}(?:\.\d{1,3}){3}`
)

// rowSpec describes one table row format: a pattern and which capture group
// holds which column (0 = absent).
type rowSpec struct {
	re                    *regexp.Regexp
	mac, ip, iface, vlanC int
	vlanNameC             int // group holding a name whose trailing digits are the VLAN ("VLAN30", "vlan30")
}

// parseRows applies spec to every line of output.
func parseRows(output string, spec rowSpec) []LocatorRecord {
	var out []LocatorRecord
	for _, m := range spec.re.FindAllStringSubmatch(strings.ReplaceAll(output, "\r", ""), -1) {
		rec := LocatorRecord{}
		if spec.mac > 0 {
			if n, err := NormalizeMAC(m[spec.mac]); err == nil {
				rec.MAC = FormatMAC(n, MACColon)
			}
		}
		if spec.ip > 0 {
			rec.IP = m[spec.ip]
		}
		if spec.iface > 0 {
			rec.Interface = strings.TrimSpace(m[spec.iface])
		}
		if spec.vlanC > 0 {
			rec.VLAN, _ = strconv.Atoi(m[spec.vlanC])
		}
		if rec.VLAN == 0 && spec.vlanNameC > 0 {
			rec.VLAN = vlanFromTrailingDigits(m[spec.vlanNameC])
		}
		if rec.VLAN == 0 {
			rec.VLAN = vlanFromName(rec.Interface)
		}
		out = append(out, rec)
	}
	return out
}

var reVLANInName = regexp.MustCompile(`(?i)(?:vlan(?:if)?|vl|bdi|irb\.|vlan\.)\s*(\d+)$`)

// vlanFromName extracts the VLAN from an SVI style name ("Vlan30", "Vlanif30",
// "irb.30"); 0 when the name carries none.
func vlanFromName(name string) int {
	if m := reVLANInName.FindStringSubmatch(name); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// vlanFromTrailingDigits reads "VLAN30" / "v30" style Junos VLAN names.
func vlanFromTrailingDigits(name string) int {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	if i == len(name) {
		return 0
	}
	n, _ := strconv.Atoi(name[i:])
	return n
}

func rowRe(p string) *regexp.Regexp { return regexp.MustCompile(`(?mi)` + p) }

// locatorDriver implements NetworkLocator (and TrunkDetector when the trunk
// fields are set).
type locatorDriver struct {
	style    MACStyle
	macCmd   string // format with one %s for the MAC; "" = no MAC table query
	macSpec  *rowSpec
	macPost  func([]LocatorRecord) []LocatorRecord
	ipCmd    string // format with one %s for the IP; "" = no ARP query
	ipSpec   *rowSpec
	ipSpecs  []*rowSpec
	ipPost   func([]LocatorRecord) []LocatorRecord
	trunkCmd string
	trunkRe  *regexp.Regexp
}

func (d locatorDriver) FindMACCommand(mac string) string {
	if d.macCmd == "" {
		return ""
	}
	n, err := NormalizeMAC(mac)
	if err != nil {
		return ""
	}
	return strings.Replace(d.macCmd, "%s", FormatMAC(n, d.style), 1)
}

func (d locatorDriver) ParseMAC(output string) []LocatorRecord {
	if d.macSpec == nil {
		return nil
	}
	recs := parseRows(output, *d.macSpec)
	if d.macPost != nil {
		recs = d.macPost(recs)
	}
	return recs
}

func (d locatorDriver) FindIPCommand(ip string) string {
	if d.ipCmd == "" || net.ParseIP(strings.TrimSpace(ip)) == nil {
		return ""
	}
	return strings.Replace(d.ipCmd, "%s", strings.TrimSpace(ip), 1)
}

func (d locatorDriver) ParseIP(output string) []LocatorRecord {
	var specs []*rowSpec
	if d.ipSpec != nil {
		specs = append(specs, d.ipSpec)
	}
	specs = append(specs, d.ipSpecs...)
	if len(specs) == 0 {
		return nil
	}
	var recs []LocatorRecord
	for _, spec := range specs {
		if spec == nil {
			continue
		}
		recs = append(recs, parseRows(output, *spec)...)
	}
	if d.ipPost != nil {
		recs = d.ipPost(recs)
	}
	return recs
}

func (d locatorDriver) TrunkPortsCommand() string { return d.trunkCmd }

func (d locatorDriver) ParseTrunkPorts(output string) []string {
	if d.trunkRe == nil {
		return nil
	}
	var ports []string
	for _, m := range d.trunkRe.FindAllStringSubmatch(strings.ReplaceAll(output, "\r", ""), -1) {
		ports = append(ports, m[1])
	}
	return ports
}

// splitSVIPort turns an Arista ARP "Vlan30, Ethernet14" interface column into
// the VLAN (from the SVI) and the physical port.
func splitSVIPort(recs []LocatorRecord) []LocatorRecord {
	for i, r := range recs {
		if svi, port, ok := strings.Cut(r.Interface, ","); ok {
			recs[i].VLAN = vlanFromName(strings.TrimSpace(svi))
			recs[i].Interface = strings.TrimSpace(port)
		} else {
			recs[i].VLAN = vlanFromName(strings.TrimSpace(r.Interface))
		}
	}
	return recs
}

// ---- driver table ----------------------------------------------------------

var (
	ciscoMAC = &rowSpec{re: rowRe(`^\s*(\d+|All)\s+(` + reMACDotted + `)\s+\w+\s+(\S+)`), mac: 2, iface: 3, vlanC: 1}
	ciscoARP = &rowSpec{re: rowRe(`^\s*Internet\s+(` + reIPv4 + `)\s+\S+\s+(` + reMACDotted + `)\s+\S+\s+(\S+)`), ip: 1, mac: 2, iface: 3}

	aristaMAC = &rowSpec{re: rowRe(`^\s*(\d+)\s+(` + reMACDotted + `)\s+\w+\s+([^\s,]+)`), mac: 2, iface: 3, vlanC: 1}
	aristaARP = &rowSpec{re: rowRe(`^\s*(` + reIPv4 + `)\s+\S+\s+(` + reMACDotted + `)\s+(.+?)\s*$`), ip: 1, mac: 2, iface: 3}
)

// cpuPorts are internal/CPU pseudo ports that never identify a physical access port.
var cpuPorts = regexp.MustCompile(`(?i)^(?:cpu|router|rtr|sup-eth\d*|switch|self|internal|vme|me0|vlan\d+|vlanif\d+|irb(?:\.\d+)?|bdi\d+|)$`)

// IsInternalPort reports whether name is a CPU / internal pseudo port.
func IsInternalPort(name string) bool { return cpuPorts.MatchString(strings.TrimSpace(name)) }

// aggregatePorts are link aggregates, which are uplinks by construction.
var aggregatePorts = regexp.MustCompile(`(?i)^(?:po\d+|port-channel\s*\d+|ae\d+(?:\.\d+)?|eth-trunk\s*\d+|bridge-aggregation\s*\d+|ag\s*\d+|lag\s*\d+)$`)

// IsAggregatePort reports whether name is a port-channel / LAG.
func IsAggregatePort(name string) bool { return aggregatePorts.MatchString(strings.TrimSpace(name)) }

var locatorDrivers = map[string]NetworkLocator{
	Cisco: locatorDriver{
		style: MACDotted, macCmd: "show mac address-table address %s", macSpec: ciscoMAC,
		ipCmd: "show ip arp %s", ipSpec: ciscoARP,
		trunkCmd: "show interfaces trunk",
		trunkRe:  rowRe(`^(\S+)\s+(?:on|auto|desirable|nonegotiate)\s+\S+\s+trunking\s`),
	},
	CiscoSB: locatorDriver{
		style: MACColon, macCmd: "show mac address-table address %s",
		macSpec: &rowSpec{re: rowRe(`^\s*(\d+)\s+(` + reMACColon + `)\s+(\S+)\s+\w+`), mac: 2, iface: 3, vlanC: 1},
		ipCmd:   "show arp",
		ipSpec:  &rowSpec{re: rowRe(`^\s*((?:vlan\s*\d+|\S+))\s+(` + reIPv4 + `)\s+(` + reMACColon + `)\s+\w+`), ip: 2, mac: 3, iface: 1},
	},
	CiscoASA: locatorDriver{
		ipCmd:  "show arp",
		ipSpec: &rowSpec{re: rowRe(`^\s*(\S+)\s+(` + reIPv4 + `)\s+(` + reMACDotted + `)\s+\d+`), ip: 2, mac: 3, iface: 1},
	},
	Junos: locatorDriver{
		style: MACColon, macCmd: `show ethernet-switching table | match %s`,
		macSpec: &rowSpec{re: rowRe(`^\s*(\S+)\s+(` + reMACColon + `)\s+\S+\s+\S+\s+(\S+)`), mac: 2, iface: 3, vlanNameC: 1},
		ipCmd:   `show arp no-resolve | match %s`,
		ipSpec:  &rowSpec{re: rowRe(`^\s*(` + reMACColon + `)\s+(` + reIPv4 + `)\s+\S+\s+(\S+)`), mac: 1, ip: 2, iface: 3},
	},
	Huawei: locatorDriver{
		style: MACHuawei, macCmd: "display mac-address %s",
		macSpec: &rowSpec{re: rowRe(`^\s*(` + reMACHyphen + `)\s+(\d+)(?:/\S+)?\s+(\S+)\s+\w+`), mac: 1, vlanC: 2, iface: 3},
		ipCmd:   "display arp | include %s",
		ipSpec:  &rowSpec{re: rowRe(`^\s*(` + reIPv4 + `)\s+(` + reMACHyphen + `)\s+(?:\d+|--)\s+\S+\s+(\S+)(?:\s+(\d+)/\S+)?`), ip: 1, mac: 2, iface: 3, vlanC: 4},
	},
	Fortinet: locatorDriver{
		ipCmd:  "get system arp",
		ipSpec: &rowSpec{re: rowRe(`^\s*(` + reIPv4 + `)\s+\d+\s+(` + reMACColon + `)\s+(\S+)`), ip: 1, mac: 2, iface: 3},
	},
	Arista: locatorDriver{
		style: MACDotted, macCmd: "show mac address-table address %s", macSpec: aristaMAC,
		ipCmd: "show ip arp %s", ipSpec: aristaARP, ipPost: splitSVIPort,
		trunkCmd: "show interfaces trunk",
		trunkRe:  rowRe(`^(\S+)\s+trunk\s+trunking\b`),
	},
	VyOS: locatorDriver{
		ipCmd: "show arp",
		ipSpecs: []*rowSpec{
			// Modern VyOS (1.3/1.4): "Address Interface Link layer address State"
			{re: rowRe(`^\s*(` + reIPv4 + `)\s+(\S+)\s+(` + reMACColon + `)\s+\S+\s*$`), ip: 1, iface: 2, mac: 3},
			// Legacy VyOS: "Address HWtype HWaddress Flags Mask Iface"
			{re: rowRe(`^\s*(` + reIPv4 + `)\s+\w+\s+(` + reMACColon + `)\s+\w+\s+(?:\*\s+)?(\S+)\s*$`), ip: 1, mac: 2, iface: 3},
		},
	},
	Ruijie: locatorDriver{
		style: MACDotted, macCmd: "show mac-address-table address %s",
		macSpec: &rowSpec{re: rowRe(`^\s*(\d+)\s+(` + reMACDotted + `)\s+\w+\s+(.+?)\s*$`), mac: 2, iface: 3, vlanC: 1},
		ipCmd:   "show arp",
		ipSpec:  &rowSpec{re: rowRe(`^\s*\S+\s+(` + reIPv4 + `)\s+\S+\s+(` + reMACDotted + `)\s+\S+\s+(.+?)\s*$`), ip: 1, mac: 2, iface: 3},
	},
	// Aruba: AOS-CX.
	Aruba: locatorDriver{
		style: MACColon, macCmd: "show mac-address-table | include %s",
		macSpec: &rowSpec{re: rowRe(`^\s*(` + reMACColon + `)\s+(\d+)\s+\w+\s+(\S+)`), mac: 1, vlanC: 2, iface: 3},
		ipCmd:   "show arp | include %s",
		ipSpec:  &rowSpec{re: rowRe(`^\s*(` + reIPv4 + `)\s+(` + reMACColon + `)\s+(\S+)\s+(\S+)`), ip: 1, mac: 2, iface: 4, vlanNameC: 3},
	},
	CheckPoint: locatorDriver{
		ipCmd:  "show arp dynamic all",
		ipSpec: &rowSpec{re: rowRe(`^\s*(` + reIPv4 + `)\s+(?:\w+\s+)?(` + reMACColon + `)\s+(?:\w+\s+)?(\S+)\s*$`), ip: 1, mac: 2, iface: 3},
	},
	PaloAlto: locatorDriver{
		ipCmd:  "show arp all",
		ipSpec: &rowSpec{re: rowRe(`^\s*(\S+)\s+(` + reIPv4 + `)\s+(` + reMACColon + `)\s+(\S+)\s+\w\s+\d+`), ip: 2, mac: 3, iface: 4},
	},
	PfSense: locatorDriver{
		ipCmd:  "arp -an",
		ipSpec: &rowSpec{re: rowRe(`\((` + reIPv4 + `)\) at (` + reMACColon + `) on (\S+)`), ip: 1, mac: 2, iface: 3},
	},
	// Sophos: no table command verified; left unsupported.
}

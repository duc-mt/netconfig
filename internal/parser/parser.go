// Package parser extracts structured data (JSON-serializable maps and structs)
// from raw text outputs produced by operational network show/display/get commands.
package parser

import (
	"regexp"
	"strings"
	"unicode"
)

// InterfaceInfo represents structured network interface state.
type InterfaceInfo struct {
	Interface string `json:"interface"`
	IPAddress string `json:"ip_address,omitempty"`
	Status    string `json:"status,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Admin     string `json:"admin,omitempty"`
	Link      string `json:"link,omitempty"`
	Proto     string `json:"proto,omitempty"`
	Local     string `json:"local,omitempty"`
	Method    string `json:"method,omitempty"`
	OK        string `json:"ok,omitempty"`
}

// RouteInfo represents a parsed routing table entry.
type RouteInfo struct {
	Protocol  string `json:"protocol"`
	Network   string `json:"network"`
	Gateway   string `json:"gateway,omitempty"`
	NextHop   string `json:"next_hop,omitempty"`
	Interface string `json:"interface,omitempty"`
	Metric    string `json:"metric,omitempty"`
	Distance  string `json:"distance,omitempty"`
}

var (
	reShowIntBrief = regexp.MustCompile(`(?i)(?:show\s+ip(?:v6)?\s+int(?:erface)?\s+br(?:ief)?|display\s+ip\s+int(?:erface)?\s+br(?:ief)?)`)
	reShowIntTerse = regexp.MustCompile(`(?i)show\s+int(?:erfaces)?\s+terse`)
	reShowVyOSInt  = regexp.MustCompile(`(?i)show\s+int(?:erfaces)?$`)
	reShowVersion  = regexp.MustCompile(`(?i)(?:show\s+version|display\s+version|get\s+system\s+status|show\s+system\s+info)`)
	reShowRoute    = regexp.MustCompile(`(?i)(?:show\s+ip(?:v6)?\s+route|display\s+ip\s+routing-table|show\s+route|get\s+router\s+info\s+routing-table.*)`)
)

// ParseCommandOutput parses raw command output into structured data based on the command.
// If specialized parsers do not match or cannot parse, it falls back to generic table parsing,
// then generic key-value parsing, then returns a list of non-empty text lines.
func ParseCommandOutput(cmd, output string) any {
	cleanOut := cleanTerminal(output)
	normCmd := strings.TrimSpace(cmd)

	switch {
	case reShowIntBrief.MatchString(normCmd):
		if res, ok := ParseInterfaceBrief(cleanOut); ok && len(res) > 0 {
			return res
		}
	case reShowIntTerse.MatchString(normCmd):
		if res, ok := ParseJunosInterfacesTerse(cleanOut); ok && len(res) > 0 {
			return res
		}
	case reShowVyOSInt.MatchString(normCmd):
		if res, ok := ParseVyOSInterfaces(cleanOut); ok && len(res) > 0 {
			return res
		}
	case reShowVersion.MatchString(normCmd):
		if res, ok := ParseVersion(cleanOut); ok && len(res) > 0 {
			return res
		}
	case reShowRoute.MatchString(normCmd):
		if res, ok := ParseRouteTable(cleanOut); ok && len(res) > 0 {
			return res
		}
	}

	// Fall back to generic table parser
	if tbl, ok := ParseTable(cleanOut); ok && len(tbl) > 0 {
		return tbl
	}

	// Fall back to generic key-value parser
	if kv, ok := ParseKeyValue(cleanOut); ok && len(kv) > 1 {
		return kv
	}

	// Fall back to trimmed non-empty lines
	lines := splitNonEmpty(cleanOut)
	if len(lines) == 1 {
		return lines[0]
	}
	return lines
}

// ParseInterfaceBrief parses "show ip interface brief" (Cisco, Arista, Fortinet)
// and multi-vendor operational interface tables (Huawei, Cisco SB, Aruba, Junos, Check Point).
func ParseInterfaceBrief(output string) ([]InterfaceInfo, bool) {
	clean := cleanTerminal(output)

	// 1. Juniper Junos "show interfaces terse"
	if strings.Contains(clean, "Interface") && strings.Contains(clean, "Admin") && strings.Contains(clean, "Link") {
		return ParseJunosInterfacesTerse(clean)
	}

	// 2. Cisco Small Business "show interfaces status"
	if (strings.Contains(clean, "Flow") && strings.Contains(clean, "State")) ||
		(strings.Contains(clean, "Port") && strings.Contains(clean, "Duplex") && strings.Contains(clean, "Speed")) {
		if res, ok := parseCiscoSBInterfaceStatus(clean); ok && len(res) > 0 {
			return res, true
		}
	}

	// 3. Aruba AOS-S "show interfaces brief"
	if strings.Contains(clean, "Status and Counters - Port Status") ||
		(strings.Contains(clean, "Port") && strings.Contains(clean, "Enabled") && strings.Contains(clean, "Status")) {
		if res, ok := parseArubaInterfaceBrief(clean); ok && len(res) > 0 {
			return res, true
		}
	}

	// 4. Fortinet FortiOS "get system interface physical"
	if (strings.Contains(clean, "==[") || strings.Contains(clean, "== [")) && (strings.Contains(clean, "status:") || strings.Contains(clean, "mode:")) {
		if res, ok := parseFortinetInterfacePhysical(clean); ok && len(res) > 0 {
			return res, true
		}
	}

	// 5. Check Point Gaia "show interfaces"
	if (strings.Contains(clean, "name:") && strings.Contains(clean, "status:")) ||
		(strings.Contains(clean, "Interface ") && strings.Contains(clean, "State:")) {
		if res, ok := parseCheckPointInterfaces(clean); ok && len(res) > 0 {
			return res, true
		}
	}

	// 6. Huawei "display interface brief"
	if strings.Contains(clean, "Interface") && strings.Contains(clean, "PHY") && strings.Contains(clean, "Protocol") {
		if res, ok := parseHuaweiInterfaceBrief(clean); ok && len(res) > 0 {
			return res, true
		}
	}

	// 7. Ruijie RGOS "show interfaces status"
	if strings.Contains(clean, "Interface") && strings.Contains(clean, "Status") && strings.Contains(clean, "Duplex") && strings.Contains(clean, "Speed") && strings.Contains(clean, "Type") {
		if res, ok := parseRuijieInterfaceStatus(clean); ok && len(res) > 0 {
			return res, true
		}
	}

	// 8. Standard Cisco / Huawei IP interface brief tables
	lines := strings.Split(clean, "\n")
	var result []InterfaceInfo
	headerIdx := -1

	for i, line := range lines {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), "interface") &&
			(strings.Contains(strings.ToLower(l), "ip-address") ||
				strings.Contains(strings.ToLower(l), "ip address") ||
				strings.Contains(strings.ToLower(l), "physical")) {
			headerIdx = i
			break
		}
	}

	if headerIdx == -1 {
		return nil, false
	}

	for i := headerIdx + 1; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Cisco format: Interface IP-Address OK? Method Status Protocol
		// Status might be two words: "administratively down"
		if len(fields) >= 6 && (fields[2] == "YES" || fields[2] == "NO") {
			status := fields[4]
			protocol := fields[5]
			if len(fields) >= 7 && strings.EqualFold(fields[4], "administratively") && strings.EqualFold(fields[5], "down") {
				status = "administratively down"
				protocol = fields[6]
			}
			result = append(result, InterfaceInfo{
				Interface: fields[0],
				IPAddress: fields[1],
				OK:        fields[2],
				Method:    fields[3],
				Status:    status,
				Protocol:  protocol,
			})
			continue
		}

		// Huawei format: Interface IP Address/Mask Physical Protocol
		if len(fields) >= 4 {
			result = append(result, InterfaceInfo{
				Interface: fields[0],
				IPAddress: fields[1],
				Status:    fields[2],
				Protocol:  fields[3],
			})
		}
	}

	return result, len(result) > 0
}

func parseHuaweiInterfaceBrief(output string) ([]InterfaceInfo, bool) {
	lines := strings.Split(output, "\n")
	var result []InterfaceInfo
	headerIdx := -1
	for i, line := range lines {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "Interface") && strings.Contains(l, "PHY") && strings.Contains(l, "Protocol") {
			headerIdx = i
			break
		}
	}
	if headerIdx == -1 {
		return nil, false
	}
	for i := headerIdx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "PHY:") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "(") || strings.HasPrefix(line, "InUti") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		phy := fields[1]
		proto := fields[2]
		status := "down"
		if strings.HasPrefix(strings.ToLower(phy), "up") {
			status = "up"
		} else if strings.HasPrefix(phy, "*") {
			status = "administratively down"
		}
		result = append(result, InterfaceInfo{
			Interface: fields[0],
			Status:    status,
			Protocol:  proto,
		})
	}
	return result, len(result) > 0
}

func parseRuijieInterfaceStatus(output string) ([]InterfaceInfo, bool) {
	lines := strings.Split(output, "\n")
	var result []InterfaceInfo
	headerIdx := -1
	for i, line := range lines {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "Interface") && strings.Contains(l, "Status") && strings.Contains(l, "Duplex") && strings.Contains(l, "Speed") {
			headerIdx = i
			break
		}
	}
	if headerIdx == -1 {
		return nil, false
	}
	for i := headerIdx + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		intfName := fields[0]
		status := fields[1]
		if (strings.HasPrefix(fields[0], "Gigabit") || strings.HasPrefix(fields[0], "TenGigabit") || strings.HasPrefix(fields[0], "Fast")) && len(fields) >= 3 {
			intfName = fields[0] + " " + fields[1]
			status = fields[2]
		}
		result = append(result, InterfaceInfo{
			Interface: intfName,
			Status:    status,
		})
	}
	return result, len(result) > 0
}

var reCiscoSBPort = regexp.MustCompile(`(?i)^(fa\d+|gi\d+|ge\d+|te\d+|po\d+|eth\d+|e\d+|\d+/\d+(?:/\d+)?)\s+`)

func parseCiscoSBInterfaceStatus(output string) ([]InterfaceInfo, bool) {
	lines := strings.Split(output, "\n")
	var result []InterfaceInfo
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "Port") || strings.HasPrefix(trimmed, "---") {
			continue
		}
		if !reCiscoSBPort.MatchString(trimmed) {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		port := fields[0]
		status := "down"
		for _, f := range fields[1:] {
			if strings.EqualFold(f, "up") {
				status = "up"
				break
			}
			if strings.EqualFold(f, "down") {
				status = "down"
				break
			}
		}
		result = append(result, InterfaceInfo{
			Interface: port,
			Status:    status,
		})
	}
	return result, len(result) > 0
}

var reArubaPort = regexp.MustCompile(`^\s*([0-9]+|[A-Z][0-9]+)\s+`)

func parseArubaInterfaceBrief(output string) ([]InterfaceInfo, bool) {
	lines := strings.Split(output, "\n")
	var result []InterfaceInfo
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "Port") || strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "Status") {
			continue
		}
		if !reArubaPort.MatchString(trimmed) {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		port := fields[0]
		status := "down"
		for _, f := range fields[1:] {
			if strings.EqualFold(f, "up") {
				status = "up"
				break
			}
			if strings.EqualFold(f, "down") {
				status = "down"
				break
			}
		}
		result = append(result, InterfaceInfo{
			Interface: port,
			Status:    status,
		})
	}
	return result, len(result) > 0
}

var reFortiStatusUp = regexp.MustCompile(`(?i)status:\s*up`)

var reFortiPortHeader = regexp.MustCompile(`==\s*\[([^\]]+)\]`)

func parseFortinetInterfacePhysical(output string) ([]InterfaceInfo, bool) {
	locs := reFortiPortHeader.FindAllStringSubmatchIndex(output, -1)
	if len(locs) == 0 {
		return nil, false
	}
	var result []InterfaceInfo
	for i := 0; i < len(locs); i++ {
		name := output[locs[i][2]:locs[i][3]]
		if name == "onboard" || name == "slot" {
			continue // container category header
		}
		end := len(output)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		body := output[locs[i][1]:end]
		status := "down"
		if reFortiStatusUp.MatchString(body) {
			status = "up"
		}
		result = append(result, InterfaceInfo{
			Interface: name,
			Status:    status,
		})
	}
	return result, len(result) > 0
}

var reCPName = regexp.MustCompile(`(?i)name:\s*(\S+)`)
var reCPStatus = regexp.MustCompile(`(?i)status:\s*(\S+)`)
var reCPIfName = regexp.MustCompile(`(?i)Interface\s+(\S+):`)
var reCPState = regexp.MustCompile(`(?i)State:\s*(\S+)`)

func parseCheckPointInterfaces(output string) ([]InterfaceInfo, bool) {
	var result []InterfaceInfo
	lines := strings.Split(output, "\n")
	currName := ""
	for _, line := range lines {
		if m := reCPName.FindStringSubmatch(line); len(m) > 1 {
			currName = m[1]
			continue
		}
		if currName != "" {
			if m := reCPStatus.FindStringSubmatch(line); len(m) > 1 {
				st := strings.ToLower(m[1])
				status := "down"
				if strings.Contains(st, "up") || strings.Contains(st, "full") || strings.Contains(st, "half") || strings.Contains(st, "1/") || strings.Contains(st, "2.5/") || strings.Contains(st, "10/") {
					status = "up"
				}
				result = append(result, InterfaceInfo{
					Interface: currName,
					Status:    status,
				})
				currName = ""
			}
		}
	}

	if len(result) == 0 {
		// Fallback for "Interface eth0:\n State: Up"
		for _, line := range lines {
			if m := reCPIfName.FindStringSubmatch(line); len(m) > 1 {
				currName = m[1]
				continue
			}
			if currName != "" {
				if m := reCPState.FindStringSubmatch(line); len(m) > 1 {
					st := strings.ToLower(m[1])
					status := "down"
					if strings.Contains(st, "up") {
						status = "up"
					}
					result = append(result, InterfaceInfo{
						Interface: currName,
						Status:    status,
					})
					currName = ""
				}
			}
		}
	}

	return result, len(result) > 0
}

// ParseJunosInterfacesTerse parses Junos "show interfaces terse".
func ParseJunosInterfacesTerse(output string) ([]InterfaceInfo, bool) {
	lines := strings.Split(output, "\n")
	var result []InterfaceInfo
	headerIdx := -1

	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Interface") && strings.Contains(line, "Admin") && strings.Contains(line, "Link") {
			headerIdx = i
			break
		}
	}
	if headerIdx == -1 {
		return nil, false
	}

	currentParent := ""
	for i := headerIdx + 1; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			currentParent = fields[0]
			result = append(result, InterfaceInfo{
				Interface: fields[0],
				Admin:     fields[1],
				Link:      fields[2],
				Status:    fields[2],
			})
			if len(fields) >= 5 {
				result[len(result)-1].Proto = fields[3]
				result[len(result)-1].Local = fields[4]
			}
		} else {
			// Sub-interface continuation
			proto := fields[0]
			local := ""
			if len(fields) > 1 {
				local = fields[1]
			}
			result = append(result, InterfaceInfo{
				Interface: currentParent,
				Proto:     proto,
				Local:     local,
			})
		}
	}
	return result, len(result) > 0
}

// ParseVyOSInterfaces parses VyOS "show interfaces".
func ParseVyOSInterfaces(output string) ([]InterfaceInfo, bool) {
	lines := strings.Split(output, "\n")
	var result []InterfaceInfo
	headerIdx := -1

	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Interface") && strings.Contains(line, "IP Address") {
			headerIdx = i
			break
		}
	}
	if headerIdx == -1 {
		return nil, false
	}

	for i := headerIdx + 1; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r\n")
		if strings.HasPrefix(strings.TrimSpace(line), "---") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		inf := InterfaceInfo{Interface: fields[0]}
		if len(fields) >= 3 && strings.Contains(fields[2], "/") {
			inf.IPAddress = fields[1]
			inf.Status = fields[2]
		} else if len(fields) >= 2 {
			if strings.Contains(fields[1], "/") && !strings.Contains(fields[1], ".") {
				inf.Status = fields[1]
			} else {
				inf.IPAddress = fields[1]
			}
		}
		result = append(result, inf)
	}
	return result, len(result) > 0
}

// ParseVersion extracts device software version, uptime, hardware model and serial number.
func ParseVersion(output string) (map[string]string, bool) {
	res := make(map[string]string)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		// Cisco IOS / Arista Version
		if strings.Contains(lower, "version ") && res["version"] == "" {
			parts := strings.Split(line, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(strings.ToLower(p), "version ") {
					res["version"] = strings.TrimPrefix(p, "Version ")
					break
				}
			}
		}

		// Uptime
		if strings.Contains(lower, "uptime is ") {
			idx := strings.Index(lower, "uptime is ")
			res["uptime"] = strings.TrimSpace(line[idx+10:])
		}

		// System image
		if strings.Contains(lower, "system image file is ") {
			idx := strings.Index(lower, "system image file is ")
			res["system_image"] = strings.Trim(strings.TrimSpace(line[idx+21:]), `"`)
		}

		// Hardware model
		if (strings.HasPrefix(lower, "cisco ") || strings.HasPrefix(lower, "arista ")) &&
			strings.Contains(lower, "processor") && res["model"] == "" {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				res["model"] = fields[1]
			}
		}

		// Serial number
		if strings.Contains(lower, "processor board id") {
			idx := strings.Index(lower, "processor board id")
			res["serial_number"] = strings.TrimSpace(line[idx+18:])
		}

		// Huawei format: VRP (R) software, Version 5.170 ...
		if strings.Contains(line, "VRP (R) software, Version") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "Version" && i+1 < len(fields) {
					res["version"] = strings.Trim(fields[i+1], ",")
				}
			}
		}

		// Fortinet format: FortiGate-VM64 v7.0.5...
		if strings.HasPrefix(line, "Version:") {
			res["version"] = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
		if strings.HasPrefix(line, "Serial-Number:") {
			res["serial_number"] = strings.TrimSpace(strings.TrimPrefix(line, "Serial-Number:"))
		}
		if strings.HasPrefix(line, "Hostname:") {
			res["hostname"] = strings.TrimSpace(strings.TrimPrefix(line, "Hostname:"))
		}

		// Junos format: Model: srx300, Junos: 20.4R3
		if strings.HasPrefix(line, "Model:") {
			res["model"] = strings.TrimSpace(strings.TrimPrefix(line, "Model:"))
		}
		if strings.HasPrefix(line, "Junos:") {
			res["junos_version"] = strings.TrimSpace(strings.TrimPrefix(line, "Junos:"))
		}
	}

	return res, len(res) > 0
}

var (
	reRouteCisco   = regexp.MustCompile(`^([A-Z*]+)\s+([0-9./]+)(?:\s+\[([0-9/]+)\])?(?:\s+(?:is directly connected|via\s+([0-9.]+)))?(?:,\s+(?:\d+:\d+:\d+,\s+)?([0-9a-zA-Z/._:-]+))?`)
	reRouteHuawei  = regexp.MustCompile(`^([0-9.]+/\d+)\s+([A-Za-z]+)\s+(\d+)\s+(\d+)\s+[A-Za-z]*\s+([0-9.]+)\s+(\S+)`)
	reRouteGeneric = regexp.MustCompile(`^([0-9.]+/\d+)\s+(?:via\s+([0-9.]+)|is directly connected)`)
)

// ParseRouteTable parses routing table outputs across multi-vendor syntaxes.
func ParseRouteTable(output string) ([]RouteInfo, bool) {
	lines := strings.Split(output, "\n")
	var result []RouteInfo

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Codes:") || strings.HasPrefix(line, "Gateway of") || strings.HasPrefix(line, "Destination/Mask") || strings.HasPrefix(line, "Route Table") {
			continue
		}

		if m := reRouteCisco.FindStringSubmatch(line); len(m) >= 3 && m[2] != "" {
			ri := RouteInfo{
				Protocol: strings.TrimSpace(m[1]),
				Network:  strings.TrimSpace(m[2]),
			}
			if len(m) > 3 && m[3] != "" {
				parts := strings.Split(m[3], "/")
				ri.Distance = parts[0]
				if len(parts) > 1 {
					ri.Metric = parts[1]
				}
			}
			if len(m) > 4 && m[4] != "" {
				ri.NextHop = m[4]
				ri.Gateway = m[4]
			}
			if len(m) > 5 && m[5] != "" {
				ri.Interface = m[5]
			}
			result = append(result, ri)
			continue
		}

		if m := reRouteHuawei.FindStringSubmatch(line); len(m) > 6 {
			result = append(result, RouteInfo{
				Network:   m[1],
				Protocol:  m[2],
				Distance:  m[3],
				Metric:    m[4],
				NextHop:   m[5],
				Gateway:   m[5],
				Interface: m[6],
			})
			continue
		}

		if m := reRouteGeneric.FindStringSubmatch(line); len(m) > 1 {
			gw := ""
			if len(m) > 2 {
				gw = m[2]
			}
			result = append(result, RouteInfo{
				Network: m[1],
				Gateway: gw,
				NextHop: gw,
			})
			continue
		}
	}

	return result, len(result) > 0
}

// ParseTable parses generic tabular output by detecting header columns separated by multiple spaces
// or underlined by a divider line (---- ----).
func ParseTable(output string) ([]map[string]string, bool) {
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return nil, false
	}

	headerIdx := -1
	var headers []string
	var colRanges [][2]int

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}

		// Check if the next line is a divider line (e.g. "----  ----")
		if i+1 < len(lines) {
			nextTrimmed := strings.TrimSpace(lines[i+1])
			if len(nextTrimmed) > 4 && isDivider(nextTrimmed) && strings.Contains(nextTrimmed, "-") {
				headerIdx = i
				colRanges = parseDividerSpans(lines[i+1])
				headers = make([]string, len(colRanges))
				for c, rng := range colRanges {
					if rng[0] < len(line) {
						end := rng[1]
						if end > len(line) {
							end = len(line)
						}
						headers[c] = strings.TrimSpace(line[rng[0]:end])
					}
				}
				break
			}
		}

		// Look for a line containing 2 or more capitalized column names separated by 2+ spaces
		words := splitMultiSpace(line)
		if len(words) >= 2 && looksLikeHeader(words) {
			headerIdx = i
			headers = words
			colRanges = computeColumnRanges(line, words)
			break
		}
	}

	if headerIdx == -1 || len(headers) < 2 {
		return nil, false
	}

	// Sanitize header keys
	keys := make([]string, len(headers))
	for i, h := range headers {
		keys[i] = sanitizeKey(h)
	}

	var rows []map[string]string
	startLine := headerIdx + 1
	if startLine < len(lines) && isDivider(strings.TrimSpace(lines[startLine])) {
		startLine++
	}

	for i := startLine; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isDivider(trimmed) {
			continue
		}

		row := make(map[string]string)
		for c, rng := range colRanges {
			if rng[0] >= len(line) {
				continue
			}
			end := rng[1]
			if end > len(line) {
				end = len(line)
			}
			val := strings.TrimSpace(line[rng[0]:end])
			if val != "" && c < len(keys) && keys[c] != "" {
				row[keys[c]] = val
			}
		}
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}

	return rows, len(rows) > 0
}

func parseDividerSpans(divider string) [][2]int {
	var spans [][2]int
	start := -1
	for i, r := range divider {
		if r == '-' || r == '=' {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				spans = append(spans, [2]int{start, i})
				start = -1
			}
		}
	}
	if start != -1 {
		spans = append(spans, [2]int{start, len(divider)})
	}
	for i := 0; i < len(spans)-1; i++ {
		spans[i][1] = spans[i+1][0]
	}
	if len(spans) > 0 {
		spans[len(spans)-1][1] = 9999
	}
	return spans
}

// ParseKeyValue parses lines of "Key: Value" or "Key is Value".
func ParseKeyValue(output string) (map[string]string, bool) {
	res := make(map[string]string)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			k, v, ok = strings.Cut(line, " is ")
		}
		if ok {
			key := sanitizeKey(strings.TrimSpace(k))
			val := strings.TrimSpace(v)
			if key != "" && val != "" && len(key) < 50 {
				res[key] = val
			}
		}
	}
	return res, len(res) > 0
}

func looksLikeHeader(words []string) bool {
	upperCount := 0
	for _, w := range words {
		if len(w) > 0 && (unicode.IsUpper(rune(w[0])) || strings.Contains(w, "-") || strings.Contains(w, "_")) {
			upperCount++
		}
	}
	return float64(upperCount)/float64(len(words)) >= 0.7
}

func isDivider(s string) bool {
	for _, r := range s {
		if r != '-' && r != '=' && r != ' ' && r != '+' {
			return false
		}
	}
	return true
}

func splitMultiSpace(s string) []string {
	var parts []string
	start := -1
	spaces := 0
	for i, r := range s {
		if unicode.IsSpace(r) {
			if start != -1 {
				spaces++
			}
		} else {
			if start == -1 {
				start = i
			} else if spaces >= 2 {
				parts = append(parts, strings.TrimSpace(s[start:i-spaces]))
				start = i
			}
			spaces = 0
		}
	}
	if start != -1 {
		parts = append(parts, strings.TrimSpace(s[start:]))
	}
	return parts
}

func computeColumnRanges(line string, words []string) [][2]int {
	ranges := make([][2]int, len(words))
	cur := 0
	for i, w := range words {
		idx := strings.Index(line[cur:], w)
		if idx == -1 {
			ranges[i] = [2]int{cur, len(line)}
			break
		}
		pos := cur + idx
		ranges[i][0] = pos
		if i > 0 {
			ranges[i-1][1] = pos
		}
		cur = pos + len(w)
	}
	if len(words) > 0 {
		ranges[len(words)-1][1] = 9999
	}
	return ranges
}

func sanitizeKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '/' || r == '.' || r == '_' {
			b.WriteRune('_')
		}
	}
	res := strings.Trim(b.String(), "_")
	for strings.Contains(res, "__") {
		res = strings.ReplaceAll(res, "__", "_")
	}
	return res
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

var reANSI = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func cleanTerminal(s string) string {
	s = reANSI.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

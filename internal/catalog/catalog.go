// ==============================================================================
// File name:     catalog.go
// Description:   Embedded operational and diagnostic command catalog by vendor.
// License:       MIT
// ==============================================================================
package catalog

import (
	"bufio"
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed *.txt
var commandFiles embed.FS

// vendorAliases maps common vendor inputs / inventory aliases to catalog keys.
var vendorAliases = map[string]string{
	"aruba":          "aruba_aos-s",
	"aruba-s":        "aruba_aos-s",
	"aruba_s":        "aruba_aos-s",
	"aruba_aos_s":    "aruba_aos-s",
	"aruba_aos-s":    "aruba_aos-s",
	"procurve":       "aruba_aos-s",
	"aruba-cx":       "aruba_aos-cx",
	"aruba_cx":       "aruba_aos-cx",
	"aruba_aos_cx":   "aruba_aos-cx",
	"aruba_aos-cx":   "aruba_aos-cx",
	"cisco":          "cisco_ios",
	"cisco-ios":      "cisco_ios",
	"cisco_ios":      "cisco_ios",
	"ios":            "cisco_ios",
	"ios-xe":         "cisco_ios",
	"ios_xe":         "cisco_ios",
	"cisco_sb":       "cisco_sb",
	"cisco-sb":       "cisco_sb",
	"cisco_nxos":     "cisco_nxos",
	"cisco-nxos":     "cisco_nxos",
	"nxos":           "cisco_nxos",
	"nexus":          "cisco_nxos",
	"asa":            "asa",
	"cisco_asa":      "asa",
	"cisco-asa":      "asa",
	"checkpoint":     "checkpoint",
	"gaia":           "checkpoint",
	"checkpoint-smb": "checkpoint",
	"dell":           "dell",
	"extreme":        "extreme",
	"fortinet":       "fortinet",
	"fortios":        "fortinet",
	"fortigate":      "fortinet",
	"fgt":            "fortinet",
	"h3c":            "h3c",
	"hp":             "hp",
	"huawei":         "huawei",
	"vrp":            "huawei",
	"juniper":        "juniper",
	"junos":          "juniper",
	"mikrotik":       "mikrotik",
	"routeros":       "mikrotik",
	"nokia":          "nokia",
	"paloalto":       "paloalto",
	"panos":          "paloalto",
	"pan-os":         "paloalto",
	"panorama":       "panorama",
	"pfsense":        "pfsense",
	"ruijie":         "ruijie",
	"rgos":           "ruijie",
	"sonicwall":      "sonicwall",
	"sophos":         "sophos",
	"sfos":           "sophos",
	"watchguard":     "watchguard",
}

// NormalizeVendor resolves an alias to the canonical catalog vendor key.
func NormalizeVendor(vendor string) string {
	v := strings.ToLower(strings.TrimSpace(vendor))
	v = strings.TrimSuffix(v, "_commands.txt")
	v = strings.TrimSuffix(v, ".txt")
	if canon, ok := vendorAliases[v]; ok {
		return canon
	}
	return v
}

// ListVendors returns all available catalog vendor keys in sorted order.
func ListVendors() []string {
	entries, err := commandFiles.ReadDir(".")
	if err != nil {
		return nil
	}
	var list []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, "_commands.txt") {
			key := strings.TrimSuffix(name, "_commands.txt")
			list = append(list, key)
		}
	}
	sort.Strings(list)
	return list
}

// GetRawContent returns the full unmodified command file content (including comments).
func GetRawContent(vendor string) (string, error) {
	key := NormalizeVendor(vendor)
	filename := key + "_commands.txt"
	data, err := commandFiles.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("vendor %q not found in catalog (available: %s)", vendor, strings.Join(ListVendors(), ", "))
	}
	return string(data), nil
}

// GetCommands extracts executable non-empty, non-comment lines for the vendor.
func GetCommands(vendor string) ([]string, error) {
	content, err := GetRawContent(vendor)
	if err != nil {
		return nil, err
	}

	var cmds []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cmds = append(cmds, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading commands for %s: %w", vendor, err)
	}
	return cmds, nil
}

// Section represents a titled section of commands in the vendor catalog file.
type Section struct {
	Title    string   `json:"title"`
	Commands []string `json:"commands"`
}

// GetSections parses the catalog file into grouped sections based on '# --- <Title> ---'.
func GetSections(vendor string) ([]Section, error) {
	content, err := GetRawContent(vendor)
	if err != nil {
		return nil, err
	}

	var sections []Section
	currentSection := Section{Title: "General"}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# ---") || strings.HasPrefix(line, "# ===") {
			cleanTitle := strings.Trim(line, "#=- ")
			if cleanTitle != "" && !strings.Contains(cleanTitle, "Healthcheck") {
				if len(currentSection.Commands) > 0 {
					sections = append(sections, currentSection)
				}
				currentSection = Section{Title: cleanTitle}
				continue
			}
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		currentSection.Commands = append(currentSection.Commands, line)
	}
	if len(currentSection.Commands) > 0 {
		sections = append(sections, currentSection)
	}
	return sections, nil
}

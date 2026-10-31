// ==============================================================================
// File name:     catalog_test.go
// Description:   Unit tests for embedded vendor command catalog.
// License:       MIT
// ==============================================================================
package catalog

import (
	"testing"
)

func TestCatalogListVendors(t *testing.T) {
	vendors := ListVendors()
	if len(vendors) < 15 {
		t.Fatalf("expected at least 15 vendors, got %d: %v", len(vendors), vendors)
	}

	expected := []string{"aruba_aos-cx", "aruba_aos-s", "cisco_ios", "cisco_nxos", "checkpoint", "fortinet", "huawei", "juniper", "ruijie"}
	for _, exp := range expected {
		found := false
		for _, v := range vendors {
			if v == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected vendor %q in catalog list", exp)
		}
	}
}

func TestCatalogGetCommands(t *testing.T) {
	tests := []struct {
		vendor    string
		minCmds   int
		sampleCmd string
	}{
		{"cisco_ios", 10, "show version"},
		{"cisco", 10, "show ip interface brief"},
		{"aruba_aos-s", 10, "show system"},
		{"checkpoint", 5, "show software-version"},
		{"fortinet", 5, "get system status"},
		{"huawei", 10, "display version"},
		{"juniper", 10, "show interfaces terse"},
		{"ruijie", 10, "show version"},
	}

	for _, tt := range tests {
		t.Run(tt.vendor, func(t *testing.T) {
			cmds, err := GetCommands(tt.vendor)
			if err != nil {
				t.Fatalf("GetCommands(%q) error: %v", tt.vendor, err)
			}
			if len(cmds) < tt.minCmds {
				t.Errorf("GetCommands(%q) returned %d commands, want >= %d", tt.vendor, len(cmds), tt.minCmds)
			}
			found := false
			for _, c := range cmds {
				if c == tt.sampleCmd {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("GetCommands(%q) did not contain %q", tt.vendor, tt.sampleCmd)
			}
		})
	}
}

func TestCatalogGetRawContent(t *testing.T) {
	raw, err := GetRawContent("cisco_ios")
	if err != nil {
		t.Fatalf("GetRawContent failed: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("GetRawContent returned empty string")
	}

	_, errNotFound := GetRawContent("nonexistent_vendor_xyz")
	if errNotFound == nil {
		t.Fatal("expected error for nonexistent vendor")
	}
}

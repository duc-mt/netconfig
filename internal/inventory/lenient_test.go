// ==============================================================================
// File name:     lenient_test.go
// Description:   Tests for the forgiving inventory loader used by "netops log".
// License:       MIT
// ==============================================================================

package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadLenient(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "inventory.csv")
	content := `hostname,address,port,vendor,credential_group
# Comment line
core-sw-01,10.10.1.1,22,cisco_ios,site_a
dc-fw-01,10.20.1.1,,fortigate,site_b
edge-rtr-01,10.30.1.1,2222,juniper_junos
"quoted-sw",10.40.1.1,22,aruba,datacenter
bad-line
invalid-port,10.50.1.1,99999,cisco_ios
`
	if err := os.WriteFile(csvPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp csv: %v", err)
	}

	devices, warnings := LoadLenient(csvPath)
	if len(devices) != 4 {
		t.Fatalf("expected 4 valid devices, got %d", len(devices))
	}
	if len(warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d: %v", len(warnings), warnings)
	}
	if devices[0].Hostname != "core-sw-01" || devices[0].Group != "site_a" {
		t.Errorf("unexpected device 0: %+v", devices[0])
	}
	if devices[1].Hostname != "dc-fw-01" || devices[1].Port != 22 || devices[1].Group != "site_b" {
		t.Errorf("unexpected device 1: %+v", devices[1])
	}
	if devices[2].Port != 2222 || devices[2].Group != DefaultGroup {
		t.Errorf("unexpected device 2: %+v", devices[2])
	}
	if devices[3].Hostname != "quoted-sw" || devices[3].Group != "datacenter" {
		t.Errorf("unexpected device 3: %+v", devices[3])
	}
}

func TestLoadLenientMissingFile(t *testing.T) {
	devices, warnings := LoadLenient(filepath.Join(t.TempDir(), "nope.csv"))
	if len(devices) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0].Error(), "opening inventory file") {
		t.Fatalf("devices=%v warnings=%v", devices, warnings)
	}
}

func TestParseLenientDefaultsAndJump(t *testing.T) {
	devs, warns := ParseLenient(strings.NewReader("sw1,10.0.0.1\nsw2,10.0.0.2,830,Junos,DC1,Bastion-A\n"))
	if len(warns) != 0 || len(devs) != 2 {
		t.Fatalf("devs=%+v warns=%v", devs, warns)
	}
	if d := devs[0]; d.Port != DefaultPort || d.Vendor != DefaultLogVendor || d.Group != DefaultGroup || d.JumpHost != "" {
		t.Errorf("defaults not applied: %+v", d)
	}
	if d := devs[1]; d.Port != 830 || d.Vendor != "junos" || d.Group != "dc1" || d.JumpHost != "bastion-a" {
		t.Errorf("row parsed wrong: %+v", d)
	}
}

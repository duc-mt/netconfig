// ==============================================================================
// File name:     retention_test.go
// Description:   Tests that finding and pruning backups touches only one device's files.
// License:       MIT
// ==============================================================================
package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netconfig/internal/inventory"
	"netconfig/internal/vendor"
)

// historyFile writes one backup of a device in a run and dates it so that
// higher run numbers are newer.
func historyFile(t *testing.T, root string, run int, platformDir, name string) string {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprintf("backup-2026-10-%02d-0100", run), platformDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-time.Duration(40-run) * time.Hour)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
	return path
}

func existing(paths []string) (n int) {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			n++
		}
	}
	return n
}

// Retention deletes what it considers a device's own old backups. A device
// whose name merely starts with another's ("core" and "core_backup", "sw_1" and
// "sw_1_lab") must not lose its history to the shorter name's retention.
func TestPruneNeverTouchesAnotherDevicesBackups(t *testing.T) {
	root := t.TempDir()
	profile, _ := vendor.Lookup("cisco")
	spec := archiveFor(profile)

	pairs := []struct{ short, long string }{{"core", "core_backup"}, {"sw_1", "sw_1_lab"}, {"r1", "r1_"}}
	files := map[string][]string{}
	for _, p := range pairs {
		for run := 1; run <= 12; run++ {
			files[p.short] = append(files[p.short], historyFile(t, root, run, spec.Dir, p.short+spec.Ext))
			files[p.long] = append(files[p.long], historyFile(t, root, run, spec.Dir, p.long+spec.Ext))
		}
	}

	for _, p := range pairs {
		dev := inventory.Device{Hostname: p.short, Address: "10.0.0.1", Vendor: profile.Name}
		matches, err := findMatchingBackups(root, dev, spec.Ext)
		if err != nil || len(matches) != 12 {
			t.Fatalf("%s: found %d backups (%v), want exactly its own 12", p.short, len(matches), err)
		}
		if pruned := pruneBackups(root, dev, spec.Ext, 10, 0); pruned != 2 {
			t.Errorf("%s: pruned %d files, want its own 2", p.short, pruned)
		}
	}
	for _, p := range pairs {
		if n := existing(files[p.long]); n != 12 {
			t.Errorf("%s lost backups to the retention of %s: %d of 12 left", p.long, p.short, n)
		}
		if n := existing(files[p.short]); n != 10 {
			t.Errorf("%s keeps %d backups, want 10", p.short, n)
		}
	}
}

// When two devices share a file name (hostnames that sanitise alike), the
// second is saved as <host>_<address>; that exact name is still its own.
func TestCollisionFileNameIsStillFound(t *testing.T) {
	root := t.TempDir()
	profile, _ := vendor.Lookup("cisco")
	spec := archiveFor(profile)
	dev := inventory.Device{Hostname: "core-sw-01", Address: "10.10.1.1", Vendor: profile.Name}
	alt := "core-sw-01_10_10_1_1" + spec.Ext

	var mine []string
	for run := 1; run <= 5; run++ {
		mine = append(mine, historyFile(t, root, run, spec.Dir, alt))
	}
	other := historyFile(t, root, 5, spec.Dir, "core-sw-01_10_10_9_9"+spec.Ext) // same host, another address

	matches, err := findMatchingBackups(root, dev, spec.Ext)
	if err != nil || len(matches) != 5 {
		t.Fatalf("found %d, want its own 5 collision files (%v)", len(matches), err)
	}
	if pruneBackups(root, dev, spec.Ext, 3, 0) != 2 || existing(mine) != 3 {
		t.Error("retention must prune the collision files of this device")
	}
	if existing([]string{other}) != 1 {
		t.Error("a file with another device's address is not this device's")
	}
}

// Both the plain and the collision name of one device, in one run, are its own.
func TestPlainAndCollisionNamesBothCount(t *testing.T) {
	root := t.TempDir()
	profile, _ := vendor.Lookup("cisco")
	spec := archiveFor(profile)
	dev := inventory.Device{Hostname: "gw", Address: "10.0.0.5", Vendor: profile.Name}
	historyFile(t, root, 1, spec.Dir, "gw"+spec.Ext)
	historyFile(t, root, 2, spec.Dir, "gw_10_0_0_5"+spec.Ext)
	if matches, _ := findMatchingBackups(root, dev, spec.Ext); len(matches) != 2 {
		t.Errorf("found %d, want 2", len(matches))
	}
}

// Backups kept under the netbackup directory name and under the profile's own
// name are both found; the newest wins whichever directory it is in.
func TestFindSpansBothPlatformDirectoryNames(t *testing.T) {
	root := t.TempDir()
	profile, _ := vendor.Lookup("cisco")
	spec := archiveFor(profile)
	dev := inventory.Device{Hostname: "sw1", Address: "10.0.0.1", Vendor: profile.Name}
	historyFile(t, root, 1, spec.Dir, "sw1"+spec.Ext)
	newest := historyFile(t, root, 2, profile.Name, "sw1"+spec.Ext) // a tree written under the profile's name

	matches, _ := findMatchingBackups(root, dev, spec.Ext)
	if len(matches) != 2 || matches[0].path != newest {
		t.Errorf("matches = %+v, want both with %s newest", matches, newest)
	}
}

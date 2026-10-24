// ==============================================================================
// File name:     backup_show_cmd_test.go
// Description:   Tests for the "backup show" subcommand.
// License:       MIT
// ==============================================================================
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// backupTree writes a small backup tree and returns its root.
func backupTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]struct {
		body string
		age  time.Duration
	}{
		"backup-2026-10-01-0100/cisco_ios/core-sw1.cfg":     {"hostname core-sw1\nOLD\n", 48 * time.Hour},
		"backup-2026-10-02-0100/cisco_ios/core-sw1.cfg":     {"hostname core-sw1\nNEW\n", 24 * time.Hour},
		"backup-2026-10-02-0100/cisco_ios/core-sw1.diff":    {"+NEW\n-OLD\n", 24 * time.Hour},
		"backup-2026-10-02-0100/cisco_ios/core-sw10.cfg":    {"hostname core-sw10\n", 24 * time.Hour},
		"backup-2026-10-01-0100/juniper_junos/edge-mx1.set": {"set system host-name edge-mx1\n", 48 * time.Hour},
		"backup-2026-10-02-0100/fortigate/fw-1.conf":        {"config system global\nend\n", 24 * time.Hour},
		"backup-2026-10-02-0100/cisco_ios/gw-a1.cfg":        {"gw-a1\n", 24 * time.Hour},
		"backup-2026-10-02-0100/cisco_ios/gw-a2.cfg":        {"gw-a2\n", 24 * time.Hour},
	}
	for rel, f := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-f.age)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// backupShow runs the subcommand with a non-terminal stdin and captured output.
func backupShow(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	in, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out, errb bytes.Buffer
	code = runBackupShow(args, in, &out, &errb)
	return code, out.String(), errb.String()
}

func TestShowBackupListsNodes(t *testing.T) {
	root := backupTree(t)
	code, out, _ := backupShow(t, "-backup-dir", root, "-l")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := "Available nodes in backup history:\n  - core-sw1\n  - core-sw10\n  - edge-mx1\n  - fw-1\n  - gw-a1\n  - gw-a2\n"
	if out != want {
		t.Errorf("list output:\n got  %q\n want %q", out, want)
	}
	// every platform shows up, not just the one whose extension the old script knew
	for _, n := range []string{"edge-mx1", "fw-1"} {
		if !strings.Contains(out, n) {
			t.Errorf("%s missing from the list", n)
		}
	}
}

func TestShowBackupMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	for _, args := range [][]string{{"-backup-dir", missing, "-l"}, {"-backup-dir", missing, "core"}} {
		code, _, errOut := backupShow(t, args...)
		if code != 1 || !strings.Contains(errOut, missing) || !strings.Contains(errOut, "not found") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut)
		}
	}
}

func TestShowBackupPrintsThePathOfTheNewestFile(t *testing.T) {
	root := backupTree(t)
	code, out, _ := backupShow(t, "-backup-dir", root, "-p", "core-sw1")
	want := filepath.Join(root, "backup-2026-10-02-0100", "cisco_ios", "core-sw1.cfg") + "\n"
	if code != 0 || out != want {
		t.Errorf("exit %d, out %q, want %q", code, out, want)
	}

	// an exact name wins over a longer name that merely contains it
	_, out, _ = backupShow(t, "-backup-dir", root, "-p", "CORE-SW1")
	if out != want {
		t.Errorf("case-insensitive exact match: %q", out)
	}
}

func TestShowBackupAcceptsFlagsAfterTheNodeAndTheOutAlias(t *testing.T) {
	root := backupTree(t)
	code, out, _ := backupShow(t, "core-sw1", "-p", "-out", root)
	if code != 0 || !strings.HasSuffix(strings.TrimSpace(out), "core-sw1.cfg") {
		t.Errorf("exit %d, out %q", code, out)
	}
}

func TestShowBackupUniqueSubstringMatch(t *testing.T) {
	root := backupTree(t)
	code, out, _ := backupShow(t, "-backup-dir", root, "-p", "edge")
	if code != 0 || !strings.HasSuffix(strings.TrimSpace(out), filepath.Join("juniper_junos", "edge-mx1.set")) {
		t.Errorf("exit %d, out %q", code, out)
	}
}

func TestShowBackupDisplaysTheFileWhenNotOnATerminal(t *testing.T) {
	root := backupTree(t)
	code, out, _ := backupShow(t, "-backup-dir", root, "core-sw1")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(out, "==> Latest config for 'core-sw1': ") {
		t.Errorf("missing header: %q", out)
	}
	if !strings.Contains(out, "NEW\n") || strings.Contains(out, "OLD") {
		t.Errorf("must show the newest configuration only: %q", out)
	}
}

func TestShowBackupDiff(t *testing.T) {
	root := backupTree(t)
	code, out, _ := backupShow(t, "-backup-dir", root, "-d", "core-sw1")
	if code != 0 || !strings.Contains(out, "==> Latest diff for 'core-sw1'") || !strings.Contains(out, "+NEW\n-OLD\n") {
		t.Errorf("exit %d, out %q", code, out)
	}

	// edge-mx1 has a configuration but never changed, so no diff
	code, _, errOut := backupShow(t, "-backup-dir", root, "-d", "edge-mx1")
	if code != 1 || !strings.Contains(errOut, "No diff files found matching 'edge-mx1'") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

func TestShowBackupNoMatchSuggestsTheList(t *testing.T) {
	code, _, errOut := backupShow(t, "-backup-dir", backupTree(t), "ghost")
	if code != 1 || !strings.Contains(errOut, "No config files found matching 'ghost'") ||
		!strings.Contains(errOut, "netconfig backup show -l") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

func TestShowBackupAmbiguousWithoutATerminalListsTheCandidates(t *testing.T) {
	code, out, errOut := backupShow(t, "-backup-dir", backupTree(t), "gw-a")
	if code != 1 || out != "" {
		t.Errorf("exit %d, stdout %q", code, out)
	}
	for _, want := range []string{"Multiple nodes match 'gw-a'", "  - gw-a1", "  - gw-a2", "Please be more specific"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr missing %q: %q", want, errOut)
		}
	}
}

func TestShowBackupUsageErrors(t *testing.T) {
	root := backupTree(t)
	for name, args := range map[string][]string{
		"no node":       {"-backup-dir", root},
		"two nodes":     {"-backup-dir", root, "a", "b"},
		"unknown flag":  {"-backup-dir", root, "-zzz", "a"},
		"directory arg": {"-backup-dir"},
	} {
		if code, _, _ := backupShow(t, args...); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
	}
	if code, _, errOut := backupShow(t, "-h"); code != 0 || !strings.Contains(errOut, "netconfig backup show") {
		t.Errorf("-h: exit %d, stderr %q", code, errOut)
	}
}

func TestSelectNode(t *testing.T) {
	cands := []string{"gw-a1", "gw-a2", "gw-b1"}
	tests := []struct {
		name, input string
		want        string
		ok          bool
	}{
		{"valid choice", "2\n", "gw-a2", true},
		{"first", "1\n", "gw-a1", true},
		{"retries after an invalid answer", "9\nabc\n0\n3\n", "gw-b1", true},
		{"quit", "q\n", "", false},
		{"quit upper-case", "Q\n", "", false},
		{"end of input", "", "", false},
	}
	for _, tt := range tests {
		var out bytes.Buffer
		got, ok := selectNode(strings.NewReader(tt.input), &out, cands, "gw")
		if got != tt.want || ok != tt.ok {
			t.Errorf("%s: got %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.ok)
		}
		if !strings.Contains(out.String(), "Multiple nodes match 'gw':") || !strings.Contains(out.String(), "[3] gw-b1") {
			t.Errorf("%s: menu not shown: %q", tt.name, out.String())
		}
	}
	var out bytes.Buffer
	selectNode(strings.NewReader("7\n1\n"), &out, cands, "gw")
	if !strings.Contains(out.String(), "Invalid selection. Please enter a number between 1 and 3.") {
		t.Errorf("no hint after an invalid answer: %q", out.String())
	}
}

func TestPagerCommand(t *testing.T) {
	tests := []struct {
		name, pager string
		hasLess     bool
		want        []string
	}{
		{"PAGER wins", "most", true, []string{"most"}},
		{"PAGER with arguments", "less -SR", true, []string{"less", "-SR"}},
		{"less as the default", "", true, []string{"less", "-R"}},
		{"nothing available", "", false, nil},
		{"blank PAGER", "   ", true, []string{"less", "-R"}},
	}
	for _, tt := range tests {
		got := pagerCommand(tt.pager, tt.hasLess)
		if strings.Join(got, "\x00") != strings.Join(tt.want, "\x00") {
			t.Errorf("%s: pagerCommand(%q, %v) = %q, want %q", tt.name, tt.pager, tt.hasLess, got, tt.want)
		}
	}
}

func openDevNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

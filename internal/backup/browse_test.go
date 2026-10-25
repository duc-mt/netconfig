// ==============================================================================
// File name:     browse_test.go
// Description:   Tests for browsing an existing backup tree.
// License:       MIT
// ==============================================================================
package backup

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// put writes a file in the backup tree with the given modification time.
func put(t *testing.T, root, rel string, age time.Duration) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(rel), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
	return p
}

func sampleTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// two runs; the second one is newer
	put(t, root, "backup-2026-10-01-0100/cisco_ios/core-sw1.cfg", 48*time.Hour)
	put(t, root, "backup-2026-10-02-0100/cisco_ios/core-sw1.cfg", 24*time.Hour)
	put(t, root, "backup-2026-10-02-0100/cisco_ios/core-sw1.diff", 24*time.Hour)
	put(t, root, "backup-2026-10-01-0100/juniper_junos/edge-mx1.set", 48*time.Hour)
	put(t, root, "backup-2026-10-02-0100/fortigate/fw-1.conf", 24*time.Hour)
	put(t, root, "backup-2026-10-02-0100/pfsense/gw.xml", 24*time.Hour)
	put(t, root, "backup-2026-10-02-0100/vyos/vy1.config", 24*time.Hour)
	// hostnames with dots keep everything before the extension
	put(t, root, "backup-2026-10-02-0100/cisco_ios/dist.dc1.example.com.cfg", 24*time.Hour)
	// things that are not backups
	put(t, root, "backup-2026-10-02-0100/cisco_ios/.core-sw1.cfg.tmp-123", time.Hour)
	put(t, root, "backup-2026-10-02-0100/cisco_ios/README.txt.tmp", time.Hour)
	put(t, root, "reports/notes/stray.cfg", time.Hour)
	put(t, root, "backup-2026-10-02-0100/toplevel.cfg", time.Hour)
	return root
}

func TestListNodesIsExtensionAgnostic(t *testing.T) {
	// Verify that show looks for all supported extensions across all vendors,
	// rather than only single platform extensions.
	got, err := ListNodes(sampleTree(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"core-sw1", "dist.dc1.example.com", "edge-mx1", "fw-1", "gw", "vy1"}
	if !slices.Equal(got, want) {
		t.Errorf("nodes = %q, want %q", got, want)
	}
}

func TestListNodesMissingDirectory(t *testing.T) {
	_, err := ListNodes(filepath.Join(t.TempDir(), "nope"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want one wrapping os.ErrNotExist", err)
	}
}

func TestListNodesEmptyTree(t *testing.T) {
	got, err := ListNodes(t.TempDir())
	if err != nil || len(got) != 0 {
		t.Errorf("empty tree: %q, %v", got, err)
	}
}

func TestMatchNodes(t *testing.T) {
	nodes := []string{"core-sw1", "core-sw10", "Edge-GW-01", "edge-gw-02", "dist.dc1.example.com"}
	tests := []struct {
		query     string
		wantExact string
		want      []string
	}{
		{"core-sw1", "core-sw1", []string{"core-sw1", "core-sw10"}}, // exact wins over the longer name
		{"CORE-SW1", "core-sw1", []string{"core-sw1", "core-sw10"}}, // case-insensitive
		{"edge-gw-01", "Edge-GW-01", []string{"Edge-GW-01"}},
		{"gw", "", []string{"Edge-GW-01", "edge-gw-02"}},
		{"sw10", "", []string{"core-sw10"}},
		{"nothing", "", nil},
		// the query is text, not a pattern: the shell script fed it to grep
		{"dist.dc1", "", []string{"dist.dc1.example.com"}},
		{"dist-dc1", "", nil},
		{"gw-0.", "", nil},
		{"[", "", nil},
		{"", "", nodes}, // an empty query matches everything; callers reject it earlier
	}
	for _, tt := range tests {
		exact, got := MatchNodes(nodes, tt.query)
		if exact != tt.wantExact || !slices.Equal(got, tt.want) {
			t.Errorf("MatchNodes(%q) = %q, %q; want %q, %q", tt.query, exact, got, tt.wantExact, tt.want)
		}
	}
}

func TestLatestPicksTheNewestFileForTheNode(t *testing.T) {
	root := sampleTree(t)

	got, err := Latest(root, "core-sw1", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "backup-2026-10-02-0100", "cisco_ios", "core-sw1.cfg"); got != want {
		t.Errorf("latest config = %s, want %s", got, want)
	}

	diff, err := Latest(root, "core-sw1", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "backup-2026-10-02-0100", "cisco_ios", "core-sw1.diff"); diff != want {
		t.Errorf("latest diff = %s, want %s", diff, want)
	}

	// other platforms and extensions
	for node, rel := range map[string]string{
		"edge-mx1":             "backup-2026-10-01-0100/juniper_junos/edge-mx1.set",
		"fw-1":                 "backup-2026-10-02-0100/fortigate/fw-1.conf",
		"gw":                   "backup-2026-10-02-0100/pfsense/gw.xml",
		"vy1":                  "backup-2026-10-02-0100/vyos/vy1.config",
		"dist.dc1.example.com": "backup-2026-10-02-0100/cisco_ios/dist.dc1.example.com.cfg",
	} {
		got, err := Latest(root, node, false)
		if err != nil || got != filepath.Join(root, filepath.FromSlash(rel)) {
			t.Errorf("Latest(%q) = %q, %v; want %s", node, got, err, rel)
		}
	}
}

func TestLatestUsesModificationTimeAcrossPlatformDirectories(t *testing.T) {
	// a device that was re-categorised keeps its newest file wherever it is
	root := t.TempDir()
	put(t, root, "backup-2026-10-01-0100/cisco_ios/box.cfg", 48*time.Hour)
	newest := put(t, root, "backup-2026-10-02-0100/cisco_asa/box.cfg", time.Hour)
	got, err := Latest(root, "box", false)
	if err != nil || got != newest {
		t.Errorf("Latest = %q, %v; want %s", got, err, newest)
	}
}

func TestLatestBreaksTiesByRunName(t *testing.T) {
	root := t.TempDir()
	put(t, root, "backup-2026-10-01-0100/cisco_ios/box.cfg", time.Hour)
	later := put(t, root, "backup-2026-10-02-0100/cisco_ios/box.cfg", time.Hour)
	// same age, so same mtime to the second; set exactly equal
	when := time.Now().Add(-time.Hour)
	for _, p := range []string{filepath.Join(root, "backup-2026-10-01-0100/cisco_ios/box.cfg"), later} {
		_ = os.Chtimes(p, when, when)
	}
	if got, _ := Latest(root, "box", false); got != later {
		t.Errorf("a tie must go to the later run: got %s", got)
	}
}

func TestLatestReportsWhatIsMissing(t *testing.T) {
	root := sampleTree(t)
	if _, err := Latest(root, "edge-mx1", true); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no diff exists for edge-mx1: %v", err)
	}
	if _, err := Latest(root, "ghost", false); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unknown node: %v", err)
	}
	if _, err := Latest(filepath.Join(root, "nope"), "x", false); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing dir: %v", err)
	}
}

// A node with only a diff (the config file was pruned) is not "available" as a
// configuration, but is as a diff.
func TestNodesAreTrackedPerKind(t *testing.T) {
	root := t.TempDir()
	put(t, root, "backup-2026-10-01-0100/cisco_ios/only-diff.diff", time.Hour)
	if _, err := Latest(root, "only-diff", false); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config of a diff-only node: %v", err)
	}
	if _, err := Latest(root, "only-diff", true); err != nil {
		t.Errorf("diff of a diff-only node: %v", err)
	}
	if nodes, _ := ListNodes(root); len(nodes) != 0 {
		t.Errorf("a diff-only node must not be listed as having a backup: %q", nodes)
	}
}

// "backup show -d" can only offer devices that have a diff: most devices have
// a configuration but only those that changed have a diff.
func TestListDiffNodes(t *testing.T) {
	got, err := ListDiffNodes(sampleTree(t))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"core-sw1"}; !slices.Equal(got, want) {
		t.Errorf("diff nodes = %q, want %q", got, want)
	}

	root := t.TempDir()
	put(t, root, "backup-2026-10-01-0100/cisco_ios/only-diff.diff", time.Hour)
	if got, _ := ListDiffNodes(root); !slices.Equal(got, []string{"only-diff"}) {
		t.Errorf("diff-only node: %q", got)
	}
	if _, err := ListDiffNodes(filepath.Join(root, "nope")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing dir: %v", err)
	}
}

// A Tree is scanned once: listing, matching and looking up the newest file all
// answer from that one pass over the directory.
func TestTreeAnswersEveryQuestionFromOneScan(t *testing.T) {
	root := sampleTree(t)
	tree, err := ScanTree(root)
	if err != nil {
		t.Fatal(err)
	}
	// the directory is gone: only a cached scan can still answer
	listing := tree.Nodes(false)
	for _, e := range []string{"backup-2026-10-01-0100", "backup-2026-10-02-0100", "reports"} {
		if err := os.RemoveAll(filepath.Join(root, e)); err != nil {
			t.Fatal(err)
		}
	}
	if again := tree.Nodes(false); !slices.Equal(listing, again) || len(listing) != 6 {
		t.Errorf("a second listing must not depend on the directory: %q then %q", listing, again)
	}
	if got := tree.Nodes(true); !slices.Equal(got, []string{"core-sw1"}) {
		t.Errorf("diff nodes = %q", got)
	}
}

func TestTreeLatestAgreesWithTheStandaloneFunctions(t *testing.T) {
	root := sampleTree(t)
	tree, err := ScanTree(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"core-sw1", "edge-mx1", "fw-1", "gw", "vy1", "dist.dc1.example.com"} {
		want, werr := Latest(root, node, false)
		got, gerr := tree.Latest(node, false)
		if got != want || (werr == nil) != (gerr == nil) {
			t.Errorf("%s: tree says %q (%v), Latest says %q (%v)", node, got, gerr, want, werr)
		}
	}
	if _, err := tree.Latest("ghost", false); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unknown node: %v", err)
	}
	if _, err := tree.Latest("edge-mx1", true); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a node without a diff: %v", err)
	}
	if nodes, _ := ListNodes(root); !slices.Equal(nodes, tree.Nodes(false)) {
		t.Errorf("ListNodes %q differs from Tree.Nodes %q", nodes, tree.Nodes(false))
	}
	if _, err := ScanTree(filepath.Join(root, "nope")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing directory: %v", err)
	}
}

package task

import (
	"strconv"
	"strings"
	"testing"
)

func TestDiffConfigAddedAndRemoved(t *testing.T) {
	before := "hostname old\ninterface eth0\n no shutdown\n"
	after := "hostname new\ninterface eth0\n no shutdown\nntp server 1.1.1.1\n"

	lines, added, removed, ok := diffConfig(before, after)
	if !ok {
		t.Fatal("diffConfig reported not ok for small input")
	}
	if added != 2 || removed != 1 {
		t.Fatalf("added/removed = %d/%d, want 2/1 (lines: %v)", added, removed, lines)
	}
	want := map[string]bool{"-hostname old": false, "+hostname new": false, "+ntp server 1.1.1.1": false}
	for _, l := range lines {
		if _, ok := want[l]; ok {
			want[l] = true
		}
	}
	for l, seen := range want {
		if !seen {
			t.Errorf("expected line %q in diff output: %v", l, lines)
		}
	}
	// Unchanged lines must not appear at all.
	for _, l := range lines {
		if strings.Contains(l, "interface eth0") || strings.Contains(l, "no shutdown") {
			t.Errorf("unchanged line leaked into diff output: %q", l)
		}
	}
}

func TestDiffConfigNoChange(t *testing.T) {
	cfg := "hostname sw1\ninterface eth0\n no shutdown\n"
	lines, added, removed, ok := diffConfig(cfg, cfg)
	if !ok {
		t.Fatal("diffConfig reported not ok for small input")
	}
	if len(lines) != 0 || added != 0 || removed != 0 {
		t.Errorf("identical config should produce no diff lines, got %v (added=%d removed=%d)", lines, added, removed)
	}
}

func TestDiffConfigIgnoresBlankLinesAndCR(t *testing.T) {
	before := "hostname sw1\r\n\r\ninterface eth0\r\n"
	after := "hostname sw1\n\ninterface eth0\n"
	lines, added, removed, ok := diffConfig(before, after)
	if !ok {
		t.Fatal("diffConfig reported not ok for small input")
	}
	if len(lines) != 0 || added != 0 || removed != 0 {
		t.Errorf("CRLF vs LF and blank lines should not count as a difference, got %v (added=%d removed=%d)", lines, added, removed)
	}
}

func TestDiffConfigTooLargeIsSkipped(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxDiffLines; i++ {
		b.WriteString("line ")
		b.WriteString(strconv.Itoa(i))
		b.WriteByte('\n')
	}
	before := b.String()
	after := before + "one more line\n"

	_, _, _, ok := diffConfig(before, after)
	if ok {
		t.Error("expected diffConfig to report not ok for input over maxDiffLines")
	}
}

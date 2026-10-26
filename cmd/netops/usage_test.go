// ==============================================================================
// File name:     usage_test.go
// Description:   Tests for grouped help output and the flags shared by commands.
// License:       MIT
// ==============================================================================
package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
	"time"
)

func sampleFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.String("inventory", "inventory.csv", "device list")
	fs.Int("retention-count", 10, "how many to keep")
	fs.Bool("redact", true, "mask secrets")
	fs.Bool("force", false, "save even if unchanged")
	fs.Bool("save-unchanged", false, "alias for -force")
	fs.String("backup-dir", "backups", "where backups go")
	fs.String("out", "backups", "alias for -backup-dir")
	fs.Duration("timeout", 30*time.Second, "per-device budget")
	fs.String("note", "", "free text")
	fs.Bool("update-known-hosts", false, "alias for -host-key-policy update") // a shortcut, not a synonym
	fs.String("host-key-policy", "update", "policy for host keys")
	return fs
}

func TestGroupedUsageFoldsAliasesNextToTheirFlag(t *testing.T) {
	var out bytes.Buffer
	printFlagGroups(&out, sampleFlagSet(), []flagGroup{
		{"Backups", []string{"backup-dir", "retention-count", "redact", "force"}},
		{"Devices", []string{"inventory"}},
	})
	got := out.String()
	for _, want := range []string{
		"Backups:\n", "Devices:\n",
		"-backup-dir string", `where backups go (default "backups"; also -out)`,
		"-retention-count int", "how many to keep (default 10)",
		"-redact", "mask secrets (default true)",
		"-force", "save even if unchanged (also -save-unchanged)",
		"-inventory string",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("help is missing %q:\n%s", want, got)
		}
	}
	// aliases are folded, not listed as flags of their own
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-out") || strings.HasPrefix(strings.TrimSpace(line), "-save-unchanged") {
			t.Errorf("an alias is listed as a flag of its own: %q", line)
		}
	}
	// groups come out in the order given
	if strings.Index(got, "Backups:") > strings.Index(got, "Devices:") {
		t.Error("groups must keep the declared order")
	}
	// zero defaults are not printed
	if strings.Contains(got, "(default false)") || strings.Contains(got, `(default "")`) {
		t.Errorf("a zero default is shown:\n%s", got)
	}
}

// A flag nobody remembered to put in a group must still be documented: help
// that silently omits a flag is worse than help that is badly organised.
func TestGroupedUsageNeverHidesAFlag(t *testing.T) {
	fs := sampleFlagSet()
	var out bytes.Buffer
	printFlagGroups(&out, fs, []flagGroup{{"Backups", []string{"backup-dir"}}})
	got := out.String()
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(got, "-"+f.Name) {
			t.Errorf("-%s is missing from the help:\n%s", f.Name, got)
		}
	})
	if !strings.Contains(got, "Other flags:") {
		t.Errorf("ungrouped flags need a section of their own:\n%s", got)
	}
	// an "alias" that is really a shortcut for a different flag is a flag in its own right
	if !strings.Contains(got, "-update-known-hosts") || strings.Contains(got, "also -update-known-hosts") {
		t.Errorf("-update-known-hosts is a shortcut, not a synonym of -host-key-policy:\n%s", got)
	}
}

func TestGroupedUsageToleratesUnknownNames(t *testing.T) {
	var out bytes.Buffer
	printFlagGroups(&out, sampleFlagSet(), []flagGroup{{"Backups", []string{"no-such-flag", "backup-dir"}}})
	if !strings.Contains(out.String(), "-backup-dir") {
		t.Error("a group naming a flag that does not exist must still print the rest")
	}
}

// ---- the real commands ------------------------------------------------------

func TestBackupHelpDocumentsEveryFlagInItsSection(t *testing.T) {
	var o backupOpts
	fs := newBackupFlagSet(&o, &bytes.Buffer{})
	var out bytes.Buffer
	printFlagGroups(&out, fs, backupFlagGroups)
	help := out.String()

	// every flag shows up, and nothing fell through to "Other flags"
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.Contains(help, "-"+f.Name) {
			t.Errorf("-%s is not in the backup help", f.Name)
		}
	})
	if strings.Contains(help, "Other flags:") {
		t.Errorf("a backup flag is in no group; add it to backupFlagGroups:\n%s", help)
	}
	// the groups name only real flags (a typo would silently drop a flag)
	for _, g := range backupFlagGroups {
		for _, name := range g.names {
			if fs.Lookup(name) == nil {
				t.Errorf("group %q names -%s, which is not a backup flag", g.title, name)
			}
		}
	}
	for _, section := range []string{"Backups:", "Reports and compliance:", "Connection:", "Jump hosts and routing:", "Logging:"} {
		if !strings.Contains(help, section) {
			t.Errorf("section %q is missing:\n%s", section, help)
		}
	}
	for _, alias := range []string{"also -out", "also -md-report", "also -save-unchanged", "also -known-hosts-policy", "also -force"} {
		if strings.Contains(help, alias) {
			t.Errorf("unexpected legacy alias note %q found in backup help", alias)
		}
	}
}

// Declared once, so the commands cannot disagree about what a shared flag is
// called, what it defaults to, or what it says in -h.
func TestSharedFlagsAreTheSameInEveryCommand(t *testing.T) {
	shared := []string{
		"inventory", "limit", "concurrency", "connect-timeout", "command-timeout", "env-file", "key-file",
		"log-dir", "no-color", "known-hosts", "host-key-policy", "update-known-hosts",
		"legacy-algorithms", "tcp-mss", "jump", "jump-host", "jump-user", "jump-key-file",
		"mesh-fallback", "memory", "memory-file",
	}
	var o backupOpts
	backupFS := newBackupFlagSet(&o, &bytes.Buffer{})

	in := openDevNull(t)
	defer in.Close()
	var classicHelp bytes.Buffer
	run([]string{"-h"}, in, &bytes.Buffer{}, &classicHelp)

	for _, name := range shared {
		f := backupFS.Lookup(name)
		if f == nil {
			t.Errorf("backup has no -%s", name)
			continue
		}
		if !strings.Contains(classicHelp.String(), "  -"+name) {
			t.Errorf("the classic runner has no -%s", name)
			continue
		}
		// the help line (usage and default) is identical in both
		line := helpEntry(classicHelp.String(), name)
		var own bytes.Buffer
		one := flag.NewFlagSet("x", flag.ContinueOnError)
		one.SetOutput(&own)
		one.Var(f.Value, f.Name, f.Usage)
		one.Lookup(name).DefValue = f.DefValue
		one.PrintDefaults()
		if want := helpEntry(own.String(), name); line != want {
			t.Errorf("-%s is described differently:\n classic: %q\n backup:  %q", name, line, want)
		}
	}
}

// helpEntry returns the usage line(s) PrintDefaults prints for one flag.
func helpEntry(help, name string) string {
	lines := strings.Split(help, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "  -"+name+" ") || l == "  -"+name {
			return strings.TrimSpace(strings.Join(lines[i+1:i+2], " "))
		}
	}
	return ""
}

func TestHintPasswordFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-password", "secret"}, "passwords are never accepted"},
		{[]string{"-p=secret"}, "passwords are never accepted"},
		{[]string{"-jump-password", "secret"}, "jump host passwords are never accepted"},
		{[]string{"--jump-password=secret"}, "jump host passwords are never accepted"},
	} {
		var buf bytes.Buffer
		hintPasswordFlag(tc.args, &buf)
		if !strings.Contains(buf.String(), tc.want) {
			t.Errorf("hintPasswordFlag(%v) = %q, want substring %q", tc.args, buf.String(), tc.want)
		}
	}
}

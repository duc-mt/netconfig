// ==============================================================================
// File name:     audit_offline_test.go
// Description:   Tests for offline audits (--file, --from-backups) and --generate-fix.
// License:       MIT
// ==============================================================================
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/internal/task"
)

const offlineVyosGood = "set system host-name r1\nset service ntp server 10.0.0.1\nset system syslog host 10.0.0.9 facility all level notice\nset system login radius server 10.0.0.5 key k\nset system login banner pre-login 'authorised use only'\n"

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runAuditArgs(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runAudit(args, nil, &out, &errb)
	return code, out.String(), errb.String()
}

func TestAuditFileOffline(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "r1.config")
	writeFile(t, good, offlineVyosGood)
	code, out, errs := runAuditArgs("--file", good, "--vendor", "vyos")
	if code != task.ExitOK {
		t.Fatalf("compliant file: exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "r1") {
		t.Errorf("host name should come from the file name:\n%s", out)
	}

	bad := filepath.Join(dir, "r2.config")
	writeFile(t, bad, "set system host-name r2\nset service telnet\n")
	fix := filepath.Join(dir, "fix.txt")
	code, out, _ = runAuditArgs("--file", bad, "--vendor", "vyos", "--generate-fix", fix)
	if code != exitNonCompliant {
		t.Fatalf("non-compliant file: exit %d, want %d\n%s", code, exitNonCompliant, out)
	}
	data, err := os.ReadFile(fix)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"==== r2 (vyos) ====", "[HIGH]", "delete service telnet"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("fix file lacks %q:\n%s", want, data)
		}
	}
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			t.Errorf("fix file must be comments only, got %q", l)
		}
	}
}

func TestAuditOfflineFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--file", "x.config"},
		{"--vendor", "cisco"},
		{"--file", "x", "--vendor", "cisco", "--from-backups", "y"},
		{"--file", "x", "--vendor", "nosuchvendor"},
		{"--from-backups", filepath.Join(t.TempDir(), "missing")},
	} {
		if code, _, _ := runAuditArgs(args...); code != task.ExitFatal {
			t.Errorf("%v: exit %d, want %d", args, code, task.ExitFatal)
		}
	}
}

func TestAuditOfflineRefusesIncompleteConfig(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "e.config")
	writeFile(t, empty, "\n")
	if code, _, errs := runAuditArgs("--file", empty, "--vendor", "vyos"); code != task.ExitPartial || !strings.Contains(errs, "cannot audit") {
		t.Errorf("empty config: exit %d, stderr %q", code, errs)
	}
	curly := filepath.Join(dir, "j.config")
	writeFile(t, curly, "system {\n    host-name j1;\n}\n")
	if code, _, errs := runAuditArgs("--file", curly, "--vendor", "junos"); code != task.ExitPartial || !strings.Contains(errs, "display set") {
		t.Errorf("curly junos config: exit %d, stderr %q", code, errs)
	}
}

func TestAuditFromBackupsPicksNewestRun(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "backup-2026-01-01-0000", "vyos", "old.config"), offlineVyosGood)
	writeFile(t, filepath.Join(root, "backup-2026-02-01-0000", "vyos", "new.config"), offlineVyosGood)
	writeFile(t, filepath.Join(root, "backup-2026-02-01-0000", "vyos", "new.diff"), "not a config")
	writeFile(t, filepath.Join(root, "backup-2026-02-01-0000", "mystery", "x.config"), "set a b")
	code, out, errs := runAuditArgs("--from-backups", root)
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "new") || strings.Contains(out, "old") {
		t.Errorf("only the newest run should be audited:\n%s", out)
	}
	if !strings.Contains(errs, "mystery") {
		t.Errorf("unknown vendor directory should be reported: %q", errs)
	}
	// a single run directory works as well
	if code, _, _ := runAuditArgs("--from-backups", filepath.Join(root, "backup-2026-01-01-0000")); code != task.ExitOK {
		t.Errorf("single run directory: exit %d", code)
	}
}

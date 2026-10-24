// ==============================================================================
// File name:     launcher_test.go
// Description:   Tests for the ./run launcher's subcommand routing.
// License:       MIT
// ==============================================================================
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// launcherTree copies the real launcher scripts next to a stub "netconfig"
// binary that prints one argument per line, so what the launcher passes on can
// be checked without building anything.
func launcherTree(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the POSIX launcher is not used on Windows")
	}
	root := t.TempDir()
	copyFile := func(src, dst string) {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	repo := filepath.Join("..", "..")
	copyFile(filepath.Join(repo, "run"), filepath.Join(root, "run"))
	copyFile(filepath.Join(repo, "show-backup"), filepath.Join(root, "show-backup"))
	copyFile(filepath.Join(repo, "scripts", "run.sh"), filepath.Join(root, "scripts", "run.sh"))
	stub := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "netconfig"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func launch(t *testing.T, root, script string, args ...string) []string {
	t.Helper()
	out, err := exec.Command("/bin/sh", append([]string{filepath.Join(root, script)}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", script, args, err, out)
	}
	return strings.Fields(string(out))
}

func TestLauncherRoutesSubcommandsWithoutAppendingCommands(t *testing.T) {
	root := launcherTree(t)
	tests := []struct {
		name string
		args []string
		want []string
	}{
		// subcommands go straight through
		{"backup", []string{"backup", "-limit", "core-*", "-dry-run"}, []string{"backup", "-limit", "core-*", "-dry-run"}},
		{"backup without flags", []string{"backup"}, []string{"backup"}},
		{"backup help", []string{"backup", "--help"}, []string{"backup", "--help"}},
		{"backup show", []string{"backup", "show", "-l"}, []string{"backup", "show", "-l"}},
		{"backup show node", []string{"backup", "show", "-d", "core-sw1"}, []string{"backup", "show", "-d", "core-sw1"}},
		{"backup show help", []string{"backup", "show", "--help"}, []string{"backup", "show", "--help"}},
		// the retired spelling is not a subcommand any more: the binary answers it
		// with a rename hint (see TestOldShowBackupFormSaysWhatToUseInstead)
		{"old show-backup", []string{"show-backup", "-l"}, []string{"show-backup", "-l", "-commands", "commands.txt"}},

		// the classic runner still defaults to commands.txt
		{"no arguments", nil, []string{"-commands", "commands.txt"}},
		{"flags only", []string{"-limit", "core-*", "-dry-run"}, []string{"-limit", "core-*", "-dry-run", "-commands", "commands.txt"}},
		{"explicit commands", []string{"-commands", "my.txt"}, []string{"-commands", "my.txt"}},
		{"explicit commands=", []string{"-commands=my.txt", "-yes"}, []string{"-commands=my.txt", "-yes"}},
		{"template", []string{"-template", "t.tmpl", "-var", "a=b"}, []string{"-template", "t.tmpl", "-var", "a=b"}},
		{"help", []string{"-h"}, []string{"-h"}},
		{"version", []string{"-version"}, []string{"-version"}},

		// only the FIRST argument selects a subcommand
		{"a flag value that looks like a subcommand", []string{"-limit", "backup"}, []string{"-limit", "backup", "-commands", "commands.txt"}},
		{"subcommand name later", []string{"-inventory", "x.csv", "backup"}, []string{"-inventory", "x.csv", "backup", "-commands", "commands.txt"}},
	}
	for _, tt := range tests {
		if got := launch(t, root, filepath.Join("scripts", "run.sh"), tt.args...); strings.Join(got, "\x00") != strings.Join(tt.want, "\x00") {
			t.Errorf("run.sh %s: binary got %q, want %q", tt.name, got, tt.want)
		}
		// the root ./run launcher is the same thing
		if got := launch(t, root, "run", tt.args...); strings.Join(got, "\x00") != strings.Join(tt.want, "\x00") {
			t.Errorf("run %s: binary got %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestShowBackupHelperScript(t *testing.T) {
	root := launcherTree(t)
	got := launch(t, root, "show-backup", "-p", "core-sw1")
	if want := []string{"backup", "show", "-p", "core-sw1"}; strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("./show-backup passed %q, want %q", got, want)
	}

	// it works when invoked from another directory through a relative path
	cmd := exec.Command("/bin/sh", filepath.Join(root, "show-backup"), "-l")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Join(strings.Fields(string(out)), " ") != "backup show -l" {
		t.Errorf("from another directory: %v %q", err, out)
	}

	info, err := os.Stat(filepath.Join("..", "..", "show-backup"))
	if err != nil || info.Mode()&0o111 == 0 {
		t.Errorf("the show-backup helper must be executable: %v %v", info, err)
	}
}

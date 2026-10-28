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

// launcherTree copies the real launcher scripts next to a stub "netops"
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
	copyFile(filepath.Join(repo, "scripts", "run.sh"), filepath.Join(root, "scripts", "run.sh"))
	stub := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "netops"), []byte(stub), 0o755); err != nil {
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
		{"backup redact help", []string{"backup", "redact", "--help"}, []string{"backup", "redact", "--help"}},
		{"backup redact file", []string{"backup", "redact", "sw1.cfg"}, []string{"backup", "redact", "sw1.cfg"}},

		// the apply subcommand defaults to commands.txt
		{"apply without flags", []string{"apply"}, []string{"apply", "-commands", "commands.txt"}},
		{"apply flags only", []string{"apply", "-limit", "core-*", "-dry-run"}, []string{"apply", "-limit", "core-*", "-dry-run", "-commands", "commands.txt"}},
		{"apply explicit commands", []string{"apply", "-commands", "my.txt"}, []string{"apply", "-commands", "my.txt"}},
		{"apply explicit commands=", []string{"apply", "-commands=my.txt", "-yes"}, []string{"apply", "-commands=my.txt", "-yes"}},
		{"apply template", []string{"apply", "-template", "t.tmpl", "-var", "a=b"}, []string{"apply", "-template", "t.tmpl", "-var", "a=b"}},
		{"apply help", []string{"apply", "-h"}, []string{"apply", "-h"}},

		// config subcommands pass through
		{"config user add", []string{"config", "user", "add", "-u", "alice"}, []string{"config", "user", "add", "-u", "alice"}},
		{"config vlan add", []string{"config", "vlan", "add", "--id", "100"}, []string{"config", "vlan", "add", "--id", "100"}},

		// retired spelling is passed through to binary
		{"old show-backup", []string{"show-backup", "-l"}, []string{"show-backup", "-l"}},

		// strict subcommand enforcement: arguments without subcommand pass straight through to binary
		{"no arguments", nil, nil},
		{"flags only without subcommand", []string{"-limit", "core-*", "-dry-run"}, []string{"-limit", "core-*", "-dry-run"}},
		{"help", []string{"-h"}, []string{"-h"}},
		{"version", []string{"-version"}, []string{"-version"}},

		// only the FIRST argument selects a subcommand
		{"a flag value that looks like a subcommand", []string{"-limit", "apply"}, []string{"-limit", "apply"}},
		{"subcommand name later", []string{"-inventory", "x.csv", "apply"}, []string{"-inventory", "x.csv", "apply"}},
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

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

		// the config subcommand defaults to commands.txt
		{"config without flags", []string{"config"}, []string{"config", "-commands", "commands.txt"}},
		{"config flags only", []string{"config", "-limit", "core-*", "-dry-run"}, []string{"config", "-limit", "core-*", "-dry-run", "-commands", "commands.txt"}},
		{"config explicit commands", []string{"config", "-commands", "my.txt"}, []string{"config", "-commands", "my.txt"}},
		{"config explicit commands=", []string{"config", "-commands=my.txt", "-yes"}, []string{"config", "-commands=my.txt", "-yes"}},
		{"config template", []string{"config", "-template", "t.tmpl", "-var", "a=b"}, []string{"config", "-template", "t.tmpl", "-var", "a=b"}},
		{"config help", []string{"config", "-h"}, []string{"config", "-h"}},

		// retired spelling is passed through to binary for rename hint
		{"old show-backup", []string{"show-backup", "-l"}, []string{"show-backup", "-l"}},

		// strict subcommand enforcement: arguments without subcommand pass straight through to binary
		{"no arguments", nil, nil},
		{"flags only without subcommand", []string{"-limit", "core-*", "-dry-run"}, []string{"-limit", "core-*", "-dry-run"}},
		{"help", []string{"-h"}, []string{"-h"}},
		{"version", []string{"-version"}, []string{"-version"}},

		// only the FIRST argument selects a subcommand
		{"a flag value that looks like a subcommand", []string{"-limit", "config"}, []string{"-limit", "config"}},
		{"subcommand name later", []string{"-inventory", "x.csv", "config"}, []string{"-inventory", "x.csv", "config"}},
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

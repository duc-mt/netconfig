// ==============================================================================
// File name:     exec_cmd_test.go
// Description:   Tests for the "exec" subcommand.
// License:       MIT
// ==============================================================================
package main

import (
	"strings"
	"testing"

	"netops/internal/task"
)

func TestExecRunsOperationalCommandOnly(t *testing.T) {
	w := factsWS(t)
	code, _, stderr := w.run("exec", "-limit", "sw-a", "show", "clock")
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\n%s", code, task.ExitOK, stderr)
	}
	mustContain(t, "stderr", stderr, "10:00:00")
	d := w.dev("sw-a")
	if d.cfg != 0 || d.writes != 0 {
		t.Errorf("exec entered config mode (%d) or saved (%d)", d.cfg, d.writes)
	}
	if got := strings.Join(d.cmds, "|"); !strings.Contains(got, "show clock") {
		t.Errorf("device never received the command: %q", got)
	}
	if n := len(w.dev("sw-b").cmds); n != 0 {
		t.Errorf("-limit leaked to sw-b (%d commands)", n)
	}
}

func TestExecJSONFormat(t *testing.T) {
	w := factsWS(t)
	code, stdout, stderr := w.run("exec", "-limit", "sw-a", "-format", "json", "show clock")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stdout", stdout, `"hostname": "sw-a"`)
}

func TestExecValidation(t *testing.T) {
	w := factsWS(t)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no command":      {[]string{"exec", "-limit", "sw-a"}, "no command given"},
		"bad format":      {[]string{"exec", "-format", "xml", "show clock"}, "-format must be"},
		"command + file":  {[]string{"exec", "-commands", "x.txt", "show clock"}, "not both"},
		"missing cmdfile": {[]string{"exec", "-commands", "/nonexistent/x.txt"}, "netops exec:"},
	} {
		code, _, stderr := w.run(tc.args...)
		if code != task.ExitFatal {
			t.Errorf("%s: exit %d, want fatal", name, code)
		}
		mustContain(t, name, stderr, tc.want)
	}
	if n := w.totalOpens(); n != 0 {
		t.Errorf("validation errors must precede any connection, got %d opens", n)
	}
}

func TestExecHelp(t *testing.T) {
	code, stdout, _ := dispatchOut(t, "exec", "-h")
	if code != task.ExitOK {
		t.Fatalf("exit %d", code)
	}
	mustContain(t, "help", stdout, "netops exec:", "operational")
}

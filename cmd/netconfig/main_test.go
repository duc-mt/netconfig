package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netconfig/internal/task"
)

// fixture writes an inventory and a commands file and returns the base args.
// No credentials are configured, so a run that gets past the pre-flight stage
// skips every device instead of opening a connection: these tests never touch
// the network.
func fixture(t *testing.T, vendorName, commands string) []string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, k := range []string{"NETCONFIG_USERNAME", "NETCONFIG_PASSWORD", "NETCONFIG_JUMP_HOST"} {
		t.Setenv(k, "")
	}
	inv := write("inventory.csv", "hostname,address,port,vendor,credential_group\nsw1,192.0.2.1,22,"+vendorName+",default\n")
	cmds := write("commands.txt", commands)
	hosts := write("known_hosts", "")
	return []string{"-inventory", inv, "-commands", cmds, "-log-dir", filepath.Join(dir, "logs"),
		"-env-file", filepath.Join(dir, "none.env"), "-known-hosts", hosts, "-no-color"}
}

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var out, errOut bytes.Buffer
	code := run(args, stdin, &out, &errOut)
	return code, errOut.String() + out.String()
}

func TestStrictSafetyBlocksLockoutBeforeAnyConnection(t *testing.T) {
	base := fixture(t, "cisco", "no ip route 0.0.0.0 0.0.0.0 192.0.2.254\n")

	code, out := runCLI(t, base...)
	if code != task.ExitFatal {
		t.Fatalf("exit = %d, want %d\n%s", code, task.ExitFatal, out)
	}
	for _, want := range []string{"default-route-removed", "pre-flight safety check blocked", "sw1 (1)", "-force"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "connecting to") {
		t.Fatalf("no device may be contacted when the lint blocks the run:\n%s", out)
	}

	// -force accepts the lockout risk: the run proceeds (and, with no
	// credentials configured, skips the device instead of connecting).
	code, out = runCLI(t, append(base, "-force")...)
	if code != task.ExitPartial || strings.Contains(out, "blocked the run") {
		t.Fatalf("-force must release a lockout block: exit=%d\n%s", code, out)
	}
	// -allow-dangerous is for destructive commands only.
	code, _ = runCLI(t, append(base, "-allow-dangerous", "-yes")...)
	if code != task.ExitFatal {
		t.Fatalf("-allow-dangerous must not release a lockout: exit=%d", code)
	}
	// Strict mode off: findings are warnings only.
	code, out = runCLI(t, append(base, "-strict-safety=false", "-yes")...)
	if code != task.ExitPartial || !strings.Contains(out, "LINT CRITICAL") {
		t.Fatalf("exit=%d, the finding must still be reported:\n%s", code, out)
	}
}

func TestStrictSafetyBlocksDestructiveUnlessAllowed(t *testing.T) {
	base := fixture(t, "cisco", "no router bgp 65000\n")

	code, out := runCLI(t, append(base, "-yes")...)
	if code != task.ExitFatal || !strings.Contains(out, "teardown-routing-process") {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	code, _ = runCLI(t, append(base, "-force")...)
	if code != task.ExitFatal {
		t.Fatalf("-force must not release a destructive command: exit=%d", code)
	}
	code, out = runCLI(t, append(base, "-allow-dangerous", "-yes")...)
	if code != task.ExitPartial || strings.Contains(out, "blocked the run") {
		t.Fatalf("-allow-dangerous must release it: exit=%d\n%s", code, out)
	}
}

func TestLintNeverBlocksDryRun(t *testing.T) {
	base := fixture(t, "cisco", "no router bgp 65000\nno ip route 0.0.0.0 0.0.0.0\n")
	code, out := runCLI(t, append(base, "-dry-run")...)
	if code == task.ExitFatal {
		t.Fatalf("a dry run changes nothing and must not be blocked:\n%s", out)
	}
	if !strings.Contains(out, "would block a real run") {
		t.Fatalf("a dry run should say what would block a real run:\n%s", out)
	}
}

func TestLintChecksOperationalCommands(t *testing.T) {
	base := fixture(t, "cisco", "clear ip bgp *\n")
	if code, out := runCLI(t, append(base, "-op")...); code != task.ExitFatal || !strings.Contains(out, "clear-bgp-all") {
		t.Fatalf("a destructive operational command is blocked too: exit=%d\n%s", code, out)
	}
	base = fixture(t, "cisco", "show ip route 0.0.0.0\n")
	if code, out := runCLI(t, append(base, "-op")...); code == task.ExitFatal {
		t.Fatalf("read-only commands pass:\n%s", out)
	}
}

func TestPlanRendersImpactMatrix(t *testing.T) {
	base := fixture(t, "huawei", "interface GE0/0/1\nshutdown\n")
	code, out := runCLI(t, append(base, "-plan", "-yes", "-dry-run", "-commit-confirm", "5")...)
	if code == task.ExitFatal {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	for _, want := range []string{
		"netconfig change plan (DRY-RUN", "HOST", "VENDOR", "CMDS", "RISK", "IMPACT", "ROLLBACK",
		"sw1", "huawei", "HIGH", "Interface", "UNSAFE",
		"interface-shutdown",    // the finding behind the risk level
		"UNSAFE / OOB REQUIRED", // per-device hazard line for -commit-confirm
		"2 command(s)", "will be validated",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Apply these changes") {
		t.Fatalf("-plan replaces the classic prompt:\n%s", out)
	}
}

func TestPlanNeedsATerminalToAskForConfirmation(t *testing.T) {
	base := fixture(t, "cisco", "hostname lab1\n")
	code, out := runCLI(t, append(base, "-plan")...)
	if code != task.ExitFatal || !strings.Contains(out, "-plan needs a terminal") {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	if strings.Contains(out, "connecting to") {
		t.Fatal("nothing may be contacted before the operator confirmed")
	}
	// The matrix is still shown before the refusal.
	if !strings.Contains(out, "netconfig change plan") {
		t.Fatalf("plan not rendered:\n%s", out)
	}
}

func TestSafetyFlagValidation(t *testing.T) {
	base := fixture(t, "cisco", "hostname lab1\n")
	dir := t.TempDir()
	badVerify := filepath.Join(dir, "bad.verify")
	_ = os.WriteFile(badVerify, []byte("verify show version\n"), 0o600) // no condition
	slowVerify := filepath.Join(dir, "slow.verify")
	_ = os.WriteFile(slowVerify, []byte("verify show version\n expect: ok\n retries: 30\n interval: 10s\n"), 0o600)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"negative commit-confirm", []string{"-commit-confirm", "-1"}, "must not be negative"},
		{"commit-confirm with -op", []string{"-op", "-commit-confirm", "5"}, "cannot be used with -op"},
		{"verify-file with -op", []string{"-op", "-verify-file", badVerify}, "cannot be used with -op"},
		{"missing verify file", []string{"-verify-file", filepath.Join(dir, "missing")}, "read verify file"},
		{"invalid verify file", []string{"-verify-file", badVerify}, "no expect"},
		{"window shorter than retries", []string{"-commit-confirm", "1", "-verify-file", slowVerify}, "too short"},
	}
	for _, tc := range cases {
		code, out := runCLI(t, append(append([]string{}, base...), tc.args...)...)
		if code != task.ExitFatal || !strings.Contains(out, tc.want) {
			t.Errorf("%s: exit=%d, want fatal containing %q:\n%s", tc.name, code, tc.want, out)
		}
		if strings.Contains(out, "connecting to") {
			t.Errorf("%s: invalid input must be rejected before any connection", tc.name)
		}
	}
}

func TestInlineVerifyBlockErrorsAreFatal(t *testing.T) {
	base := fixture(t, "cisco", "hostname lab1\n!@verify show version\n")
	code, out := runCLI(t, base...)
	if code != task.ExitFatal || !strings.Contains(out, "inline verify") {
		t.Fatalf("exit=%d\n%s", code, out)
	}
}

func TestInlineVerifyBlocksAreNotCommands(t *testing.T) {
	base := fixture(t, "cisco", "hostname lab1\n!@verify show version\n!@  expect: ok\n")
	code, out := runCLI(t, append(base, "-plan", "-yes", "-dry-run")...)
	if code == task.ExitFatal {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "1 command(s)") {
		t.Fatalf("only 'hostname lab1' is a command:\n%s", out)
	}
}

func TestPlanHeaderMatchesTheMode(t *testing.T) {
	base := fixture(t, "cisco", "show version\n")
	code, out := runCLI(t, append(base, "-op", "-plan", "-yes")...)
	if code == task.ExitFatal || !strings.Contains(out, "will receive operational commands") || strings.Contains(out, "saved/committed") {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	base = fixture(t, "cisco", "hostname lab1\n")
	code, out = runCLI(t, append(base, "-plan", "-yes")...)
	if code == task.ExitFatal || !strings.Contains(out, "will be modified and their configuration saved/committed") {
		t.Fatalf("exit=%d\n%s", code, out)
	}
}

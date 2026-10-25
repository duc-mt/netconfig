package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/internal/memory"
	"netops/internal/task"
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
	for _, k := range []string{"NETOPS_USERNAME", "NETOPS_PASSWORD", "NETOPS_JUMP_HOST"} {
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
		"netops change plan (DRY-RUN", "HOST", "VENDOR", "CMDS", "RISK", "IMPACT", "ROLLBACK",
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
	if !strings.Contains(out, "netops change plan") {
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

func TestNewFlagsValidation(t *testing.T) {
	base := fixture(t, "cisco", "hostname lab1\n")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"negative canary", []string{"-canary", "-1"}, "-canary must not be negative"},
		{"negative batch-size", []string{"-batch-size", "-1"}, "-batch-size must not be negative"},
		{"invalid max-fail-percent", []string{"-max-fail-percent", "150"}, "-max-fail-percent must be between 0 and 100"},
		{"invalid format", []string{"-format", "xml"}, "-format must be 'text' or 'json'"},
		{"pre-diff with op", []string{"-op", "-pre-diff"}, "-pre-diff inspects configuration changes and cannot be used with -op"},
	}

	for _, tc := range cases {
		code, out := runCLI(t, append(append([]string{}, base...), tc.args...)...)
		if code != task.ExitFatal || !strings.Contains(out, tc.want) {
			t.Errorf("%s: exit=%d, want fatal containing %q:\n%s", tc.name, code, tc.want, out)
		}
	}
}

func TestOpModeFormatJSON(t *testing.T) {
	base := fixture(t, "cisco", "show ip interface brief\n")
	code, out := runCLI(t, append(base, "-op", "-format", "json", "-yes")...)
	// Device skipped due to missing credentials in test fixture, so code is ExitPartial
	if code != task.ExitPartial {
		t.Errorf("exit = %d, want ExitPartial\n%s", code, out)
	}
	if !strings.Contains(out, "sw1") {
		t.Errorf("output should mention device sw1:\n%s", out)
	}
}

func TestRouteMemoryCLI(t *testing.T) {
	memFile := filepath.Join(t.TempDir(), "test_memory.json")

	// 1. Show memory when empty
	code, out := runCLI(t, "-show-memory", "-memory-file", memFile)
	if code != task.ExitOK {
		t.Fatalf("exit = %d, want ExitOK (%s)", code, out)
	}
	if !strings.Contains(out, "No learned routes") {
		t.Fatalf("expected empty memory message, got:\n%s", out)
	}

	// 2. Populate memory directly
	mem, err := memory.Load(memFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.Record("NHG-VYOS", "10.255.255.1", "NHG-TRANSIT-GW-01", "10.255.255.4:22", "auto-fallback"); err != nil {
		t.Fatal(err)
	}

	// 3. Show memory when populated
	code, out = runCLI(t, "-show-memory", "-memory-file", memFile)
	if code != task.ExitOK {
		t.Fatalf("exit = %d, want ExitOK (%s)", code, out)
	}
	if !strings.Contains(out, "NHG-VYOS") || !strings.Contains(out, "10.255.255.4:22") {
		t.Fatalf("expected populated table with NHG-VYOS, got:\n%s", out)
	}

	// 4. Clear memory
	code, out = runCLI(t, "-clear-memory", "-memory-file", memFile)
	if code != task.ExitOK {
		t.Fatalf("exit = %d, want ExitOK (%s)", code, out)
	}
	if !strings.Contains(out, "Route memory cleared") {
		t.Fatalf("expected cleared message, got:\n%s", out)
	}

	// 5. Verify empty again
	code, out = runCLI(t, "-show-memory", "-memory-file", memFile)
	if code != task.ExitOK || !strings.Contains(out, "No learned routes") {
		t.Fatalf("expected empty after clear, got:\n%s", out)
	}
}

func TestUpdateKnownHostsFlags(t *testing.T) {
	base := fixture(t, "cisco", "show version\n")

	// Test -update-known-hosts flag accepts without error
	code, out := runCLI(t, append(base, "-update-known-hosts", "-yes")...)
	if code != task.ExitPartial {
		t.Fatalf("exit = %d, want ExitPartial\n%s", code, out)
	}

	// Test -replace-host-keys flag accepts without error
	code, out = runCLI(t, append(base, "-replace-host-keys", "-yes")...)
	if code != task.ExitPartial {
		t.Fatalf("exit = %d, want ExitPartial\n%s", code, out)
	}

	// Test -host-key-policy update
	code, out = runCLI(t, append(base, "-host-key-policy", "update", "-yes")...)
	if code != task.ExitPartial {
		t.Fatalf("exit = %d, want ExitPartial\n%s", code, out)
	}
}

func TestStrictSubcommandDispatch(t *testing.T) {
	in, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	runDispatch := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := dispatch(args, in, &out, &errb)
		return code, out.String(), errb.String()
	}

	// 1. Missing subcommand
	code, _, stderr := runDispatch()
	if code != task.ExitFatal || !strings.Contains(stderr, "missing subcommand") {
		t.Fatalf("empty args must exit fatal with missing subcommand, got code=%d:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "config") || !strings.Contains(stderr, "backup") {
		t.Fatalf("missing subcommand output must list available subcommands:\n%s", stderr)
	}

	// 2. Unknown subcommand
	code, _, stderr = runDispatch("invalid-subcmd")
	if code != task.ExitFatal || !strings.Contains(stderr, `unknown subcommand "invalid-subcmd"`) {
		t.Fatalf("unknown subcmd must exit fatal, got code=%d:\n%s", code, stderr)
	}

	// 3. Flags passed at root without subcommand
	code, _, stderr = runDispatch("-dry-run")
	if code != task.ExitFatal || !strings.Contains(stderr, `unknown subcommand "-dry-run"`) {
		t.Fatalf("flags without subcmd must exit fatal, got code=%d:\n%s", code, stderr)
	}

	// 4. Top-level help
	code, _, stderr = runDispatch("-h")
	if code != task.ExitOK || !strings.Contains(stderr, "Subcommands:") {
		t.Fatalf("-h must exit OK with root usage, got code=%d:\n%s", code, stderr)
	}

	code, _, stderr = runDispatch("help")
	if code != task.ExitOK || !strings.Contains(stderr, "Subcommands:") {
		t.Fatalf("help must exit OK with root usage, got code=%d:\n%s", code, stderr)
	}

	// 5. Config subcommand help
	code, _, stderr = runDispatch("config", "-h")
	if code != task.ExitOK || !strings.Contains(stderr, "netops config - apply configuration") {
		t.Fatalf("config -h must exit OK with config usage, got code=%d:\n%s", code, stderr)
	}
}

func TestDiffFlagValidation(t *testing.T) {
	base := fixture(t, "cisco", "show version")

	// -diff without -backup must fail
	code, out := runCLI(t, append(base, "-diff")...)
	if code != task.ExitFatal || !strings.Contains(out, "-diff requires -backup") {
		t.Fatalf("expected '-diff requires -backup', got code=%d output:\n%s", code, out)
	}

	// -show-diff flag is no longer accepted
	code, out = runCLI(t, append(base, "-show-diff")...)
	if code != task.ExitFatal || !strings.Contains(out, "flag provided but not defined: -show-diff") {
		t.Fatalf("expected unknown flag for -show-diff, got code=%d output:\n%s", code, out)
	}
}

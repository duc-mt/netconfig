package task

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netconfig/internal/vendor"
)

// ---- helpers ----------------------------------------------------------------

// recorder keeps every line sent to a host across all of its sessions, in
// order (the fake transport only remembers the latest session).
type recorder struct {
	mu    sync.Mutex
	lines map[string][]string
}

func newRecorder() *recorder { return &recorder{lines: map[string][]string{}} }

func (r *recorder) wrap(next func(host, line string) (string, error)) func(host, line string) (string, error) {
	return func(host, line string) (string, error) {
		r.mu.Lock()
		r.lines[host] = append(r.lines[host], line)
		r.mu.Unlock()
		if next != nil {
			return next(host, line)
		}
		return "", nil
	}
}

func (r *recorder) of(host string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.lines[host])
}

func (r *recorder) count(host, line string) int {
	n := 0
	for _, l := range r.of(host) {
		if l == line {
			n++
		}
	}
	return n
}

// logText returns everything the run logged for the runner.
func logText(t *testing.T, r *Runner) string {
	t.Helper()
	data, err := os.ReadFile(r.Log.Path())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// reopenFailTransport fails every Open from the n-th one on, per host: the
// first session (the change) works, a fresh one (the reachability probe, or a
// rollback) does not - what a lockout looks like from the outside.
type reopenFailTransport struct {
	*fakeTransport
	mu       sync.Mutex
	opens    map[string]int
	failFrom int
}

func (t *reopenFailTransport) Open(ctx context.Context, tgt Target) (Session, error) {
	t.mu.Lock()
	t.opens[tgt.Device.Hostname]++
	n := t.opens[tgt.Device.Hostname]
	t.mu.Unlock()
	if n >= t.failFrom {
		return nil, &fakeErr{"connect", "connection refused"}
	}
	return t.fakeTransport.Open(ctx, tgt)
}

func bgpRule(t *testing.T) []VerifyRule {
	t.Helper()
	rules, err := ParseVerifyRules("verify show bgp summary\n expect: Established\n")
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func runOne(t *testing.T, r *Runner, vendorName string, cmds ...string) Result {
	t.Helper()
	res := r.Run(context.Background(), mkJobs(t, vendorName, cmds, "sw1"))
	return res[0]
}

// ---- commit-confirm ---------------------------------------------------------

func TestCommitConfirmJunosSuccess(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "run show bgp summary" {
			return "Peer 10.0.0.2 Established", nil
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{CommitConfirm: 5, Verify: bgpRule(t)})
	res := runOne(t, r, "junos", "set system host-name lab1")

	if res.Status != StatusSucceeded {
		t.Fatalf("status=%v category=%s detail=%s", res.Status, res.Category, res.Detail)
	}
	want := []string{
		"configure", "set system host-name lab1",
		"commit confirmed 5", // timed commit: the deadman is running
		"show system uptime", // probe on a brand-new session
		"run show bgp summary",
		"commit", // confirm, only after everything passed
		"exit",
	}
	if got := rec.of("sw1"); !slices.Equal(got, want) {
		t.Fatalf("sent\n got %q\nwant %q", got, want)
	}
	if tr.opened != 2 {
		t.Fatalf("opened %d sessions, want 2 (change + reachability probe)", tr.opened)
	}
	if res.SafetyRating != "SAFE" || res.VerifyPassed != 1 || res.VerifyTotal != 1 {
		t.Fatalf("rating=%q verify=%d/%d", res.SafetyRating, res.VerifyPassed, res.VerifyTotal)
	}
	for _, want := range []string{"1 command(s) applied", "commit-confirm (5 min) confirmed", "1/1 check(s) passed"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("detail %q lacks %q", res.Detail, want)
		}
	}
}

func TestCommitConfirmWithoutChecksStillProvesReachability(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(nil)
	r := newRunner(t, tr, Options{CommitConfirm: 5})
	res := runOne(t, r, "junos", "set system host-name lab1")
	if res.Status != StatusSucceeded || res.VerifyTotal != 0 {
		t.Fatalf("%+v", res)
	}
	want := []string{"configure", "set system host-name lab1", "commit confirmed 5", "show system uptime", "commit", "exit"}
	if got := rec.of("sw1"); !slices.Equal(got, want) {
		t.Fatalf("sent\n got %q\nwant %q", got, want)
	}
}

func TestCommitConfirmLostConnectivityIsNotConfirmed(t *testing.T) {
	tr := &reopenFailTransport{fakeTransport: newFakeTransport(), opens: map[string]int{}, failFrom: 2}
	rec := newRecorder()
	tr.respond = rec.wrap(nil)
	r := newRunner(t, tr, Options{CommitConfirm: 5, Verify: bgpRule(t)})
	res := runOne(t, r, "junos", "set system host-name lab1")

	if res.Status != StatusFailed || res.Category != CatVerifyFailed {
		t.Fatalf("status=%v category=%s detail=%s", res.Status, res.Category, res.Detail)
	}
	if !strings.Contains(res.Detail, "VERIFY FAILED") || !strings.Contains(res.Detail, "management reachability lost") {
		t.Fatalf("detail = %q", res.Detail)
	}
	got := rec.of("sw1")
	if slices.Contains(got, "run show bgp summary") {
		t.Fatalf("checks must not run when the device is unreachable: %q", got)
	}
	if rec.count("sw1", "commit") != 0 {
		t.Fatalf("the change must NOT be confirmed: %q", got)
	}
	if !slices.Equal(got[len(got)-2:], []string{"rollback 0", "exit"}) {
		t.Fatalf("session must be left cleanly: %q", got)
	}
	if res.VerifyTotal != 1 || res.VerifyPassed != 0 {
		t.Fatalf("verify %d/%d", res.VerifyPassed, res.VerifyTotal)
	}
	if !strings.Contains(logText(t, r), "NOT confirmed") {
		t.Fatal("the operator must be told the device will revert by itself")
	}
}

func TestCommitConfirmVerifyFailureLeavesDeadmanToRevert(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "run show bgp summary" {
			return "Peer 10.0.0.2 Active", nil
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{CommitConfirm: 5, Verify: bgpRule(t)})
	res := runOne(t, r, "junos", "set system host-name lab1")

	if res.Status != StatusFailed || res.Category != CatVerifyFailed {
		t.Fatalf("status=%v category=%s", res.Status, res.Category)
	}
	if !strings.HasPrefix(res.Detail, "VERIFY FAILED") {
		t.Fatalf("detail = %q", res.Detail)
	}
	if rec.count("sw1", "commit") != 0 {
		t.Fatalf("an unverified change must not be confirmed: %q", rec.of("sw1"))
	}
	if res.Rollback != RollbackNone {
		t.Fatalf("without -rollback-on-fail nothing is reverted early: %v", res.Rollback)
	}
	if res.CommandsApplied != 1 {
		t.Fatalf("the command was applied before verification failed: %d", res.CommandsApplied)
	}
}

func TestCommitConfirmVerifyFailureNativeAbort(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "run show bgp summary" {
			return "Peer 10.0.0.2 Active", nil
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{CommitConfirm: 5, Verify: bgpRule(t), RollbackOnFail: true})
	res := runOne(t, r, "junos", "set system host-name lab1")

	if res.Status != StatusFailed || res.Category != CatVerifyFailed || res.Rollback != RollbackOK {
		t.Fatalf("status=%v category=%s rollback=%v", res.Status, res.Category, res.Rollback)
	}
	got := rec.of("sw1")
	tail := got[len(got)-4:]
	if !slices.Equal(tail, []string{"run show bgp summary", "rollback 1", "commit", "exit"}) {
		t.Fatalf("expected the native immediate revert after the failed check, got %q", got)
	}
	if tr.opened != 2 {
		t.Fatalf("native revert needs no backup session: opened=%d", tr.opened)
	}
}

func TestCommitConfirmClassicIOSReload(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(nil)
	r := newRunner(t, tr, Options{CommitConfirm: 5, AllowRebootRollback: true})
	res := runOne(t, r, "ios", "hostname lab1")

	if res.Status != StatusSucceeded {
		t.Fatalf("%+v", res)
	}
	want := []string{
		"reload in 5", "configure terminal", "hostname lab1", "end",
		"show clock", // reachability probe on a new session
		"reload cancel", "write memory",
	}
	if got := rec.of("sw1"); !slices.Equal(got, want) {
		t.Fatalf("sent\n got %q\nwant %q", got, want)
	}
	if res.SafetyRating != "REBOOT REQUIRED" || !strings.Contains(res.Detail, "commit-confirm (5 min) confirmed") {
		t.Fatalf("rating=%q detail=%q", res.SafetyRating, res.Detail)
	}
	if !strings.Contains(logText(t, r), "RELOAD") {
		t.Fatal("arming a reload must be loudly announced")
	}
}

func TestCommitConfirmClassicIOSWithoutRebootConsentFallsBack(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(nil)
	r := newRunner(t, tr, Options{CommitConfirm: 5})
	res := runOne(t, r, "ios", "hostname lab1")

	if res.Status != StatusSucceeded {
		t.Fatalf("%+v", res)
	}
	if got := rec.of("sw1"); !slices.Equal(got, []string{"configure terminal", "hostname lab1", "end", "write memory"}) {
		t.Fatalf("no reload may be armed without -allow-reboot-rollback: %q", got)
	}
	if strings.Contains(res.Detail, "commit-confirm") {
		t.Fatalf("nothing was confirmed, detail must not claim it: %q", res.Detail)
	}
	if res.SafetyRating != "REBOOT REQUIRED" {
		t.Fatalf("rating = %q", res.SafetyRating)
	}
	if !strings.Contains(logText(t, r), "-allow-reboot-rollback is not set") {
		t.Fatal("the fallback to client-side rollback must be logged")
	}
}

func TestCommitConfirmClientOnlyEmitsHazardWarning(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(nil)
	r := newRunner(t, tr, Options{CommitConfirm: 5, AllowRebootRollback: true})
	res := runOne(t, r, "huawei", "sysname lab1")

	if res.Status != StatusSucceeded || res.SafetyRating != "UNSAFE / OOB REQUIRED" {
		t.Fatalf("%+v", res)
	}
	if tr.opened != 1 || slices.Contains(rec.of("sw1"), "show clock") {
		t.Fatal("a platform without an on-box timer runs the plain plan: no reachability probe, no confirm")
	}
	text := logText(t, r)
	if !strings.Contains(text, vendor.HazardClientOnly) {
		t.Fatalf("hazard warning missing from the log:\n%s", text)
	}
	if !strings.Contains(text, "WARN") || !strings.Contains(text, "[sw1]") {
		t.Fatalf("the hazard must be a host-tagged warning:\n%s", text)
	}
}

func TestCommitConfirmArmingFailsClosed(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if strings.HasPrefix(line, "configure terminal revert timer") {
			return "%Archive not configured", nil // not a pattern IOS errors match
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{CommitConfirm: 5})
	res := runOne(t, r, "ios-xe", "hostname lab1")

	if res.Status != StatusFailed || res.Category != CatConfirmFailed {
		t.Fatalf("status=%v category=%s detail=%s", res.Status, res.Category, res.Detail)
	}
	if got := rec.of("sw1"); slices.Contains(got, "hostname lab1") {
		t.Fatalf("no change may be made when the safety net could not be armed: %q", got)
	}
	if res.CommandsApplied != 0 {
		t.Fatalf("applied = %d", res.CommandsApplied)
	}
}

func TestCommitConfirmWindowExhausted(t *testing.T) {
	var offset atomic.Int64
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "show system uptime" { // the probe is slow: the window runs out
			offset.Add(int64(10 * time.Minute))
		}
		if line == "run show bgp summary" {
			return "Established", nil
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{CommitConfirm: 5, Verify: bgpRule(t)})
	r.Now = func() time.Time { return base.Add(time.Duration(offset.Load())) }
	res := runOne(t, r, "junos", "set system host-name lab1")

	if res.Status != StatusFailed || res.Category != CatConfirmFailed {
		t.Fatalf("status=%v category=%s detail=%s", res.Status, res.Category, res.Detail)
	}
	if rec.count("sw1", "commit") != 0 {
		t.Fatalf("confirming after the window may confirm nothing, or worse: %q", rec.of("sw1"))
	}
}

func TestCommitConfirmFailureWhileArmedSkipsBackupRollback(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		switch line {
		case "show running-config":
			return "hostname lab1\ninterface Gi0/1\nend\n", nil
		case "bad command":
			return "% Invalid input detected at '^' marker.", nil
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{
		CommitConfirm: 5, AllowRebootRollback: true,
		Backup: true, BackupDir: t.TempDir(), RollbackOnFail: true,
	})
	res := runOne(t, r, "ios", "bad command")

	if res.Status != StatusFailed || res.Category != CatSyntaxError {
		t.Fatalf("status=%v category=%s", res.Status, res.Category)
	}
	if res.Rollback != RollbackNone || tr.opened != 1 {
		t.Fatalf("the on-box timer owns the revert: rollback=%v opened=%d", res.Rollback, tr.opened)
	}
	got := rec.of("sw1")
	if got[len(got)-1] != "end" {
		t.Fatalf("configuration mode must be left: %q", got)
	}
	text := logText(t, r)
	if !strings.Contains(text, "NOT confirmed") || !strings.Contains(text, "RELOAD") || !strings.Contains(text, "reload cancel") {
		t.Fatalf("operator must learn the device will reload and how to stop it:\n%s", text)
	}
}

func TestCommitConfirmSessionLossOnTimedCommitAssumesDeadmanRuns(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		switch line {
		case "show running-config":
			return "hostname lab1\ninterface Ethernet1\nend\n", nil
		case "commit timer 00:05:00":
			return "", &fakeErr{"timeout", "no prompt before the timeout"} // the commit cut our session
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{CommitConfirm: 5, Backup: true, BackupDir: t.TempDir(), RollbackOnFail: true})
	res := runOne(t, r, "arista", "hostname lab1")

	if res.Status != StatusFailed || res.Category != CatTimeout {
		t.Fatalf("status=%v category=%s", res.Status, res.Category)
	}
	if res.Rollback != RollbackNone || tr.opened != 1 {
		t.Fatalf("the timed commit may have taken effect: no backup rollback may be attempted over it (rollback=%v opened=%d)", res.Rollback, tr.opened)
	}
	if !strings.Contains(logText(t, r), "NOT confirmed") {
		t.Fatal("the operator must be told the device rolls back by itself")
	}
}

func TestCommitConfirmDryRunIsNotExercised(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(nil)
	r := newRunner(t, tr, Options{DryRun: true, CommitConfirm: 5, Verify: bgpRule(t)})
	res := runOne(t, r, "junos", "set system host-name lab1")

	if res.Status != StatusSucceeded {
		t.Fatalf("%+v", res)
	}
	got := rec.of("sw1")
	for _, bad := range []string{"commit confirmed 5", "run show bgp summary", "show system uptime"} {
		if slices.Contains(got, bad) {
			t.Fatalf("dry-run must not exercise %q: %q", bad, got)
		}
	}
	if res.VerifyTotal != 0 {
		t.Fatalf("no checks run on a dry run: %d", res.VerifyTotal)
	}
	if !strings.Contains(logText(t, r), "not exercised") {
		t.Fatal("dry-run should say commit-confirm and verification are not exercised")
	}
}

func TestOperationalModeIgnoresCommitConfirm(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(nil)
	r := newRunner(t, tr, Options{OpMode: true, CommitConfirm: 5, Verify: bgpRule(t)})
	res := runOne(t, r, "junos", "show version")
	if res.Status != StatusSucceeded || res.SafetyRating != "" || res.VerifyTotal != 0 {
		t.Fatalf("%+v", res)
	}
	if got := rec.of("sw1"); !slices.Equal(got, []string{"show version"}) {
		t.Fatalf("sent %q", got)
	}
}

// ---- verification -----------------------------------------------------------

func TestVerifyPlainModePasses(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "show bgp summary" {
			return "Peer 10.0.0.2 Established", nil
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{Verify: bgpRule(t)})
	res := runOne(t, r, "cisco", "hostname lab1")

	if res.Status != StatusSucceeded {
		t.Fatalf("%+v", res)
	}
	want := []string{"configure terminal", "hostname lab1", "end", "write memory", "show bgp summary"}
	if got := rec.of("sw1"); !slices.Equal(got, want) {
		t.Fatalf("sent\n got %q\nwant %q", got, want)
	}
	if res.Detail != "1 command(s) applied, 1/1 check(s) passed" {
		t.Fatalf("detail = %q", res.Detail)
	}
	if tr.opened != 1 {
		t.Fatal("no commit-confirm: no extra reachability session")
	}
}

func TestVerifyFailureTriggersRollbackEngine(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		switch line {
		case "show running-config":
			return "hostname lab1\ninterface Gi0/1\nend\n", nil
		case "show bgp summary":
			return "Peer 10.0.0.2 Idle", nil
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{Verify: bgpRule(t), Backup: true, BackupDir: t.TempDir(), RollbackOnFail: true})
	res := runOne(t, r, "cisco", "ntp server 10.9.9.9")

	if res.Status != StatusFailed || res.Category != CatVerifyFailed {
		t.Fatalf("status=%v category=%s", res.Status, res.Category)
	}
	if res.Rollback != RollbackOK || tr.opened != 2 {
		t.Fatalf("rollback=%v opened=%d: -rollback-on-fail must trigger the rollback engine", res.Rollback, tr.opened)
	}
	if rec.count("sw1", "hostname lab1") != 1 {
		t.Fatalf("the backup must have been re-applied: %q", rec.of("sw1"))
	}
}

func TestVerifyFailureWithoutRollbackFlagOnlyReports(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "show bgp summary" {
			return "Idle", nil
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{Verify: bgpRule(t)})
	res := runOne(t, r, "cisco", "ntp server 10.9.9.9")
	if res.Status != StatusFailed || res.Category != CatVerifyFailed || res.Rollback != RollbackNone || tr.opened != 1 {
		t.Fatalf("%+v opened=%d", res, tr.opened)
	}
	if !strings.Contains(logText(t, r), "VERIFY FAILED") {
		t.Fatal("a failed assertion must be logged prominently")
	}
}

func TestVerifyRetriesUntilConverged(t *testing.T) {
	var calls atomic.Int32
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "show bgp summary" {
			if calls.Add(1) < 3 {
				return "Peer 10.0.0.2 Active", nil
			}
			return "Peer 10.0.0.2 Established", nil
		}
		return "", nil
	})
	rules, err := ParseVerifyRules("verify show bgp summary\n expect: Established\n retries: 3\n interval: 1ms\n")
	if err != nil {
		t.Fatal(err)
	}
	r := newRunner(t, tr, Options{Verify: rules})
	res := runOne(t, r, "cisco", "hostname lab1")
	if res.Status != StatusSucceeded || rec.count("sw1", "show bgp summary") != 3 {
		t.Fatalf("status=%v sends=%d detail=%s", res.Status, rec.count("sw1", "show bgp summary"), res.Detail)
	}

	calls.Store(-100) // never converges
	res = runOne(t, r, "cisco", "hostname lab1")
	if res.Status != StatusFailed || res.Category != CatVerifyFailed {
		t.Fatalf("retries are bounded: %+v", res)
	}
}

func TestVerifyDeviceRejectingCheckFails(t *testing.T) {
	tr, _ := newFakeTransport(), newRecorder()
	tr.respond = func(host, line string) (string, error) {
		if line == "show bgp summary" {
			return "% Invalid input detected at '^' marker.", nil
		}
		return "", nil
	}
	rules, _ := ParseVerifyRules("verify show bgp summary\n not-contains: Idle\n") // would pass on the error text alone
	r := newRunner(t, tr, Options{Verify: rules})
	res := runOne(t, r, "cisco", "hostname lab1")
	if res.Status != StatusFailed || !strings.Contains(res.Detail, "device rejected the command") {
		t.Fatalf("a rejected check command is a failed check, never a pass: %+v", res)
	}
}

func TestVerifyDeadSessionFailsWithoutRetryStorm(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "show bgp summary" {
			return "", &fakeErr{"session", "connection reset by peer"}
		}
		return "", nil
	})
	rules, _ := ParseVerifyRules("verify show bgp summary\n expect: Established\n retries: 5\n interval: 1ms\n")
	r := newRunner(t, tr, Options{Verify: rules})
	res := runOne(t, r, "cisco", "hostname lab1")
	if res.Status != StatusFailed || res.Category != CatVerifyFailed {
		t.Fatalf("%+v", res)
	}
	if n := rec.count("sw1", "show bgp summary"); n != 1 {
		t.Fatalf("a dead session is not retried on the same session: %d sends", n)
	}
}

func TestVerifyRulesAreScopedPerDevice(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "show bgp summary" && host == "bad" {
			return "Idle", nil
		}
		if line == "show bgp summary" {
			return "Established", nil
		}
		return "", nil
	})
	rules, err := ParseVerifyRules(`
verify show bgp summary
  expect: Established
  vendors: cisco
verify show system uptime
  expect: up
  vendors: junos
`)
	if err != nil {
		t.Fatal(err)
	}
	r := newRunner(t, tr, Options{Verify: rules})
	jobs := mkJobs(t, "cisco", []string{"hostname x"}, "good", "bad")
	jobs = append(jobs, mkJobs(t, "junos", []string{"set system host-name x"}, "jn")...)
	res := r.Run(context.Background(), jobs)

	if res[0].Status != StatusSucceeded || res[0].VerifyTotal != 1 {
		t.Fatalf("good: %+v", res[0])
	}
	if res[1].Status != StatusFailed || res[1].Category != CatVerifyFailed {
		t.Fatalf("one device failing verification: %+v", res[1])
	}
	if res[2].VerifyTotal != 1 || rec.count("jn", "show bgp summary") != 0 {
		t.Fatalf("a cisco-only rule must not run on junos: %+v", res[2])
	}
	if s := Summarize(res); s.Succeeded < 1 {
		t.Fatalf("a failing device must not take down the others: %+v", s)
	}
}

func TestVerifyOutputIsKeptInOutputFile(t *testing.T) {
	dir := t.TempDir()
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		switch line {
		case "show bgp summary":
			return "Peer 10.0.0.2 Established", nil
		case "hostname lab1":
			return "ok", nil // output files are written only when the change produced output
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{Verify: bgpRule(t), OutputDir: dir})
	if res := runOne(t, r, "cisco", "hostname lab1"); res.Status != StatusSucceeded {
		t.Fatalf("%+v", res)
	}
	data, err := os.ReadFile(dir + "/sw1.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "=== verify: show bgp summary ===") || !strings.Contains(string(data), "Established") {
		t.Fatalf("audit output lacks the verification evidence:\n%s", data)
	}
}

func TestResultResetBetweenRetries(t *testing.T) {
	var opens atomic.Int32
	tr := newFakeTransport()
	tr.respond = func(host, line string) (string, error) { return "", nil }
	flaky := &countingTransport{fakeTransport: tr, opens: &opens}
	r := newRunner(t, flaky, Options{MaxRetries: 1, CommitConfirm: 5, Verify: bgpRule(t)})
	res := runOne(t, r, "junos", "set system host-name lab1")
	// Attempt 1 fails verification (empty output): not a retryable category,
	// so exactly one attempt must have run and its verify counts must stand.
	if res.Category != CatVerifyFailed || res.VerifyTotal != 1 || opens.Load() != 2 {
		t.Fatalf("category=%s verify=%d/%d opens=%d", res.Category, res.VerifyPassed, res.VerifyTotal, opens.Load())
	}
}

type countingTransport struct {
	*fakeTransport
	opens *atomic.Int32
}

func (c *countingTransport) Open(ctx context.Context, t Target) (Session, error) {
	c.opens.Add(1)
	return c.fakeTransport.Open(ctx, t)
}

func TestNativeAbortFailureFallsBackToTheDeadmanTimer(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		switch line {
		case "run show bgp summary":
			return "Peer 10.0.0.2 Active", nil
		case "rollback 1":
			return "error: could not load rollback 1", nil
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{CommitConfirm: 5, Verify: bgpRule(t), RollbackOnFail: true})
	res := runOne(t, r, "junos", "set system host-name lab1")

	if res.Status != StatusFailed || res.Category != CatVerifyFailed || res.Rollback != RollbackNone {
		t.Fatalf("a failed immediate revert must not be reported as rolled back: %+v", res)
	}
	got := rec.of("sw1")
	if got[len(got)-2] != "rollback 0" || got[len(got)-1] != "exit" {
		t.Fatalf("after a failed abort the session is still cleaned up: %q", got)
	}
	text := logText(t, r)
	if !strings.Contains(text, "native rollback failed") || !strings.Contains(text, "NOT confirmed") {
		t.Fatalf("the operator must learn that the timer owns the revert:\n%s", text)
	}
}

func TestReachabilityProbeFailureOnTheNewSession(t *testing.T) {
	tr, rec := newFakeTransport(), newRecorder()
	tr.respond = rec.wrap(func(host, line string) (string, error) {
		if line == "show system uptime" { // the probe command, on the new session
			return "", &fakeErr{"session", "connection reset by peer"}
		}
		return "", nil
	})
	r := newRunner(t, tr, Options{CommitConfirm: 5})
	res := runOne(t, r, "junos", "set system host-name lab1")
	if res.Status != StatusFailed || res.Category != CatVerifyFailed || !strings.Contains(res.Detail, "probe on new session failed") {
		t.Fatalf("%+v", res)
	}
	if rec.count("sw1", "commit") != 0 {
		t.Fatalf("not confirmed: %q", rec.of("sw1"))
	}
}

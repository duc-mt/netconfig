// ==============================================================================
// Package main implements Implementation and logic for task_test..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run task_test.go [options]
// Notes:         Go package implementation
// ==============================================================================
package task

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"netconfig/internal/credentials"
	"netconfig/internal/inventory"
	"netconfig/internal/logging"
)

// ---- fakes ------------------------------------------------------------------

type fakeErr struct{ kind, msg string }

func (e *fakeErr) Error() string     { return e.msg }
func (e *fakeErr) ErrorKind() string { return e.kind }

type fakeSession struct {
	host string
	tr   *fakeTransport
	mu   sync.Mutex
	sent []string
}

func (s *fakeSession) Send(ctx context.Context, line string, timeout time.Duration) (string, error) {
	s.mu.Lock()
	s.sent = append(s.sent, line)
	s.mu.Unlock()
	if s.tr.respond != nil {
		return s.tr.respond(s.host, line)
	}
	return "", nil
}

func (s *fakeSession) Close() error {
	s.tr.mu.Lock()
	s.tr.active--
	s.tr.mu.Unlock()
	return nil
}

type fakeTransport struct {
	mu        sync.Mutex
	sessions  map[string]*fakeSession
	openErr   map[string]error
	panicOn   map[string]bool
	respond   func(host, line string) (string, error)
	delay     time.Duration
	active    int
	maxActive int
	opened    int
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		sessions: map[string]*fakeSession{},
		openErr:  map[string]error{},
		panicOn:  map[string]bool{},
	}
}

func (t *fakeTransport) Open(ctx context.Context, tgt Target) (Session, error) {
	host := tgt.Device.Hostname
	t.mu.Lock()
	t.opened++
	t.active++
	if t.active > t.maxActive {
		t.maxActive = t.active
	}
	panicNow := t.panicOn[host]
	openErr := t.openErr[host]
	t.mu.Unlock()

	if t.delay > 0 {
		time.Sleep(t.delay)
	}
	if panicNow {
		panic("boom on " + host)
	}
	if openErr != nil {
		t.mu.Lock()
		t.active--
		t.mu.Unlock()
		return nil, openErr
	}
	s := &fakeSession{host: host, tr: t}
	t.mu.Lock()
	t.sessions[host] = s
	t.mu.Unlock()
	return s, nil
}

func (t *fakeTransport) sent(host string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.sessions[host]; s != nil {
		return s.sent
	}
	return nil
}

func mkJobs(t *testing.T, vendorName string, cmds []string, hosts ...string) []Job {
	t.Helper()
	var devs []inventory.Device
	for i, h := range hosts {
		devs = append(devs, inventory.Device{
			Hostname: h, Address: fmt.Sprintf("10.0.0.%d", i+1), Port: 22, Vendor: vendorName, Group: "default",
		})
	}
	jobs, err := BuildJobs(devs, StaticCommands(cmds))
	if err != nil {
		t.Fatal(err)
	}
	for i := range jobs {
		jobs[i].Cred = credentials.Credential{Username: "svc", Password: "pw-for-tests"}
	}
	return jobs
}

func newRunner(t *testing.T, tr Transport, opts Options) *Runner {
	t.Helper()
	log, err := logging.New(logging.Options{Dir: t.TempDir(), Console: nil})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if opts.Concurrency == 0 {
		opts.Concurrency = 2
	}
	if opts.CommandTimeout == 0 {
		opts.CommandTimeout = time.Second
	}
	return &Runner{Transport: tr, Log: log, Opts: opts}
}

// ---- execution --------------------------------------------------------------

func TestApplyCisco(t *testing.T) {
	tr := newFakeTransport()
	r := newRunner(t, tr, Options{})
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname lab1", "ntp server 10.9.9.9"}, "sw1"))

	if res[0].Status != StatusSucceeded || res[0].Category != "" {
		t.Fatalf("result = %+v", res[0])
	}
	want := []string{"configure terminal", "hostname lab1", "ntp server 10.9.9.9", "end", "write memory"}
	if got := tr.sent("sw1"); !slices.Equal(got, want) {
		t.Errorf("sent %q, want %q", got, want)
	}
	if !strings.Contains(res[0].Detail, "2 command(s) applied") {
		t.Errorf("detail = %q", res[0].Detail)
	}
}

func TestSyntaxErrorAbortsWithoutSaving(t *testing.T) {
	tr := newFakeTransport()
	tr.respond = func(host, line string) (string, error) {
		if line == "bogus" {
			return "% Invalid input detected at '^' marker.\n", nil
		}
		return "", nil
	}
	r := newRunner(t, tr, Options{})
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname x", "bogus", "ntp server 1.1.1.1"}, "sw1"))

	if res[0].Status != StatusFailed || res[0].Category != CatSyntaxError {
		t.Fatalf("result = %+v", res[0])
	}
	if !strings.Contains(res[0].Detail, "bogus") {
		t.Errorf("detail should name the rejected command: %q", res[0].Detail)
	}
	want := []string{"configure terminal", "hostname x", "bogus", "end"} // cleanup "end"; no later commands, no "write memory"
	if got := tr.sent("sw1"); !slices.Equal(got, want) {
		t.Errorf("sent %q, want %q", got, want)
	}
}

func TestJunosCommitFailureRollsBack(t *testing.T) {
	tr := newFakeTransport()
	tr.respond = func(host, line string) (string, error) {
		if line == "commit" {
			return "error: configuration check-out failed\n", nil
		}
		return "", nil
	}
	r := newRunner(t, tr, Options{})
	res := r.Run(context.Background(), mkJobs(t, "junos", []string{"set system host-name x"}, "mx1"))

	if res[0].Status != StatusFailed || res[0].Category != CatCommitFailed {
		t.Fatalf("result = %+v", res[0])
	}
	want := []string{"configure", "set system host-name x", "commit", "rollback 0", "exit"}
	if got := tr.sent("mx1"); !slices.Equal(got, want) {
		t.Errorf("sent %q, want %q", got, want)
	}
}

func TestDryRunNeverPersistsOnAnyVendor(t *testing.T) {
	persist := []string{"write memory", "commit", "save"}
	for _, name := range []string{"cisco", "junos", "huawei", "fortinet", "arista"} {
		tr := newFakeTransport()
		r := newRunner(t, tr, Options{DryRun: true})
		res := r.Run(context.Background(), mkJobs(t, name, []string{"hostname lab1"}, "dev1"))

		if res[0].Status != StatusSucceeded || !strings.Contains(res[0].Detail, "dry-run") {
			t.Errorf("%s: result = %+v", name, res[0])
		}
		for _, line := range tr.sent("dev1") {
			if slices.Contains(persist, line) {
				t.Errorf("%s: dry-run sent %q", name, line)
			}
		}
		if len(tr.sent("dev1")) == 0 {
			t.Errorf("%s: dry-run should still talk to the device (probe/validate)", name)
		}
	}
}

func TestDryRunOnProbeOnlyVendorSendsNoConfiguration(t *testing.T) {
	for _, name := range []string{"cisco", "huawei", "fortinet"} {
		tr := newFakeTransport()
		r := newRunner(t, tr, Options{DryRun: true})
		r.Run(context.Background(), mkJobs(t, name, []string{"hostname lab1"}, "dev1"))
		if slices.Contains(tr.sent("dev1"), "hostname lab1") {
			t.Errorf("%s: configuration command was sent during dry-run: %q", name, tr.sent("dev1"))
		}
	}
}

func TestDryRunValidatesOnJunos(t *testing.T) {
	tr := newFakeTransport()
	r := newRunner(t, tr, Options{DryRun: true})
	res := r.Run(context.Background(), mkJobs(t, "junos", []string{"set system host-name x"}, "mx1"))
	want := []string{"configure", "set system host-name x", "show | compare", "commit check", "rollback 0", "exit"}
	if got := tr.sent("mx1"); !slices.Equal(got, want) {
		t.Errorf("sent %q, want %q", got, want)
	}
	if !strings.Contains(res[0].Detail, "validated on device") {
		t.Errorf("detail = %q", res[0].Detail)
	}
}

func TestOpenErrorsAreCategorised(t *testing.T) {
	tr := newFakeTransport()
	tr.openErr["a"] = &fakeErr{"auth", "authentication failed"}
	tr.openErr["b"] = &fakeErr{"timeout", "handshake timeout"}
	tr.openErr["c"] = &fakeErr{"hostkey", "host key changed"}
	tr.openErr["d"] = &fakeErr{"connect", "connection refused"}
	tr.openErr["e"] = errors.New("something unclassified")
	tr.openErr["f"] = fmt.Errorf("dial: %w", context.Canceled)
	r := newRunner(t, tr, Options{})
	hosts := []string{"a", "b", "c", "d", "e", "f", "ok"}
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname x"}, hosts...))

	want := []Category{CatAuthFailed, CatTimeout, CatHostKeyFailed, CatConnectFailed, CatConnectFailed, CatCancelled, ""}
	for i, h := range hosts {
		if res[i].Category != want[i] {
			t.Errorf("%s: category = %q, want %q", h, res[i].Category, want[i])
		}
	}
	if res[6].Status != StatusSucceeded {
		t.Errorf("a failing neighbour must not affect the healthy device: %+v", res[6])
	}
	if ExitCode(res) != ExitPartial {
		t.Errorf("exit code = %d, want %d", ExitCode(res), ExitPartial)
	}
}

func TestSessionErrorsAreCategorised(t *testing.T) {
	tr := newFakeTransport()
	tr.respond = func(host, line string) (string, error) {
		switch host {
		case "slow":
			return "partial", &fakeErr{"timeout", "no prompt"}
		case "drop":
			return "", &fakeErr{"session", "connection closed"}
		case "weird":
			return "", errors.New("unexpected")
		}
		return "", nil
	}
	r := newRunner(t, tr, Options{})
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname x"}, "slow", "drop", "weird"))
	want := []Category{CatTimeout, CatSessionError, CatSessionError}
	for i := range res {
		if res[i].Status != StatusFailed || res[i].Category != want[i] {
			t.Errorf("%s: %+v, want category %s", res[i].Device.Hostname, res[i], want[i])
		}
	}
}

func TestPanicIsIsolatedPerDevice(t *testing.T) {
	tr := newFakeTransport()
	tr.panicOn["sw2"] = true
	r := newRunner(t, tr, Options{Concurrency: 1})
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname x"}, "sw1", "sw2", "sw3"))

	if res[1].Status != StatusFailed || res[1].Category != CatPanic {
		t.Fatalf("sw2 = %+v", res[1])
	}
	if res[0].Status != StatusSucceeded || res[2].Status != StatusSucceeded {
		t.Errorf("neighbours of the panicking device must still run: %+v / %+v", res[0], res[2])
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	tr := newFakeTransport()
	tr.delay = 20 * time.Millisecond
	r := newRunner(t, tr, Options{Concurrency: 3})
	hosts := []string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8"}
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname x"}, hosts...))

	for _, x := range res {
		if x.Status != StatusSucceeded {
			t.Fatalf("%+v", x)
		}
	}
	if tr.maxActive > 3 {
		t.Errorf("max concurrent sessions = %d, want <= 3", tr.maxActive)
	}
	if tr.opened != len(hosts) {
		t.Errorf("opened %d sessions, want %d", tr.opened, len(hosts))
	}
}

func TestResultsKeepInventoryOrder(t *testing.T) {
	tr := newFakeTransport()
	tr.delay = 5 * time.Millisecond
	r := newRunner(t, tr, Options{Concurrency: 4})
	hosts := []string{"a1", "a2", "a3", "a4", "a5", "a6"}
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname x"}, hosts...))
	for i, h := range hosts {
		if res[i].Device.Hostname != h {
			t.Errorf("result %d is %s, want %s", i, res[i].Device.Hostname, h)
		}
	}
}

func TestCancelledBeforeStartSkipsEverything(t *testing.T) {
	tr := newFakeTransport()
	r := newRunner(t, tr, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := r.Run(ctx, mkJobs(t, "cisco", []string{"hostname x"}, "sw1", "sw2"))
	for _, x := range res {
		if x.Status != StatusSkipped || x.Category != CatCancelled {
			t.Errorf("%+v", x)
		}
	}
	if tr.opened != 0 {
		t.Errorf("no session may be opened after cancellation, opened=%d", tr.opened)
	}
}

// ---- backup -----------------------------------------------------------------

func TestBackupIsWrittenBeforeChanges(t *testing.T) {
	tr := newFakeTransport()
	tr.respond = func(host, line string) (string, error) {
		if line == "show running-config" {
			return "hostname old\n!\nend\n", nil
		}
		return "", nil
	}
	dir := t.TempDir()
	r := newRunner(t, tr, Options{Backup: true, BackupDir: dir})
	r.Now = func() time.Time { return time.Date(2026, 10, 3, 10, 15, 0, 0, time.UTC) }
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname new"}, "sw/1"))

	if res[0].Status != StatusSucceeded {
		t.Fatalf("result = %+v", res[0])
	}
	if want := filepath.Join(dir, "sw_1_20261003-101500.cfg"); res[0].BackupPath != want {
		t.Errorf("backup path = %q, want %q", res[0].BackupPath, want)
	}
	data, err := os.ReadFile(res[0].BackupPath)
	if err != nil || !strings.Contains(string(data), "hostname old") {
		t.Fatalf("backup content = %q err=%v", data, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(res[0].BackupPath); st.Mode().Perm() != 0o600 {
			t.Errorf("backup mode = %v, want 0600", st.Mode().Perm())
		}
	}
	sent := tr.sent("sw/1")
	if len(sent) < 2 || sent[0] != "show running-config" || sent[1] != "configure terminal" {
		t.Errorf("backup must precede configuration: %q", sent)
	}
}

func TestBackupFailureBlocksChanges(t *testing.T) {
	tr := newFakeTransport()
	tr.respond = func(host, line string) (string, error) {
		if line == "show running-config" {
			return "% Invalid input detected at '^' marker.\n", nil
		}
		return "", nil
	}
	r := newRunner(t, tr, Options{Backup: true, BackupDir: t.TempDir()})
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname new"}, "sw1"))

	if res[0].Status != StatusFailed || res[0].Category != CatBackupFailed {
		t.Fatalf("result = %+v", res[0])
	}
	if got := tr.sent("sw1"); !slices.Equal(got, []string{"show running-config"}) {
		t.Errorf("nothing may be changed after a failed backup, sent %q", got)
	}
}

// ---- preparation ------------------------------------------------------------

func TestSkippedJobsNeverOpenSessions(t *testing.T) {
	devs := []inventory.Device{
		{Hostname: "ok", Address: "10.0.0.1", Port: 22, Vendor: "cisco", Group: "dc1"},
		{Hostname: "nokia1", Address: "10.0.0.2", Port: 22, Vendor: "nokia", Group: "dc1"},
		{Hostname: "nocred", Address: "10.0.0.3", Port: 22, Vendor: "cisco", Group: "dc9"},
		{Hostname: "cisco-only", Address: "10.0.0.4", Port: 22, Vendor: "junos", Group: "dc1"},
	}
	src, err := TemplateCommands(`{{ if eq .Vendor "cisco" }}hostname {{ .Hostname }}{{ end }}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := BuildJobs(devs, src)
	if err != nil {
		t.Fatal(err)
	}
	ResolveCredentials(jobs, func(group string) (credentials.Credential, error) {
		if group == "dc9" {
			return credentials.Credential{}, fmt.Errorf("%w for group %q", credentials.ErrNotFound, group)
		}
		return credentials.Credential{Username: "u", Password: "p"}, nil
	})

	wantSkip := []Category{"", CatUnsupportedVendor, CatNoCredentials, CatNoCommands}
	for i, j := range jobs {
		if j.Skip != wantSkip[i] {
			t.Errorf("%s: skip = %q, want %q", j.Device.Hostname, j.Skip, wantSkip[i])
		}
	}

	tr := newFakeTransport()
	r := newRunner(t, tr, Options{})
	res := r.Run(context.Background(), jobs)
	if res[0].Status != StatusSucceeded {
		t.Errorf("runnable device: %+v", res[0])
	}
	for _, x := range res[1:] {
		if x.Status != StatusSkipped {
			t.Errorf("%s should be skipped: %+v", x.Device.Hostname, x)
		}
	}
	if tr.opened != 1 {
		t.Errorf("sessions opened = %d, want exactly 1", tr.opened)
	}
	if ExitCode(res) != ExitPartial {
		t.Errorf("skipped devices must not yield exit 0, got %d", ExitCode(res))
	}
}

func TestTemplateFailureIsFatalBeforeAnythingRuns(t *testing.T) {
	src, err := TemplateCommands("ntp server {{ .Vars.ntp }}", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = BuildJobs([]inventory.Device{{Hostname: "sw1", Vendor: "cisco"}}, src)
	if err == nil || !strings.Contains(err.Error(), "sw1") {
		t.Fatalf("expected a render error naming the device, got %v", err)
	}
}

func TestParseCommands(t *testing.T) {
	got := ParseCommands("# comment\n\n! cisco comment\n  hostname x  \r\nend\n")
	if want := []string{"hostname x", "end"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTemplateRendering(t *testing.T) {
	text := strings.Join([]string{
		"hostname {{ .Hostname | upper }}",
		"{{ if eq .Vendor \"cisco\" }}ip domain-name {{ .Vars.domain }}{{ end }}",
		"# a comment",
		"! {{ .Address }}:{{ .Port }} group={{ .Group }}",
	}, "\n")
	src, err := TemplateCommands(text, map[string]string{"domain": "example.net"})
	if err != nil {
		t.Fatal(err)
	}

	cisco := inventory.Device{Hostname: "sw1", Address: "10.0.0.1", Port: 22, Vendor: "ios-xe", Group: "dc1"}
	got, err := src(cisco)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"hostname SW1", "ip domain-name example.net"}; !slices.Equal(got, want) {
		t.Errorf("cisco: got %q, want %q", got, want)
	}

	junos := inventory.Device{Hostname: "mx1", Address: "10.0.0.2", Port: 22, Vendor: "junos", Group: "dc1"}
	got, err = src(junos)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"hostname MX1"}; !slices.Equal(got, want) {
		t.Errorf("junos: got %q, want %q", got, want)
	}

	if _, err := TemplateCommands("{{ .Hostname", nil); err == nil {
		t.Error("expected a parse error for a broken template")
	}
}

// ---- audit log --------------------------------------------------------------

func TestLogContainsTraceButMasksSecretsInCommands(t *testing.T) {
	tr := newFakeTransport()
	tr.respond = func(host, line string) (string, error) {
		if line == "show clock" {
			return "10:00:00 UTC\n", nil
		}
		return "", nil
	}
	r := newRunner(t, tr, Options{})
	cmds := []string{"hostname lab1", "username admin secret 5 $1$abcd$hashvalue"}
	r.Run(context.Background(), mkJobs(t, "cisco", cmds, "sw1"))
	_ = r.Log.Close()

	data, err := os.ReadFile(r.Log.Path())
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	for _, want := range []string{">> configure terminal", ">> hostname lab1", ">> write memory", "[sw1]"} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q", want)
		}
	}
	if strings.Contains(log, "$1$abcd$hashvalue") {
		t.Errorf("secret from a configuration command leaked into the log:\n%s", log)
	}
	if !strings.Contains(log, "username admin secret 5 <redacted>") {
		t.Errorf("log should keep the command shape with the value masked:\n%s", log)
	}
}

// ---- summary ----------------------------------------------------------------

func TestSummaryAndExitCode(t *testing.T) {
	mk := func(host string, st Status, cat Category, detail string) Result {
		return Result{
			Device: inventory.Device{Hostname: host, Address: "10.0.0.1", Port: 22, Vendor: "cisco"},
			Status: st, Category: cat, Detail: detail, Duration: 1500 * time.Millisecond,
		}
	}
	results := []Result{
		mk("sw1", StatusSucceeded, "", "2 command(s) applied"),
		mk("sw2", StatusFailed, CatAuthFailed, "authentication failed"),
		mk("sw3", StatusFailed, CatAuthFailed, "authentication failed"),
		mk("sw4", StatusFailed, CatTimeout, "no prompt"),
		mk("sw5", StatusSkipped, CatNoCredentials, "group dc9"),
	}
	sum := Summarize(results)
	if sum.Succeeded != 1 || sum.Failed != 3 || sum.Skipped != 1 {
		t.Fatalf("counts = %d/%d/%d", sum.Succeeded, sum.Failed, sum.Skipped)
	}
	if got := sum.ByCategory[CatAuthFailed]; !slices.Equal(got, []string{"sw2", "sw3"}) {
		t.Errorf("AUTH_FAILED hosts = %v", got)
	}

	plain := sum.Render(RenderOptions{})
	for _, want := range []string{
		"Succeeded: 1", "Failed: 3", "Skipped: 1", "(total 5)",
		"Failure reasons:", "AUTH_FAILED", "TIMEOUT", "Skipped reasons:", "NO_CREDENTIALS",
		"sw2, sw3", "SUCCEEDED", "FAILED", "SKIPPED", "1.5s",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("summary missing %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "\x1b[") {
		t.Errorf("plain summary contains ANSI codes:\n%q", plain)
	}
	if !strings.Contains(sum.Render(RenderOptions{Color: true}), "\x1b[31m") {
		t.Error("coloured summary should contain red for failures")
	}
	if !strings.Contains(sum.Render(RenderOptions{DryRun: true}), "DRY-RUN") {
		t.Error("dry-run banner missing")
	}

	if ExitCode(results) != ExitPartial {
		t.Errorf("mixed results: exit %d", ExitCode(results))
	}
	if ExitCode(results[:1]) != ExitOK {
		t.Errorf("all succeeded: exit %d", ExitCode(results[:1]))
	}
	if ExitCode(results[4:]) != ExitPartial {
		t.Errorf("only skipped: exit %d, want %d", ExitCode(results[4:]), ExitPartial)
	}
}

// ---- commands-applied progress ----------------------------------------------

func TestCommandsAppliedOnSuccess(t *testing.T) {
	tr := newFakeTransport()
	r := newRunner(t, tr, Options{})
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname lab1", "ntp server 10.9.9.9"}, "sw1"))

	if res[0].CommandsApplied != 2 || res[0].CommandsTotal != 2 {
		t.Errorf("CommandsApplied/Total = %d/%d, want 2/2", res[0].CommandsApplied, res[0].CommandsTotal)
	}
}

func TestCommandsAppliedTracksMidPlanFailure(t *testing.T) {
	tr := newFakeTransport()
	tr.respond = func(host, line string) (string, error) {
		if line == "bogus" {
			return "% Invalid input detected at '^' marker.\n", nil
		}
		return "", nil
	}
	r := newRunner(t, tr, Options{})
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname x", "bogus", "ntp server 1.1.1.1"}, "sw1"))

	if res[0].Status != StatusFailed {
		t.Fatalf("result = %+v", res[0])
	}
	if res[0].CommandsTotal != 3 {
		t.Errorf("CommandsTotal = %d, want 3", res[0].CommandsTotal)
	}
	if res[0].CommandsApplied != 1 {
		t.Errorf("CommandsApplied = %d, want 1 (only %q got through before %q was rejected)",
			res[0].CommandsApplied, "hostname x", "bogus")
	}
}

func TestCommandsTotalSetEvenOnConnectFailure(t *testing.T) {
	tr := newFakeTransport()
	tr.openErr = map[string]error{"sw1": &fakeErr{kind: "connect", msg: "no route to host"}}
	r := newRunner(t, tr, Options{})
	res := r.Run(context.Background(), mkJobs(t, "cisco", []string{"hostname x", "ntp server 1.1.1.1"}, "sw1"))

	if res[0].Status != StatusFailed || res[0].Category != CatConnectFailed {
		t.Fatalf("result = %+v", res[0])
	}
	if res[0].CommandsTotal != 2 || res[0].CommandsApplied != 0 {
		t.Errorf("CommandsApplied/Total = %d/%d, want 0/2", res[0].CommandsApplied, res[0].CommandsTotal)
	}
}

// ---- rollback outcome --------------------------------------------------------

func TestRollbackOutcomeRecorded(t *testing.T) {
	t.Run("succeeds", func(t *testing.T) {
		tr := newFakeTransport()
		tr.respond = func(host, line string) (string, error) {
			switch line {
			case "show configuration | no-more":
				return "set system host-name old\n", nil
			case "commit":
				return "error: configuration check-out failed\n", nil
			}
			return "", nil
		}
		r := newRunner(t, tr, Options{Backup: true, BackupDir: t.TempDir(), RollbackOnFail: true})
		res := r.Run(context.Background(), mkJobs(t, "junos", []string{"set system host-name x"}, "mx1"))

		if res[0].Status != StatusFailed || res[0].Category != CatCommitFailed {
			t.Fatalf("result = %+v", res[0])
		}
		if res[0].Rollback != RollbackOK {
			t.Errorf("Rollback = %v, want RollbackOK", res[0].Rollback)
		}
	})

	t.Run("fails", func(t *testing.T) {
		tr := newFakeTransport()
		tr.respond = func(host, line string) (string, error) {
			switch line {
			case "show configuration | no-more":
				return "set system host-name old\n", nil
			case "commit":
				return "error: configuration check-out failed\n", nil
			case "set system host-name old":
				// Only the rollback plan re-sends the backed-up line; a hard
				// transport error there (as opposed to a device-rejected
				// pattern match) is what makes the rollback itself fail.
				return "", errors.New("connection reset by peer")
			}
			return "", nil
		}
		r := newRunner(t, tr, Options{Backup: true, BackupDir: t.TempDir(), RollbackOnFail: true})
		res := r.Run(context.Background(), mkJobs(t, "junos", []string{"set system host-name x"}, "mx1"))

		if res[0].Status != StatusFailed || res[0].Category != CatCommitFailed {
			t.Fatalf("result = %+v", res[0])
		}
		if res[0].Rollback != RollbackFailed {
			t.Errorf("Rollback = %v, want RollbackFailed", res[0].Rollback)
		}
	})
}

// ---- result table rendering --------------------------------------------------

func TestRenderShowsFailedFirst(t *testing.T) {
	mk := func(host string, st Status) Result {
		return Result{Device: inventory.Device{Hostname: host, Vendor: "cisco"}, Status: st}
	}
	results := []Result{
		mk("ok1", StatusSucceeded),
		mk("skip1", StatusSkipped),
		mk("fail1", StatusFailed),
		mk("ok2", StatusSucceeded),
		mk("fail2", StatusFailed),
	}
	out := Summarize(results).Render(RenderOptions{})

	wantOrder := []string{"fail1", "fail2", "skip1", "ok1", "ok2"}
	last := -1
	for _, host := range wantOrder {
		idx := strings.Index(out, host)
		if idx < 0 {
			t.Fatalf("host %q missing from table:\n%s", host, out)
		}
		if idx < last {
			t.Errorf("rows out of order at %q; want FAILED, then SKIPPED, then SUCCEEDED (original order kept within each group):\n%s", host, out)
		}
		last = idx
	}
}

func TestRenderAppliedAndBackupColumns(t *testing.T) {
	results := []Result{
		{
			Device: inventory.Device{Hostname: "sw1", Vendor: "cisco"}, Status: StatusSucceeded,
			CommandsApplied: 3, CommandsTotal: 3, BackupPath: "/backups/sw1.cfg",
		},
		{
			Device: inventory.Device{Hostname: "sw2", Vendor: "cisco"}, Status: StatusFailed, Category: CatCommitFailed,
			CommandsApplied: 1, CommandsTotal: 3, BackupPath: "/backups/sw2.cfg", Rollback: RollbackOK,
		},
	}
	out := Summarize(results).Render(RenderOptions{})

	for _, want := range []string{"APPLIED", "3/3", "1/3", "BACKUP", "SAVED", "ROLLED_BACK"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}

func TestRenderHidesBackupColumnWhenUnused(t *testing.T) {
	results := []Result{
		{Device: inventory.Device{Hostname: "sw1", Vendor: "cisco"}, Status: StatusSucceeded, CommandsApplied: 1, CommandsTotal: 1},
	}
	out := Summarize(results).Render(RenderOptions{})
	if strings.Contains(out, "BACKUP") {
		t.Errorf("BACKUP column should be hidden when no result used -backup:\n%s", out)
	}
}

func TestRenderNarrowWidthDropsColumnsAndShrinksDetail(t *testing.T) {
	// Under 90 chars so it survives the table's normal cap untouched at full
	// (Width: 0) width; long enough that a 60-column terminal still has to
	// shrink it further.
	longDetail := "device rejected a configuration command with a long explanatory message"
	results := []Result{
		{
			Device: inventory.Device{Hostname: "edge-sw01", Address: "10.0.0.1", Vendor: "cisco"},
			Status: StatusFailed, Category: CatSyntaxError, Detail: longDetail,
		},
	}
	sum := Summarize(results)

	wide := sum.Render(RenderOptions{})
	if !strings.Contains(wide, "ADDRESS") || !strings.Contains(wide, "VENDOR") {
		t.Fatalf("expected ADDRESS and VENDOR columns with no width limit:\n%s", wide)
	}
	if !strings.Contains(wide, longDetail) {
		t.Fatalf("expected the full detail message with no width limit:\n%s", wide)
	}

	narrow := sum.Render(RenderOptions{Width: 60})
	lines := strings.Split(narrow, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least a title and header line:\n%s", narrow)
	}
	if n := utf8.RuneCountInString(lines[1]); n > 60 {
		t.Errorf("header row exceeds the requested width 60 (got %d): %q", n, lines[1])
	}
	if strings.Contains(narrow, "VENDOR") {
		t.Errorf("expected VENDOR to be dropped at width 60:\n%s", narrow)
	}
	if strings.Contains(narrow, longDetail) {
		t.Errorf("expected DETAIL to be truncated at width 60:\n%s", narrow)
	}
}

// ---- CSV report ---------------------------------------------------------------

func TestWriteCSVReport(t *testing.T) {
	results := []Result{
		{
			Device: inventory.Device{Hostname: "sw1", Address: "10.0.0.1", Vendor: "cisco"},
			Status: StatusSucceeded, Duration: 2 * time.Second,
			CommandsApplied: 3, CommandsTotal: 3,
		},
		{
			Device: inventory.Device{Hostname: "sw2", Address: "10.0.0.2", Vendor: "junos"},
			Status: StatusFailed, Category: CatAuthFailed, Detail: "authentication failed",
			CommandsTotal: 2,
		},
	}
	path := filepath.Join(t.TempDir(), "report.csv")
	if err := WriteCSVReport(path, results, ""); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"hostname,address,vendor,status,category,detail,duration_ms,commands_applied,commands_total,backup_path,rollback,output_file",
		"sw1,10.0.0.1,cisco,SUCCEEDED,,,2000,3,3,,,",
		"sw2,10.0.0.2,junos,FAILED,AUTH_FAILED,authentication failed,0,0,2,,,",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("CSV report missing %q in:\n%s", want, text)
		}
	}
}

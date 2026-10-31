package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"netops/internal/inventory"
	"netops/internal/log/collector"
	"netops/internal/log/parser"
	"netops/internal/log/pipeline"
	"netops/internal/log/report"
	"netops/internal/log/store"
	"netops/internal/task"
)

// logFakeIOS is a Cisco-IOS-like device with a fixed log buffer (so repeated
// polls see the same lines, as on a real device) that tests can append to.
type logFakeIOS struct {
	mu    sync.Mutex
	base  time.Time
	extra []string
	execs []string
}

func (f *logFakeIOS) stamp(ago time.Duration) string {
	return f.base.Add(-ago).Format("Jan _2 15:04:05.000")
}

func (f *logFakeIOS) addLine(line string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extra = append(f.extra, line)
}

func (f *logFakeIOS) count(cmd string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.execs {
		if c == cmd {
			n++
		}
	}
	return n
}

func (f *logFakeIOS) respond(cmd string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, cmd)
	switch cmd {
	case "show logging":
		out := "Syslog logging: enabled\n    Log Buffer (65536 bytes):\n\n" +
			f.stamp(5*time.Minute) + ": %SYS-5-CONFIG_I: Configured from console by tanvt on vty0 (10.10.10.50)\n" +
			f.stamp(4*time.Minute) + ": %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Dead timer expired\n" +
			f.stamp(3*time.Minute) + ": %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down\n" +
			f.stamp(2*time.Minute) + ": %SYS-5-CONFIG_I: Configured from console by \x1b[2Jevil on vty1 (6.6.6.6)\n"
		return out + strings.Join(f.extra, "")
	case "show clock":
		return "*" + time.Now().Add(3*time.Second).Format("15:04:05.000 MST Mon Jan 2 2006") + "\n"
	}
	return "output of [" + cmd + "]\n"
}

// pinLogDaytime makes the local zone a fixed offset at which "now" reads 14:00.
// netops log reclassifies config changes between 00:00 and 06:00 local as
// AFTER_HOURS_CHANGE, so without this the tests would pass in the daytime and
// fail if they happened to run at night. It must run before anything captures
// time.Local (the fake device formats its log lines in local time, and the app
// reads time.Local when it starts).
func pinLogDaytime(t *testing.T) {
	t.Helper()
	old := time.Local
	now := time.Now().UTC()
	// Whole minutes only: RFC 3339 (hence the JSON state files) cannot represent
	// an offset with a seconds component, and real zones never have one.
	offset := (14*3600 - (now.Hour()*3600 + now.Minute()*60 + now.Second())) / 60 * 60
	time.Local = time.FixedZone("netops-log-test", offset)
	t.Cleanup(func() { time.Local = old })
}

func startLogFakeIOS(t *testing.T) (*logFakeIOS, string, int) {
	t.Helper()
	pinLogDaytime(t)
	dev := &logFakeIOS{base: time.Now()}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "u" && string(pw) == "p" {
			return nil, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for r := range creqs {
							if r.Type != "exec" {
								r.Reply(false, nil)
								continue
							}
							n := binary.BigEndian.Uint32(r.Payload[:4])
							cmd := string(r.Payload[4 : 4+n])
							r.Reply(true, nil)
							ch.Write([]byte(dev.respond(cmd)))
							ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							ch.Close()
							return
						}
					}()
				}
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return dev, host, port
}

type logEnv struct {
	dir  string
	args []string // common collect flags
}

func newLogEnv(t *testing.T, inventory string) logEnv {
	t.Helper()
	t.Setenv("NETOPS_USERNAME", "u")
	t.Setenv("NETOPS_PASSWORD", "p")
	t.Setenv("NETOPS_JUMP_HOST", "")
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.csv")
	if err := os.WriteFile(inv, []byte("hostname,address,port,vendor,credential_group,jump_host\n"+inventory), 0o600); err != nil {
		t.Fatal(err)
	}
	return logEnv{dir: dir, args: []string{
		"--inventory", inv, "--env-file", filepath.Join(dir, "none.env"), "--data-dir", filepath.Join(dir, "data"),
		"--known-hosts", filepath.Join(dir, "known_hosts"), "--jump=false",
	}}
}

// opts builds the options of an in-process collect run over this environment.
func (e logEnv) opts(concurrency int, timeout, interval time.Duration) logCollectOpts {
	return logCollectOpts{
		logConn: logConn{
			inventory: e.args[1], envFile: e.args[3], connectTimeout: timeout, commandTimeout: timeout,
			knownHosts: e.args[7], hostKeyPolicy: "accept-new", legacyAlgorithms: true,
		},
		dataDir: e.args[5], concurrency: concurrency, interval: interval,
	}
}

func (e logEnv) run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var o, er bytes.Buffer
	code = runLog(args, nil, &o, &er)
	return o.String(), er.String(), code
}

func (e logEnv) collect(t *testing.T) (string, int) {
	return e.collectWith(t)
}

// collectWith runs one collect pass with extra flags.
func (e logEnv) collectWith(t *testing.T, extra ...string) (string, int) {
	_, stderr, code := e.run(t, append(append([]string{"collect"}, extra...), e.args...)...)
	return stderr, code
}

func (e logEnv) logEntries(t *testing.T) []collector.LogEntry {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(e.dir, "data", "logs", "*.jsonl"))
	var out []collector.LogEntry
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == "" {
				continue
			}
			var le collector.LogEntry
			if err := json.Unmarshal([]byte(line), &le); err != nil {
				t.Fatalf("bad JSONL: %v", err)
			}
			out = append(out, le)
		}
	}
	return out
}

func (e logEnv) incidents(t *testing.T) []collector.IncidentReport {
	t.Helper()
	rs, err := store.ListIncidents(store.IncidentsDir(filepath.Join(e.dir, "data")), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// --no-config-diff restores the previous behaviour: configuration changes are
// logged but never open an SSH session of their own.
func TestLogCollectNoConfigDiffFlag(t *testing.T) {
	dev, host, port := startLogFakeIOS(t)
	e := newLogEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n", host, port))
	if stderr, code := e.collectWith(t, "--no-config-diff"); code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	incs := e.incidents(t)
	if len(incs) != 2 { // OSPF down + link down only
		t.Fatalf("want 2 incidents, got %d", len(incs))
	}
	for _, inc := range incs {
		if inc.Playbook == "config_change" || inc.ConfigDiff != "" {
			t.Errorf("config diff captured despite --no-config-diff: %+v", inc)
		}
	}
	if n := dev.count("show archive config differences nvram:startup-config system:running-config"); n != 0 {
		t.Errorf("the comparison ran %d time(s) with --no-config-diff", n)
	}
}

func TestLogCollectEndToEnd(t *testing.T) {
	dev, host, port := startLogFakeIOS(t)
	e := newLogEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n", host, port))

	// ---- first poll: ingest, classify, correct skew, triage ----
	stderr, code := e.collect(t)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	entries := e.logEntries(t)
	if len(entries) != 4 {
		t.Fatalf("want 4 entries (banner lines are not events), got %d\n%s", len(entries), stderr)
	}
	byEvent := map[string]collector.LogEntry{}
	for _, le := range entries {
		byEvent[le.Event] = le
	}
	for _, ev := range []string{"CONFIG_CHANGE", "OSPF_ADJ_DOWN", "LINK_DOWN"} {
		if _, ok := byEvent[ev]; !ok {
			t.Errorf("missing event %s", ev)
		}
	}
	var tanvt collector.LogEntry
	for _, le := range entries {
		if le.User == "tanvt" {
			tanvt = le
		}
	}
	if tanvt.ID == "" || tanvt.SessionID != "vty0" || tanvt.SourceIP != "10.10.10.50" {
		t.Errorf("config change lost its attribution: %+v", tanvt)
	}
	if skew := entries[0].SkewMs; skew < 1500 || skew > 6000 {
		t.Errorf("skew_ms = %d, want about +3000 (the fake clock runs 3s fast)", skew)
	}
	// Corrected time should land close to the true event time (5 minutes ago).
	if d := time.Since(tanvt.Timestamp); d < 4*time.Minute || d > 6*time.Minute {
		t.Errorf("corrected timestamp is %v old, want about 5m (event was 5m before the fake's 'now')", d)
	}
	// OSPF down + link down + one config_change capture (the second config line,
	// "evil", is inside the 5 minute cooldown of the first and is not a fault).
	playbooks := map[string]collector.IncidentReport{}
	for _, inc := range e.incidents(t) {
		playbooks[inc.Playbook] = inc
	}
	if len(e.incidents(t)) != 3 || playbooks["ospf_adj_down"].ID == "" || playbooks["link_down"].ID == "" || playbooks["config_change"].ID == "" {
		t.Fatalf("want 3 incidents (ospf_adj_down, link_down, config_change), got %+v\n%s", playbooks, stderr)
	}
	const diffCmd = "show archive config differences nvram:startup-config system:running-config"
	if got := playbooks["config_change"]; got.ConfigDiff != "output of ["+diffCmd+"]\n" || dev.count(diffCmd) != 1 {
		t.Errorf("config diff capture: ConfigDiff=%q, device ran the comparison %d time(s)", got.ConfigDiff, dev.count(diffCmd))
	}
	if dev.count("show ip ospf neighbor") != 1 {
		t.Errorf("ospf playbook should have run once, ran %d times", dev.count("show ip ospf neighbor"))
	}
	if _, err := os.Stat(store.StatePath(filepath.Join(e.dir, "data"))); err != nil {
		t.Errorf("state file missing: %v", err)
	}

	// ---- second poll of the same buffer: nothing new, nothing triaged ----
	stderr, code = e.collect(t)
	if code != 0 || len(e.logEntries(t)) != 4 || len(e.incidents(t)) != 3 {
		t.Fatalf("repeat poll must be idempotent: code=%d entries=%d incidents=%d\n%s", code, len(e.logEntries(t)), len(e.incidents(t)), stderr)
	}
	if !strings.Contains(stderr, "0 new log entries") {
		t.Errorf("summary should report 0 new entries:\n%s", stderr)
	}

	// ---- a new OSPF-down line: stored, but the persisted cooldown stops triage ----
	dev.addLine(dev.stamp(30*time.Second) + ": %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.9 on GigabitEthernet0/2 from FULL to DOWN, Neighbor Down: Dead timer expired\n")
	stderr, code = e.collect(t)
	if code != 0 || len(e.logEntries(t)) != 5 {
		t.Fatalf("new line must be stored: code=%d entries=%d\n%s", code, len(e.logEntries(t)), stderr)
	}
	if dev.count("show ip ospf neighbor") != 1 || len(e.incidents(t)) != 3 {
		t.Errorf("cooldown must hold across runs: ospf execs=%d incidents=%d", dev.count("show ip ospf neighbor"), len(e.incidents(t)))
	}
	if !strings.Contains(stderr, "in cooldown") {
		t.Errorf("suppression should be logged:\n%s", stderr)
	}

	// ---- query / timeline / incidents ----
	out, _, code := e.run(t, "query", "--data-dir", filepath.Join(e.dir, "data"), "--category", "FAULT", "--since", "1h", "--no-color")
	if code != 0 || !strings.Contains(out, "OSPF_ADJ_DOWN") || !strings.Contains(out, "LINK_DOWN") || strings.Contains(out, "CONFIG_CHANGE") {
		t.Errorf("query --category FAULT:\n%s", out)
	}
	out, _, code = e.run(t, "query", "--data-dir", filepath.Join(e.dir, "data"), "--user", "tanvt", "--format", "json", "--since", "1h")
	var js []collector.LogEntry
	if code != 0 || json.Unmarshal([]byte(out), &js) != nil || len(js) != 1 || js[0].User != "tanvt" {
		t.Errorf("query --user tanvt --format json: code=%d out=%s", code, out)
	}
	out, _, code = e.run(t, "timeline", "--data-dir", filepath.Join(e.dir, "data"), "--from", time.Now().Add(-30*time.Minute).Format("2006-01-02 15:04:05"), "--no-color")
	if code != 0 || !strings.Contains(out, "[CONFIG]") || !strings.Contains(out, "└── Likely caused by config change by tanvt") {
		t.Errorf("timeline should attribute the OSPF fault to tanvt's change:\n%s", out)
	}
	out, _, code = e.run(t, "incidents", "--data-dir", filepath.Join(e.dir, "data"), "--since", "1h", "--no-color")
	if code != 0 || !strings.Contains(out, "ospf_adj_down") || !strings.Contains(out, "link_down") || !strings.Contains(out, "config_change") {
		t.Errorf("incidents list:\n%s", out)
	}
	id := e.incidents(t)[0].ID
	// Default text format
	out, _, code = e.run(t, "incidents", "--data-dir", filepath.Join(e.dir, "data"), "--id", id[:4])
	if code != 0 || !strings.Contains(out, "INCIDENT REPORT:") || !strings.Contains(out, "DIAGNOSTICS") {
		t.Errorf("incidents --id (text): code=%d\n%s", code, out)
	}
	// Explicit json format
	out, _, code = e.run(t, "incidents", "--data-dir", filepath.Join(e.dir, "data"), "--id", id[:4], "--format", "json")
	var rep collector.IncidentReport
	if code != 0 || json.Unmarshal([]byte(out), &rep) != nil || rep.ID != id || len(rep.Diagnostics) == 0 {
		t.Errorf("incidents --id (json): code=%d\n%s", code, out)
	}

	// ---- a hostile device cannot drive the operator's terminal or forge log lines ----
	if strings.Contains(stderr, "\x1b") {
		t.Errorf("escape from device text reached netops log's own log output:\n%q", stderr)
	}
	out, _, _ = e.run(t, "query", "--data-dir", filepath.Join(e.dir, "data"), "--since", "1h")
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape from device text reached the table output:\n%q", out)
	}
}

func TestLogCollectExitCodes(t *testing.T) {
	// A device that cannot be reached: the run completes but nothing was polled.
	e := newLogEnv(t, "DEAD,127.0.0.1,1,cisco_ios,default,\n")
	stderr, code := e.collect(t)
	if code != task.ExitFatal || !strings.Contains(stderr, "no device could be polled") {
		t.Errorf("all devices failing must exit 1, got %d\n%s", code, stderr)
	}

	// An unsupported vendor alongside a healthy device: partial failure is still success.
	_, host, port := startLogFakeIOS(t)
	e = newLogEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\nPF,%s,%d,sophos,default,\n", host, port, host, port))
	stderr, code = e.collect(t)
	if code != 0 {
		t.Errorf("partial failure must exit 0, got %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "PF: netops log has no log fetch command") {
		t.Errorf("unsupported vendor should be reported:\n%s", stderr)
	}

	for name, tc := range map[string]struct {
		args []string
		want int
	}{
		"no args":             {nil, task.ExitFatal},
		"unknown command":     {[]string{"bogus"}, task.ExitFatal},
		"help":                {[]string{"help"}, task.ExitOK},
		"bad flag":            {[]string{"query", "--nope"}, task.ExitFatal},
		"bad category":        {[]string{"query", "--category", "NOPE"}, task.ExitFatal},
		"bad severity":        {[]string{"query", "--severity", "LOUD"}, task.ExitFatal},
		"bad format":          {[]string{"query", "--format", "xml"}, task.ExitFatal},
		"bad since":           {[]string{"query", "--since", "soon"}, task.ExitFatal},
		"timeline bad range":  {[]string{"timeline", "--from", "2026-10-20 10:00:00", "--to", "2026-10-20 09:00:00"}, task.ExitFatal},
		"timeline bad time":   {[]string{"timeline", "--from", "yesterday"}, task.ExitFatal},
		"collect zero conc":   {[]string{"collect", "--concurrency", "0"}, task.ExitFatal},
		"monitor tiny interv": {[]string{"monitor", "--interval", "1s"}, task.ExitFatal},
		"collect stray arg":   {[]string{"collect", "extra"}, task.ExitFatal},
		"collect no inv":      {[]string{"collect", "--inventory", "/nonexistent/inv.csv", "--data-dir", t.TempDir()}, task.ExitFatal},
		"incidents unknown":   {[]string{"incidents", "--data-dir", t.TempDir(), "--id", "zzzz"}, task.ExitFatal},
	} {
		var o, er bytes.Buffer
		if got := runLog(tc.args, nil, &o, &er); got != tc.want {
			t.Errorf("%s: exit %d, want %d\nstdout: %s\nstderr: %s", name, got, tc.want, o.String(), er.String())
		}
		if name == "collect no inv" && !strings.Contains(er.String(), "Tip: Run 'netops init'") {
			t.Errorf("collect no inv should include tip on stderr: %s", er.String())
		}
	}
}

// A persistent failure must be logged once, and its recovery once, rather than
// every cycle (monitor mode runs a cycle every couple of minutes).
func TestLogFailureLoggingIsDeduplicated(t *testing.T) {
	_, host, port := startLogFakeIOS(t)
	e := newLogEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\nDEAD,127.0.0.1,1,cisco_ios,default,\n", host, port))

	var stderr bytes.Buffer
	log := &logLogger{w: &stderr}
	// A narrow interval shrinks the start stagger so three cycles stay quick.
	o := e.opts(4, 2*time.Second, 4*time.Second)
	a, err := newLogApp(o, nil, io.Discard, log)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()

	for i := 0; i < 3; i++ {
		a.cycle(t.Context())
	}
	if n := strings.Count(stderr.String(), "DEAD: poll failed"); n != 1 {
		t.Errorf("a persistent failure must be logged once, logged %d times:\n%s", n, stderr.String())
	}
	if n := strings.Count(stderr.String(), "cycle complete"); n != 3 {
		t.Errorf("each cycle still gets its summary line, got %d", n)
	}
}

func TestLogStderrLoggerSanitises(t *testing.T) {
	var b bytes.Buffer
	l := &logLogger{w: &b}
	l.Info("%s", "forged\nERROR fake line \x1b[2J")
	if strings.Count(b.String(), "\n") != 1 || strings.Contains(b.String(), "\x1b") {
		t.Errorf("log injection not neutralised: %q", b.String())
	}
}

func TestLogSecondCollectorOnSameDataDirIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no data-directory lock on Windows")
	}
	_, host, port := startLogFakeIOS(t)
	e := newLogEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n", host, port))
	o := e.opts(1, time.Second, 0)
	var sink bytes.Buffer
	first, err := newLogApp(o, nil, io.Discard, &logLogger{w: &sink})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newLogApp(o, nil, io.Discard, &logLogger{w: &sink}); !errors.Is(err, errLogAlreadyRunning) {
		t.Fatalf("a second collector on the same data dir must be refused, got %v", err)
	}
	first.close()
	again, err := newLogApp(o, nil, io.Discard, &logLogger{w: &sink})
	if err != nil {
		t.Fatalf("the lock must be released on close: %v", err)
	}
	again.close()
}

func TestLogWarnEveryRateLimits(t *testing.T) {
	var b bytes.Buffer
	a := &logApp{log: &logLogger{w: &b}, warnedAt: make(map[string]time.Time)}
	for i := 0; i < 5; i++ {
		a.warnEvery("k", time.Hour, "repeat")
		a.warnEvery("once", 0, "only-once")
	}
	a.warnEvery("other", time.Hour, "different key")
	if got := strings.Count(b.String(), "repeat"); got != 1 {
		t.Errorf("rate-limited warning logged %d times", got)
	}
	if got := strings.Count(b.String(), "only-once"); got != 1 {
		t.Errorf("once-only warning logged %d times", got)
	}
	if !strings.Contains(b.String(), "different key") {
		t.Error("distinct keys are independent")
	}
	// After the interval elapses the warning is allowed again.
	a.warnedAt["k"] = time.Now().Add(-2 * time.Hour)
	a.warnEvery("k", time.Hour, "repeat")
	if got := strings.Count(b.String(), "repeat"); got != 2 {
		t.Errorf("warning must re-arm after the interval, logged %d times", got)
	}
}

func TestLogCollectDryRun(t *testing.T) {
	_, host, port := startLogFakeIOS(t)
	e := newLogEnv(t, fmt.Sprintf("SW-DRY,%s,%d,cisco_ios,default,\n", host, port))
	dataDir := filepath.Join(e.dir, "data")

	// Run with --dry-run: should exit 0 and print the audit table to stdout.
	stdout, stderr, code := e.run(t, append([]string{"collect", "--dry-run"}, e.args...)...)
	if code != 0 {
		t.Fatalf("dry-run exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// The connectivity table must appear on stdout with the right columns.
	for _, want := range []string{"DEVICE", "ADDRESS", "VENDOR", "STATUS", "DURATION", "SKEW", "SW-DRY", "OK"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q\nstdout: %s", want, stdout)
		}
	}

	// The summary line must appear in the log output (stderr).
	if !strings.Contains(stderr, "dry-run complete") {
		t.Errorf("stderr missing 'dry-run complete':\n%s", stderr)
	}

	// No log files, state file, or lock must be created under data/.
	if _, err := os.Stat(dataDir); err == nil {
		// data/ may not exist at all; if it does, it must be empty.
		entries, _ := os.ReadDir(dataDir)
		if len(entries) != 0 {
			names := make([]string, len(entries))
			for i, en := range entries {
				names[i] = en.Name()
			}
			t.Errorf("dry-run must not create files in data/; found: %v", names)
		}
	}
}

func TestLogCollectDryRunAllFail(t *testing.T) {
	// An unreachable device: dry-run must exit 1 when every device fails.
	e := newLogEnv(t, "DEAD,127.0.0.1,1,cisco_ios,default,\n")
	_, stderr, code := e.run(t, append([]string{"collect", "--dry-run"}, e.args...)...)
	if code != task.ExitFatal {
		t.Errorf("all-fail dry-run must exit 1, got %d\nstderr: %s", code, stderr)
	}
}

// logReportSection returns the text of one "=== <title> ... ===" section of the
// table output, up to the next heading.
func logReportSection(t *testing.T, out, title string) string {
	t.Helper()
	i := strings.Index(out, "=== "+title)
	if i < 0 {
		t.Fatalf("section %q missing:\n%s", title, out)
	}
	rest := out[i+4:]
	if j := strings.Index(rest, "\n=== "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// seedLogReportHistory adds days of history the fake device cannot produce (its
// buffer only holds the last few minutes): an earlier part of the current
// 7-day window, a previous-week window, and one entry too old for either.
// Timestamps are at noon UTC so no test run can straddle a day boundary.
func seedLogReportHistory(t *testing.T, dataDir string) {
	t.Helper()
	midnight := time.Now().UTC().Truncate(24 * time.Hour)
	noon := func(daysAgo int, minute int) time.Time {
		return midnight.AddDate(0, 0, -daysAgo).Add(12*time.Hour + time.Duration(minute)*time.Minute)
	}
	var entries []collector.LogEntry
	add := func(host, category, event, user, srcIP string, ts time.Time) {
		entries = append(entries, collector.LogEntry{
			ID: collector.EntryID(host, fmt.Sprint(event, user, srcIP, ts.UnixNano())), Timestamp: ts, DeviceTS: ts,
			Hostname: host, Category: category, Severity: "WARNING", Event: event, User: user, SourceIP: srcIP,
			Summary: event, Raw: event,
		})
	}
	// current window
	for m := 0; m < 3; m++ {
		add("SW-CORE", "FAULT", "LINK_DOWN", "", "", noon(3, m))
	}
	add("SW-CORE", "CONFIG", "CONFIG_CHANGE", "bachngo", "", noon(3, 10))
	add("SW-CORE", "CONFIG", "CONFIG_CHANGE", "bachngo", "", noon(3, 11))
	add("SW-CORE", "SECURITY", "AFTER_HOURS_CHANGE", "night", "", noon(2, 0))
	add("SW-A", "AUTH", "LOGIN_FAILURE", "", "203.0.113.9", noon(3, 20))
	add("SW-B", "AUTH", "LOGIN_FAILURE", "", "203.0.113.9", noon(3, 21))
	add("SW-B", "AUTH", "LOGIN_FAILURE", "", "203.0.113.9", noon(3, 22))
	add("SW-A", "AUTH", "LOGIN_FAILURE", "", "198.51.100.7", noon(3, 23))
	// previous week
	add("SW-CORE", "FAULT", "LINK_DOWN", "", "", noon(9, 0))
	add("SW-CORE", "CONFIG", "CONFIG_CHANGE", "bachngo", "", noon(9, 1))
	add("SW-CORE", "CONFIG", "CONFIG_CHANGE", "bachngo", "", noon(9, 2))
	add("SW-A", "AUTH", "LOGIN_FAILURE", "", "203.0.113.9", noon(9, 3))
	// older than both windows: must appear nowhere
	add("SW-OLD", "FAULT", "LINK_DOWN", "", "", noon(20, 0))

	w, err := store.NewJSONLWriter(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(entries); err != nil {
		t.Fatal(err)
	}

	// Incidents: two where triage could not connect (SW-GONE every time), one
	// where a command failed on a reachable device.
	now := time.Now()
	for _, r := range []collector.IncidentReport{
		{ID: "seed-gone-1", Timestamp: now.Add(-24 * time.Hour), Hostname: "SW-GONE", Playbook: "link_down",
			Diagnostics: []collector.DiagCmd{{Command: "(connect)", Error: "dial tcp: i/o timeout"}}},
		{ID: "seed-gone-2", Timestamp: now.Add(-48 * time.Hour), Hostname: "SW-GONE", Playbook: "link_down",
			Diagnostics: []collector.DiagCmd{{Command: "(connect)", Error: "dial tcp: i/o timeout"}}},
		{ID: "seed-partial", Timestamp: now.Add(-3 * time.Hour), Hostname: "SW-LAB", Playbook: "link_down",
			Diagnostics: []collector.DiagCmd{{Command: "show version", Output: "ok"}, {Command: "show ip route", Error: "timeout"}}},
	} {
		if _, err := store.WriteIncident(store.IncidentsDir(dataDir), r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLogReportEndToEnd(t *testing.T) {
	_, host, port := startLogFakeIOS(t)
	e := newLogEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n", host, port))
	dataDir := filepath.Join(e.dir, "data")

	// ---- nothing collected yet: exit 0 and "no data" lines, never an error ----
	out, stderr, code := e.run(t, "report", "--data-dir", dataDir, "--no-color")
	if code != 0 || stderr != "" || strings.Count(out, "No matching events.") != 6 || !strings.Contains(out, "No incidents.") || !strings.Contains(out, "No outages.") {
		t.Fatalf("empty data dir: code=%d stderr=%q\n%s", code, stderr, out)
	}
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--format", "json")
	var empty map[string]json.RawMessage
	if code != 0 || json.Unmarshal([]byte(out), &empty) != nil || len(empty) != 9 || string(empty["noisy_devices"]) != "[]" {
		t.Fatalf("empty data dir, json: code=%d\n%s", code, out)
	}

	// ---- real collection (SW-LAB: 2 faults, 2 config changes, 2 incidents), plus older days ----
	// --no-config-diff: this test checks report arithmetic over a known set of
	// incidents; config-diff captures have their own tests.
	if stderr, code := e.collectWith(t, "--no-config-diff"); code != 0 {
		t.Fatalf("collect: exit %d\n%s", code, stderr)
	}
	seedLogReportHistory(t, dataDir)

	// ---- table ----
	out, stderr, code = e.run(t, "report", "--data-dir", dataDir, "--no-color")
	if code != 0 || stderr != "" {
		t.Fatalf("report: code=%d stderr=%q\n%s", code, stderr, out)
	}
	for _, bad := range []string{"\x1b", "\x07", "\r", "SW-OLD"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q:\n%q", bad, out)
		}
	}
	last := -1
	for _, h := range []string{"Noisy Devices (top 10, last 7d)", "Change Accountability", "Security Watchlist (top 10, last 7d)",
		"Event Volume by Category/Day", "Week-over-Week (last 7d vs previous 7d)", "Triage Reach", "Outages", "Device Health", "Classification Coverage"} {
		i := strings.Index(out, "=== "+h)
		if i < 0 || i < last {
			t.Fatalf("heading %q missing or out of order:\n%s", h, out)
		}
		last = i
	}

	match := func(section, pattern string) {
		t.Helper()
		if !regexp.MustCompile(pattern).MatchString(section) {
			t.Errorf("want /%s/ in:\n%s", pattern, section)
		}
	}
	noisy := logReportSection(t, out, "Noisy Devices")
	match(noisy, `SW-CORE\s*│\s*3`)
	match(noisy, `SW-LAB\s*│\s*2`)
	if strings.Index(noisy, "SW-CORE") > strings.Index(noisy, "SW-LAB") {
		t.Errorf("most faults first:\n%s", noisy)
	}

	changes := logReportSection(t, out, "Change Accountability")
	match(changes, `bachngo\s*│\s*2\s*│\s*0\s*│\s*SW-CORE`)
	match(changes, `night\s*│\s*1\s*│\s*1\s*│\s*SW-CORE`)
	match(changes, `tanvt\s*│\s*1\s*│\s*0\s*│\s*SW-LAB`)
	match(changes, `After-hours changes: 1`)
	match(changes, `\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s*│\s*SW-CORE\s*│\s*night`)
	if !strings.Contains(changes, "?[2Jevil") {
		t.Errorf("the hostile user name should appear neutralised:\n%s", changes)
	}

	watch := logReportSection(t, out, "Security Watchlist")
	match(watch, `203\.0\.113\.9\s*│\s*2\s*│\s*3\s*│\s*0\s*│\s*SW-A, SW-B`)
	match(watch, `198\.51\.100\.7\s*│\s*1\s*│\s*1\s*│\s*0\s*│\s*SW-A`)
	if strings.Contains(watch, "6.6.6.6") || strings.Index(watch, "203.0.113.9") > strings.Index(watch, "198.51.100.7") {
		t.Errorf("a source on more devices ranks first, and config-change IPs are not logins:\n%s", watch)
	}

	day3 := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -3).Format("2006-01-02")
	match(logReportSection(t, out, "Event Volume"), day3+`\s*│\s*2\s*│\s*4\s*│\s*3\s*│\s*0\s*│\s*0`)

	delta := logReportSection(t, out, "Week-over-Week")
	match(delta, `CONFIG\s*│\s*2\s*│\s*4\s*│\s*\+2\s*│\s*\+100\.0%`)
	match(delta, `AUTH\s*│\s*1\s*│\s*4\s*│\s*\+3\s*│\s*\+300\.0%`)
	match(delta, `FAULT\s*│\s*1\s*│\s*5\s*│\s*\+4\s*│\s*\+400\.0%`)
	match(delta, `SECURITY\s*│\s*0\s*│\s*1\s*│\s*\+1\s*│\s*n/a`)
	match(delta, `SYSTEM\s*│\s*0\s*│\s*0\s*│\s*0\s*│\s*n/a`)
	match(delta, `TOTAL\s*│\s*4\s*│\s*14\s*│\s*\+10\s*│\s*\+250\.0%`)

	closure := logReportSection(t, out, "Triage Reach")
	match(closure, `Incidents:\s+5`)
	match(closure, `All diagnostics succeeded:\s+2 \(40\.0%\)`)
	match(closure, `Unreachable during triage:\s+2 \(40\.0%\)`)
	match(closure, `Some commands failed:\s+1 \(20\.0%\)`)
	match(closure, `SW-GONE\s*│\s*2\s*│\s*2\s*│\s*yes`)

	// The collection that just ran left a health record: SW-LAB is fine, so
	// the section only says so.
	match(logReportSection(t, out, "Device Health"), `All 1 devices healthy\.`)
	// Every collected line was classified except the banner-free few the fake
	// device prints; coverage is reported per vendor.
	match(logReportSection(t, out, "Classification Coverage"), `cisco_ios\s*│\s*\d+\s*│\s*\d+\s*│\s*\d+\.\d%`)
	match(logReportSection(t, out, "Outages"), `No outages\.|Outages: \d+`)

	// ---- json ----
	out, stderr, code = e.run(t, "report", "--data-dir", dataDir, "--format", "json")
	if code != 0 || stderr != "" || !json.Valid([]byte(out)) {
		t.Fatalf("report --format json: code=%d stderr=%q\n%s", code, stderr, out)
	}
	if strings.Contains(out, "\x1b") {
		t.Error("raw ESC in JSON output")
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if got := rep.NoisyDevices; len(got) != 2 || got[0] != (report.DeviceFaultCount{Hostname: "SW-CORE", Count: 3}) || got[1] != (report.DeviceFaultCount{Hostname: "SW-LAB", Count: 2}) {
		t.Errorf("noisy_devices = %+v", got)
	}
	if ca := rep.ChangeAccountability; ca.Total != 5 || ca.AfterHoursCount != 1 || ca.AfterHours[0].User != "night" || ca.AfterHours[0].Hostname != "SW-CORE" || ca.ByUser[0].User != "bachngo" {
		t.Errorf("change_accountability = %+v", ca)
	}
	if w := rep.SecurityWatchlist; len(w) != 2 || w[0].SourceIP != "203.0.113.9" || w[0].DistinctHosts != 2 || w[0].Events != 3 {
		t.Errorf("security_watchlist = %+v", w)
	}
	var faults int
	for _, row := range rep.VolumeByCategory {
		faults += row["FAULT"]
	}
	if faults != 5 {
		t.Errorf("volume_by_category FAULT total = %d, want 5 (2 collected + 3 seeded; none from SW-OLD)", faults)
	}
	if w := rep.WeekOverWeek; w == nil || w.Categories[2].Category != "FAULT" || w.Categories[2].ChangePct == nil || *w.Categories[2].ChangePct != 400 ||
		w.Categories[3].ChangePct != nil || w.Total.Current != 14 || w.Total.Previous != 4 {
		t.Errorf("week_over_week = %+v", w)
	}
	if ic := rep.IncidentClosure; ic.Total != 5 || ic.Succeeded != 2 || ic.Unreachable != 2 || ic.PartialFailure != 1 ||
		len(ic.UnreachableHosts) != 1 || ic.UnreachableHosts[0] != (report.UnreachableHost{Hostname: "SW-GONE", Unreachable: 2, Incidents: 2, Always: true}) {
		t.Errorf("incident_closure = %+v", ic)
	}

	// ---- flags: --top, --since, --compare ----
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--format", "json", "--top", "1")
	var top1 report.Report
	if code != 0 || json.Unmarshal([]byte(out), &top1) != nil || len(top1.NoisyDevices) != 1 || len(top1.SecurityWatchlist) != 1 ||
		len(top1.ChangeAccountability.ByUser) != 4 {
		t.Errorf("--top 1 caps the two rankings only: code=%d\n%s", code, out)
	}

	// 24h: only the collected events; no delta unless asked for.
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--format", "json", "--since", "24h")
	var day report.Report
	if code != 0 || json.Unmarshal([]byte(out), &day) != nil || day.WeekOverWeek != nil ||
		len(day.NoisyDevices) != 1 || day.NoisyDevices[0].Hostname != "SW-LAB" || len(day.SecurityWatchlist) != 0 {
		t.Errorf("--since 24h: code=%d\n%s", code, out)
	}
	if !strings.Contains(out, `"week_over_week": null`) {
		t.Errorf("week_over_week must be an explicit null when not computed:\n%s", out)
	}
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--since", "24h", "--compare", "--no-color")
	if code != 0 || !strings.Contains(out, "=== Window-over-Window (last 24h vs the equal window before it) ===") {
		t.Errorf("--since 24h --compare:\n%s", out)
	}
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--compare=false", "--no-color")
	if code != 0 || strings.Contains(out, "Week-over-Week") || !strings.Contains(out, "=== Triage Reach") {
		t.Errorf("--compare=false must drop the delta section:\n%s", out)
	}

	// ---- usage errors exit 2 without touching stdout ----
	for _, args := range [][]string{{"--format", "xml"}, {"--top", "0"}, {"--since", "bogus"}, {"--nope"}} {
		out, stderr, code := e.run(t, append([]string{"report", "--data-dir", dataDir}, args...)...)
		if code != task.ExitFatal || out != "" || stderr == "" {
			t.Errorf("report %v: code=%d stdout=%q stderr=%q, want exit %d, an error on stderr and nothing on stdout", args, code, out, stderr, task.ExitFatal)
		}
	}

	// report only reads: running it changed nothing under the data directory.
	before := len(e.logEntries(t))
	e.run(t, "report", "--data-dir", dataDir)
	if after := len(e.logEntries(t)); after != before {
		t.Errorf("report modified the logs: %d -> %d entries", before, after)
	}
}

// TestStatusEndToEnd drives collection health end to end: a healthy device, a
// dead one, an unsupported platform and (before the first poll) devices that
// are only in the inventory, through collection cycles, "netops log status" and
// "netops log report".
func TestLogStatusEndToEnd(t *testing.T) {
	_, host, port := startLogFakeIOS(t)
	e := newLogEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n"+
		"DEAD,127.0.0.1,1,cisco_ios,default,\n"+ // connection refused, instantly
		"PF,%s,%d,sophos,default,\n", host, port, host, port))
	dataDir := filepath.Join(e.dir, "data")
	inv := filepath.Join(e.dir, "inventory.csv")
	status := func(extra ...string) (string, string, int) {
		return e.run(t, append([]string{"status", "--inventory", inv, "--data-dir", dataDir, "--no-color"}, extra...)...)
	}
	// startApp is a collector over the test inventory. A narrow interval
	// shrinks the start stagger so a cycle takes milliseconds.
	startApp := func() (*logApp, *bytes.Buffer) {
		var stderr bytes.Buffer
		a, err := newLogApp(e.opts(4, 2*time.Second, time.Second), nil, io.Discard, &logLogger{w: &stderr})
		if err != nil {
			t.Fatal(err)
		}
		return a, &stderr
	}
	row := func(out, dev string) string {
		t.Helper()
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, dev+" ") || strings.Contains(l, "│ "+dev+" ") {
				return l
			}
		}
		t.Fatalf("no row for %s in:\n%s", dev, out)
		return ""
	}

	// Nothing polled yet: every inventory device is NEVER POLLED, and --fail says so.
	out, stderr, code := status()
	if code != 0 || stderr != "" || strings.Count(out, "NEVER POLLED") != 3 {
		t.Fatalf("before any poll: code=%d stderr=%q\n%s", code, stderr, out)
	}
	if _, _, code := status("--fail"); code != task.ExitFatal {
		t.Errorf("--fail with unhealthy devices: exit %d, want %d", code, task.ExitFatal)
	}

	// One cycle: SW-LAB is polled, DEAD refuses, PF has no fetch command.
	a, _ := startApp()
	a.cycle(t.Context())
	out, _, code = status()
	if code != 0 {
		t.Fatalf("status: exit %d", code)
	}
	if r := row(out, "SW-LAB"); !strings.Contains(r, "OK") {
		t.Errorf("SW-LAB should be OK: %q", r)
	}
	if r := row(out, "DEAD"); !regexp.MustCompile(`FAILING.*-.*1`).MatchString(r) {
		t.Errorf("DEAD should be FAILING with 1 failed poll and no successful one: %q", r)
	}
	if r := row(out, "PF"); !strings.Contains(r, "UNSUPPORTED") || !strings.Contains(r, "no log fetch command") {
		t.Errorf("PF should be UNSUPPORTED, not an outage: %q", r)
	}
	if strings.Index(out, "DEAD") > strings.Index(out, "SW-LAB") {
		t.Errorf("the failing device must be listed first:\n%s", out)
	}
	if _, _, code := status("--fail"); code != task.ExitFatal {
		t.Errorf("--fail: exit %d, want %d", code, task.ExitFatal)
	}

	// A second cycle extends the failure run; the healthy device stays healthy.
	a.cycle(t.Context())
	a.close()
	out, _, _ = status()
	if r := row(out, "DEAD"); !regexp.MustCompile(`FAILING.*-.*2`).MatchString(r) {
		t.Errorf("two failed polls in a row: %q", r)
	}
	if r := row(out, "PF"); regexp.MustCompile(`UNSUPPORTED\s*│\s*-\s*│\s*\d`).MatchString(r) {
		t.Errorf("an unsupported platform shows no failure count: %q", r)
	}
	if r := row(out, "SW-LAB"); !strings.Contains(r, "OK") {
		t.Errorf("SW-LAB should still be OK: %q", r)
	}

	// JSON is a plain array with explicit nulls for what never happened.
	out, _, code = status("--format", "json")
	var rows []report.DeviceStatus
	if code != 0 || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 3 {
		t.Fatalf("status --format json: code=%d\n%s", code, out)
	}
	byHost := map[string]report.DeviceStatus{}
	for _, r := range rows {
		byHost[r.Hostname] = r
	}
	if d := byHost["DEAD"]; d.Status != "FAILING" || d.ConsecutiveFailures != 2 || d.LastSuccess != nil || d.FailingSince == nil || d.LastError == "" {
		t.Errorf("DEAD = %+v", d)
	}
	if s := byHost["SW-LAB"]; s.Status != "OK" || s.LastSuccess == nil || s.LastNewLogs == nil {
		t.Errorf("SW-LAB = %+v", s)
	}

	// The thresholds are knobs: with 1ns nothing has been polled "recently"
	// and no log line is "new" any more.
	out, _, _ = status("--stale-after", "1ns")
	if r := row(out, "SW-LAB"); !strings.Contains(r, "STALE") || !strings.Contains(r, "is collect running?") {
		t.Errorf("--stale-after 1ns: %q", r)
	}
	out, _, _ = status("--silent-after", "1ns")
	if r := row(out, "SW-LAB"); !strings.Contains(r, "SILENT") || !strings.Contains(r, "no new log lines since") {
		t.Errorf("--silent-after 1ns: %q", r)
	}

	// The report carries the same picture, and names only what needs attention.
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--no-color")
	if code != 0 {
		t.Fatalf("report: exit %d", code)
	}
	health := logReportSection(t, out, "Device Health")
	if !strings.Contains(health, "2 of 3 devices need attention") || !strings.Contains(health, "DEAD") || !strings.Contains(health, "PF") {
		t.Errorf("report device health:\n%s", health)
	}
	if regexp.MustCompile(`(?m)^SW-LAB\s`).MatchString(health) {
		t.Errorf("a healthy device is not listed:\n%s", health)
	}

	// The health file is diagnostics: a corrupt one is reported but changes
	// neither the exit code nor what the next collection does, and is replaced.
	if err := os.WriteFile(store.HealthPath(dataDir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, code = status()
	if code != 0 || !strings.Contains(stderr, "corrupt") || strings.Count(out, "NEVER POLLED") != 3 {
		t.Errorf("corrupt health file: code=%d stderr=%q\n%s", code, stderr, out)
	}
	a, log := startApp()
	a.cycle(t.Context())
	a.close()
	if !strings.Contains(log.String(), "corrupt") || !strings.Contains(log.String(), "cycle complete") {
		t.Errorf("a corrupt health file must be reported and must not stop the cycle:\n%s", log.String())
	}
	if out, stderr, _ = status(); stderr != "" || !strings.Contains(row(out, "SW-LAB"), "OK") {
		t.Errorf("the next collection should have replaced the bad file: %q\n%s", stderr, out)
	}

	// Usage errors.
	for _, args := range [][]string{{"--format", "xml"}, {"--stale-after", "0s"}, {"--nope"}, {"extra"}} {
		if out, stderr, code := status(args...); code != task.ExitFatal || out != "" || stderr == "" {
			t.Errorf("status %v: code=%d stdout=%q stderr=%q", args, code, out, stderr)
		}
	}
}

// TestOutagesEndToEnd follows raw device log lines all the way to the report:
// parsed, classified (recovery events and the interface/neighbor they are
// about), stored as JSONL, streamed back and paired into outages.
func TestLogOutagesEndToEnd(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	stamp := func(ago time.Duration) string { return now.Add(-ago).Format("Jan _2 15:04:05.000") + ":" }

	// Cisco logs the link and the line protocol for one physical event, a
	// moment apart: each pair must count as one outage, not two.
	iosLines := strings.Join([]string{
		stamp(3*time.Hour) + " %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
		stamp(3*time.Hour-time.Second) + " %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down",
		stamp(3*time.Hour-20*time.Minute) + " %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up",
		stamp(3*time.Hour-20*time.Minute-time.Second) + " %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up",
		stamp(50*time.Minute) + " %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down BGP Notification sent",
		stamp(20*time.Minute) + " %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Up",
	}, "\n")
	// A neighbor that dropped and never came back. FULL appears in both the
	// down and the (absent) up line: only the direction tells them apart.
	ospfLines := stamp(90*time.Minute) + " %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on GigabitEthernet0/2 from FULL to DOWN, Neighbor Down: Dead timer expired\n" +
		stamp(80*time.Minute) + " %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.9 on GigabitEthernet0/3 from FULL to LOADING, Bad LS Req"

	cls := pipeline.NewClassifier(time.UTC)
	var entries []collector.LogEntry
	for host, raw := range map[string]string{"R1": iosLines, "R2": ospfLines} {
		dev := inventory.Device{Hostname: host, Address: "10.0.0.1", Vendor: "cisco_ios"}
		got := parser.Parse("cisco_ios", raw, dev, parser.Options{Ref: now, Location: time.UTC})
		for i := range got {
			got[i].Timestamp = got[i].DeviceTS
		}
		cls.ClassifyAll(got)
		entries = append(entries, got...)
	}
	if len(entries) != 8 {
		t.Fatalf("parsed %d entries, want 8", len(entries))
	}

	dataDir := filepath.Join(t.TempDir(), "data")
	w, err := store.NewJSONLWriter(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(entries); err != nil {
		t.Fatal(err)
	}

	// The interface / neighbor is part of what is stored.
	var stored strings.Builder
	files, _ := filepath.Glob(filepath.Join(store.LogsDir(dataDir), "*.jsonl"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		stored.Write(b)
	}
	for _, want := range []string{`"object":"GigabitEthernet0/1"`, `"object":"10.0.0.1"`, `"object":"10.255.255.4"`, `"event":"LINK_UP"`, `"event":"BGP_PEER_UP"`} {
		if !strings.Contains(stored.String(), want) {
			t.Errorf("stored logs lack %s", want)
		}
	}

	out, stderr, code := (logEnv{}).run(t, "report", "--data-dir", dataDir, "--since", "24h", "--format", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("report: code=%d stderr=%q\n%s", code, stderr, out)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	o := rep.Outages
	if o.Total != 3 || o.Resolved != 2 || o.Open != 1 || o.Untracked != 0 || o.MeanSecondsToRecover != 1500 {
		t.Fatalf("outages = %+v\n(the FULL→LOADING line is neither an outage nor a recovery; the doubled Cisco events are one each)", o)
	}
	// Longest first: the open OSPF neighbor (a lower bound), the BGP peer, the link.
	ospf, bgp, link := o.Longest[0], o.Longest[1], o.Longest[2]
	if !ospf.Open || ospf.Kind != "ospf" || ospf.Object != "10.255.255.4" || ospf.Hostname != "R2" || ospf.Up != nil || ospf.DurationSeconds < 5400 || ospf.DurationSeconds > 5400+120 {
		t.Errorf("ospf = %+v", ospf)
	}
	if bgp.Open || bgp.Kind != "bgp" || bgp.Object != "10.0.0.1" || bgp.DurationSeconds != 1800 {
		t.Errorf("bgp = %+v", bgp)
	}
	if link.Open || link.Kind != "link" || link.Object != "GigabitEthernet0/1" || link.DurationSeconds != 1200 {
		t.Errorf("link = %+v", link)
	}
	// Recoveries are not faults: R1 has two link-down lines and one BGP down, R2 one OSPF down.
	if got := rep.NoisyDevices; len(got) != 2 || got[0] != (report.DeviceFaultCount{Hostname: "R1", Count: 3}) || got[1] != (report.DeviceFaultCount{Hostname: "R2", Count: 1}) {
		t.Errorf("noisy_devices = %+v (the up events must not count as faults)", got)
	}

	// And the table says it in words.
	tbl, _, _ := (logEnv{}).run(t, "report", "--data-dir", dataDir, "--since", "24h", "--no-color")
	section := logReportSection(t, tbl, "Outages")
	for _, want := range []string{"Outages: 3 (2 resolved, 1 still open)", "Mean time to recover: 25m", "(open)"} {
		if !strings.Contains(section, want) {
			t.Errorf("outages section lacks %q:\n%s", want, section)
		}
	}
}

func TestLogFindDevice(t *testing.T) {
	devs := []inventory.Device{
		{Hostname: "core-gw-1", Address: "10.0.0.1"},
		{Hostname: "core-gw-2", Address: "10.0.0.2"},
		{Hostname: "edge-1", Address: "10.0.1.1"},
	}
	if d, err := logFindDevice(devs, "CORE-GW-2"); err != nil || d.Address != "10.0.0.2" {
		t.Errorf("exact (case-insensitive): %v %v", d, err)
	}
	if d, err := logFindDevice(devs, "10.0.1.1"); err != nil || d.Hostname != "edge-1" {
		t.Errorf("by address: %v %v", d, err)
	}
	if d, err := logFindDevice(devs, "edge"); err != nil || d.Hostname != "edge-1" {
		t.Errorf("unique prefix: %v %v", d, err)
	}
	if _, err := logFindDevice(devs, "core"); err == nil {
		t.Error("ambiguous prefix should fail")
	}
	if _, err := logFindDevice(devs, "nope"); err == nil {
		t.Error("unknown device should fail")
	}
}

func TestLogDiagnoseUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runLog([]string{"diagnose"}, nil, &out, &errb); code != task.ExitFatal {
		t.Errorf("no device: code %d, want %d", code, task.ExitFatal)
	}
	if code := runLog([]string{"diagnose", "--interface", "Gi0/1;x", "r1"}, nil, &out, &errb); code != task.ExitFatal {
		t.Errorf("bad interface: code %d, want %d", code, task.ExitFatal)
	}
}

// ---- netops log listen -----------------------------------------------------------------------

func TestLogResolveListenAddrs(t *testing.T) {
	for _, tc := range []struct {
		name         string
		bind         string
		port         int
		proto        string
		udp, tcp     int
		wantU, wantT string
		wantErr      bool
	}{
		{"defaults", "", 514, "udp,tcp", 0, 0, ":514", ":514", false},
		{"udp only", "", 5514, "udp", 0, 0, ":5514", "", false},
		{"tcp only, bound", "10.0.0.5", 601, "tcp", 0, 0, "", "10.0.0.5:601", false},
		{"per-protocol override", "", 514, "udp,tcp", 5514, 0, ":5514", ":514", false},
		{"both overrides", "127.0.0.1", 514, "UDP, tcp", 1514, 2514, "127.0.0.1:1514", "127.0.0.1:2514", false},
		{"override of a disabled protocol is ignored", "", 514, "udp", 0, 9999, ":514", "", false},
		{"ipv6 bind", "::1", 514, "udp", 0, 0, "[::1]:514", "", false},
		{"unknown protocol", "", 514, "udp,sctp", 0, 0, "", "", true},
		{"no protocol", "", 514, " , ", 0, 0, "", "", true},
		{"port 0", "", 0, "udp", 0, 0, "", "", true},
		{"port too large", "", 70000, "udp", 0, 0, "", "", true},
		{"bad override", "", 514, "udp", 70000, 0, "", "", true},
	} {
		got, err := resolveLogListenAddrs(tc.bind, tc.port, tc.proto, tc.udp, tc.tcp)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v", tc.name, err)
			continue
		}
		if err == nil && (got.udpAddr != tc.wantU || got.tcpAddr != tc.wantT) {
			t.Errorf("%s: got %q / %q, want %q / %q", tc.name, got.udpAddr, got.tcpAddr, tc.wantU, tc.wantT)
		}
	}
}

func TestLogListenUsageAndStartupErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runLog([]string{"listen", "-h"}, nil, &out, &errb); code != task.ExitOK || !strings.Contains(errb.String(), "--accept-unknown") {
		t.Errorf("-h: code %d, stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := runLog([]string{"listen", "--proto", "sctp"}, nil, &out, &errb); code != task.ExitFatal || !strings.Contains(errb.String(), "unknown protocol") {
		t.Errorf("bad proto: code %d, stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := runLog([]string{"listen", "extra"}, nil, &out, &errb); code != task.ExitFatal {
		t.Errorf("stray argument: code %d", code)
	}
	// An empty inventory would drop every sender: refuse to start.
	dir := t.TempDir()
	empty := filepath.Join(dir, "inv.csv")
	if err := os.WriteFile(empty, []byte("hostname,address,port,vendor,credential_group,jump_host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := runLog([]string{"listen", "--inventory", empty, "--data-dir", filepath.Join(dir, "d"), "--port", "0"}, nil, &out, &errb); code != task.ExitFatal {
		t.Errorf("port 0 is invalid: code %d", code)
	}
	errb.Reset()
	if code := runLog([]string{"listen", "--inventory", empty, "--data-dir", filepath.Join(dir, "d"), "--port", "25999"}, nil, &out, &errb); code != task.ExitFatal || !strings.Contains(errb.String(), "no devices") {
		t.Errorf("empty inventory: code %d, stderr %q", code, errb.String())
	}
}

func TestLogListenerLockIsSeparateFromTheCollectorLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no data-directory lock on Windows")
	}
	dir := t.TempDir()
	relCollector, err := lockLogDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A collect/monitor run holds its lock; a listener still starts beside it.
	relListener, err := lockLogListener(dir)
	if err != nil {
		t.Fatalf("listener must not be blocked by the collector lock: %v", err)
	}
	// Two listeners on one data directory are refused.
	if _, err := lockLogListener(dir); !errors.Is(err, errLogAlreadyRunning) {
		t.Fatalf("second listener must be refused, got %v", err)
	}
	// And a collector still cannot start twice.
	if _, err := lockLogDataDir(dir); !errors.Is(err, errLogAlreadyRunning) {
		t.Fatalf("second collector must be refused, got %v", err)
	}
	relListener()
	relCollector()
	if rel, err := lockLogListener(dir); err != nil {
		t.Fatalf("listener lock must be released: %v", err)
	} else {
		rel()
	}
}

// ---- netops log top / monitor --tui ---------------------------------------------------------

func TestLogTopFlagsAndNonInteractiveRefusal(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runLog([]string{"top", "-h"}, nil, &out, &errb); code != task.ExitOK || !strings.Contains(errb.String(), "Ctrl+C") || !strings.Contains(errb.String(), "-refresh") {
		t.Errorf("-h: code %d, stderr %q", code, errb.String())
	}
	for name, args := range map[string][]string{
		"refresh too fast": {"top", "--refresh", "10ms"},
		"stray argument":   {"top", "now"},
		"bad stale":        {"top", "--stale-after", "0s"},
		"unknown flag":     {"top", "--bogus"},
	} {
		errb.Reset()
		if code := runLog(args, nil, &out, &errb); code != task.ExitFatal {
			t.Errorf("%s: code %d, stderr %q", name, code, errb.String())
		}
	}
	// Under "go test" stdin/stdout are not a terminal: refuse with a pointer to
	// the scriptable commands instead of writing escape codes into a pipe.
	errb.Reset()
	if code := runLog([]string{"top", "--data-dir", t.TempDir()}, nil, &out, &errb); code != task.ExitFatal || !strings.Contains(errb.String(), "interactive terminal") {
		t.Errorf("non-tty: code %d, stderr %q", code, errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("escape sequences written to a non-terminal: %q", out.String())
	}
	errb.Reset()
	if code := runLog([]string{"monitor", "--tui", "--data-dir", t.TempDir(), "--inventory", "none.csv"}, nil, &out, &errb); code != task.ExitFatal || !strings.Contains(errb.String(), "--tui needs an interactive terminal") {
		t.Errorf("monitor --tui on a non-tty: code %d, stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := runLog([]string{"collect", "--tui"}, nil, &out, &errb); code != task.ExitFatal {
		t.Errorf("--tui is a monitor flag only: code %d", code)
	}
}

// ---- netops log diagnose: probe and JSON -----------------------------------------------------

func TestLogDiagnoseProbeAndJSONFlags(t *testing.T) {
	_, host, port := startLogFakeIOS(t)
	e := newLogEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n", host, port))
	args := func(extra ...string) []string {
		// diagnose has no --data-dir; the flag package stops at the first
		// positional argument, so the device comes last.
		a := []string{"diagnose"}
		a = append(a, extra...)
		for i := 0; i < len(e.args); i++ {
			if e.args[i] == "--data-dir" {
				i++ // skip its value
				continue
			}
			a = append(a, e.args[i])
		}
		return append(a, "SW-LAB")
	}

	// Default: the probe section is shown, first, in the text report.
	out, stderr, code := e.run(t, args("--no-color")...)
	if code != 0 && code != task.ExitFatal {
		t.Fatalf("diagnose: code %d\n%s", code, stderr)
	}
	iProbe, iSSH := strings.Index(out, "Path & Reachability Probe"), strings.Index(out, "SSH connect")
	if iProbe < 0 || iSSH < 0 || iProbe > iSSH || !strings.Contains(out, "TCP 127.0.0.1:") {
		t.Errorf("text report should start with the probe:\n%s", out)
	}
	// The fake Cisco answers "show power inline" with junk; the PoE section is present.
	if !strings.Contains(out, "PoE power budget") {
		t.Errorf("a Cisco switch gets a PoE section:\n%s", out)
	}

	// --no-probe drops it.
	out, _, _ = e.run(t, args("--no-color", "--no-probe")...)
	if strings.Contains(out, "Path & Reachability Probe") {
		t.Errorf("--no-probe still probed:\n%s", out)
	}

	// --json: one valid JSON document with probe/poe/sections, nothing else on stdout.
	out, stderr, _ = e.run(t, args("--json")...)
	var rep struct {
		Hostname string                         `json:"hostname"`
		Vendor   string                         `json:"vendor"`
		Healthy  bool                           `json:"healthy"`
		Probe    *struct{ Name, Status string } `json:"probe"`
		PoE      *struct{ Name string }         `json:"poe"`
		Sections []struct{ Name string }        `json:"sections"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s\nstderr: %s", err, out, stderr)
	}
	if rep.Hostname != "SW-LAB" || rep.Vendor != "cisco_ios" || rep.Probe == nil || rep.Probe.Name != "Path & Reachability Probe" ||
		rep.PoE == nil || len(rep.Sections) == 0 {
		t.Errorf("JSON report: %+v\n%s", rep, out)
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "password") {
		t.Errorf("JSON must be plain and free of secrets:\n%s", out)
	}
	out, _, _ = e.run(t, args("--json", "--no-probe")...)
	if strings.Contains(out, `"probe"`) {
		t.Errorf("--json --no-probe still carries a probe:\n%s", out)
	}
}

// ==============================================================================
// Dispatcher, flag harmonisation and multicall
// ==============================================================================

// logSubcommands is the complete, ordered list of "netops log" subcommands.
var logSubcommands = []string{"collect", "monitor", "listen", "query", "timeline", "incidents", "report", "status", "top", "diagnose"}

func TestLogBareInvocationIsAUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runLog(nil, nil, &out, &errb); code != task.ExitFatal {
		t.Fatalf("bare 'netops log' exit = %d, want %d", code, task.ExitFatal)
	}
	if out.Len() != 0 {
		t.Errorf("a usage error must leave stdout empty, got %q", out.String())
	}
	if !strings.HasPrefix(errb.String(), "netops log: missing subcommand\n\n") {
		t.Errorf("stderr must start with the missing-subcommand line, got %q", errb.String())
	}
	if !strings.Contains(errb.String(), logUsageText) {
		t.Errorf("stderr must carry the full log usage:\n%s", errb.String())
	}
}

func TestLogHelpGoesToStdout(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help", "-help"} {
		var out, errb bytes.Buffer
		if code := runLog([]string{arg}, nil, &out, &errb); code != task.ExitOK {
			t.Errorf("netops log %s: exit %d, want %d", arg, code, task.ExitOK)
		}
		if out.String() != logUsageText || errb.Len() != 0 {
			t.Errorf("netops log %s: usage must be on stdout only (stdout %d bytes, stderr %q)", arg, out.Len(), errb.String())
		}
	}
	for _, name := range logSubcommands {
		if !strings.Contains(logUsageText, "\n  "+name+" ") {
			t.Errorf("the usage text does not list the %q subcommand", name)
		}
	}
}

// init, telegram-test and version are root commands; the merge must not
// duplicate them under "netops log".
func TestLogRejectsUnknownAndMovedSubcommands(t *testing.T) {
	for _, name := range []string{"bogus", "init", "telegram-test", "version", "-version", ""} {
		var out, errb bytes.Buffer
		if code := runLog([]string{name}, nil, &out, &errb); code != task.ExitFatal {
			t.Errorf("netops log %q: exit %d, want %d", name, code, task.ExitFatal)
		}
		if !strings.Contains(errb.String(), "unknown subcommand") || !strings.Contains(errb.String(), "Subcommands:") {
			t.Errorf("netops log %q: want an unknown-subcommand error plus the usage, got %q", name, errb.String())
		}
		if out.Len() != 0 {
			t.Errorf("netops log %q wrote to stdout: %q", name, out.String())
		}
	}
}

func TestLogIsReachableFromTheRootDispatcher(t *testing.T) {
	in := openDevNull(t)
	defer in.Close()

	var out, errb bytes.Buffer
	if code := dispatch([]string{"log"}, in, &out, &errb); code != task.ExitFatal || !strings.Contains(errb.String(), "netops log: missing subcommand") {
		t.Errorf("dispatch(log): exit %d, stderr %q", code, errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := dispatch([]string{"log", "-h"}, in, &out, &errb); code != task.ExitOK || out.String() != logUsageText {
		t.Errorf("dispatch(log -h): exit %d, stdout %d bytes", code, out.Len())
	}
	out.Reset()
	errb.Reset()
	if code := dispatch([]string{"log", "status", "--data-dir", t.TempDir(), "--inventory", filepath.Join(t.TempDir(), "none.csv")}, in, &out, &errb); code != task.ExitOK {
		t.Errorf("dispatch(log status) on an empty data dir: exit %d, stderr %q", code, errb.String())
	}
}

func TestRootHelpListsTheLogSubcommand(t *testing.T) {
	if !strings.Contains(rootUsageText, "  log            network log monitor and auto-triage (netops log -h)\n") {
		t.Errorf("the root usage does not describe the log subcommand:\n%s", rootUsageText)
	}
	in := openDevNull(t)
	defer in.Close()
	var out, errb bytes.Buffer
	if code := dispatch([]string{"-h"}, in, &out, &errb); code != task.ExitOK || !strings.Contains(errb.String(), "netops log -h") {
		t.Errorf("netops -h: exit %d, stderr %q", code, errb.String())
	}
}

// Every subcommand parses its flags and documents them; the help names the
// harmonised netops flags rather than the pre-merge netlog ones.
func TestLogEverySubcommandDocumentsItsFlags(t *testing.T) {
	conn := []string{"connect-timeout", "command-timeout", "inventory", "env-file", "host-key-policy", "known-hosts", "legacy-algorithms", "jump", "jump-host"}
	want := map[string][]string{
		"collect":   append([]string{"data-dir", "concurrency", "dry-run", "no-config-diff", "no-peer-triage", "retention-days", "after-hours-start", "after-hours-end", "no-color"}, conn...),
		"monitor":   append([]string{"data-dir", "concurrency", "interval", "tui", "no-config-diff", "no-peer-triage", "retention-days", "after-hours-start", "after-hours-end", "no-color"}, conn...),
		"listen":    {"inventory", "data-dir", "bind", "port", "proto", "udp-port", "tcp-port", "accept-unknown", "drop-unclassified", "after-hours-start", "after-hours-end", "stats-interval"},
		"query":     {"limit", "user", "category", "severity", "event", "since", "format", "data-dir", "no-color"},
		"timeline":  {"from", "to", "limit", "data-dir", "no-color"},
		"incidents": {"id", "since", "format", "data-dir", "no-color"},
		"report":    {"since", "top", "compare", "format", "data-dir", "no-color"},
		"status":    {"data-dir", "stale-after", "fail", "no-color"},
		"top":       {"data-dir", "refresh", "inventory", "stale-after"},
		"diagnose":  append([]string{"interface", "raw", "fail", "no-probe", "json", "no-color"}, conn...),
	}
	if len(want) != len(logSubcommands) {
		t.Fatalf("the table covers %d subcommands, there are %d", len(want), len(logSubcommands))
	}
	for _, name := range logSubcommands {
		var out, errb bytes.Buffer
		if code := runLog([]string{name, "-h"}, nil, &out, &errb); code != task.ExitOK {
			t.Errorf("netops log %s -h: exit %d, want %d", name, code, task.ExitOK)
			continue
		}
		help := errb.String() // flag help is printed to stderr, as for every netops subcommand
		if !strings.Contains(help, "Usage: netops log "+name) {
			t.Errorf("netops log %s -h has no usage line:\n%s", name, help)
		}
		if strings.Contains(help, "Other flags:") {
			t.Errorf("netops log %s has a flag in no help group:\n%s", name, help)
		}
		for _, flagName := range want[name] {
			if !strings.Contains(help, "  -"+flagName) {
				t.Errorf("netops log %s -h does not document -%s", name, flagName)
			}
		}
		for _, gone := range []string{"known-hosts-policy", "insecure-ignore-host-key", "netlog", "NETLOG"} {
			if strings.Contains(help, gone) {
				t.Errorf("netops log %s -h still mentions %q:\n%s", name, gone, help)
			}
		}
	}
}

func TestLogFlagGroupsNameOnlyRealFlags(t *testing.T) {
	check := func(name string, fs *flag.FlagSet, groups []flagGroup) {
		t.Helper()
		grouped := map[string]bool{}
		for _, g := range groups {
			for _, n := range g.names {
				grouped[n] = true
			}
		}
		// A group may list flags of the sibling command (collect and monitor share
		// one table), but every real flag must be in some group.
		fs.VisitAll(func(f *flag.Flag) {
			if !grouped[f.Name] && !aliasUsage.MatchString(f.Usage) {
				t.Errorf("%s: -%s is in no help group", name, f.Name)
			}
		})
	}
	var c logCollectOpts
	check("collect", newLogCollectFlagSet(&c, &bytes.Buffer{}, false), logCollectFlagGroups)
	var m logCollectOpts
	check("monitor", newLogCollectFlagSet(&m, &bytes.Buffer{}, true), logCollectFlagGroups)
	// Every name in a group exists in collect or monitor (a typo would silently hide a flag).
	cf, mf := newLogCollectFlagSet(&logCollectOpts{}, &bytes.Buffer{}, false), newLogCollectFlagSet(&logCollectOpts{}, &bytes.Buffer{}, true)
	for _, g := range logCollectFlagGroups {
		for _, n := range g.names {
			if cf.Lookup(n) == nil && mf.Lookup(n) == nil {
				t.Errorf("group %q names -%s, which is neither a collect nor a monitor flag", g.title, n)
			}
		}
	}
}

// The connection flags are declared once (logConn) with the netops names and
// defaults, so collect, monitor and diagnose cannot drift from the other commands.
func TestLogConnectionFlagsMatchNetopsDefaults(t *testing.T) {
	var cf commonFlags
	netops := flag.NewFlagSet("netops", flag.ContinueOnError)
	cf.register(netops)

	var o logCollectOpts
	log := newLogCollectFlagSet(&o, &bytes.Buffer{}, true)

	for _, name := range []string{"connect-timeout", "command-timeout", "env-file", "host-key-policy", "legacy-algorithms", "jump", "jump-host", "inventory", "concurrency"} {
		want, got := netops.Lookup(name), log.Lookup(name)
		if want == nil || got == nil {
			t.Fatalf("-%s missing (netops %v, log %v)", name, want != nil, got != nil)
		}
		if want.DefValue != got.DefValue {
			t.Errorf("-%s defaults to %q in netops log but %q in netops", name, got.DefValue, want.DefValue)
		}
	}
	if o.connectTimeout != 10*time.Second || o.commandTimeout != 30*time.Second {
		t.Errorf("timeouts = %s/%s, want 10s/30s", o.connectTimeout, o.commandTimeout)
	}
	if o.hostKeyPolicy != "update" || o.knownHosts != "known_hosts" || o.dataDir != "data" || o.concurrency != 10 {
		t.Errorf("defaults: policy %q known-hosts %q data-dir %q concurrency %d", o.hostKeyPolicy, o.knownHosts, o.dataDir, o.concurrency)
	}
	if o.interval != collector.DefaultInterval || collector.DefaultInterval != 2*time.Minute {
		t.Errorf("monitor interval = %s, want 2m", o.interval)
	}

	// The documented host key policies are all accepted; anything else is refused up front.
	for _, p := range []string{"strict", "accept-new", "update", "insecure"} {
		o.hostKeyPolicy = p
		if err := o.validateConn(); err != nil {
			t.Errorf("--host-key-policy %s rejected: %v", p, err)
		}
	}
	o.hostKeyPolicy = "whatever"
	if err := o.validateConn(); err == nil || !strings.Contains(err.Error(), "--host-key-policy") {
		t.Errorf("an invalid policy must be refused, got %v", err)
	}
}

func TestLogHostMatcher(t *testing.T) {
	cases := []struct {
		limit string
		host  string
		want  bool
	}{
		{"", "anything", true},
		{"core", "CORE-GW-1", true}, // case-insensitive substring, as "netlog query --host" always was
		{"core", "edge-1", false},
		{"core-*", "core-gw-1", true},    // globs
		{"core-*", "edge-core-1", false}, // a glob must match the whole name
		{"edge-?", "edge-1", true},
		{"edge, dist", "dist-3", true}, // comma-separated list
		{"edge, dist", "core-1", false},
	}
	for _, c := range cases {
		match, err := logHostMatcher(c.limit)
		if err != nil {
			t.Fatalf("%q: %v", c.limit, err)
		}
		if got := match(c.host); got != c.want {
			t.Errorf("limit %q vs %q = %v, want %v", c.limit, c.host, got, c.want)
		}
	}
	if _, err := logHostMatcher("bad[pattern"); err == nil {
		t.Error("an invalid glob must be an error")
	}
}

// seedLogEvents stores one recent event per hostname.
func seedLogEvents(t *testing.T, dataDir string, hosts ...string) {
	t.Helper()
	w, err := store.NewJSONLWriter(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	var entries []collector.LogEntry
	for i, h := range hosts {
		ts := time.Now().UTC().Add(-time.Duration(i+1) * time.Minute)
		entries = append(entries, collector.LogEntry{
			ID: fmt.Sprintf("seed-%d", i), Timestamp: ts, DeviceTS: ts, Hostname: h, IP: "10.0.0." + strconv.Itoa(i+1),
			Vendor: "cisco_ios", Category: "FAULT", Severity: "ERROR", Event: "LINK_DOWN",
			Summary: "Interface Gi0/1 down on " + h, Raw: "%LINK-3-UPDOWN: Interface Gi0/1 on " + h,
		})
	}
	if err := w.Append(entries); err != nil {
		t.Fatal(err)
	}
}

// --limit filters query and timeline by hostname, and --host is its alias.
func TestLogLimitAndHostAliasFilterQueryAndTimeline(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	seedLogEvents(t, dataDir, "core-gw-1", "edge-1", "dist-3")
	e := logEnv{}

	hostsIn := func(out string) []string {
		var got []string
		for _, h := range []string{"core-gw-1", "edge-1", "dist-3"} {
			if strings.Contains(out, h) {
				got = append(got, h)
			}
		}
		return got
	}
	for _, cmd := range []string{"query", "timeline"} {
		for _, flagName := range []string{"--limit", "--host", "-limit", "-host"} {
			args := []string{cmd, "--data-dir", dataDir, "--no-color", flagName, "edge,dist-*"}
			if cmd == "timeline" {
				args = append(args, "--from", time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05"))
			}
			out, stderr, code := e.run(t, args...)
			if code != task.ExitOK {
				t.Fatalf("%v: exit %d, stderr %q", args, code, stderr)
			}
			if got := hostsIn(out); len(got) != 2 || got[0] != "edge-1" || got[1] != "dist-3" {
				t.Errorf("%v shows %v, want exactly edge-1 and dist-3:\n%s", args, got, out)
			}
		}
		// no limit: everything
		args := []string{cmd, "--data-dir", dataDir, "--no-color"}
		if cmd == "timeline" {
			args = append(args, "--from", time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05"))
		}
		if out, _, _ := e.run(t, args...); len(hostsIn(out)) != 3 {
			t.Errorf("%s without --limit should list all three devices:\n%s", cmd, out)
		}
	}
	if _, stderr, code := e.run(t, "query", "--data-dir", dataDir, "--limit", "bad[glob"); code != task.ExitFatal || !strings.Contains(stderr, "--limit") {
		t.Errorf("a malformed --limit must be refused: exit %d stderr %q", code, stderr)
	}
}

// --format is table|json everywhere; JSON goes to stdout with nothing else mixed in.
func TestLogFormatTableAndJSON(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	seedLogEvents(t, dataDir, "core-gw-1", "edge-1")
	if _, err := store.WriteIncident(store.IncidentsDir(dataDir), collector.IncidentReport{
		ID: "abcd1234", Timestamp: time.Now().Add(-time.Hour), Hostname: "core-gw-1", Playbook: "link_down",
		Diagnostics: []collector.DiagCmd{{Command: "show version", Output: "ok"}},
	}); err != nil {
		t.Fatal(err)
	}
	e := logEnv{}

	out, stderr, code := e.run(t, "query", "--data-dir", dataDir, "--format", "json")
	var entries []collector.LogEntry
	if code != task.ExitOK || stderr != "" || json.Unmarshal([]byte(out), &entries) != nil || len(entries) != 2 {
		t.Fatalf("query --format json: exit %d stderr %q out %q", code, stderr, out)
	}
	if out, _, code := e.run(t, "query", "--data-dir", dataDir, "--format", "table", "--no-color"); code != task.ExitOK || !strings.Contains(out, "core-gw-1") {
		t.Errorf("query --format table: exit %d out %q", code, out)
	}
	// "text" is the pre-merge spelling of the table format and stays accepted.
	if _, _, code := e.run(t, "query", "--data-dir", dataDir, "--format", "text"); code != task.ExitOK {
		t.Errorf("query --format text: exit %d", code)
	}

	out, stderr, code = e.run(t, "incidents", "--data-dir", dataDir, "--format", "json")
	var reports []collector.IncidentReport
	if code != task.ExitOK || stderr != "" || json.Unmarshal([]byte(out), &reports) != nil || len(reports) != 1 || reports[0].ID != "abcd1234" {
		t.Fatalf("incidents --format json: exit %d stderr %q out %q", code, stderr, out)
	}
	out, _, code = e.run(t, "incidents", "--data-dir", dataDir, "--id", "abcd", "--format", "json")
	var one collector.IncidentReport
	if code != task.ExitOK || json.Unmarshal([]byte(out), &one) != nil || one.ID != "abcd1234" {
		t.Fatalf("incidents --id --format json: exit %d out %q", code, out)
	}
	// an empty window is an empty JSON array, not null
	empty := t.TempDir()
	if out, _, code := e.run(t, "incidents", "--data-dir", empty, "--format", "json"); code != task.ExitOK || strings.TrimSpace(out) != "[]" {
		t.Errorf("incidents --format json with nothing stored: exit %d out %q", code, out)
	}

	for _, cmd := range []string{"query", "incidents", "report", "status"} {
		if _, stderr, code := e.run(t, cmd, "--data-dir", dataDir, "--format", "yaml"); code != task.ExitFatal || !strings.Contains(stderr, "--format must be") {
			t.Errorf("%s --format yaml: exit %d stderr %q", cmd, code, stderr)
		}
	}
}

// Credentials resolve through NETOPS_* only: the old NETLOG_* variables are not
// consulted, so a device whose only credentials are NETLOG_* cannot log in.
func TestLogDoesNotReadNetlogEnvironmentVariables(t *testing.T) {
	_, host, port := startLogFakeIOS(t)
	e := newLogEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n", host, port))
	t.Setenv("NETOPS_USERNAME", "")
	t.Setenv("NETOPS_PASSWORD", "")
	t.Setenv("NETLOG_USERNAME", "u")
	t.Setenv("NETLOG_PASSWORD", "p")

	stderr, code := e.collect(t)
	if code != task.ExitFatal || !strings.Contains(stderr, "no device could be polled") {
		t.Fatalf("NETLOG_* credentials must not be honoured: exit %d\n%s", code, stderr)
	}
	if _, found := e.logEntriesOrNil(); found {
		t.Error("nothing may be collected without NETOPS_* credentials")
	}

	// The same run with NETOPS_* set succeeds.
	t.Setenv("NETOPS_USERNAME", "u")
	t.Setenv("NETOPS_PASSWORD", "p")
	if stderr, code := e.collect(t); code != task.ExitOK {
		t.Fatalf("with NETOPS_* credentials: exit %d\n%s", code, stderr)
	}
}

// logEntriesOrNil reports whether any log file exists, without failing the test.
func (e logEnv) logEntriesOrNil() ([]string, bool) {
	files, _ := filepath.Glob(filepath.Join(e.dir, "data", "logs", "*.jsonl"))
	return files, len(files) > 0
}

// The --jump-host flag becomes NETOPS_JUMP_HOST for the credential resolver, and
// an explicit "direct" in the inventory forces a direct connection.
func TestLogJumpHostFlagFeedsTheResolver(t *testing.T) {
	var o logCollectOpts
	fs := newLogCollectFlagSet(&o, &bytes.Buffer{}, false)
	if err := fs.Parse([]string{"--jump-host", "bastion.example:2222", "--env-file", filepath.Join(t.TempDir(), "none.env"), "--known-hosts", filepath.Join(t.TempDir(), "kh")}); err != nil {
		t.Fatal(err)
	}
	tp, err := o.transport(nil, &bytes.Buffer{}, &logLogger{w: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if got := tp.resolver.JumpDefaults().Host; got != "bastion.example:2222" {
		t.Errorf("JumpDefaults().Host = %q, want the --jump-host value", got)
	}
	if tp.ssh.HostKeyCallback == nil || tp.ssh.ConnectTimeout != 10*time.Second || tp.ssh.CommandTimeout != 30*time.Second || !tp.ssh.LegacyAlgorithms {
		t.Errorf("ssh options not built from the harmonised defaults: %+v", tp.ssh)
	}
}

func TestLogMulticallArgs(t *testing.T) {
	cases := []struct {
		exec string
		args []string
		want []string
	}{
		{"netops", []string{"status"}, []string{"status"}},
		{"netops", nil, nil},
		{"netlog", nil, []string{"log"}},
		{"netlog", []string{"status"}, []string{"log", "status"}},
		{"netlog", []string{"query", "--since", "1h"}, []string{"log", "query", "--since", "1h"}},
		{"netlog", []string{"-h"}, []string{"log", "-h"}},
		{"netlog", []string{"init"}, []string{"init"}},
		{"netlog", []string{"telegram-test", "-h"}, []string{"telegram-test", "-h"}},
		{"netlog", []string{"version"}, []string{"version"}},
		{"netlog", []string{"--version"}, []string{"--version"}},
		{"netlog", []string{"-v"}, []string{"version"}},
		{"netlog-1.0", []string{"collect"}, []string{"log", "collect"}},
		{"netlog.exe", []string{"top"}, []string{"log", "top"}},
		{"NETLOG.EXE", []string{"top"}, []string{"log", "top"}},
		{"netlogger", []string{"status"}, []string{"status"}}, // only "netlog" and "netlog-*" are aliases
	}
	for _, c := range cases {
		if got := multicallArgs(c.exec, c.args); !slices.Equal(got, c.want) {
			t.Errorf("multicallArgs(%q, %v) = %v, want %v", c.exec, c.args, got, c.want)
		}
	}
}

// The log subcommands never accept stray positional arguments, except
// diagnose which takes exactly one device.
func TestLogRejectsStrayArguments(t *testing.T) {
	for _, name := range []string{"collect", "monitor", "listen", "query", "timeline", "incidents", "report", "status", "top"} {
		var out, errb bytes.Buffer
		if code := runLog([]string{name, "extra"}, nil, &out, &errb); code != task.ExitFatal || !strings.Contains(errb.String(), `unexpected argument "extra"`) {
			t.Errorf("netops log %s extra: exit %d stderr %q", name, code, errb.String())
		}
	}
}

// "netops log status" flags a device as STALE after an hour by default.
func TestLogStatusStaleAfterDefaultsToOneHour(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runLog([]string{"status", "-h"}, nil, &out, &errb); code != task.ExitOK {
		t.Fatalf("status -h: exit %d", code)
	}
	if !strings.Contains(errb.String(), "(default 1h0m0s)") || logStatusStaleAfter != time.Hour {
		t.Errorf("status --stale-after must default to 1h:\n%s", errb.String())
	}
}

// A missing inventory is reported once, with the init tip, rather than as both
// a load error and an "inventory contains no devices" message.
func TestLogDiagnoseMissingInventoryMessage(t *testing.T) {
	var out, errb bytes.Buffer
	missing := filepath.Join(t.TempDir(), "none.csv")
	if code := runLog([]string{"diagnose", "sw1", "--inventory", missing}, nil, &out, &errb); code != task.ExitFatal {
		t.Fatalf("exit %d, want %d", code, task.ExitFatal)
	}
	msg := errb.String()
	if !strings.Contains(msg, "opening inventory file") || !strings.Contains(msg, "netops init") {
		t.Errorf("want the load error and the init tip, got:\n%s", msg)
	}
	if strings.Contains(msg, "contains no devices") {
		t.Errorf("a missing file must not also be reported as an empty inventory:\n%s", msg)
	}

	// An existing but empty inventory is the "no devices" case, without the tip.
	empty := filepath.Join(t.TempDir(), "empty.csv")
	if err := os.WriteFile(empty, []byte("hostname,address\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := runLog([]string{"diagnose", "sw1", "--inventory", empty}, nil, &out, &errb); code != task.ExitFatal || !strings.Contains(errb.String(), "contains no devices") || strings.Contains(errb.String(), "netops init") {
		t.Errorf("empty inventory: exit %d, stderr:\n%s", code, errb.String())
	}
}

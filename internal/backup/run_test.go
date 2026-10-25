// ==============================================================================
// File name:     run_test.go
// Description:   Tests for fetching and running backups over a task.Transport.
// License:       MIT
// ==============================================================================
package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netconfig/internal/errcat"
	"netconfig/internal/inventory"
	"netconfig/internal/task"
	"netconfig/internal/vendor"
)

// kindErr is a typed failure like netconfig's sshclient.Error.
type kindErr struct{ kind, msg string }

func (e *kindErr) Error() string     { return e.msg }
func (e *kindErr) ErrorKind() string { return e.kind }

// fakeDevice scripts one device. openErrs are consumed one per Open attempt;
// once they run out, Open succeeds.
type fakeDevice struct {
	openErrs []error
	output   string
	sendErr  error
}

// fakeTransport is a task.Transport that never touches the network.
type fakeTransport struct {
	mu       sync.Mutex
	devices  map[string]*fakeDevice // by hostname
	opens    map[string]int
	targets  []task.Target
	sent     []string
	timeouts []time.Duration
	closed   atomic.Int32

	delay      time.Duration // how long each Open takes
	active     atomic.Int32  // sessions currently open
	maxActive  atomic.Int32
	byIP       map[string]*atomic.Int32
	maxPerIP   atomic.Int32
	trackPerIP bool
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{devices: map[string]*fakeDevice{}, opens: map[string]int{}, byIP: map[string]*atomic.Int32{}}
}

func (f *fakeTransport) add(host string, d *fakeDevice) { f.devices[host] = d }

func (f *fakeTransport) Open(ctx context.Context, tgt task.Target) (task.Session, error) {
	f.mu.Lock()
	host := tgt.Device.Hostname
	dev := f.devices[host]
	f.opens[host]++
	f.targets = append(f.targets, tgt)
	var err error
	if dev != nil && len(dev.openErrs) > 0 {
		err, dev.openErrs = dev.openErrs[0], dev.openErrs[1:]
	}
	ip := tgt.Device.Address
	if f.byIP[ip] == nil {
		f.byIP[ip] = new(atomic.Int32)
	}
	perIP := f.byIP[ip]
	f.mu.Unlock()

	if dev == nil {
		return nil, &kindErr{"connect", "dial tcp: no such host"}
	}
	if err != nil {
		return nil, err
	}
	n := f.active.Add(1)
	for {
		m := f.maxActive.Load()
		if n <= m || f.maxActive.CompareAndSwap(m, n) {
			break
		}
	}
	p := perIP.Add(1)
	for {
		m := f.maxPerIP.Load()
		if p <= m || f.maxPerIP.CompareAndSwap(m, p) {
			break
		}
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return &fakeSession{f: f, dev: dev, perIP: perIP}, nil
}

type fakeSession struct {
	f     *fakeTransport
	dev   *fakeDevice
	perIP *atomic.Int32
	once  sync.Once
}

func (s *fakeSession) Send(ctx context.Context, line string, timeout time.Duration) (string, error) {
	s.f.mu.Lock()
	s.f.sent = append(s.f.sent, line)
	s.f.timeouts = append(s.f.timeouts, timeout)
	s.f.mu.Unlock()
	return s.dev.output, s.dev.sendErr
}

func (s *fakeSession) Close() error {
	s.once.Do(func() {
		s.f.closed.Add(1)
		s.f.active.Add(-1)
		s.perIP.Add(-1)
	})
	return nil
}

const (
	iosConfig = "version 15.2\n!\nhostname sw1\ninterface Gi0/1\n description uplink\n!\nend"
	// Junos in "set" form has no end marker.
	junosConfig = "set system host-name r1\nset interfaces ge-0/0/0 description uplink"
)

func testConfig(t *testing.T, tr task.Transport) Config {
	t.Helper()
	return Config{
		Transport: tr,
		Target: func(dev inventory.Device, prof *vendor.Profile) (task.Target, error) {
			return task.Target{}, nil
		},
		OutputDir:   t.TempDir(),
		RunName:     "backup-test",
		Concurrency: 4,
		Redact:      true,
	}
}

func device(host, addr, vendorName string) inventory.Device {
	return inventory.Device{Hostname: host, Address: addr, Port: 22, Vendor: vendorName}
}

func categoryOf(t *testing.T, err error) errcat.Category {
	t.Helper()
	var ce *errcat.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not an *errcat.Error", err)
	}
	return ce.Category
}

func TestFetchConfigRunsTheProfileCommandOverTheTransport(t *testing.T) {
	tr := newFakeTransport()
	tr.add("sw1", &fakeDevice{output: iosConfig})
	cfg := testConfig(t, tr)
	cfg.CommandTimeout = 20 * time.Second
	cfg.ConnectTimeout = 7 * time.Second
	var traces []string
	cfg.Logf = func(host, format string, args ...any) {
		traces = append(traces, host+": "+fmt.Sprintf(format, args...))
	}

	prof, _ := vendor.Lookup("cisco")
	dev := device("sw1", "10.0.0.1", "cisco")
	out, err := fetchConfig(context.Background(), dev, prof, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if out != iosConfig {
		t.Errorf("output = %q", out)
	}
	if len(tr.sent) != 1 || tr.sent[0] != "show running-config" {
		t.Errorf("sent %q, want the profile's backup command", tr.sent)
	}
	if tr.timeouts[0] != 60*time.Second {
		t.Errorf("backup command timeout = %v, want 3x the command timeout", tr.timeouts[0])
	}
	got := tr.targets[0]
	if got.Device.Hostname != "sw1" || got.Profile != prof {
		t.Errorf("target device/profile = %+v / %v", got.Device, got.Profile)
	}
	if got.ConnectTimeout != 7*time.Second || got.LoginTimeout != 20*time.Second {
		t.Errorf("timeouts connect=%v login=%v", got.ConnectTimeout, got.LoginTimeout)
	}
	if got.Logf == nil {
		t.Fatal("the connection trace hook was not wired")
	}
	got.Logf("hello %d", 1)
	if len(traces) != 1 || traces[0] != "sw1: hello 1" {
		t.Errorf("traces = %q", traces)
	}
	if tr.closed.Load() != 1 {
		t.Errorf("the session was closed %d times, want 1", tr.closed.Load())
	}
}

func TestFetchConfigDefaultTimeouts(t *testing.T) {
	tr := newFakeTransport()
	tr.add("sw1", &fakeDevice{output: iosConfig})
	prof, _ := vendor.Lookup("cisco")
	if _, err := fetchConfig(context.Background(), device("sw1", "10.0.0.1", "cisco"), prof, testConfig(t, tr)); err != nil {
		t.Fatal(err)
	}
	if tr.targets[0].ConnectTimeout != 10*time.Second || tr.timeouts[0] != 90*time.Second {
		t.Errorf("defaults: connect=%v backup=%v", tr.targets[0].ConnectTimeout, tr.timeouts[0])
	}
}

func TestFetchConfigUsesTheArchiveCommand(t *testing.T) {
	tr := newFakeTransport()
	tr.add("r1", &fakeDevice{output: junosConfig})
	prof, _ := vendor.Lookup("junos")
	if _, err := fetchConfig(context.Background(), device("r1", "10.0.0.2", "junos"), prof, testConfig(t, tr)); err != nil {
		t.Fatal(err)
	}
	if want := "show configuration | display set"; tr.sent[0] != want {
		t.Errorf("sent %q, want %q (netbackup archives Junos as set commands)", tr.sent[0], want)
	}
}

func TestFetchConfigSophosMultiCommand(t *testing.T) {
	tr := newFakeTransport()
	tr.add("fw1", &fakeDevice{output: "Port1 Zonetype:LAN MTU:1500"})
	prof, _ := vendor.Lookup("sophos")
	out, err := fetchConfig(context.Background(), device("fw1", "10.0.0.3", "sophos"), prof, testConfig(t, tr))
	if err != nil {
		t.Fatal(err)
	}
	wantCmds := []string{
		"system diagnostics show version-info",
		"show network interfaces",
		"show static-route",
		"system ha show details",
	}
	if !slices.Equal(tr.sent, wantCmds) {
		t.Errorf("sent = %v, want %v", tr.sent, wantCmds)
	}
	for _, cmd := range wantCmds {
		header := fmt.Sprintf("=== %s ===", cmd)
		if !strings.Contains(out, header) {
			t.Errorf("output missing section header %q", header)
		}
	}
}

func TestFetchConfigClassifiesFailures(t *testing.T) {
	prof, _ := vendor.Lookup("cisco")
	tests := []struct {
		name string
		dev  *fakeDevice
		want errcat.Category
	}{
		{"authentication", &fakeDevice{openErrs: []error{&kindErr{"auth", "connect: ssh: unable to authenticate"}}}, errcat.CategoryAuthFailed},
		{"enable rejected", &fakeDevice{openErrs: []error{&kindErr{"auth", "enable: access denied"}}}, errcat.CategoryAuthFailed},
		{"refused", &fakeDevice{openErrs: []error{&kindErr{"connect", "dial tcp 10.0.0.1:22: connection refused"}}}, errcat.CategoryUnreachable},
		{"no prompt after login", &fakeDevice{openErrs: []error{&kindErr{"timeout", "login: no prompt within 30s"}}}, errcat.CategoryUnreachable},
		{"host key", &fakeDevice{openErrs: []error{&kindErr{"hostkey", "knownhosts: key mismatch"}}}, errcat.CategoryConnectFailed},
		{"command timeout", &fakeDevice{output: "part of", sendErr: &kindErr{"timeout", "send: no prompt within 90s"}}, errcat.CategoryTimeout},
		{"session dropped", &fakeDevice{sendErr: &kindErr{"session", "send: connection dropped"}}, errcat.CategorySessionError},
		{"device rejected the command", &fakeDevice{output: "% Invalid input detected at '^' marker."}, errcat.CategoryCommandFailed},
		{"truncated backup", &fakeDevice{output: "version 15.2\n!\nhostname sw1\ninterface Gi0/1"}, errcat.CategoryTruncatedOutput},
		{"empty backup", &fakeDevice{output: ""}, errcat.CategoryTruncatedOutput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newFakeTransport()
			tr.add("sw1", tt.dev)
			_, err := fetchConfig(context.Background(), device("sw1", "10.0.0.1", "cisco"), prof, testConfig(t, tr))
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := categoryOf(t, err); got != tt.want {
				t.Errorf("category = %s, want %s (%v)", got, tt.want, err)
			}
		})
	}

	t.Run("rejection names the command and the device's line", func(t *testing.T) {
		tr := newFakeTransport()
		tr.add("sw1", &fakeDevice{output: "% Invalid input detected at '^' marker."})
		_, err := fetchConfig(context.Background(), device("sw1", "10.0.0.1", "cisco"), prof, testConfig(t, tr))
		if err == nil || !strings.Contains(err.Error(), `"show running-config"`) || !strings.Contains(err.Error(), "Invalid input") {
			t.Errorf("error = %v", err)
		}
	})
}

func TestFetchConfigSurfacesTargetAndConfigurationProblems(t *testing.T) {
	prof, _ := vendor.Lookup("cisco")
	dev := device("sw1", "10.0.0.1", "cisco")

	cfg := testConfig(t, newFakeTransport())
	cfg.Target = func(inventory.Device, *vendor.Profile) (task.Target, error) {
		return task.Target{}, errors.New("no credentials for group \"dc1\"")
	}
	if _, err := fetchConfig(context.Background(), dev, prof, cfg); err == nil || !strings.Contains(err.Error(), "dc1") {
		t.Errorf("credential error not surfaced: %v", err)
	}

	if _, err := fetchConfig(context.Background(), dev, prof, Config{}); err == nil {
		t.Error("a Config without a transport must fail, not panic")
	}
}

func TestFetchConfigDryRunOpensASessionButSendsNothing(t *testing.T) {
	tr := newFakeTransport()
	tr.add("sw1", &fakeDevice{output: iosConfig})
	cfg := testConfig(t, tr)
	cfg.DryRun = true
	prof, _ := vendor.Lookup("cisco")
	out, err := fetchConfig(context.Background(), device("sw1", "10.0.0.1", "cisco"), prof, cfg)
	if err != nil || out != "" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if tr.opens["sw1"] != 1 || len(tr.sent) != 0 || tr.closed.Load() != 1 {
		t.Errorf("opens=%d sent=%q closed=%d", tr.opens["sw1"], tr.sent, tr.closed.Load())
	}
}

func TestRunAllSavesEachPlatformInNetbackupLayout(t *testing.T) {
	tr := newFakeTransport()
	tr.add("sw1", &fakeDevice{output: iosConfig})
	tr.add("r1", &fakeDevice{output: junosConfig})
	tr.add("fw1", &fakeDevice{output: "config system global\n    set hostname fw1\nend"})
	cfg := testConfig(t, tr)

	devs := []inventory.Device{
		device("sw1", "10.0.0.1", "cisco_ios"), // netbackup's name for the profile
		device("r1", "10.0.0.2", "junos"),
		device("fw1", "10.0.0.3", "fortigate"),
	}
	results := RunAll(context.Background(), devs, cfg)
	for _, r := range results {
		if !r.Success || r.Err != nil {
			t.Fatalf("%s failed: %v", r.Device.Hostname, r.Err)
		}
	}
	for _, want := range []string{
		"backup-test/cisco_ios/sw1.cfg",
		"backup-test/juniper_junos/r1.set",
		"backup-test/fortigate/fw1.conf",
	} {
		if _, err := os.Stat(filepath.Join(cfg.OutputDir, want)); err != nil {
			t.Errorf("expected %s: %v", want, err)
		}
	}
	if results[0].Device.Hostname != "sw1" || results[2].Device.Hostname != "fw1" {
		t.Error("results must keep the inventory order")
	}
}

func TestRunAllAutoDetectsCiscoVariants(t *testing.T) {
	tr := newFakeTransport()
	tr.add("sw-ios", &fakeDevice{output: iosConfig})
	tr.add("sw-sb", &fakeDevice{output: "config-file-header\nunit-type-control-start\nunit-type unit 1\nunit-type-control-end\ninterface gigabitethernet1\nexit\n"})
	tr.add("fw-asa", &fakeDevice{output: "ASA Version 9.8(4)\ninterface Management0/0\n: end\n"})
	cfg := testConfig(t, tr)

	devs := []inventory.Device{
		device("sw-ios", "10.0.0.1", "cisco"),
		device("sw-sb", "10.0.0.2", "cisco"),
		device("fw-asa", "10.0.0.3", "cisco"),
	}
	results := RunAll(context.Background(), devs, cfg)
	for _, r := range results {
		if !r.Success || r.Err != nil {
			t.Fatalf("%s failed: %v", r.Device.Hostname, r.Err)
		}
	}
	for _, want := range []string{
		"backup-test/cisco_ios/sw-ios.cfg",
		"backup-test/cisco_sb/sw-sb.cfg",
		"backup-test/cisco_asa/fw-asa.cfg",
	} {
		if _, err := os.Stat(filepath.Join(cfg.OutputDir, want)); err != nil {
			t.Errorf("expected %s: %v", want, err)
		}
	}
}

func TestRunAllSecondRunDetectsUnchangedAndChanged(t *testing.T) {
	tr := newFakeTransport()
	tr.add("sw1", &fakeDevice{output: iosConfig})
	cfg := testConfig(t, tr)
	cfg.ShowDiff = true
	dev := []inventory.Device{device("sw1", "10.0.0.1", "cisco")}

	cfg.RunName = "backup-2026-10-01-1000"
	if r := RunAll(context.Background(), dev, cfg)[0]; !r.Success || r.Unchanged {
		t.Fatalf("first run: %+v", r)
	}

	cfg.RunName = "backup-2026-10-02-1000"
	r := RunAll(context.Background(), dev, cfg)[0]
	if !r.Success || !r.Unchanged || r.BytesWritten != 0 {
		t.Errorf("identical config must be Unchanged and not rewritten: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(cfg.OutputDir, cfg.RunName)); !os.IsNotExist(err) {
		t.Errorf("an unchanged device must not create a new run directory: %v", err)
	}

	tr.devices["sw1"].output = strings.Replace(iosConfig, "uplink", "core uplink", 1)
	cfg.RunName = "backup-2026-10-03-1000"
	r = RunAll(context.Background(), dev, cfg)[0]
	if !r.Success || r.Unchanged || !r.HasDiff || r.DiffAdded != 1 || r.DiffRemoved != 1 {
		t.Errorf("changed config: %+v", r)
	}
}

func TestRunAllReportsEachFailureWithoutStoppingTheOthers(t *testing.T) {
	tr := newFakeTransport()
	tr.add("good", &fakeDevice{output: iosConfig})
	tr.add("badauth", &fakeDevice{openErrs: []error{&kindErr{"auth", "connect: unable to authenticate"}}})
	tr.add("cut", &fakeDevice{output: "version 15.2\n!\nhostname cut\ninterface Gi0/1"})
	cfg := testConfig(t, tr)

	devs := []inventory.Device{
		device("good", "10.0.0.1", "cisco"),
		device("badauth", "10.0.0.2", "cisco"),
		device("ghost", "10.0.0.3", "cisco"), // the transport does not know it: unreachable
		device("cut", "10.0.0.4", "cisco"),
		device("baddev", "10.0.0.5", "nosuchvendor"), // not a netconfig vendor
	}
	res := RunAll(context.Background(), devs, cfg)

	want := []struct {
		ok  bool
		cat errcat.Category
	}{
		{true, ""},
		{false, errcat.CategoryAuthFailed},
		{false, errcat.CategoryUnreachable},
		{false, errcat.CategoryTruncatedOutput},
		{false, errcat.CategoryUnknown},
	}
	for i, w := range want {
		if res[i].Success != w.ok || res[i].Category != w.cat {
			t.Errorf("%s: success=%v category=%q err=%v; want success=%v category=%q",
				devs[i].Hostname, res[i].Success, res[i].Category, res[i].Err, w.ok, w.cat)
		}
	}
	if err := res[4].Err; err == nil || !strings.Contains(err.Error(), `unsupported vendor "nosuchvendor"`) || !strings.Contains(err.Error(), "cisco_sb") {
		t.Errorf("unsupported vendor error should list what is supported: %v", err)
	}
	if tr.opens["baddev"] != 0 {
		t.Error("a device with an unsupported vendor must not be contacted")
	}
}

func TestRunAllNeverSavesAFailedOrTruncatedBackup(t *testing.T) {
	tr := newFakeTransport()
	tr.add("cut", &fakeDevice{output: "version 15.2\n!\nhostname cut\ninterface Gi0/1"})
	cfg := testConfig(t, tr)
	RunAll(context.Background(), []inventory.Device{device("cut", "10.0.0.1", "cisco")}, cfg)
	if entries, _ := os.ReadDir(cfg.OutputDir); len(entries) != 0 {
		t.Errorf("a truncated backup left files behind: %v", entries)
	}
}

func TestRunAllRetriesTransientDrops(t *testing.T) {
	defer func(old time.Duration) { rateLimitBackoff = old }(rateLimitBackoff)
	rateLimitBackoff = time.Millisecond
	tr := newFakeTransport()
	tr.add("sw1", &fakeDevice{
		openErrs: []error{errors.New("ssh: handshake failed: EOF"), &kindErr{"connect", "read: connection reset by peer"}},
		output:   iosConfig,
	})
	cfg := testConfig(t, tr)
	cfg.Retries = 2
	cfg.RetryDelay = time.Millisecond

	r := RunAll(context.Background(), []inventory.Device{device("sw1", "10.0.0.1", "cisco")}, cfg)[0]
	if !r.Success {
		t.Fatalf("expected success after retries: %v", r.Err)
	}
	if tr.opens["sw1"] != 3 {
		t.Errorf("opens = %d, want 3 (two transient drops, then success)", tr.opens["sw1"])
	}
}

func TestRunAllDoesNotRetryAuthenticationFailures(t *testing.T) {
	tr := newFakeTransport()
	tr.add("sw1", &fakeDevice{openErrs: []error{
		&kindErr{"auth", "connect: unable to authenticate"},
		&kindErr{"auth", "connect: unable to authenticate"},
	}})
	cfg := testConfig(t, tr)
	cfg.Retries = 3
	cfg.RetryDelay = time.Millisecond

	r := RunAll(context.Background(), []inventory.Device{device("sw1", "10.0.0.1", "cisco")}, cfg)[0]
	if r.Success || r.Category != errcat.CategoryAuthFailed {
		t.Fatalf("result: %+v", r)
	}
	if tr.opens["sw1"] != 1 {
		t.Errorf("opens = %d: retrying a rejected password risks locking the account", tr.opens["sw1"])
	}
}

// Retrying a rejected password counts against the account's lockout
// threshold on every attempt, and retrying a host key mismatch just repeats a
// security failure; a command the device refused will be refused again.
func TestRunAllRetryPolicy(t *testing.T) {
	failures := func(n int, err error) []error {
		out := make([]error, n)
		for i := range out {
			out[i] = err
		}
		return out
	}
	tests := []struct {
		name      string
		dev       *fakeDevice
		wantOpens int
		wantOK    bool
	}{
		{"auth failure", &fakeDevice{openErrs: failures(5, &kindErr{"auth", "connect: unable to authenticate"})}, 1, false},
		{"enable rejected", &fakeDevice{openErrs: failures(5, &kindErr{"auth", "enable: access denied"})}, 1, false},
		{"host key mismatch", &fakeDevice{openErrs: failures(5, &kindErr{"hostkey", "knownhosts: key mismatch"})}, 1, false},
		{"device rejects the command", &fakeDevice{output: "% Invalid input detected at '^' marker."}, 1, false},
		{"connection refused", &fakeDevice{openErrs: failures(2, &kindErr{"connect", "dial tcp: connection refused"}), output: iosConfig}, 3, true},
		{"login timeout", &fakeDevice{openErrs: failures(2, &kindErr{"timeout", "login: no prompt within 30s"}), output: iosConfig}, 3, true},
		{"session dropped", &fakeDevice{openErrs: failures(2, &kindErr{"session", "start shell: broken"}), output: iosConfig}, 3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newFakeTransport()
			tr.add("sw1", tt.dev)
			cfg := testConfig(t, tr)
			cfg.Retries = 3
			cfg.RetryDelay = time.Millisecond
			r := RunAll(context.Background(), []inventory.Device{device("sw1", "10.0.0.1", "cisco")}, cfg)[0]
			if r.Success != tt.wantOK {
				t.Errorf("success = %v (%v), want %v", r.Success, r.Err, tt.wantOK)
			}
			if tr.opens["sw1"] != tt.wantOpens {
				t.Errorf("opened %d times, want %d", tr.opens["sw1"], tt.wantOpens)
			}
		})
	}
}

func TestRunAllDryRunSavesNothing(t *testing.T) {
	tr := newFakeTransport()
	tr.add("sw1", &fakeDevice{output: iosConfig})
	cfg := testConfig(t, tr)
	cfg.DryRun = true
	r := RunAll(context.Background(), []inventory.Device{device("sw1", "10.0.0.1", "cisco")}, cfg)[0]
	if !r.Success || !r.DryRun {
		t.Fatalf("result: %+v", r)
	}
	if entries, _ := os.ReadDir(cfg.OutputDir); len(entries) != 0 {
		t.Errorf("dry run wrote %v", entries)
	}
	if len(tr.sent) != 0 {
		t.Errorf("dry run sent %q", tr.sent)
	}
}

func TestRunAllReportsProgress(t *testing.T) {
	tr := newFakeTransport()
	var devs []inventory.Device
	for i := 0; i < 6; i++ {
		h := fmt.Sprintf("sw%d", i)
		tr.add(h, &fakeDevice{output: iosConfig})
		devs = append(devs, device(h, fmt.Sprintf("10.0.0.%d", i+1), "cisco"))
	}
	cfg := testConfig(t, tr)
	var mu sync.Mutex
	var seen []int
	cfg.OnProgress = func(done, total int, _ Result) {
		mu.Lock()
		defer mu.Unlock()
		if total != 6 {
			t.Errorf("total = %d", total)
		}
		seen = append(seen, done)
	}
	RunAll(context.Background(), devs, cfg)
	if len(seen) != 6 {
		t.Fatalf("progress called %d times, want 6", len(seen))
	}
	for _, want := range []int{1, 2, 3, 4, 5, 6} {
		found := false
		for _, s := range seen {
			found = found || s == want
		}
		if !found {
			t.Errorf("completed count %d never reported: %v", want, seen)
		}
	}
}

func TestRunAllHonoursConcurrencyAndSerialisesPerAddress(t *testing.T) {
	tr := newFakeTransport()
	tr.delay = 15 * time.Millisecond
	var devs []inventory.Device
	for i := 0; i < 8; i++ { // 8 devices behind 4 addresses: two per address
		h := fmt.Sprintf("sw%d", i)
		tr.add(h, &fakeDevice{output: iosConfig})
		devs = append(devs, device(h, fmt.Sprintf("10.0.0.%d", i%4+1), "cisco"))
	}
	cfg := testConfig(t, tr)
	cfg.Concurrency = 3
	for _, r := range RunAll(context.Background(), devs, cfg) {
		if !r.Success {
			t.Fatalf("%s: %v", r.Device.Hostname, r.Err)
		}
	}
	if m := tr.maxActive.Load(); m > 3 {
		t.Errorf("%d sessions open at once, concurrency limit is 3", m)
	}
	if m := tr.maxPerIP.Load(); m != 1 {
		t.Errorf("%d simultaneous sessions to one address, want 1 (connection-limit protection)", m)
	}
}

func TestRunAllStopsWhenCancelled(t *testing.T) {
	tr := newFakeTransport()
	tr.add("sw1", &fakeDevice{output: iosConfig})
	cfg := testConfig(t, tr)
	cfg.DialJitter = time.Hour // the jitter wait is where cancellation must be noticed
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := RunAll(ctx, []inventory.Device{device("sw1", "10.0.0.1", "cisco")}, cfg)[0]
	if r.Success || r.Err == nil {
		t.Errorf("cancelled run reported %+v", r)
	}
	if tr.opens["sw1"] != 0 {
		t.Error("a cancelled run must not connect")
	}
}

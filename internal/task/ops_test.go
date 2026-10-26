// ==============================================================================
// File name:     ops_test.go
// Description:   Integration tests for the idempotent change workflows,
//
//	against a small stateful virtual device.
//
// License:       MIT
// ==============================================================================
package task

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/internal/credentials"
	"netops/internal/inventory"
	"netops/internal/logging"
	"netops/internal/vendor"
)

// ---- a stateful virtual IOS-like device -------------------------------------

type viosUser struct {
	priv int
	hash string
}

type viosDev struct {
	mu          sync.Mutex
	users       map[string]viosUser
	vlans       map[int]string
	enable      string // stored enable hash; "" = none
	requireEnab bool   // logins must present the enable secret
	rejectPw    map[string]string
	rejectEnab  bool // any enable secret other than the original is refused at login
	origEnable  string
	rejectShow  bool // the device refuses the state-check commands

	saved       viosSnapshot
	writes      int
	cfgSessions int
	cmds        []string
}

type viosSnapshot struct {
	users  map[string]viosUser
	vlans  map[int]string
	enable string
}

func hashPW(pw string) string {
	s := sha256.Sum256([]byte(pw))
	return "$9$" + hex.EncodeToString(s[:6])
}

func newVIOS() *viosDev {
	d := &viosDev{
		users:    map[string]viosUser{"svc": {15, hashPW("pw-for-tests")}, "bob": {15, hashPW("oldpass")}},
		vlans:    map[int]string{1: "default"},
		enable:   hashPW("enable-old"),
		rejectPw: map[string]string{},
	}
	d.origEnable = d.enable
	d.saved = d.snapshot()
	return d
}

func (d *viosDev) snapshot() viosSnapshot {
	s := viosSnapshot{users: map[string]viosUser{}, vlans: map[int]string{}, enable: d.enable}
	for k, v := range d.users {
		s.users[k] = v
	}
	for k, v := range d.vlans {
		s.vlans[k] = v
	}
	return s
}

func (d *viosDev) auth(c credentials.Credential) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, ok := d.users[c.Username]
	if !ok || u.hash != hashPW(c.Password) || d.rejectPw[c.Username] == c.Password {
		return &fakeErr{"auth", "authentication failed"}
	}
	if d.requireEnab {
		e := c.EnablePassword
		if e == "" {
			e = c.Password
		}
		if d.enable != hashPW(e) || d.rejectEnab && d.enable != d.origEnable {
			return &fakeErr{"auth", "enable authentication failed"}
		}
	}
	return nil
}

var (
	reVUserNew  = regexp.MustCompile(`^username (\S+) privilege (\d+) secret 0 (\S+)$`)
	reVUserPw   = regexp.MustCompile(`^username (\S+) secret 0 (\S+)$`)
	reVUserHash = regexp.MustCompile(`^username (\S+) privilege (\d+) secret 9 (\S+)$`)
	reVUserDel  = regexp.MustCompile(`^no username (\S+)$`)
	reVShowUser = regexp.MustCompile(`^show running-config \| include \^username (\S+) $`)
	reVShowVLAN = regexp.MustCompile(`^show vlan id (\d+)$`)
	reVVLAN     = regexp.MustCompile(`^vlan (\d+)$`)
	reVName     = regexp.MustCompile(`^name (\S+)$`)
	reVNoVLAN   = regexp.MustCompile(`^no vlan (\d+)$`)
	reVEnable   = regexp.MustCompile(`^enable secret 0 (\S+)$`)
	reVEnableH  = regexp.MustCompile(`^enable secret 9 (\S+)$`)
)

type viosSess struct {
	d      *viosDev
	inCfg  bool
	curVID int
}

func (s *viosSess) exec(line string) string {
	d := s.d
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cmds = append(d.cmds, line)
	if d.rejectShow && strings.HasPrefix(line, "show ") && line != "show clock" {
		return "% Invalid input detected at '^' marker.\n"
	}
	switch {
	case line == "configure terminal":
		s.inCfg = true
		d.cfgSessions++
	case line == "end":
		s.inCfg, s.curVID = false, 0
	case line == "write memory":
		d.writes++
		d.saved = d.snapshot()
	case line == "show clock":
		return "10:00:00 UTC\n"
	case reVShowUser.MatchString(line):
		name := reVShowUser.FindStringSubmatch(line)[1]
		if u, ok := d.users[name]; ok {
			return fmt.Sprintf("username %s privilege %d secret 9 %s\n", name, u.priv, u.hash)
		}
		return ""
	case line == "show running-config | include ^enable ":
		if d.enable == "" {
			return ""
		}
		return "enable secret 9 " + d.enable + "\n"
	case reVShowVLAN.MatchString(line):
		id, _ := strconv.Atoi(reVShowVLAN.FindStringSubmatch(line)[1])
		if name, ok := d.vlans[id]; ok {
			return fmt.Sprintf("VLAN Name                             Status    Ports\n---- -------------------------------- --------- -----\n%-4d %-32s active    Gi1/0/1\n", id, name)
		}
		return fmt.Sprintf("VLAN id %d not found in current VLAN database\n", id)
	case !s.inCfg:
		return "% Invalid input detected at '^' marker.\n"
	case reVUserNew.MatchString(line):
		m := reVUserNew.FindStringSubmatch(line)
		p, _ := strconv.Atoi(m[2])
		d.users[m[1]] = viosUser{p, hashPW(m[3])}
	case reVUserHash.MatchString(line):
		m := reVUserHash.FindStringSubmatch(line)
		p, _ := strconv.Atoi(m[2])
		d.users[m[1]] = viosUser{p, m[3]}
	case reVUserPw.MatchString(line):
		m := reVUserPw.FindStringSubmatch(line)
		u := d.users[m[1]]
		if u.priv == 0 {
			u.priv = 1
		}
		u.hash = hashPW(m[2])
		d.users[m[1]] = u
	case reVUserDel.MatchString(line):
		delete(d.users, reVUserDel.FindStringSubmatch(line)[1])
	case reVEnable.MatchString(line):
		d.enable = hashPW(reVEnable.FindStringSubmatch(line)[1])
	case reVEnableH.MatchString(line):
		d.enable = reVEnableH.FindStringSubmatch(line)[1]
	case line == "no enable secret":
		d.enable = ""
	case reVVLAN.MatchString(line):
		id, _ := strconv.Atoi(reVVLAN.FindStringSubmatch(line)[1])
		if _, ok := d.vlans[id]; !ok {
			d.vlans[id] = fmt.Sprintf("VLAN%04d", id)
		}
		s.curVID = id
	case reVName.MatchString(line) && s.curVID != 0:
		d.vlans[s.curVID] = reVName.FindStringSubmatch(line)[1]
	case reVNoVLAN.MatchString(line):
		id, _ := strconv.Atoi(reVNoVLAN.FindStringSubmatch(line)[1])
		delete(d.vlans, id)
	default:
		return "% Invalid input detected at '^' marker.\n"
	}
	return ""
}

// ---- a transport that records every session and routes to virtual devices ----

type opOpen struct {
	host string
	cred credentials.Credential
}

type opTransport struct {
	mu     sync.Mutex
	devs   map[string]*viosDev
	script func(host, line string) string // for devices that are not a viosDev
	opens  []opOpen
	sent   map[string][]string // host -> every command, in order
}

func newOpTransport() *opTransport {
	return &opTransport{devs: map[string]*viosDev{}, sent: map[string][]string{}}
}

type opSession struct {
	t    *opTransport
	host string
	v    *viosSess
}

func (t *opTransport) Open(_ context.Context, tgt Target) (Session, error) {
	host := tgt.Device.Hostname
	t.mu.Lock()
	t.opens = append(t.opens, opOpen{host, tgt.Cred})
	d := t.devs[host]
	t.mu.Unlock()
	s := &opSession{t: t, host: host}
	if d != nil {
		if err := d.auth(tgt.Cred); err != nil {
			return nil, err
		}
		s.v = &viosSess{d: d}
	}
	return s, nil
}

func (s *opSession) Send(_ context.Context, line string, _ time.Duration) (string, error) {
	s.t.mu.Lock()
	s.t.sent[s.host] = append(s.t.sent[s.host], line)
	s.t.mu.Unlock()
	if s.v != nil {
		return s.v.exec(line), nil
	}
	if s.t.script != nil {
		return s.t.script(s.host, line), nil
	}
	return "", nil
}

func (s *opSession) Close() error { return nil }

func (t *opTransport) opensFor(host, user string) []credentials.Credential {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []credentials.Credential
	for _, o := range t.opens {
		if o.host == host && o.cred.Username == user {
			out = append(out, o.cred)
		}
	}
	return out
}

func (t *opTransport) commands(host string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.sent[host]...)
}

// ---- harness ---------------------------------------------------------------

type harness struct {
	t    *testing.T
	tr   *opTransport
	r    *Runner
	logs *bytes.Buffer
}

func newHarness(t *testing.T, opts Options, hosts ...string) (*harness, []*viosDev) {
	t.Helper()
	tr := newOpTransport()
	var devs []*viosDev
	for _, h := range hosts {
		d := newVIOS()
		tr.devs[h] = d
		devs = append(devs, d)
	}
	buf := &bytes.Buffer{}
	log, err := logging.New(logging.Options{Console: buf, Verbose: true})
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
	if opts.ConnectTimeout == 0 {
		opts.ConnectTimeout = time.Second
	}
	return &harness{t: t, tr: tr, r: &Runner{Transport: tr, Log: log, Opts: opts}, logs: buf}, devs
}

func (h *harness) jobs(vendorName string, capable Capability, hosts ...string) []Job {
	h.t.Helper()
	var devs []inventory.Device
	for i, host := range hosts {
		devs = append(devs, inventory.Device{Hostname: host, Address: fmt.Sprintf("10.0.0.%d", i+1), Port: 22, Vendor: vendorName, Group: "default"})
	}
	jobs := BuildCapabilityJobs(devs, "test", capable)
	for i := range jobs {
		jobs[i].Cred = credentials.Credential{Username: "svc", Password: "pw-for-tests"}
	}
	return jobs
}

// change runs both phases and returns the merged results.
func (h *harness) change(jobs []Job, d Decider) []Result {
	h.t.Helper()
	ctx := context.Background()
	decisions, checked := h.r.Decide(ctx, jobs, d)
	apply, idx := BuildApplyJobs(jobs, checked, decisions)
	return MergeResults(checked, idx, h.r.Run(ctx, apply))
}

func always(*vendor.Profile) (bool, string) { return true, "" }

func mustNotContain(t *testing.T, haystack, needle, what string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("%s leaked %q", what, needle)
	}
}

// ---- user add / user del ----------------------------------------------------

func TestUserAddIdempotent(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1", "sw2")
	devs[1].users["alice"] = viosUser{15, hashPW("whatever")}
	spec := UserSpec{Username: "alice", Password: "S3cretPass", Privilege: 15}
	jobs := h.jobs(vendor.Cisco, UserAddCapability(spec), "sw1", "sw2")

	res := h.change(jobs, UserAdd(spec))
	if code := ExitCode(res); code != ExitOK {
		t.Fatalf("exit code %d, results %+v", code, res)
	}
	if u, ok := devs[0].users["alice"]; !ok || u.priv != 15 || u.hash != hashPW("S3cretPass") {
		t.Errorf("sw1 did not get the account: %+v", devs[0].users)
	}
	if devs[0].saved.users["alice"].hash != hashPW("S3cretPass") || devs[0].writes != 1 {
		t.Errorf("sw1 change was not saved exactly once (writes=%d)", devs[0].writes)
	}
	// sw2 already had the user: [SKIPPED], and the device was never put in config mode
	if devs[1].cfgSessions != 0 || devs[1].writes != 0 {
		t.Errorf("sw2 was touched (cfg=%d writes=%d)", devs[1].cfgSessions, devs[1].writes)
	}
	if devs[1].users["alice"].hash != hashPW("whatever") {
		t.Error("an existing user's password was overwritten without --update-password")
	}
	if !strings.Contains(res[1].Detail, "already exists") {
		t.Errorf("sw2 detail = %q", res[1].Detail)
	}
	if !strings.Contains(h.logs.String(), "[SKIPPED]") {
		t.Error("no [SKIPPED] line was logged")
	}

	// running it again changes nothing anywhere
	writes := devs[0].writes
	res = h.change(jobs, UserAdd(spec))
	if ExitCode(res) != ExitOK || devs[0].writes != writes || devs[0].cfgSessions != 1 {
		t.Errorf("second run was not a no-op: writes=%d cfg=%d res=%+v", devs[0].writes, devs[0].cfgSessions, res)
	}
	mustNotContain(t, h.logs.String(), "S3cretPass", "the log")
}

func TestUserAddUpdatePassword(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1")
	spec := UserSpec{Username: "bob", Password: "Rotat3dPass", Privilege: 15, UpdatePassword: true}
	res := h.change(h.jobs(vendor.Cisco, UserAddCapability(spec), "sw1"), UserAdd(spec))
	if res[0].Status != StatusSucceeded || devs[0].users["bob"].hash != hashPW("Rotat3dPass") {
		t.Errorf("password not updated: %+v %+v", res[0], devs[0].users["bob"])
	}
}

func TestUserDelIdempotent(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1", "sw2")
	delete(devs[1].users, "bob")
	jobs := h.jobs(vendor.Cisco, UserDelCapability("bob"), "sw1", "sw2")

	res := h.change(jobs, UserDel("bob"))
	if ExitCode(res) != ExitOK {
		t.Fatalf("results %+v", res)
	}
	if _, ok := devs[0].users["bob"]; ok || devs[0].writes != 1 {
		t.Errorf("sw1 still has bob or was not saved: %+v writes=%d", devs[0].users, devs[0].writes)
	}
	if devs[1].cfgSessions != 0 || !strings.Contains(res[1].Detail, "does not exist") {
		t.Errorf("sw2 should be skipped as absent: cfg=%d detail=%q", devs[1].cfgSessions, res[1].Detail)
	}
	if _, ok := devs[0].users["svc"]; !ok {
		t.Error("an unrelated account disappeared")
	}
	res = h.change(jobs, UserDel("bob"))
	if ExitCode(res) != ExitOK || devs[0].cfgSessions != 1 {
		t.Errorf("second delete was not a no-op: %+v", res)
	}
}

func TestRejectedCheckIsNeverTreatedAsAbsent(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1")
	devs[0].rejectShow = true // e.g. no permission, or the platform lacks "| include"
	spec := UserSpec{Username: "alice", Password: "S3cretPass", Privilege: 15}
	res := h.change(h.jobs(vendor.Cisco, UserAddCapability(spec), "sw1"), UserAdd(spec))
	if res[0].Status != StatusFailed || res[0].Category != CatSyntaxError {
		t.Fatalf("result = %+v", res[0])
	}
	if devs[0].cfgSessions != 0 || len(devs[0].users) != 2 {
		t.Error("a rejected state check must not lead to any change")
	}
	if !strings.Contains(res[0].Detail, "rejected the state check") {
		t.Errorf("detail = %q", res[0].Detail)
	}
}

func TestUserCapabilityGating(t *testing.T) {
	devs := []inventory.Device{
		{Hostname: "fw1", Address: "10.0.0.1", Vendor: "paloalto"},
		{Hostname: "ar1", Address: "10.0.0.2", Vendor: "aruba"},
		{Hostname: "xx1", Address: "10.0.0.3", Vendor: "nokia"},
	}
	jobs := BuildCapabilityJobs(devs, "user add", UserAddCapability(UserSpec{Username: "bob", Password: "S3cretPass", Privilege: 15}))
	if jobs[0].Skip != CatUnsupportedOp || !strings.Contains(jobs[0].SkipDetail, "Palo Alto") {
		t.Errorf("palo alto job = %+v", jobs[0])
	}
	if jobs[1].Skip != "" {
		t.Errorf("aruba at privilege 15 should be admitted: %+v", jobs[1])
	}
	if jobs[2].Skip != CatUnsupportedVendor {
		t.Errorf("unknown vendor job = %+v", jobs[2])
	}
	// Aruba has no equivalent of privilege 5
	jobs = BuildCapabilityJobs(devs[1:2], "user add", UserAddCapability(UserSpec{Username: "bob", Password: "S3cretPass", Privilege: 5}))
	if jobs[0].Skip != CatUnsupportedOp || !strings.Contains(jobs[0].SkipDetail, "privilege level 5") {
		t.Errorf("aruba privilege 5 job = %+v", jobs[0])
	}
}

// ---- passwd -----------------------------------------------------------------

func TestPasswdRotationVerifiedBeforeSave(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1")
	spec := PasswdSpec{Username: "bob", NewPassword: "N3wPassw0rd"}
	res := h.change(h.jobs(vendor.Cisco, PasswdCapability(spec), "sw1"), Passwd(spec))
	if res[0].Status != StatusSucceeded {
		t.Fatalf("result = %+v", res[0])
	}
	d := devs[0]
	if d.users["bob"].hash != hashPW("N3wPassw0rd") || d.saved.users["bob"].hash != hashPW("N3wPassw0rd") || d.writes != 1 {
		t.Errorf("rotation not applied and saved: live=%v saved=%v writes=%d", d.users["bob"], d.saved.users["bob"], d.writes)
	}
	// the new credentials were really tried, over a fresh session
	var tried bool
	for _, c := range h.tr.opensFor("sw1", "bob") {
		tried = tried || c.Password == "N3wPassw0rd"
	}
	if !tried {
		t.Errorf("no login with the new credentials was attempted; opens: %+v", h.tr.opens)
	}
	// ordering: the login test sits between applying and saving
	cmds := h.tr.commands("sw1")
	applyAt, saveAt := -1, -1
	for i, c := range cmds {
		if strings.HasPrefix(c, "username bob secret 0 ") {
			applyAt = i
		}
		if c == "write memory" {
			saveAt = i
		}
	}
	if applyAt < 0 || saveAt < applyAt {
		t.Errorf("unexpected command order: %q", cmds)
	}
	if res[0].VerifyTotal != 1 || res[0].VerifyPassed != 1 {
		t.Errorf("verify counters = %d/%d", res[0].VerifyPassed, res[0].VerifyTotal)
	}
	mustNotContain(t, h.logs.String(), "N3wPassw0rd", "the log")
	mustNotContain(t, res[0].Detail, "N3wPassw0rd", "the result detail")
}

func TestPasswdRollsBackWhenNewCredentialsAreRejected(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1")
	d := devs[0]
	d.rejectPw["bob"] = "N3wPassw0rd" // the device accepts the config line but the login does not work
	before := d.users["bob"]
	spec := PasswdSpec{Username: "bob", NewPassword: "N3wPassw0rd"}
	res := h.change(h.jobs(vendor.Cisco, PasswdCapability(spec), "sw1"), Passwd(spec))

	r := res[0]
	if r.Status != StatusFailed || r.Category != CatVerifyFailed || r.Rollback != RollbackOK {
		t.Fatalf("result = %+v", r)
	}
	if d.users["bob"] != before {
		t.Errorf("previous credential not restored: %+v, want %+v", d.users["bob"], before)
	}
	if d.writes != 0 || d.saved.users["bob"] != before {
		t.Errorf("the failed rotation was saved (writes=%d)", d.writes)
	}
	if !strings.Contains(r.Detail, "was rejected") {
		t.Errorf("detail = %q", r.Detail)
	}
	// the account still logs in with its OLD password
	if err := d.auth(credentials.Credential{Username: "bob", Password: "oldpass"}); err != nil {
		t.Errorf("old password no longer works after rollback: %v", err)
	}
	mustNotContain(t, h.logs.String(), "N3wPassw0rd", "the log")
}

func TestPasswdOfTheLoginAccount(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1")
	spec := PasswdSpec{Username: "svc", NewPassword: "Fr3shSvcPass"}
	jobs := h.jobs(vendor.Cisco, PasswdCapability(spec), "sw1")
	res := h.change(jobs, Passwd(spec))
	if res[0].Status != StatusSucceeded || devs[0].users["svc"].hash != hashPW("Fr3shSvcPass") || devs[0].writes != 1 {
		t.Fatalf("result = %+v users=%v", res[0], devs[0].users["svc"])
	}
	// rejected: restored, and the run's own credentials still work afterwards
	h2, devs2 := newHarness(t, Options{}, "sw1")
	devs2[0].rejectPw["svc"] = "Fr3shSvcPass"
	res = h2.change(h2.jobs(vendor.Cisco, PasswdCapability(spec), "sw1"), Passwd(spec))
	if res[0].Category != CatVerifyFailed || res[0].Rollback != RollbackOK || devs2[0].writes != 0 {
		t.Fatalf("result = %+v", res[0])
	}
	if err := devs2[0].auth(credentials.Credential{Username: "svc", Password: "pw-for-tests"}); err != nil {
		t.Errorf("login account locked out after a failed rotation: %v", err)
	}
}

func TestPasswdEnableSecret(t *testing.T) {
	spec := PasswdSpec{NewPassword: "N3wEnable", Enable: true}
	h, devs := newHarness(t, Options{}, "sw1")
	devs[0].requireEnab = true
	devs[0].users["svc"] = viosUser{15, hashPW("pw-for-tests")}
	jobs := h.jobs(vendor.Cisco, PasswdCapability(spec), "sw1")
	jobs[0].Cred.EnablePassword = "enable-old"
	devs[0].enable = hashPW("enable-old")
	devs[0].origEnable = devs[0].enable
	res := h.change(jobs, Passwd(spec))
	if res[0].Status != StatusSucceeded || devs[0].enable != hashPW("N3wEnable") || devs[0].saved.enable != hashPW("N3wEnable") {
		t.Fatalf("enable rotation failed: %+v enable=%s saved=%s", res[0], devs[0].enable, devs[0].saved.enable)
	}

	// a device that refuses the new enable secret at login is rolled back
	h2, devs2 := newHarness(t, Options{}, "sw1")
	devs2[0].requireEnab, devs2[0].rejectEnab = true, true
	jobs = h2.jobs(vendor.Cisco, PasswdCapability(spec), "sw1")
	jobs[0].Cred.EnablePassword = "enable-old"
	orig := devs2[0].enable
	res = h2.change(jobs, Passwd(spec))
	if res[0].Category != CatVerifyFailed || res[0].Rollback != RollbackOK || devs2[0].enable != orig || devs2[0].writes != 0 {
		t.Fatalf("result = %+v enable=%s (want %s) writes=%d", res[0], devs2[0].enable, orig, devs2[0].writes)
	}
}

func TestPasswdUnknownUser(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1")
	spec := PasswdSpec{Username: "ghost", NewPassword: "N3wPassw0rd"}
	res := h.change(h.jobs(vendor.Cisco, PasswdCapability(spec), "sw1"), Passwd(spec))
	if res[0].Status != StatusFailed || res[0].Category != CatPrecondition || devs[0].cfgSessions != 0 {
		t.Fatalf("result = %+v cfg=%d", res[0], devs[0].cfgSessions)
	}
}

func TestPasswdCapabilityMatrix(t *testing.T) {
	spec := PasswdSpec{Username: "bob", NewPassword: "N3wPassw0rd"}
	want := map[string]bool{
		vendor.Cisco: true, vendor.CiscoSB: true, vendor.CiscoASA: true, vendor.Ruijie: true, vendor.Aruba: true,
		vendor.Huawei: true, vendor.Fortinet: true, // immediate, with a snapshot to restore
		vendor.Junos: true, vendor.Arista: true, vendor.VyOS: true, // commit-confirm
		vendor.CheckPoint: false, vendor.PaloAlto: false, vendor.PfSense: false, vendor.Sophos: false,
	}
	for name, ok := range want {
		p, _ := vendor.Lookup(name)
		got, reason := PasswdCapability(spec)(p)
		if got != ok {
			t.Errorf("%s: capable=%t (%s), want %t", name, got, reason, ok)
		}
	}
	// enable secrets: only where they exist and can be restored or confirmed
	enable := PasswdSpec{NewPassword: "N3wEnable", Enable: true}
	for name, ok := range map[string]bool{
		vendor.Cisco: true, vendor.CiscoASA: true, vendor.Arista: true, vendor.Ruijie: true, vendor.CiscoSB: true,
		vendor.Junos: false, vendor.Huawei: false, vendor.Fortinet: false, vendor.Aruba: false, vendor.VyOS: false,
	} {
		p, _ := vendor.Lookup(name)
		if got, reason := PasswdCapability(enable)(p); got != ok {
			t.Errorf("enable on %s: capable=%t (%s), want %t", name, got, reason, ok)
		}
	}
}

func TestPasswdJunosUsesCommitConfirm(t *testing.T) {
	h, _ := newHarness(t, Options{}, "jn1")
	delete(h.tr.devs, "jn1") // scripted device, not the IOS emulator
	h.tr.script = func(_, line string) string {
		if strings.HasPrefix(line, "show configuration system login") {
			return "set system login user bob class super-user\nset system login user bob authentication encrypted-password \"$6$old$hash\"\n"
		}
		return ""
	}
	spec := PasswdSpec{Username: "bob", NewPassword: "N3wPassw0rd"}
	res := h.change(h.jobs(vendor.Junos, PasswdCapability(spec), "jn1"), Passwd(spec))
	if res[0].Status != StatusSucceeded {
		t.Fatalf("result = %+v", res[0])
	}
	cmds := strings.Join(h.tr.commands("jn1"), "\n")
	for _, want := range []string{"commit confirmed 5", "set system login user bob authentication encrypted-password \"$6$"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("command stream lacks %q:\n%s", want, cmds)
		}
	}
	mustNotContain(t, cmds, "N3wPassw0rd", "the Junos command stream (the hash, not the password, goes on the wire)")
	if strings.Index(cmds, "commit confirmed 5") > strings.LastIndex(cmds, "\ncommit\n") && !strings.Contains(cmds, "\ncommit") {
		t.Error("the change was never confirmed")
	}
	if got := h.tr.opensFor("jn1", "bob"); len(got) == 0 || got[len(got)-1].Password != "N3wPassw0rd" {
		t.Errorf("the new credentials were not tested while the timer was armed: %+v", got)
	}
	mustNotContain(t, h.logs.String(), "N3wPassw0rd", "the log")
}

// ---- vlan add / vlan del ----------------------------------------------------

func TestVLANAddIdempotent(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1", "sw2")
	devs[1].vlans[30] = "Other"
	spec := VLANSpec{ID: 30, Name: "Servers"}
	jobs := h.jobs(vendor.Cisco, VLANCapability, "sw1", "sw2")

	res := h.change(jobs, VLANAdd(spec))
	if ExitCode(res) != ExitOK {
		t.Fatalf("results %+v", res)
	}
	if devs[0].vlans[30] != "Servers" || devs[0].saved.vlans[30] != "Servers" {
		t.Errorf("sw1 VLANs: live=%v saved=%v", devs[0].vlans, devs[0].saved.vlans)
	}
	if devs[1].vlans[30] != "Other" || devs[1].cfgSessions != 0 {
		t.Errorf("an existing VLAN was renamed or the device touched: %v cfg=%d", devs[1].vlans, devs[1].cfgSessions)
	}
	if !strings.Contains(res[1].Detail, "already exists") || !strings.Contains(res[1].Detail, "not applied") {
		t.Errorf("sw2 detail = %q", res[1].Detail)
	}
	res = h.change(jobs, VLANAdd(spec))
	if ExitCode(res) != ExitOK || devs[0].cfgSessions != 1 {
		t.Errorf("second add was not a no-op: %+v cfg=%d", res, devs[0].cfgSessions)
	}
}

func TestVLANDelIdempotentAndDefaultProtected(t *testing.T) {
	h, devs := newHarness(t, Options{}, "sw1", "sw2")
	devs[0].vlans[30] = "Servers"
	jobs := h.jobs(vendor.Cisco, VLANCapability, "sw1", "sw2")

	res := h.change(jobs, VLANDel(30))
	if ExitCode(res) != ExitOK {
		t.Fatalf("results %+v", res)
	}
	if _, ok := devs[0].vlans[30]; ok || devs[0].writes != 1 {
		t.Errorf("sw1 VLAN 30 still present or unsaved: %v writes=%d", devs[0].vlans, devs[0].writes)
	}
	if devs[1].cfgSessions != 0 || !strings.Contains(res[1].Detail, "does not exist") {
		t.Errorf("sw2 should be skipped: %q", res[1].Detail)
	}
	// VLAN 1 is never deleted, whatever the device says
	res = h.change(jobs, VLANDel(1))
	for i, r := range res {
		if r.Status != StatusFailed || r.Category != CatPrecondition {
			t.Errorf("sw%d VLAN 1 delete result = %+v", i+1, r)
		}
		if _, ok := devs[i].vlans[1]; !ok {
			t.Errorf("sw%d lost VLAN 1", i+1)
		}
	}
}

func TestVLANJunosDeletesByDiscoveredName(t *testing.T) {
	h, _ := newHarness(t, Options{}, "jn1")
	delete(h.tr.devs, "jn1")
	h.tr.script = func(_, line string) string {
		if strings.HasPrefix(line, "show configuration vlans") {
			return "set vlans Servers vlan-id 30\n"
		}
		return ""
	}
	res := h.change(h.jobs(vendor.Junos, VLANCapability, "jn1"), VLANDel(30))
	if res[0].Status != StatusSucceeded {
		t.Fatalf("result = %+v", res[0])
	}
	if cmds := h.tr.commands("jn1"); !contains(cmds, "delete vlans Servers") {
		t.Errorf("Junos must delete by the name it read from the device: %q", cmds)
	}
}

func TestVLANUnsupportedPlatformsAreSkippedNotFailed(t *testing.T) {
	devs := []inventory.Device{
		{Hostname: "fw1", Address: "10.0.0.1", Vendor: "fortinet"},
		{Hostname: "sw1", Address: "10.0.0.2", Vendor: "cisco"},
	}
	jobs := BuildCapabilityJobs(devs, "vlan add", VLANCapability)
	if jobs[0].Skip != CatUnsupportedOp || jobs[1].Skip != "" {
		t.Errorf("skips = %q / %q", jobs[0].Skip, jobs[1].Skip)
	}
}

// ---- change engine ----------------------------------------------------------

func TestMergeResultsKeepsCheckOutcomeForUnappliedDevices(t *testing.T) {
	checked := []Result{{Status: StatusSucceeded, Detail: "skipped: a"}, {Status: StatusSucceeded, Detail: "to apply"}, {Status: StatusFailed, Detail: "boom"}}
	applied := []Result{{Status: StatusSucceeded, Detail: "applied"}}
	got := MergeResults(checked, []int{1}, applied)
	if got[0].Detail != "skipped: a" || got[1].Detail != "applied" || got[2].Detail != "boom" {
		t.Errorf("merged = %+v", got)
	}
}

func TestDecideDoesNotApplyCanaryOrBatching(t *testing.T) {
	h, _ := newHarness(t, Options{Canary: 1, BatchSize: 1}, "sw1", "sw2", "sw3")
	spec := UserSpec{Username: "alice", Password: "S3cretPass", Privilege: 15}
	jobs := h.jobs(vendor.Cisco, UserAddCapability(spec), "sw1", "sw2", "sw3")
	decisions, checked := h.r.Decide(context.Background(), jobs, UserAdd(spec))
	var names []string
	for k := range decisions {
		names = append(names, strings.SplitN(k, "\x00", 2)[0])
	}
	sort.Strings(names)
	if len(names) != 3 {
		t.Fatalf("the read-only pass must visit every device, decided %v (%+v)", names, checked)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

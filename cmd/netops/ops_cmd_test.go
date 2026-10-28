// ==============================================================================
// File name:     ops_cmd_test.go
// Description:   End-to-end tests of the user / passwd / vlan / facts / find /
//
//	audit / diff subcommands through dispatch(), without a network.
//
// License:       MIT
// ==============================================================================
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/internal/audit"
	"netops/internal/sshclient"
	"netops/internal/task"
)

const (
	opsLoginUser = "admin"
	opsLoginPass = "s3cr3t-pw"
)

func opsHash(pw string) string {
	s := sha256.Sum256([]byte(pw))
	return "$9$" + hex.EncodeToString(s[:6])
}

// opsDev is a tiny IOS-like device with real state for users and VLANs, plus
// scripted answers for read-only commands.
type opsDev struct {
	mu      sync.Mutex
	users   map[string]string // name -> password hash
	vlans   map[int]string
	answers map[string]string
	writes  int
	cfg     int
	cmds    []string
	events  []string          // ordered log of logins and commands (SSH-level tests)
	reject  map[string]string // user -> a password the device refuses at login
}

func newOpsDev() *opsDev {
	return &opsDev{
		users:   map[string]string{opsLoginUser: opsHash(opsLoginPass), "bob": opsHash("oldpass")},
		vlans:   map[int]string{1: "default"},
		answers: map[string]string{},
		reject:  map[string]string{},
	}
}

type opsTr struct {
	mu    sync.Mutex
	devs  map[string]*opsDev
	opens map[string]int
}

func (t *opsTr) Open(_ context.Context, tgt task.Target) (task.Session, error) {
	h := tgt.Device.Hostname
	t.mu.Lock()
	t.opens[h]++
	d := t.devs[h]
	t.mu.Unlock()
	if d == nil {
		return nil, &cliKindErr{"connect", "dial tcp: no such host"}
	}
	d.mu.Lock()
	hash, ok := d.users[tgt.Cred.Username]
	d.mu.Unlock()
	if !ok || hash != opsHash(tgt.Cred.Password) {
		return nil, &cliKindErr{"auth", "ssh: unable to authenticate"}
	}
	return &opsSess{d: d}, nil
}

type opsSess struct {
	d      *opsDev
	inCfg  bool
	curVID int
}

var (
	rxNewUser = regexp.MustCompile(`^username (\S+) privilege (\d+) secret 0 (\S+)$`)
	rxPwUser  = regexp.MustCompile(`^username (\S+) secret 0 (\S+)$`)
	rxHashUsr = regexp.MustCompile(`^username (\S+) privilege (\d+) secret 9 (\S+)$`)
	rxDelUser = regexp.MustCompile(`^no username (\S+)$`)
	rxShowUsr = regexp.MustCompile(`^show running-config \| include \^username (\S+) $`)
	rxShowVl  = regexp.MustCompile(`^show vlan id (\d+)$`)
	rxVlan    = regexp.MustCompile(`^vlan (\d+)$`)
	rxVName   = regexp.MustCompile(`^name (\S+)$`)
	rxNoVlan  = regexp.MustCompile(`^no vlan (\d+)$`)
)

func (s *opsSess) Send(_ context.Context, line string, _ time.Duration) (string, error) {
	d := s.d
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cmds = append(d.cmds, line)
	d.events = append(d.events, "cmd:"+line)
	if out, ok := d.answers[line]; ok {
		return out, nil
	}
	switch {
	case line == "configure terminal":
		s.inCfg = true
		d.cfg++
	case line == "end":
		s.inCfg = false
	case line == "write memory":
		d.writes++
	case line == "show clock":
		return "10:00:00\n", nil
	case rxShowUsr.MatchString(line):
		n := rxShowUsr.FindStringSubmatch(line)[1]
		if h, ok := d.users[n]; ok {
			return fmt.Sprintf("username %s privilege 15 secret 9 %s\n", n, h), nil
		}
	case rxShowVl.MatchString(line):
		id, _ := strconv.Atoi(rxShowVl.FindStringSubmatch(line)[1])
		if n, ok := d.vlans[id]; ok {
			return fmt.Sprintf("VLAN Name   Status    Ports\n---- ------ --------- -----\n%-4d %-6s active    Gi1/0/1\n", id, n), nil
		}
		return fmt.Sprintf("VLAN id %d not found in current VLAN database\n", id), nil
	case !s.inCfg:
		return "% Invalid input detected at '^' marker.\n", nil
	case rxNewUser.MatchString(line):
		m := rxNewUser.FindStringSubmatch(line)
		d.users[m[1]] = opsHash(m[3])
	case rxHashUsr.MatchString(line):
		m := rxHashUsr.FindStringSubmatch(line)
		d.users[m[1]] = m[3]
	case rxPwUser.MatchString(line):
		m := rxPwUser.FindStringSubmatch(line)
		d.users[m[1]] = opsHash(m[2])
	case rxDelUser.MatchString(line):
		delete(d.users, rxDelUser.FindStringSubmatch(line)[1])
	case rxVlan.MatchString(line):
		id, _ := strconv.Atoi(rxVlan.FindStringSubmatch(line)[1])
		if _, ok := d.vlans[id]; !ok {
			d.vlans[id] = fmt.Sprintf("VLAN%04d", id)
		}
		s.curVID = id
	case rxVName.MatchString(line) && s.curVID != 0:
		d.vlans[s.curVID] = rxVName.FindStringSubmatch(line)[1]
	case rxNoVlan.MatchString(line):
		id, _ := strconv.Atoi(rxNoVlan.FindStringSubmatch(line)[1])
		delete(d.vlans, id)
	default:
		return "% Invalid input detected at '^' marker.\n", nil
	}
	return "", nil
}

func (s *opsSess) Close() error { return nil }

// opsWS is a self-contained working directory plus the fake network.
type opsWS struct {
	t    *testing.T
	dir  string
	tr   *opsTr
	base []string
}

func newOpsWS(t *testing.T, inventory string, hosts ...string) *opsWS {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inv := write("inventory.csv", inventory)
	env := write(".env", "NETOPS_USERNAME="+opsLoginUser+"\nNETOPS_PASSWORD="+opsLoginPass+"\n")
	tr := &opsTr{devs: map[string]*opsDev{}, opens: map[string]int{}}
	for _, h := range hosts {
		tr.devs[h] = newOpsDev()
	}
	orig := newOpsTransport
	newOpsTransport = func(sshclient.HostKeyCallback, bool, *jumpPool, []task.Target, int) task.Transport { return tr }
	t.Cleanup(func() { newOpsTransport = orig })
	for _, k := range []string{"NETOPS_NEW_PASSWORD", "NETOPS_USERNAME", "NETOPS_PASSWORD"} {
		t.Setenv(k, "")
	}
	return &opsWS{t: t, dir: dir, tr: tr, base: []string{
		"-inventory", inv, "-env-file", env,
		"-log-dir", filepath.Join(dir, "logs"), "-backup-dir", filepath.Join(dir, "backups"),
		"-known-hosts", filepath.Join(dir, "known_hosts"), "-memory=false", "-jump=false", "-no-color",
	}}
}

func (w *opsWS) run(args ...string) (code int, stdout, stderr string) {
	w.t.Helper()
	in, err := os.Open(os.DevNull)
	if err != nil {
		w.t.Fatal(err)
	}
	defer in.Close()
	var out, errb bytes.Buffer
	// subcommand and action first, then shared flags, then the command's own flags
	n := 0
	for n < len(args) && !strings.HasPrefix(args[n], "-") {
		n++
	}
	base := w.base
	if n > 0 && (args[0] == "facts" || args[0] == "find" || args[0] == "audit" || args[0] == "exec") {
		var filtered []string
		for i := 0; i < len(base); i++ {
			if base[i] == "-backup-dir" {
				i++
				continue
			}
			filtered = append(filtered, base[i])
		}
		base = filtered
	}
	full := append(append(append([]string{}, args[:n]...), base...), args[n:]...)
	code = dispatch(full, in, &out, &errb)
	return code, out.String(), errb.String()
}

func (w *opsWS) dev(h string) *opsDev { return w.tr.devs[h] }

func (w *opsWS) totalOpens() int {
	n := 0
	for _, c := range w.tr.opens {
		n += c
	}
	return n
}

func (w *opsWS) logText() string {
	var b strings.Builder
	files, _ := filepath.Glob(filepath.Join(w.dir, "logs", "*"))
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil {
			b.Write(data)
		}
	}
	return b.String()
}

const oneSwitch = "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\n"

const twoSwitches = "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\nsw2,10.0.0.2,22,cisco,\n"

func mustContain(t *testing.T, what, text string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(text, s) {
			t.Errorf("%s lacks %q:\n%s", what, s, text)
		}
	}
}

func mustNotHave(t *testing.T, what, text string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(text, s) {
			t.Errorf("%s contains %q", what, s)
		}
	}
}

// ---- user -------------------------------------------------------------------

func TestUserAddEndToEnd(t *testing.T) {
	w := newOpsWS(t, twoSwitches, "sw1", "sw2")
	w.dev("sw2").users["alice"] = opsHash("kept")
	t.Setenv("NETOPS_NEW_PASSWORD", "S3cretPass")

	code, _, stderr := w.run("config", "user", "add", "-u", "alice", "-yes")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if w.dev("sw1").users["alice"] != opsHash("S3cretPass") || w.dev("sw1").writes != 1 {
		t.Errorf("sw1: %+v writes=%d", w.dev("sw1").users, w.dev("sw1").writes)
	}
	if w.dev("sw2").users["alice"] != opsHash("kept") || w.dev("sw2").cfg != 0 {
		t.Error("sw2 already had the user and must be untouched")
	}
	mustContain(t, "stderr", stderr, "[SKIPPED]", "already exists")
	mustNotHave(t, "stderr", stderr, "S3cretPass")
	mustNotHave(t, "audit log", w.logText(), "S3cretPass")

	// idempotent: the second run changes nothing
	writes := w.dev("sw1").writes
	if code, _, stderr := w.run("config", "user", "add", "-u", "alice", "-yes"); code != task.ExitOK || w.dev("sw1").writes != writes {
		t.Errorf("second run: exit %d writes %d\n%s", code, w.dev("sw1").writes, stderr)
	}
}

func TestUserAddPasswordFromEnvironment(t *testing.T) {
	w := newOpsWS(t, twoSwitches, "sw1", "sw2")
	t.Setenv("NETOPS_NEW_PASSWORD", "EnvPassw0rd")
	code, _, stderr := w.run("config", "user", "add", "-u", "carol", "-yes")
	if code != task.ExitOK || w.dev("sw1").users["carol"] != opsHash("EnvPassw0rd") {
		t.Fatalf("exit %d users=%v\n%s", code, w.dev("sw1").users, stderr)
	}
	mustNotHave(t, "stderr", stderr, "EnvPassw0rd")
	mustNotHave(t, "audit log", w.logText(), "EnvPassw0rd")
}

func TestUserAddNeedsAPasswordSource(t *testing.T) {
	w := newOpsWS(t, oneSwitch, "sw1")
	code, _, stderr := w.run("config", "user", "add", "-u", "alice", "-yes")
	if code != task.ExitFatal || w.totalOpens() != 0 {
		t.Fatalf("exit %d opens %d", code, w.totalOpens())
	}
	mustContain(t, "stderr", stderr, "no new password")
}

func TestUserInputValidationHappensBeforeAnyConnection(t *testing.T) {
	w := newOpsWS(t, oneSwitch, "sw1")
	t.Setenv("NETOPS_NEW_PASSWORD", "S3cretPass")
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"config", "user", "add", "-u", "bad name", "-yes"}, "invalid username"},
		{[]string{"config", "user", "add", "-u", "bob;reload", "-yes"}, "invalid username"},
		{[]string{"config", "user", "add", "-u", "alice", "--privilege", "16", "-yes"}, "out of range"},
		{[]string{"config", "user", "add", "-yes"}, "invalid username"},
		{[]string{"config", "user", "add", "-u", "alice", "-p", "S3cretPass", "-yes"}, "passwords are never accepted as command-line flags"},
		{[]string{"config", "user", "frobnicate"}, "unknown action"},
		{[]string{"config", "user"}, "netops config user:"},
	} {
		code, _, stderr := w.run(tt.args...)
		if code != task.ExitFatal {
			t.Errorf("%v: exit %d", tt.args, code)
		}
		mustContain(t, fmt.Sprint(tt.args), stderr, tt.want)
	}
	for _, badPw := range []struct {
		pw   string
		want string
	}{
		{"has?question", "cannot be sent safely"},
		{"has space", "printable ASCII"},
	} {
		t.Setenv("NETOPS_NEW_PASSWORD", badPw.pw)
		code, _, stderr := w.run("config", "user", "add", "-u", "alice", "-yes")
		if code != task.ExitFatal {
			t.Errorf("%v: exit %d", badPw.pw, code)
		}
		mustContain(t, badPw.pw, stderr, badPw.want)
	}
	if w.totalOpens() != 0 {
		t.Errorf("%d connection(s) were opened for invalid input", w.totalOpens())
	}
}

func TestUserDelRefusesTheLoginAccountBeforeConnecting(t *testing.T) {
	w := newOpsWS(t, twoSwitches, "sw1", "sw2")
	// the account named in .env, whatever its case, and even with -force
	for _, name := range []string{opsLoginUser, "ADMIN"} {
		code, _, stderr := w.run("config", "user", "del", "-u", name, "-yes", "-force")
		if code != task.ExitFatal {
			t.Errorf("%s: exit %d", name, code)
		}
		mustContain(t, name, stderr, "refusing to delete", "Nothing was contacted")
	}
	if w.totalOpens() != 0 {
		t.Errorf("%d connection(s) opened: the guard must fire before connecting", w.totalOpens())
	}
	if _, ok := w.dev("sw1").users[opsLoginUser]; !ok {
		t.Error("the login account was deleted")
	}
	// NETOPS_USERNAME from the environment counts too, even when .env names someone else
	t.Setenv("NETOPS_USERNAME", "bob")
	if code, _, stderr := w.run("config", "user", "del", "-u", "bob", "-yes"); code != task.ExitFatal || w.totalOpens() != 0 {
		t.Errorf("NETOPS_USERNAME guard: exit %d opens %d\n%s", code, w.totalOpens(), stderr)
	}
}

func TestUserDelEndToEnd(t *testing.T) {
	w := newOpsWS(t, twoSwitches, "sw1", "sw2")
	delete(w.dev("sw2").users, "bob")
	code, _, stderr := w.run("config", "user", "del", "-u", "bob", "-yes")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if _, ok := w.dev("sw1").users["bob"]; ok || w.dev("sw1").writes != 1 {
		t.Errorf("sw1 still has bob: %v", w.dev("sw1").users)
	}
	if w.dev("sw2").cfg != 0 {
		t.Error("sw2 had no such user and must not be touched")
	}
	mustContain(t, "stderr", stderr, "[SKIPPED]", "does not exist")
}

func TestChangesNeedConfirmationWhenUnattended(t *testing.T) {
	w := newOpsWS(t, oneSwitch, "sw1")
	t.Setenv("NETOPS_NEW_PASSWORD", "S3cretPass")
	code, _, stderr := w.run("config", "user", "add", "-u", "alice")
	if code != task.ExitFatal {
		t.Fatalf("exit %d", code)
	}
	mustContain(t, "stderr", stderr, "nobody to confirm", "-yes")
	if _, ok := w.dev("sw1").users["alice"]; ok || w.dev("sw1").cfg != 0 {
		t.Error("a device was changed without confirmation")
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	w := newOpsWS(t, oneSwitch, "sw1")
	t.Setenv("NETOPS_NEW_PASSWORD", "S3cretPass")
	code, _, stderr := w.run("config", "user", "add", "-u", "alice", "-dry-run")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if _, ok := w.dev("sw1").users["alice"]; ok || w.dev("sw1").writes != 0 {
		t.Errorf("dry-run changed the device: %v writes=%d", w.dev("sw1").users, w.dev("sw1").writes)
	}
}

func TestUnsupportedPlatformsAreSkippedAndExitPartial(t *testing.T) {
	w := newOpsWS(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\nfw1,10.0.0.9,22,paloalto,\n", "sw1")
	t.Setenv("NETOPS_NEW_PASSWORD", "S3cretPass")
	code, _, stderr := w.run("config", "user", "add", "-u", "alice", "-yes")
	if code != task.ExitPartial {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stderr", stderr, "UNSUPPORTED_OPERATION", "Palo Alto")
	if w.tr.opens["fw1"] != 0 {
		t.Error("an unsupported device must not be contacted")
	}
	if w.dev("sw1").users["alice"] != opsHash("S3cretPass") {
		t.Error("the supported switch must still be handled")
	}
}

// ---- passwd -----------------------------------------------------------------

func TestPasswdEndToEnd(t *testing.T) {
	w := newOpsWS(t, twoSwitches, "sw1", "sw2")
	t.Setenv("NETOPS_NEW_PASSWORD", "N3wPassw0rd")
	code, _, stderr := w.run("config", "passwd", "-u", "bob", "-yes")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	for _, h := range []string{"sw1", "sw2"} {
		if w.dev(h).users["bob"] != opsHash("N3wPassw0rd") || w.dev(h).writes != 1 {
			t.Errorf("%s: %v writes=%d", h, w.dev(h).users["bob"], w.dev(h).writes)
		}
	}
	mustNotHave(t, "stderr", stderr, "N3wPassw0rd")
	mustNotHave(t, "audit log", w.logText(), "N3wPassw0rd")
}

func TestPasswdOfTheLoginAccountWarns(t *testing.T) {
	w := newOpsWS(t, oneSwitch, "sw1")
	t.Setenv("NETOPS_NEW_PASSWORD", "N3wPassw0rd")
	code, _, stderr := w.run("config", "passwd", "-u", opsLoginUser, "-yes")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stderr", stderr, "update NETOPS_PASSWORD")
}

func TestPasswdAutoGenerateWritesAPrivateFileAndNeverPrintsIt(t *testing.T) {
	w := newOpsWS(t, oneSwitch, "sw1")
	pwFile := filepath.Join(w.dir, "new-password.txt")
	code, stdout, stderr := w.run("config", "passwd", "-u", "bob", "--auto-generate", "--password-file", pwFile, "-yes")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	data, err := os.ReadFile(pwFile)
	if err != nil {
		t.Fatal(err)
	}
	pw := strings.TrimSpace(string(data))
	if len(pw) != 20 {
		t.Fatalf("generated password %q", pw)
	}
	if info, _ := os.Stat(pwFile); info.Mode().Perm() != 0o600 {
		t.Errorf("password file mode = %v, want 0600", info.Mode().Perm())
	}
	if w.dev("sw1").users["bob"] != opsHash(pw) {
		t.Error("the device does not have the generated password")
	}
	mustNotHave(t, "stdout", stdout, pw)
	mustNotHave(t, "stderr", stderr, pw)
	mustNotHave(t, "audit log", w.logText(), pw)

	// an existing file is never overwritten
	before := w.dev("sw1").users["bob"]
	code, _, stderr = w.run("config", "passwd", "-u", "bob", "--auto-generate", "--password-file", pwFile, "-yes")
	if code != task.ExitFatal || w.dev("sw1").users["bob"] != before {
		t.Errorf("reusing the file: exit %d", code)
	}
	mustContain(t, "stderr", stderr, "--password-file")
}

func TestPasswdFlagValidation(t *testing.T) {
	w := newOpsWS(t, oneSwitch, "sw1")
	t.Setenv("NETOPS_NEW_PASSWORD", "S3cretPass")
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"config", "passwd", "-yes"}, "-u <name> (or --enable) is required"},
		{[]string{"config", "passwd", "-u", "bob", "--enable"}, "either -u or --enable"},
		{[]string{"config", "passwd", "-u", "bob", "--auto-generate"}, "needs --password-file"},
		{[]string{"config", "passwd", "-u", "bob", "--password-file", "f"}, "only used with --auto-generate"},
		{[]string{"config", "passwd", "-u", "bob", "--commit-confirm", "0"}, "between 1 and 60"},
		{[]string{"config", "passwd", "-u", "bob", "-p", "S3cretPass"}, "passwords are never accepted as command-line flags"},
	} {
		code, _, stderr := w.run(tt.args...)
		if code != task.ExitFatal {
			t.Errorf("%v: exit %d", tt.args, code)
		}
		mustContain(t, fmt.Sprint(tt.args), stderr, tt.want)
	}
	t.Setenv("NETOPS_NEW_PASSWORD", "bad pass")
	code, _, stderr := w.run("config", "passwd", "-u", "bob", "-yes")
	if code != task.ExitFatal {
		t.Errorf("bad pass: exit %d", code)
	}
	mustContain(t, "bad pass", stderr, "printable ASCII")
	if w.totalOpens() != 0 {
		t.Errorf("%d connection(s) opened for invalid input", w.totalOpens())
	}
}

func TestPasswdDeviceWithoutRollbackIsSkipped(t *testing.T) {
	w := newOpsWS(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\ncp1,10.0.0.7,22,checkpoint,\n", "sw1")
	t.Setenv("NETOPS_NEW_PASSWORD", "N3wPassw0rd")
	code, _, stderr := w.run("config", "passwd", "-u", "bob", "-yes")
	if code != task.ExitPartial || w.tr.opens["cp1"] != 0 {
		t.Fatalf("exit %d opens(cp1)=%d\n%s", code, w.tr.opens["cp1"], stderr)
	}
	mustContain(t, "stderr", stderr, "UNSUPPORTED_OPERATION")
}

// ---- vlan -------------------------------------------------------------------

func TestVLANEndToEnd(t *testing.T) {
	w := newOpsWS(t, twoSwitches, "sw1", "sw2")
	w.dev("sw2").vlans[30] = "Other"
	code, _, stderr := w.run("config", "vlan", "add", "--id", "30", "--name", "Servers", "-yes")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if w.dev("sw1").vlans[30] != "Servers" || w.dev("sw1").writes != 1 {
		t.Errorf("sw1 VLANs %v", w.dev("sw1").vlans)
	}
	if w.dev("sw2").vlans[30] != "Other" || w.dev("sw2").cfg != 0 {
		t.Errorf("sw2 must be left alone: %v", w.dev("sw2").vlans)
	}
	mustContain(t, "stderr", stderr, "already exists", "not applied")

	if code, _, stderr = w.run("config", "vlan", "del", "--id", "30", "-yes"); code != task.ExitOK {
		t.Fatalf("del exit %d\n%s", code, stderr)
	}
	if _, ok := w.dev("sw1").vlans[30]; ok {
		t.Error("VLAN 30 still on sw1")
	}
}

func TestVLANValidation(t *testing.T) {
	w := newOpsWS(t, oneSwitch, "sw1")
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"config", "vlan", "add", "-yes"}, "--id is required"},
		{[]string{"config", "vlan", "add", "--id", "0", "-yes"}, "--id is required"},
		{[]string{"config", "vlan", "add", "--id", "4095", "-yes"}, "out of range"},
		{[]string{"config", "vlan", "add", "--id", "-5", "-yes"}, "out of range"},
		{[]string{"config", "vlan", "add", "--id", "30", "--name", "two words", "-yes"}, "invalid VLAN name"},
		{[]string{"config", "vlan", "del", "--id", "1", "-yes"}, "cannot be deleted"},
		{[]string{"config", "vlan", "purge"}, "unknown action"},
	} {
		code, _, stderr := w.run(tt.args...)
		if code != task.ExitFatal {
			t.Errorf("%v: exit %d", tt.args, code)
		}
		mustContain(t, fmt.Sprint(tt.args), stderr, tt.want)
	}
	if w.totalOpens() != 0 {
		t.Errorf("%d connection(s) opened for invalid input", w.totalOpens())
	}
}

// ---- facts ------------------------------------------------------------------

const factsInventory = "hostname,address,port,vendor,credential_group\nsw-b,10.0.0.2,22,cisco,\nsw-a,10.0.0.1,22,cisco,\nfw,10.0.0.9,22,sophos,\n"

func factsWS(t *testing.T) *opsWS {
	w := newOpsWS(t, factsInventory, "sw-a", "sw-b")
	for h, serial := range map[string]string{"sw-a": "FOC111", "sw-b": "FOC222"} {
		w.dev(h).answers["show version"] = "Cisco IOS Software, C2960X Software, Version 15.2(4)E10, RELEASE SOFTWARE\n" + h + " uptime is 1 week\nModel number : WS-C2960X-48\nSystem serial number : " + serial + "\n"
	}
	return w
}

func TestFactsTableAndCSV(t *testing.T) {
	w := factsWS(t)
	out := filepath.Join(w.dir, "facts.csv")
	code, stdout, stderr := w.run("facts", "--output", out)
	if code != task.ExitPartial { // "fw" is in the inventory but unreachable in this fake network
		t.Errorf("exit %d, want %d (one device could not be queried)", code, task.ExitPartial)
	}
	mustContain(t, "stderr", stderr, "CONNECT_FAILED")
	mustContain(t, "stdout", stdout, "| HOSTNAME", "| sw-a", "FOC111", "WS-C2960X-48", "15.2(4)E10")
	if strings.Index(stdout, "sw-a") > strings.Index(stdout, "sw-b") {
		t.Error("rows must be sorted by hostname")
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	defer f.Close()
	recs, err := csv.NewReader(f).ReadAll()
	if err != nil || len(recs) < 3 || strings.Join(recs[0], ",") != "hostname,ip,vendor,model,serial,version,uptime" {
		t.Fatalf("csv = %v err=%v", recs, err)
	}
	if recs[1][0] != "sw-a" || recs[1][4] != "FOC111" || recs[2][4] != "FOC222" {
		t.Errorf("csv rows = %v", recs)
	}
}

func TestFactsJSONToStdoutAndFile(t *testing.T) {
	w := factsWS(t)
	_, stdout, _ := w.run("facts", "--json")
	var rows []task.FactsRow
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if len(rows) != 2 || rows[0].Hostname != "sw-a" || rows[0].Serial != "FOC111" || rows[0].Vendor != "cisco" {
		t.Errorf("rows = %+v", rows)
	}
	mustNotHave(t, "JSON stdout", stdout, "| HOSTNAME")

	out := filepath.Join(w.dir, "facts.json")
	w.run("facts", "--output", out) // a .json name selects JSON
	data, err := os.ReadFile(out)
	if err != nil || json.Unmarshal(data, &rows) != nil || len(rows) != 2 {
		t.Errorf("json file: %v %s", err, data)
	}
}

// ---- find -------------------------------------------------------------------

func findWS(t *testing.T) *opsWS {
	w := newOpsWS(t, "hostname,address,port,vendor,credential_group\nsw-access,10.0.0.1,22,cisco,\nsw-dist,10.0.0.2,22,cisco,\nsw-gw,10.0.0.3,22,cisco,\n", "sw-access", "sw-dist", "sw-gw")
	table := func(port string) string {
		return "Vlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n  30    aabb.ccdd.eeff    DYNAMIC     " + port + "\nAll    ffff.ffff.ffff    STATIC      CPU\n"
	}
	cmd := "show mac address-table address aabb.ccdd.eeff"
	w.dev("sw-access").answers[cmd] = table("Gi1/0/14")
	w.dev("sw-dist").answers[cmd] = table("Gi1/0/48")
	w.dev("sw-dist").answers["show interfaces trunk"] = "Port        Mode             Encapsulation  Status        Native vlan\nGi1/0/48    on               802.1q         trunking      1\n"
	w.dev("sw-gw").answers["show ip arp 10.1.20.15"] = "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\nInternet  10.1.20.15              5   aabb.ccdd.eeff  ARPA   Vlan30\n"
	return w
}

func TestFindByMAC(t *testing.T) {
	w := findWS(t)
	_, stdout, stderr := w.run("find", "--mac", "AA-BB-CC-DD-EE-FF")
	mustContain(t, "stdout", stdout, "[FOUND] aa:bb:cc:dd:ee:ff (sw-access) -> Port Gi1/0/14 (VLAN 30)")
	mustNotHave(t, "stdout", stdout, "sw-dist", "CPU") // uplinks and CPU entries are hidden by default
	if t.Failed() {
		t.Log(stderr)
	}
	_, stdout, _ = w.run("find", "--mac", "aabb.ccdd.eeff", "--all")
	mustContain(t, "stdout --all", stdout, "[FOUND]", "[UPLINK] aa:bb:cc:dd:ee:ff (sw-dist) -> Port Gi1/0/48 (trunk, VLAN 30)")
}

func TestFindByIPResolvesViaARPFirst(t *testing.T) {
	w := findWS(t)
	_, stdout, stderr := w.run("find", "--ip", "10.1.20.15")
	mustContain(t, "stdout", stdout, "[FOUND] 10.1.20.15 (sw-access) -> Port Gi1/0/14 (VLAN 30)")
	mustContain(t, "stderr", stderr, "10.1.20.15 resolves to aa:bb:cc:dd:ee:ff")
}

func TestFindNotFoundAndInputErrors(t *testing.T) {
	w := findWS(t)
	code, stdout, _ := w.run("find", "--ip", "10.9.9.9")
	if code != task.ExitPartial {
		t.Errorf("not found: exit %d", code)
	}
	mustContain(t, "stdout", stdout, "[NOT FOUND]")

	code, stdout, _ = w.run("find", "--mac", "0011.2233.4455")
	if code != task.ExitPartial {
		t.Errorf("unknown MAC: exit %d", code)
	}
	mustContain(t, "stdout", stdout, "[NOT FOUND]")

	before := w.totalOpens()
	for _, tt := range [][]string{{"find"}, {"find", "--mac", "xyz"}, {"find", "--ip", "fe80::1"}, {"find", "--ip", "300.1.1.1"}} {
		if code, _, _ := w.run(tt...); code != task.ExitFatal {
			t.Errorf("%v: exit %d", tt, code)
		}
	}
	if w.totalOpens() != before {
		t.Error("invalid input must not open connections")
	}
}

// ---- audit ------------------------------------------------------------------

const cliCiscoGood = "hostname good\n!\nservice password-encryption\nip ssh version 2\nbanner motd ^Cauthorised^C\n!\nlogging host 10.0.0.9\nntp server 10.0.0.1\nsnmp-server community Str0ng RO\ntacacs-server host 10.0.0.5\nline vty 0 4\n exec-timeout 5 0\n transport input ssh\nend\n"
const cliCiscoBad = "hostname bad\n!\nsnmp-server community public RO\nline vty 0 4\n transport input all\nend\n"

func auditWS(t *testing.T) *opsWS {
	w := newOpsWS(t, "hostname,address,port,vendor,credential_group\ngood,10.0.0.1,22,cisco,\nbad,10.0.0.2,22,cisco,\n", "good", "bad")
	w.dev("good").answers["show running-config"] = cliCiscoGood
	w.dev("bad").answers["show running-config"] = cliCiscoBad
	return w
}

func TestAuditMatrixRemediationAndExitCode(t *testing.T) {
	w := auditWS(t)
	outDir := filepath.Join(w.dir, "audit_reports")
	code, stdout, stderr := w.run("audit", "--output-dir", outDir)
	if code != exitNonCompliant {
		t.Fatalf("exit %d, want %d\n%s", code, exitNonCompliant, stderr)
	}
	mustContain(t, "stdout", stdout, "| DEVICE", "SESSION-TIMEOUT", "| bad", "FAIL", "PASS", "Remediation:", "[HIGH] bad: Telnet disabled (SSH only)", "fix: On every vty line: transport input ssh")
	if strings.Contains(strings.SplitN(stdout, "Remediation:", 2)[1], "good:") {
		t.Error("the compliant device must not appear in the remediation list")
	}
	for _, ext := range []string{".csv", ".json", ".txt"} {
		m, _ := filepath.Glob(filepath.Join(outDir, "audit-*"+ext))
		if len(m) != 1 {
			t.Errorf("expected one %s report, got %v", ext, m)
		}
	}
	jm, _ := filepath.Glob(filepath.Join(outDir, "audit-*.json"))
	if len(jm) == 1 {
		var rep []struct {
			Hostname string `json:"hostname"`
			Checks   []struct {
				ID, Status string
			} `json:"checks"`
		}
		data, _ := os.ReadFile(jm[0])
		if err := json.Unmarshal(data, &rep); err != nil || len(rep) != 2 || len(rep[0].Checks) != 10 {
			t.Errorf("json report: %v %s", err, data)
		}
	}
}

func TestAuditCompliantExitsZero(t *testing.T) {
	w := auditWS(t)
	if code, _, stderr := w.run("audit", "-limit", "good"); code != task.ExitOK {
		t.Errorf("exit %d\n%s", code, stderr)
	}
}

func TestAuditIsReadOnly(t *testing.T) {
	w := auditWS(t)
	w.run("audit")
	for _, h := range []string{"good", "bad"} {
		for _, c := range w.dev(h).cmds {
			if c == "configure terminal" || c == "write memory" || strings.HasPrefix(c, "username") {
				t.Errorf("%s: audit sent %q", h, c)
			}
		}
	}
}

func TestAuditCustomRulesAndPrintDefaults(t *testing.T) {
	w := auditWS(t)
	rules := filepath.Join(w.dir, "rules.yaml")
	if err := os.WriteFile(rules, []byte("rules:\n  - id: banner\n    title: Login banner\n    severity: low\n    require: '^banner motd'\n    remediation: configure a banner\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := w.run("audit", "--rules", rules)
	if code != exitNonCompliant {
		t.Errorf("exit %d", code)
	}
	mustContain(t, "stdout", stdout, "banner", "fix: configure a banner")
	mustNotHave(t, "stdout", stdout, "SESSION-TIMEOUT")

	// --print-defaults needs no inventory or network and round-trips
	code, stdout, _ = dispatchOut(t, "audit", "--print-defaults")
	if code != task.ExitOK {
		t.Fatalf("print-defaults exit %d", code)
	}
	if rs, err := audit.ParseRules(strings.NewReader(stdout)); err != nil || len(rs) != len(audit.Defaults()) {
		t.Errorf("printed defaults do not parse back: %v (%d rules)", err, len(rs))
	}
}

func TestAuditBadRulesFileFailsBeforeConnecting(t *testing.T) {
	w := auditWS(t)
	bad := filepath.Join(w.dir, "bad.yaml")
	_ = os.WriteFile(bad, []byte("rules:\n  - id: x\n    require: '('\n"), 0o600)
	code, _, stderr := w.run("audit", "--rules", bad)
	if code != task.ExitFatal || w.totalOpens() != 0 {
		t.Errorf("exit %d opens %d", code, w.totalOpens())
	}
	mustContain(t, "stderr", stderr, "bad require pattern")
	if code, _, _ := w.run("audit", "--rules", filepath.Join(w.dir, "missing.yaml")); code != task.ExitFatal {
		t.Errorf("missing rules file: exit %d", code)
	}
}

// ---- diff -------------------------------------------------------------------

const cliIOSRunning = "Building configuration...\n\nhostname sw1\n!\ninterface GigabitEthernet1/0/14\n description old\n switchport access vlan 10\n!\nntp server 10.0.0.1\n!\nend\n"

func diffWS(t *testing.T) (*opsWS, string) {
	w := newOpsWS(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\nsw2,10.0.0.2,22,cisco,\nfw,10.0.0.9,22,paloalto,\n", "sw1", "sw2")
	w.dev("sw1").answers["show running-config"] = cliIOSRunning
	// sw2 already carries the change the command file asks for
	already := strings.Replace(cliIOSRunning, "ntp server 10.0.0.1", "ntp server 10.0.0.1\nntp server 10.0.0.2", 1)
	already = strings.Replace(already, "description old", "description new", 1)
	w.dev("sw2").answers["show running-config"] = already
	cmds := filepath.Join(w.dir, "commands.txt")
	if err := os.WriteFile(cmds, []byte("ntp server 10.0.0.2\ninterface GigabitEthernet1/0/14\ndescription new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return w, cmds
}

func TestDiffPreviewOnlyNeverChangesDevices(t *testing.T) {
	w, cmds := diffWS(t)
	code, stdout, stderr := w.run("diff", "-commands", cmds)
	if code != task.ExitPartial { // the Palo Alto box cannot be previewed and is reported
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stderr", stderr, "predicted change", "+ntp server 10.0.0.2", "-  description old", "+  description new", "predicted: no change")
	mustContain(t, "stderr", stderr, "UNSUPPORTED_OPERATION")
	mustContain(t, "stdout", stdout, "1 device(s) would change", "nothing was modified")
	for _, h := range []string{"sw1", "sw2"} {
		d := w.dev(h)
		if d.cfg != 0 || d.writes != 0 {
			t.Errorf("%s: a preview entered configuration mode (cfg=%d writes=%d)", h, d.cfg, d.writes)
		}
	}
	if w.tr.opens["fw"] != 0 {
		t.Error("the unsupported device must not be contacted")
	}
}

func TestDiffApplyConfirmsThenChangesOnlyDevicesWithADifference(t *testing.T) {
	w, cmds := diffWS(t)
	// the fake device does not know "description"; treat the lines as accepted
	for _, h := range []string{"sw1", "sw2"} {
		for _, c := range []string{"ntp server 10.0.0.2", "interface GigabitEthernet1/0/14", "description new"} {
			w.dev(h).answers[c] = ""
		}
	}
	// unattended without -yes: refused, nothing changed
	if code, _, stderr := w.run("diff", "-commands", cmds, "--apply"); code != task.ExitFatal {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if w.dev("sw1").writes != 0 {
		t.Error("changed without confirmation")
	}
	code, _, stderr := w.run("diff", "-commands", cmds, "--apply", "-yes")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if w.dev("sw1").writes != 1 {
		t.Errorf("sw1 should have been saved once, writes=%d", w.dev("sw1").writes)
	}
	if w.dev("sw2").cfg != 0 {
		t.Error("sw2 already matches: it must not be touched")
	}
}

func TestDiffRequiresCommands(t *testing.T) {
	w, _ := diffWS(t)
	code, _, stderr := w.run("diff")
	if code != task.ExitFatal {
		t.Errorf("exit %d", code)
	}
	mustContain(t, "stderr", stderr, "-commands is required")
	if code, _, _ := w.run("diff", "-commands", filepath.Join(w.dir, "nope.txt")); code != task.ExitFatal {
		t.Errorf("missing file: exit %d", code)
	}
}

// ---- shared flags and help --------------------------------------------------

func dispatchOut(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	in, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out, errb bytes.Buffer
	code := dispatch(args, in, &out, &errb)
	return code, out.String(), errb.String()
}

func TestHelpForEverySubcommand(t *testing.T) {
	readOnlyForbidden := []string{"  -backup\n", "  -backup ", "  -backup-dir", "  -dry-run", "  -rollback-on-fail", "  -canary", "  -strict-safety", "  -allow-dangerous"}
	tests := []struct {
		args        []string
		want        string
		wantFlags   string
		forbidFlags []string
	}{
		{[]string{"apply"}, "netops apply - apply configuration", "-limit", nil},
		{[]string{"config"}, "netops config: declarative resource management", "", nil},
		{[]string{"config", "user"}, "netops config user:", "", nil},
		{[]string{"config", "user", "add"}, "netops config user:", "-limit", nil},
		{[]string{"config", "user", "del"}, "netops config user:", "-limit", nil},
		{[]string{"config", "passwd"}, "netops config passwd:", "-limit", nil},
		{[]string{"config", "vlan"}, "netops config vlan:", "", nil},
		{[]string{"config", "vlan", "add"}, "netops config vlan:", "-limit", nil},
		{[]string{"config", "vlan", "del"}, "netops config vlan:", "-limit", nil},
		{[]string{"facts"}, "netops facts:", "-limit", readOnlyForbidden},
		{[]string{"find"}, "netops find:", "-limit", readOnlyForbidden},
		{[]string{"audit"}, "netops audit:", "-limit", readOnlyForbidden},
		{[]string{"exec"}, "netops exec:", "-limit", readOnlyForbidden},
		{[]string{"cve"}, "netops cve:", "-limit", nil},
		{[]string{"diff"}, "netops diff:", "-limit", nil},
		{[]string{"init"}, "netops init:", "", nil},
		{[]string{"telegram-test"}, "netops telegram-test:", "-env-file", nil},
	}
	for _, tt := range tests {
		for _, flagForm := range []string{"--help", "-h"} {
			callArgs := append(append([]string{}, tt.args...), flagForm)
			code, stdout, stderr := dispatchOut(t, callArgs...)
			if code != task.ExitOK {
				t.Errorf("%v: exit %d", callArgs, code)
			}
			out := stdout + stderr
			if !strings.Contains(out, tt.want) {
				t.Errorf("%v: help lacks %q", callArgs, tt.want)
			}
			if tt.wantFlags != "" && !strings.Contains(out, tt.wantFlags) {
				t.Errorf("%v: help lacks flag %q\nGot:\n%s", callArgs, tt.wantFlags, out)
			}
			for _, forbid := range tt.forbidFlags {
				if strings.Contains(out, forbid) {
					t.Errorf("%v: help should NOT contain %q\nGot:\n%s", callArgs, forbid, out)
				}
			}
		}
	}
}

func TestTimeoutIsAnAliasOfCommandTimeout(t *testing.T) {
	w := auditWS(t)
	if code, _, stderr := w.run("audit", "-limit", "good", "-timeout", "5s"); code != task.ExitOK {
		t.Errorf("-timeout rejected: exit %d\n%s", code, stderr)
	}
	// and the double-dash spelling of every flag works (Go's flag package accepts both)
	if code, _, stderr := w.run("audit", "-limit", "good", "--concurrency", "2", "--timeout", "5s"); code != task.ExitOK {
		t.Errorf("double dash: exit %d\n%s", code, stderr)
	}
	if code, _, _ := w.run("audit", "-timeout", "0s"); code != task.ExitFatal {
		t.Errorf("zero timeout must be rejected, exit %d", code)
	}
}

func TestApplyRunnerAndPasswordFlagsStillRefused(t *testing.T) {
	code, _, stderr := dispatchOut(t, "apply", "-password", "x")
	if code != task.ExitFatal {
		t.Errorf("exit %d", code)
	}
	mustContain(t, "stderr", stderr, "passwords are never accepted as command-line flags")
	// a command file named like a subcommand must now be given with -commands
	code, _, stderr = dispatchOut(t, "-version")
	if code != task.ExitOK || !strings.Contains(stderr, "") {
		t.Errorf("-version exit %d", code)
	}
}

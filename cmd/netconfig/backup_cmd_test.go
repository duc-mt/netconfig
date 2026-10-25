// ==============================================================================
// File name:     backup_cmd_test.go
// Description:   End-to-end tests for the "backup" subcommand and dispatch.
// License:       MIT
// ==============================================================================
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netconfig/internal/credentials"
	"netconfig/internal/inventory"
	"netconfig/internal/sshclient"
	"netconfig/internal/task"
)

const iosBackup = "version 15.2\n!\nhostname sw1\ninterface Gi0/1\n description uplink\n!\nenable secret 5 $1$abcd$XyZ123hashvalue\nend"

// cliTransport is a task.Transport for the whole command; devices are scripted
// by hostname.
type cliTransport struct {
	mu       sync.Mutex
	output   map[string]string
	authFail map[string]bool
	opens    map[string]int
	targets  map[string]task.Target
}

func (c *cliTransport) Open(_ context.Context, tgt task.Target) (task.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := tgt.Device.Hostname
	c.opens[h]++
	c.targets[h] = tgt
	if c.authFail[h] {
		return nil, &cliKindErr{"auth", "connect: ssh: unable to authenticate"}
	}
	out, ok := c.output[h]
	if !ok {
		return nil, &cliKindErr{"connect", "dial tcp: no such host"}
	}
	return cliSession{out}, nil
}

type cliKindErr struct{ kind, msg string }

func (e *cliKindErr) Error() string     { return e.msg }
func (e *cliKindErr) ErrorKind() string { return e.kind }

type cliSession struct{ out string }

func (s cliSession) Send(context.Context, string, time.Duration) (string, error) { return s.out, nil }
func (s cliSession) Close() error                                                { return nil }

// backupEnv is a self-contained working area for one command line.
type backupEnv struct {
	t    *testing.T
	dir  string
	tr   *cliTransport
	args []string
}

func newBackupEnv(t *testing.T, inventory string) *backupEnv {
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
	env := write(".env", "NETCONFIG_USERNAME=admin\nNETCONFIG_PASSWORD=s3cr3t-pw\n")
	tr := &cliTransport{
		output:   map[string]string{},
		authFail: map[string]bool{},
		opens:    map[string]int{},
		targets:  map[string]task.Target{},
	}
	orig := newBackupTransport
	newBackupTransport = func(sshclient.HostKeyCallback, bool, *jumpPool, []task.Target, int) task.Transport { return tr }
	t.Cleanup(func() { newBackupTransport = orig })

	return &backupEnv{t: t, dir: dir, tr: tr, args: []string{
		"backup",
		"-inventory", inv,
		"-env-file", env,
		"-backup-dir", filepath.Join(dir, "backups"),
		"-log-dir", filepath.Join(dir, "logs"),
		"-known-hosts", filepath.Join(dir, "known_hosts"),
		"-memory=false", "-jump=false", "-dial-jitter", "0", "-no-color",
	}}
}

// run executes the command line plus extra arguments.
func (e *backupEnv) run(extra ...string) (code int, stdout, stderr string) {
	e.t.Helper()
	in, err := os.Open(os.DevNull)
	if err != nil {
		e.t.Fatal(err)
	}
	defer in.Close()
	var out, errb bytes.Buffer
	code = dispatch(append(append([]string{}, e.args...), extra...), in, &out, &errb)
	return code, out.String(), errb.String()
}

func (e *backupEnv) path(parts ...string) string {
	return filepath.Join(append([]string{e.dir}, parts...)...)
}

func (e *backupEnv) read(parts ...string) string {
	e.t.Helper()
	data, err := os.ReadFile(e.path(parts...))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(data)
}

func (e *backupEnv) savedFiles() []string {
	var files []string
	_ = filepath.WalkDir(e.path("backups"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(e.path("backups"), p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	return files
}

const threeDevices = "hostname,address,port,vendor,credential_group\n" +
	"sw1,10.0.0.1,22,cisco,\n" +
	"r1,10.0.0.2,22,junos,\n" +
	"locked,10.0.0.3,22,cisco,\n"

func TestBackupCommandEndToEnd(t *testing.T) {
	e := newBackupEnv(t, threeDevices)
	e.tr.output["sw1"] = iosBackup
	e.tr.output["r1"] = "set system host-name r1\nset interfaces ge-0/0/0 description uplink"
	e.tr.authFail["locked"] = true

	code, stdout, stderr := e.run(
		"-html-report", e.path("report.html"),
		"-md-changelog", e.path("changelog.md"),
		"-json-report", e.path("run.json"),
		"-csv-report", e.path("run.csv"),
	)
	if code != task.ExitPartial {
		t.Fatalf("exit %d, want %d (one device failed)\nstderr:\n%s", code, task.ExitPartial, stderr)
	}

	// netbackup-compatible layout, one file per platform
	files := strings.Join(e.savedFiles(), "\n")
	for _, want := range []string{"/cisco_ios/sw1.cfg", "/juniper_junos/r1.set"} {
		if !strings.Contains(files, want) {
			t.Errorf("expected a file ending in %s, saved: %s", want, files)
		}
	}
	if strings.Contains(files, "locked") {
		t.Errorf("a failed device left a file: %s", files)
	}

	// the secret was masked on disk
	var sw1 string
	for _, f := range e.savedFiles() {
		if strings.HasSuffix(f, "/cisco_ios/sw1.cfg") {
			sw1 = e.read("backups", filepath.FromSlash(f))
		}
	}
	if strings.Contains(sw1, "XyZ123hashvalue") || !strings.Contains(sw1, "<REDACTED>") {
		t.Errorf("enable secret not masked in the saved file:\n%s", sw1)
	}

	// the run summary and the result table
	for _, want := range []string{"---- Backup run summary ----", "FAILED  locked", "AUTHENTICATION_FAILED", "Devices: 3 total, 2 succeeded, 1 failed"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q", want)
		}
	}
	if !strings.Contains(stdout, "sw1") || !strings.Contains(stdout, "locked") {
		t.Errorf("result table missing from stdout:\n%s", stdout)
	}

	// every report was written
	for _, name := range []string{"report.html", "changelog.md", "run.json", "run.csv"} {
		if got := e.read(name); !strings.Contains(got, "sw1") {
			t.Errorf("%s does not mention sw1", name)
		}
	}

	// the credentials reached the transport; the password never reached a log
	if tgt := e.tr.targets["sw1"]; tgt.Cred.Username != "admin" || tgt.Cred.Password != "s3cr3t-pw" {
		t.Errorf("credentials in target: %+v", tgt.Cred)
	}
	for _, text := range []string{stdout, stderr, e.logText()} {
		if strings.Contains(text, "s3cr3t-pw") {
			t.Error("the password leaked into the output or the log")
		}
	}
}

func (e *backupEnv) logText() string {
	entries, _ := os.ReadDir(e.path("logs"))
	var b strings.Builder
	for _, en := range entries {
		data, _ := os.ReadFile(e.path("logs", en.Name()))
		b.Write(data)
	}
	return b.String()
}

func TestBackupCommandExitsZeroWhenEverythingSucceeds(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\n")
	e.tr.output["sw1"] = iosBackup
	if code, _, stderr := e.run(); code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
}

func TestBackupCommandUnchangedSecondRun(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\n")
	e.tr.output["sw1"] = iosBackup
	e.run()
	before := e.savedFiles()
	code, _, stderr := e.run()
	if code != task.ExitOK || !strings.Contains(stderr, "UNCHANGED") {
		t.Errorf("exit %d, stderr:\n%s", code, stderr)
	}
	if after := e.savedFiles(); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Errorf("an unchanged configuration was written again: %v -> %v", before, after)
	}
}

func TestBackupCommandLimit(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\n"+
		"core-sw1,10.0.0.1,22,cisco,dc1\ncore-sw2,10.0.0.2,22,cisco,dc1\nedge-r1,10.0.0.3,22,junos,dc2\n")
	for _, h := range []string{"core-sw1", "core-sw2"} {
		e.tr.output[h] = iosBackup
	}
	e.tr.output["edge-r1"] = "set system host-name edge-r1"
	if code, _, stderr := e.run("-limit", "core-*"); code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if e.tr.opens["edge-r1"] != 0 || e.tr.opens["core-sw1"] != 1 || e.tr.opens["core-sw2"] != 1 {
		t.Errorf("-limit core-* contacted: %v", e.tr.opens)
	}

	e2 := newBackupEnv(t, "hostname,address,port,vendor,credential_group\ncore-sw1,10.0.0.1,22,cisco,dc1\nedge-r1,10.0.0.3,22,junos,dc2\n")
	e2.tr.output["edge-r1"] = "set system host-name edge-r1"
	if code, _, _ := e2.run("-limit", "@dc2"); code != task.ExitOK || e2.tr.opens["core-sw1"] != 0 || e2.tr.opens["edge-r1"] != 1 {
		t.Errorf("-limit @dc2: exit %d, opens %v", code, e2.tr.opens)
	}

	e3 := newBackupEnv(t, "hostname,address,port,vendor,credential_group\ncore-sw1,10.0.0.1,22,cisco,\n")
	if code, _, stderr := e3.run("-limit", "typo-*"); code != task.ExitFatal || !strings.Contains(stderr, "typo-*") {
		t.Errorf("a -limit that matches nothing must be fatal: exit %d\n%s", code, stderr)
	}
}

func TestBackupCommandDryRun(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\n")
	e.tr.output["sw1"] = iosBackup
	code, _, stderr := e.run("-dry-run")
	if code != task.ExitOK || !strings.Contains(stderr, "[DRY-RUN]") {
		t.Errorf("exit %d\n%s", code, stderr)
	}
	if files := e.savedFiles(); len(files) != 0 {
		t.Errorf("a dry run saved %v", files)
	}
	if e.tr.opens["sw1"] != 1 {
		t.Errorf("a dry run must still open a session: %v", e.tr.opens)
	}
}

func TestBackupCommandAcceptsNetbackupFlagSpellings(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\n")
	e.tr.output["sw1"] = iosBackup
	// -out replaces -backup-dir, -md-report replaces -md-changelog
	args := []string{
		"backup", "-inventory", e.args[2], "-env-file", e.args[4], "-out", e.path("other"),
		"-log-dir", e.path("logs"), "-known-hosts", e.path("known_hosts"), "-memory=false", "-jump=false",
		"-dial-jitter", "0", "-md-report", e.path("log.md"), "-save-unchanged", "-show-diff=false",
		"-known-hosts-policy", "accept-new", "-update-known-hosts=false", "-no-color",
	}
	in, _ := os.Open(os.DevNull)
	defer in.Close()
	var out, errb bytes.Buffer
	if code := dispatch(args, in, &out, &errb); code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, errb.String())
	}
	if _, err := os.Stat(e.path("other")); err != nil {
		t.Errorf("-out was not honoured: %v", err)
	}
	if _, err := os.Stat(e.path("log.md")); err != nil {
		t.Errorf("-md-report was not honoured: %v", err)
	}
}

func TestBackupCommandReadsNetbackupEnvironmentNames(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\n")
	e.tr.output["sw1"] = iosBackup
	// an existing netbackup .env: NETBACKUP_* only
	if err := os.WriteFile(e.args[4], []byte("NETBACKUP_USERNAME=legacy-user\nNETBACKUP_PASSWORD=legacy-pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := e.run()
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if tgt := e.tr.targets["sw1"]; tgt.Cred.Username != "legacy-user" || tgt.Cred.Password != "legacy-pw" {
		t.Errorf("NETBACKUP_* credentials were not used: %+v", tgt.Cred)
	}
	if !strings.Contains(stderr, "rename them to NETCONFIG_*") {
		t.Errorf("no deprecation warning:\n%s", stderr)
	}
	if strings.Contains(stderr, "legacy-pw") || strings.Contains(e.logText(), "legacy-pw") {
		t.Error("a legacy password leaked")
	}
}

func TestBackupCommandNetconfigNamesWinOverNetbackupOnes(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\n")
	e.tr.output["sw1"] = iosBackup
	body := "NETBACKUP_USERNAME=old\nNETBACKUP_PASSWORD=old-pw\nNETCONFIG_USERNAME=new\nNETCONFIG_PASSWORD=new-pw\n"
	if err := os.WriteFile(e.args[4], []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e.run()
	if tgt := e.tr.targets["sw1"]; tgt.Cred.Username != "new" || tgt.Cred.Password != "new-pw" {
		t.Errorf("credentials = %+v, want the NETCONFIG_* ones", tgt.Cred)
	}
}

func TestBackupCommandMissingCredentialsFailTheDeviceNotTheRun(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,dc1\nsw2,10.0.0.2,22,cisco,\n")
	e.tr.output["sw1"] = iosBackup
	e.tr.output["sw2"] = iosBackup
	// only the default credentials exist, and there is no terminal to ask; sw1's
	// group "dc1" falls back to them, so make the whole file unusable instead
	if err := os.WriteFile(e.args[4], []byte("# no credentials\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := e.run()
	if code != task.ExitPartial {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if e.tr.opens["sw1"] != 0 || e.tr.opens["sw2"] != 0 {
		t.Errorf("devices without credentials must not be contacted: %v", e.tr.opens)
	}
	if !strings.Contains(stderr, "AUTHENTICATION_FAILED") || !strings.Contains(stderr, "credentials for group") {
		t.Errorf("the failure should say what is missing:\n%s", stderr)
	}
}

func TestBackupCommandRetentionDefaultsToTen(t *testing.T) {
	var o backupOpts
	fs := newBackupFlagSet(&o, &bytes.Buffer{})
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if o.retentionCount != 10 || o.retentionDays != 0 || !o.redact || o.concurrency != 10 || o.backupDir != "backups" {
		t.Errorf("defaults: %+v", o)
	}
	if o.meshFallback {
		t.Error("tunnelling credentials through neighbouring devices must stay opt-in")
	}
}

func TestBackupCommandRejectsBadInput(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\n")
	tests := []struct {
		name  string
		extra []string
		want  string
	}{
		{"unknown flag", []string{"-nope"}, ""},
		{"stray argument", []string{"commands.txt"}, "unexpected arguments"},
		{"no workers", []string{"-concurrency", "0"}, "-concurrency"},
		{"bad timeout", []string{"-command-timeout", "0s"}, "positive"},
		{"negative retries", []string{"-retries", "-1"}, "negative"},
		{"json log format", []string{"-log-format", "json"}, "json-report"},
		{"bad host key policy", []string{"-host-key-policy", "sometimes"}, ""},
	}
	for _, tt := range tests {
		code, _, stderr := e.run(tt.extra...)
		if code != task.ExitFatal {
			t.Errorf("%s: exit %d, want %d", tt.name, code, task.ExitFatal)
		}
		if tt.want != "" && !strings.Contains(stderr, tt.want) {
			t.Errorf("%s: stderr %q does not mention %q", tt.name, stderr, tt.want)
		}
	}
	if len(e.tr.opens) != 0 {
		t.Errorf("invalid input must not reach a device: %v", e.tr.opens)
	}

	missing := newBackupEnv(t, "")
	missing.args[2] = missing.path("nope.csv")
	if code, _, stderr := missing.run(); code != task.ExitFatal || !strings.Contains(stderr, "netconfig -init") {
		t.Errorf("missing inventory: exit %d\n%s", code, stderr)
	}
}

func TestBackupCommandHelp(t *testing.T) {
	for _, flagName := range []string{"-h", "-help"} {
		in, _ := os.Open(os.DevNull)
		var out, errb bytes.Buffer
		code := dispatch([]string{"backup", flagName}, in, &out, &errb)
		in.Close()
		if code != task.ExitOK {
			t.Errorf("%s: exit %d", flagName, code)
		}
		for _, want := range []string{"netconfig backup", "-backup-dir", "-retention-count", "-golden-dir", "-html-report", "-md-changelog", "-limit", "-force", "cisco_asa", "mikrotik"} {
			if !strings.Contains(errb.String(), want) {
				t.Errorf("%s: help is missing %q", flagName, want)
			}
		}
	}
}

func TestDispatchRoutesSubcommandsAndKeepsTheClassicRunner(t *testing.T) {
	in, _ := os.Open(os.DevNull)
	defer in.Close()

	// "backup show" is routed to the viewer, like "user add" would be
	root := backupTree(t)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"backup", "show", "-backup-dir", root, "-l"}, in, &out, &errb); code != 0 || !strings.Contains(out.String(), "core-sw1") {
		t.Errorf("backup show: exit %d, out %q, err %q", code, out.String(), errb.String())
	}

	// top-level -version flag
	out.Reset()
	errb.Reset()
	if code := dispatch([]string{"-version"}, in, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "netconfig ") {
		t.Errorf("version flag: exit %d, out %q", code, out.String())
	}

	// config runner with positional commands file
	out.Reset()
	errb.Reset()
	code := dispatch([]string{"config", "-inventory", filepath.Join(t.TempDir(), "missing.csv"), "commands.txt"}, in, &out, &errb)
	if code != task.ExitFatal {
		t.Errorf("config runner with a missing inventory: exit %d", code)
	}

	// strict subcommand: running without subcommand fails
	out.Reset()
	errb.Reset()
	if code := dispatch([]string{"-inventory", "missing.csv"}, in, &out, &errb); code != task.ExitFatal || !strings.Contains(errb.String(), "unknown subcommand") {
		t.Errorf("missing subcommand must fail: exit %d, err %q", code, errb.String())
	}
}

func TestLegacyEnvHelpers(t *testing.T) {
	in := map[string]string{"NETBACKUP_USERNAME": "u", "NETBACKUP_DC1_PASSWORD": "p", "NETCONFIG_USERNAME": "explicit", "OTHER": "x"}
	got, migrated := migrateLegacyEnv(in)
	if got["NETCONFIG_USERNAME"] != "explicit" || got["NETCONFIG_DC1_PASSWORD"] != "p" || got["OTHER"] != "x" {
		t.Errorf("migrated values: %v", got)
	}
	if len(migrated) != 1 || migrated[0] != "NETBACKUP_DC1_PASSWORD" {
		t.Errorf("only entries that were actually copied are reported: %v", migrated)
	}
	if _, ok := in["NETCONFIG_DC1_PASSWORD"]; ok {
		t.Error("the input map must not be modified")
	}

	env := map[string]string{"NETBACKUP_PASSWORD": "legacy", "NETCONFIG_USERNAME": "new"}
	lookup, used := legacyLookupEnv(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if v, ok := lookup("NETCONFIG_USERNAME"); !ok || v != "new" || used() {
		t.Errorf("a set NETCONFIG_ variable must be used without a fallback: %q %v %v", v, ok, used())
	}
	if v, ok := lookup("NETCONFIG_PASSWORD"); !ok || v != "legacy" || !used() {
		t.Errorf("fallback to NETBACKUP_: %q %v %v", v, ok, used())
	}
	if _, ok := lookup("HOME"); ok {
		t.Error("only NETCONFIG_ names fall back")
	}
}

func TestCredentialErrorIsAnAuthFailure(t *testing.T) {
	var err error = &credentialError{group: "dc1", err: errors.New("no credentials")}
	var typed interface{ ErrorKind() string }
	if !errors.As(err, &typed) || typed.ErrorKind() != "auth" {
		t.Error("a missing credential must be an auth-kind error")
	}
	if !strings.Contains(err.Error(), `"dc1"`) {
		t.Errorf("message: %v", err)
	}
}

// Only the first word after "backup" selects the viewer: a flag value that
// happens to be "show" must not.
func TestBackupShowIsSelectedByTheFirstArgumentOnly(t *testing.T) {
	e := newBackupEnv(t, "hostname,address,port,vendor,credential_group\nsw1,10.0.0.1,22,cisco,\n")
	e.tr.output["sw1"] = iosBackup

	code, stdout, stderr := e.run("-limit", "show")
	if code != task.ExitFatal || !strings.Contains(stderr, "show") {
		t.Errorf("-limit show is a device filter that matches nothing: exit %d\n%s", code, stderr)
	}
	if strings.Contains(stdout+stderr, "Available nodes") || strings.Contains(stderr, "==> Latest") {
		t.Error("a flag value of \"show\" opened the viewer")
	}
	if len(e.tr.opens) != 0 {
		t.Errorf("devices were contacted: %v", e.tr.opens)
	}

	// the viewer is reached, with its own flags, by the first argument
	in := openDevNull(t)
	defer in.Close()
	var out, errb bytes.Buffer
	if code := dispatch([]string{"backup", "show", "-h"}, in, &out, &errb); code != 0 || !strings.Contains(errb.String(), "netconfig backup show") {
		t.Errorf("backup show -h: exit %d\n%s", code, errb.String())
	}
}

// "netconfig show-backup" no longer exists. Without a hint it would be taken
// for a commands file called show-backup and fail with a confusing message.
func TestOldShowBackupFormSaysWhatToUseInstead(t *testing.T) {
	in := openDevNull(t)
	defer in.Close()
	for _, args := range [][]string{{"show-backup", "-l"}, {"show-backup", "core-sw1", "-commands", "commands.txt"}} {
		var out, errb bytes.Buffer
		code := dispatch(args, in, &out, &errb)
		if code != task.ExitFatal || !strings.Contains(errb.String(), "netconfig backup show") || strings.Contains(errb.String(), "commands file") {
			t.Errorf("%v: exit %d\n%s", args, code, errb.String())
		}
		if out.Len() != 0 {
			t.Errorf("%v wrote to stdout: %q", args, out.String())
		}
	}
}

// The backup help mentions how to get to the viewer.
func TestBackupHelpPointsToShow(t *testing.T) {
	in := openDevNull(t)
	defer in.Close()
	var out, errb bytes.Buffer
	dispatch([]string{"backup", "-h"}, in, &out, &errb)
	if !strings.Contains(errb.String(), "netconfig backup show [flags] [node-name]") {
		t.Errorf("backup -h does not mention the show subcommand:\n%s", errb.String())
	}
	out.Reset()
	errb.Reset()
	dispatch([]string{"-h"}, in, &out, &errb)
	if !strings.Contains(errb.String(), "netconfig backup show") || strings.Contains(errb.String(), "netconfig show-backup") {
		t.Errorf("the top-level help must list the new form only:\n%s", errb.String())
	}
}

func TestBackupTerminalBannersCleanedCLI(t *testing.T) {
	e := newBackupEnv(t, "sw1,10.0.0.1,22,ruijie,default\n")
	rawRuijie := strings.Join([]string{
		"Building configuration...",
		"Current configuration: 7675 bytes",
		"",
		"version CS83_RGOS 12.6(3)B0703, Release(12161105)",
		"hostname sw1",
		"!",
		"end",
	}, "\n")
	e.tr.output["sw1"] = rawRuijie

	// Run 1: Default behavior automatically cleans terminal banner lines
	code, stdout, stderr := e.run()
	if code != 0 {
		t.Fatalf("run failed: %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var sw1Content string
	for _, f := range e.savedFiles() {
		if strings.HasSuffix(f, "/ruijie/sw1.cfg") {
			sw1Content = e.read("backups", filepath.FromSlash(f))
		}
	}
	wantClean := strings.Join([]string{
		"version CS83_RGOS 12.6(3)B0703, Release(12161105)",
		"hostname sw1",
		"!",
		"end",
	}, "\n")
	if sw1Content != wantClean {
		t.Errorf("default backup output mismatch:\n got: %q\nwant: %q", sw1Content, wantClean)
	}

	// Run 2: With -keep-banners flag, preserves banner lines
	e2 := newBackupEnv(t, "sw1,10.0.0.1,22,ruijie,default\n")
	e2.tr.output["sw1"] = rawRuijie
	code, stdout, stderr = e2.run("-keep-banners")
	if code != 0 {
		t.Fatalf("run with -keep-banners failed: %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var sw1Kept string
	for _, f := range e2.savedFiles() {
		if strings.HasSuffix(f, "/ruijie/sw1.cfg") {
			sw1Kept = e2.read("backups", filepath.FromSlash(f))
		}
	}
	if sw1Kept != rawRuijie {
		t.Errorf("backup with -keep-banners mismatch:\n got: %q\nwant: %q", sw1Kept, rawRuijie)
	}
}

func TestJumpForResolution(t *testing.T) {
	r := &credentials.Resolver{
		DotEnv: map[string]string{
			"NETCONFIG_JUMP_HOST":          "env-bastion:22",
			"NETCONFIG_JUMP_BASTION2_HOST": "bastion2:2222",
		},
	}
	globalDef := credentials.JumpCredentials{Host: "env-bastion:22"}

	// 1. Explicit direct bypasses global default
	directDevs := []string{"direct", "none", "-", "off", "false"}
	for _, mode := range directDevs {
		d := inventory.Device{Hostname: "dev1", JumpHost: mode}
		jc := jumpFor(r, d, "", globalDef)
		if jc.Host != "" {
			t.Errorf("jumpFor with jump_host=%q got host=%q, want empty (direct)", mode, jc.Host)
		}
	}

	// 2. Empty jump_host inherits global default
	dEmpty := inventory.Device{Hostname: "dev2", JumpHost: ""}
	jcEmpty := jumpFor(r, dEmpty, "", globalDef)
	if jcEmpty.Host != "env-bastion:22" {
		t.Errorf("jumpFor with empty jump_host got %q, want env-bastion:22", jcEmpty.Host)
	}

	// 3. Named bastion resolves
	dNamed := inventory.Device{Hostname: "dev3", JumpHost: "bastion2"}
	jcNamed := jumpFor(r, dNamed, "", globalDef)
	if jcNamed.Host != "bastion2:2222" {
		t.Errorf("jumpFor with named bastion got %q, want bastion2:2222", jcNamed.Host)
	}

	// 4. Raw host:port in jump_host
	dCustom := inventory.Device{Hostname: "dev4", JumpHost: "custom-gw:3000"}
	jcCustom := jumpFor(r, dCustom, "", globalDef)
	if jcCustom.Host != "custom-gw:3000" {
		t.Errorf("jumpFor with custom host:port got %q, want custom-gw:3000", jcCustom.Host)
	}
}

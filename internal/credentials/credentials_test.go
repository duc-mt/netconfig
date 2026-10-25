// ==============================================================================
// Package main implements Implementation and logic for credentials_test..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run credentials_test.go [options]
// Notes:         Go package implementation
// ==============================================================================
package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fakePrompter struct {
	user, pass           string
	err                  error
	userCalls, passCalls int
	lastGroup, lastUser  string
}

func (f *fakePrompter) Username(group string) (string, error) {
	f.userCalls++
	f.lastGroup = group
	return f.user, f.err
}

func (f *fakePrompter) Password(group, username string) (string, error) {
	f.passCalls++
	f.lastUser = username
	return f.pass, f.err
}

func mapEnv(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestEnvKey(t *testing.T) {
	cases := map[string]string{
		"dc1":       "NETOPS_DC1_USERNAME",
		"dc-1.east": "NETOPS_DC_1_EAST_USERNAME",
		"Site A":    "NETOPS_SITE_A_USERNAME",
		"default":   "NETOPS_DEFAULT_USERNAME",
	}
	for group, want := range cases {
		if got := EnvKey(group, "USERNAME"); got != want {
			t.Errorf("EnvKey(%q) = %q, want %q", group, got, want)
		}
	}
}

func TestDotEnvBeatsProcessEnv(t *testing.T) {
	r := &Resolver{
		DotEnv:    map[string]string{"NETOPS_USERNAME": "file-user", "NETOPS_PASSWORD": "file-pass"},
		LookupEnv: mapEnv(map[string]string{"NETOPS_USERNAME": "env-user", "NETOPS_PASSWORD": "env-pass"}),
	}
	c, err := r.Resolve("dc1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "file-user" || c.Password != "file-pass" {
		t.Errorf("got %q/%q, want the .env values", c.Username, c.Password)
	}
}

func TestFallsBackToProcessEnvPerField(t *testing.T) {
	r := &Resolver{
		DotEnv:    map[string]string{"NETOPS_PASSWORD": "file-pass"},
		LookupEnv: mapEnv(map[string]string{"NETOPS_USERNAME": "env-user"}),
	}
	c, err := r.Resolve("dc1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "env-user" || c.Password != "file-pass" {
		t.Errorf("got %q/%q", c.Username, c.Password)
	}
}

func TestGroupOverrideBeatsGlobalAcrossTiers(t *testing.T) {
	r := &Resolver{
		DotEnv: map[string]string{
			"NETOPS_USERNAME": "global-user",
			"NETOPS_PASSWORD": "global-pass",
		},
		LookupEnv: mapEnv(map[string]string{
			"NETOPS_DC1_USERNAME": "dc1-user",
			"NETOPS_DC1_PASSWORD": "dc1-pass",
		}),
	}
	c1, err := r.Resolve("dc1")
	if err != nil || c1.Username != "dc1-user" || c1.Password != "dc1-pass" {
		t.Errorf("dc1: %+v err=%v", c1, err)
	}
	c2, err := r.Resolve("dc2")
	if err != nil || c2.Username != "global-user" || c2.Password != "global-pass" {
		t.Errorf("dc2: %+v err=%v", c2, err)
	}
}

func TestEnablePassword(t *testing.T) {
	r := &Resolver{
		LookupEnv: mapEnv(map[string]string{
			"NETOPS_USERNAME":            "u",
			"NETOPS_PASSWORD":            "p",
			"NETOPS_DC1_ENABLE_PASSWORD": "en",
		}),
	}
	c, err := r.Resolve("dc1")
	if err != nil || c.EnablePassword != "en" {
		t.Errorf("got %+v err=%v", c, err)
	}
}

func TestEmptyValuesAreUnset(t *testing.T) {
	r := &Resolver{
		DotEnv:    map[string]string{"NETOPS_USERNAME": "", "NETOPS_PASSWORD": ""},
		LookupEnv: mapEnv(map[string]string{"NETOPS_USERNAME": "u", "NETOPS_PASSWORD": "p"}),
	}
	c, err := r.Resolve("g")
	if err != nil || c.Username != "u" || c.Password != "p" {
		t.Errorf("got %+v err=%v", c, err)
	}
}

func TestPromptsOnlyForMissingFields(t *testing.T) {
	pr := &fakePrompter{user: "typed-user", pass: "typed-pass"}
	r := &Resolver{
		LookupEnv: mapEnv(map[string]string{"NETOPS_DC1_USERNAME": "env-user"}),
		Prompter:  pr,
	}
	c, err := r.Resolve("dc1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "env-user" || c.Password != "typed-pass" {
		t.Errorf("got %q/%q", c.Username, c.Password)
	}
	if pr.userCalls != 0 || pr.passCalls != 1 || pr.lastUser != "env-user" {
		t.Errorf("prompter calls: user=%d pass=%d lastUser=%q", pr.userCalls, pr.passCalls, pr.lastUser)
	}
}

func TestPromptsForEverythingWhenNothingConfigured(t *testing.T) {
	pr := &fakePrompter{user: "  alice  ", pass: "s3cret"}
	r := &Resolver{LookupEnv: mapEnv(nil), Prompter: pr}
	c, err := r.Resolve("lab")
	if err != nil || c.Username != "alice" || c.Password != "s3cret" {
		t.Fatalf("got %+v err=%v", c, err)
	}
	if pr.lastGroup != "lab" {
		t.Errorf("prompted for group %q", pr.lastGroup)
	}
}

func TestPromptHappensOncePerGroup(t *testing.T) {
	pr := &fakePrompter{user: "u", pass: "p"}
	r := &Resolver{Prompter: pr}
	for i := 0; i < 3; i++ {
		if _, err := r.Resolve("dc1"); err != nil {
			t.Fatal(err)
		}
	}
	if pr.userCalls != 1 || pr.passCalls != 1 {
		t.Errorf("prompted %d/%d times, want once each", pr.userCalls, pr.passCalls)
	}
	if _, err := r.Resolve("dc2"); err != nil {
		t.Fatal(err)
	}
	if pr.userCalls != 2 {
		t.Errorf("a new group must prompt again; userCalls=%d", pr.userCalls)
	}
}

func TestNotFoundWithoutPrompter(t *testing.T) {
	r := &Resolver{LookupEnv: mapEnv(nil)}
	_, err := r.Resolve("dc9")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "NETOPS_DC9_USERNAME") {
		t.Errorf("error should name the variable to set: %v", err)
	}
}

func TestPromptFailureIsCached(t *testing.T) {
	pr := &fakePrompter{err: errors.New("EOF")}
	r := &Resolver{Prompter: pr}
	for i := 0; i < 2; i++ {
		if _, err := r.Resolve("dc1"); err == nil {
			t.Fatal("expected error")
		}
	}
	if pr.userCalls != 1 {
		t.Errorf("failed prompt repeated: %d calls", pr.userCalls)
	}
}

func TestCredentialNeverPrintsPassword(t *testing.T) {
	c := Credential{Username: "alice", Password: "hunter2-secret", EnablePassword: "enable-secret"}
	for _, s := range []string{
		fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), c.String(), fmt.Sprintf("%#v", c),
	} {
		if strings.Contains(s, "hunter2-secret") || strings.Contains(s, "enable-secret") {
			t.Errorf("secret leaked: %s", s)
		}
		if !strings.Contains(s, "alice") {
			t.Errorf("username should still be visible: %s", s)
		}
	}
}

func TestParseDotEnv(t *testing.T) {
	src := strings.Join([]string{
		"# comment",
		"",
		"NETOPS_USERNAME=admin",
		"export NETOPS_PASSWORD=pass#word   # trailing comment",
		`NETOPS_DC1_PASSWORD="quoted \"pw\" # kept"`,
		`NETOPS_DC2_PASSWORD='single $quoted \n'`,
		"NETOPS_DC3_USERNAME = spaced",
		"NETOPS_EMPTY=",
	}, "\r\n")

	got, err := ParseDotEnv(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"NETOPS_USERNAME":     "admin",
		"NETOPS_PASSWORD":     "pass#word",
		"NETOPS_DC1_PASSWORD": `quoted "pw" # kept`,
		"NETOPS_DC2_PASSWORD": `single $quoted \n`,
		"NETOPS_DC3_USERNAME": "spaced",
		"NETOPS_EMPTY":        "",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("parsed %d keys, want %d: %v", len(got), len(want), got)
	}
}

func TestParseDotEnvErrorsDoNotLeakValues(t *testing.T) {
	bad := []string{
		"just-a-line",
		"1BAD=x",
		`KEY="unterminated-secret-value`,
		`KEY='unterminated-secret-value`,
		`KEY="closed" junk`,
	}
	for _, line := range bad {
		_, err := ParseDotEnv(strings.NewReader(line + "\n"))
		if err == nil {
			t.Errorf("expected error for %q", line)
			continue
		}
		if strings.Contains(err.Error(), "secret-value") {
			t.Errorf("error leaks the value: %v", err)
		}
	}
}

func TestLoadDotEnv(t *testing.T) {
	dir := t.TempDir()

	missing, err := LoadDotEnv(filepath.Join(dir, "nope.env"))
	if err != nil || len(missing.Values) != 0 || len(missing.Warnings) != 0 {
		t.Fatalf("missing file: %+v err=%v", missing, err)
	}

	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte("NETOPS_USERNAME=u\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDotEnv(p)
	if err != nil || d.Values["NETOPS_USERNAME"] != "u" || len(d.Warnings) != 0 {
		t.Fatalf("0600 file: %+v err=%v", d, err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
		d, err = LoadDotEnv(p)
		if err != nil || len(d.Warnings) != 1 {
			t.Fatalf("0644 file should warn: %+v err=%v", d, err)
		}
	}
}

func TestJumpCredentialsResolution(t *testing.T) {
	r := &Resolver{
		DotEnv: map[string]string{
			"NETOPS_USERNAME":                 "global-dev-user",
			"NETOPS_JUMP_HOST":                "global-bastion:22",
			"NETOPS_JUMP_USERNAME":            "global-jump-user",
			"NETOPS_JUMP_PASSWORD":            "global-jump-pass",
			"NETOPS_JUMP_BASTION_DC_HOST":     "dc-bastion:2222",
			"NETOPS_JUMP_BASTION_DC_USERNAME": "dc-jump-user",
			"NETOPS_JUMP_BASTION_DC_PASSWORD": "dc-jump-pass",
		},
	}

	def := r.JumpDefaults()
	if def.Host != "global-bastion:22" || def.Username != "global-jump-user" || def.Password != "global-jump-pass" {
		t.Errorf("JumpDefaults wrong: %+v", def)
	}

	dcJump := r.ForJumpHost("bastion-dc")
	if dcJump.Host != "dc-bastion:2222" || dcJump.Username != "dc-jump-user" || dcJump.Password != "dc-jump-pass" {
		t.Errorf("ForJumpHost(bastion-dc) wrong: %+v", dcJump)
	}

	// Unknown jump host name should fall back to global jump defaults
	otherJump := r.ForJumpHost("other-bastion")
	if otherJump.Host != "global-bastion:22" || otherJump.Username != "global-jump-user" || otherJump.Password != "global-jump-pass" {
		t.Errorf("ForJumpHost(other-bastion) fallback wrong: %+v", otherJump)
	}
}

func TestKeyFileCredentialsResolution(t *testing.T) {
	r := &Resolver{
		DotEnv: map[string]string{
			"NETOPS_USERNAME":                 "global-user",
			"NETOPS_KEY_FILE":                 "/path/to/global_id_ed25519",
			"NETOPS_SITE_A_USERNAME":          "site-user",
			"NETOPS_SITE_A_KEY_FILE":          "/path/to/site_a_key",
			"NETOPS_JUMP_KEY_FILE":            "/path/to/jump_key",
			"NETOPS_JUMP_BASTION_DC_KEY_FILE": "/path/to/dc_jump_key",
		},
	}

	cDef, err := r.Resolve("default")
	if err != nil {
		t.Fatalf("Resolve(default) failed: %v", err)
	}
	if cDef.Username != "global-user" || cDef.KeyFile != "/path/to/global_id_ed25519" {
		t.Errorf("unexpected default creds: %+v", cDef)
	}

	cSiteA, err := r.Resolve("site_a")
	if err != nil {
		t.Fatalf("Resolve(site_a) failed: %v", err)
	}
	if cSiteA.Username != "site-user" || cSiteA.KeyFile != "/path/to/site_a_key" {
		t.Errorf("unexpected site_a creds: %+v", cSiteA)
	}

	jumpDef := r.JumpDefaults()
	if jumpDef.KeyFile != "/path/to/jump_key" {
		t.Errorf("unexpected jumpDef key: %+v", jumpDef)
	}

	jumpDC := r.ForJumpHost("bastion_dc")
	if jumpDC.KeyFile != "/path/to/dc_jump_key" {
		t.Errorf("unexpected jumpDC key: %+v", jumpDC)
	}
}

func TestOverridesBeatAllTiers(t *testing.T) {
	r := &Resolver{
		DotEnv: map[string]string{
			"NETOPS_USERNAME":  "file-user",
			"NETOPS_PASSWORD":  "file-pass",
			"NETOPS_JUMP_HOST": "file-bastion:22",
		},
		LookupEnv: mapEnv(map[string]string{
			"NETOPS_USERNAME": "env-user",
		}),
		Overrides: map[string]string{
			"NETOPS_USERNAME":  "flag-user",
			"NETOPS_JUMP_HOST": "flag-bastion:2222",
		},
	}
	c, err := r.Resolve("dc1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "flag-user" || c.Password != "file-pass" {
		t.Errorf("got %q/%q, want flag-user/file-pass", c.Username, c.Password)
	}
	jump := r.JumpDefaults()
	if jump.Host != "flag-bastion:2222" {
		t.Errorf("got jump host %q, want flag-bastion:2222", jump.Host)
	}
}

func TestIsDirect(t *testing.T) {
	directCases := []string{
		"direct", "DIRECT", " Direct ",
		"none", "NONE", " None ",
		"-", " - ",
		"off", "OFF",
		"false", "FALSE",
		"no", "NO",
	}
	for _, tc := range directCases {
		if !IsDirect(tc) {
			t.Errorf("IsDirect(%q) = false, want true", tc)
		}
	}

	nonDirectCases := []string{
		"", "   ",
		"default", "DEFAULT",
		"bastion", "bastion-dc",
		"192.168.1.1:22",
		"direct-gw", "none-bastion",
	}
	for _, tc := range nonDirectCases {
		if IsDirect(tc) {
			t.Errorf("IsDirect(%q) = true, want false", tc)
		}
	}
}

func TestForJumpHostDirectOverride(t *testing.T) {
	r := &Resolver{
		DotEnv: map[string]string{
			"NETOPS_JUMP_HOST":     "bastion.example.com:22",
			"NETOPS_JUMP_USERNAME": "jumpuser",
			"NETOPS_JUMP_PASSWORD": "jumppass",
		},
	}

	// Global defaults resolve to bastion
	def := r.JumpDefaults()
	if def.Host != "bastion.example.com:22" {
		t.Fatalf("unexpected global jump host: %s", def.Host)
	}

	// Direct keywords bypass bastion and return empty JumpCredentials
	for _, kw := range []string{"direct", "none", "-", "off", "false"} {
		jc := r.ForJumpHost(kw)
		if jc.Host != "" {
			t.Errorf("ForJumpHost(%q) host = %q, want empty", kw, jc.Host)
		}
	}

	// Normal named bastion falls back or resolves
	other := r.ForJumpHost("other-bastion")
	if other.Host != "bastion.example.com:22" {
		t.Errorf("ForJumpHost(other-bastion) host = %q, want bastion.example.com:22", other.Host)
	}
}

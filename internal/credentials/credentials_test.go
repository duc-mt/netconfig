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
		"dc1":       "NETCONFIG_DC1_USERNAME",
		"dc-1.east": "NETCONFIG_DC_1_EAST_USERNAME",
		"Site A":    "NETCONFIG_SITE_A_USERNAME",
		"default":   "NETCONFIG_DEFAULT_USERNAME",
	}
	for group, want := range cases {
		if got := EnvKey(group, "USERNAME"); got != want {
			t.Errorf("EnvKey(%q) = %q, want %q", group, got, want)
		}
	}
}

func TestDotEnvBeatsProcessEnv(t *testing.T) {
	r := &Resolver{
		DotEnv:    map[string]string{"NETCONFIG_USERNAME": "file-user", "NETCONFIG_PASSWORD": "file-pass"},
		LookupEnv: mapEnv(map[string]string{"NETCONFIG_USERNAME": "env-user", "NETCONFIG_PASSWORD": "env-pass"}),
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
		DotEnv:    map[string]string{"NETCONFIG_PASSWORD": "file-pass"},
		LookupEnv: mapEnv(map[string]string{"NETCONFIG_USERNAME": "env-user"}),
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
			"NETCONFIG_USERNAME": "global-user",
			"NETCONFIG_PASSWORD": "global-pass",
		},
		LookupEnv: mapEnv(map[string]string{
			"NETCONFIG_DC1_USERNAME": "dc1-user",
			"NETCONFIG_DC1_PASSWORD": "dc1-pass",
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
			"NETCONFIG_USERNAME":            "u",
			"NETCONFIG_PASSWORD":            "p",
			"NETCONFIG_DC1_ENABLE_PASSWORD": "en",
		}),
	}
	c, err := r.Resolve("dc1")
	if err != nil || c.EnablePassword != "en" {
		t.Errorf("got %+v err=%v", c, err)
	}
}

func TestEmptyValuesAreUnset(t *testing.T) {
	r := &Resolver{
		DotEnv:    map[string]string{"NETCONFIG_USERNAME": "", "NETCONFIG_PASSWORD": ""},
		LookupEnv: mapEnv(map[string]string{"NETCONFIG_USERNAME": "u", "NETCONFIG_PASSWORD": "p"}),
	}
	c, err := r.Resolve("g")
	if err != nil || c.Username != "u" || c.Password != "p" {
		t.Errorf("got %+v err=%v", c, err)
	}
}

func TestPromptsOnlyForMissingFields(t *testing.T) {
	pr := &fakePrompter{user: "typed-user", pass: "typed-pass"}
	r := &Resolver{
		LookupEnv: mapEnv(map[string]string{"NETCONFIG_DC1_USERNAME": "env-user"}),
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
	if !strings.Contains(err.Error(), "NETCONFIG_DC9_USERNAME") {
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
		fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%s", c), fmt.Sprintf("%#v", c),
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
		"NETCONFIG_USERNAME=admin",
		"export NETCONFIG_PASSWORD=pass#word   # trailing comment",
		`NETCONFIG_DC1_PASSWORD="quoted \"pw\" # kept"`,
		`NETCONFIG_DC2_PASSWORD='single $quoted \n'`,
		"NETCONFIG_DC3_USERNAME = spaced",
		"NETCONFIG_EMPTY=",
	}, "\r\n")

	got, err := ParseDotEnv(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"NETCONFIG_USERNAME":     "admin",
		"NETCONFIG_PASSWORD":     "pass#word",
		"NETCONFIG_DC1_PASSWORD": `quoted "pw" # kept`,
		"NETCONFIG_DC2_PASSWORD": `single $quoted \n`,
		"NETCONFIG_DC3_USERNAME": "spaced",
		"NETCONFIG_EMPTY":        "",
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
	if err := os.WriteFile(p, []byte("NETCONFIG_USERNAME=u\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDotEnv(p)
	if err != nil || d.Values["NETCONFIG_USERNAME"] != "u" || len(d.Warnings) != 0 {
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

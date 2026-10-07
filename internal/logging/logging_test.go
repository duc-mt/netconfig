package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Date(2026, 10, 3, 10, 15, 0, 0, time.UTC) }

func readLog(t *testing.T, l *Logger) string {
	t.Helper()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestFileAndConsoleOutput(t *testing.T) {
	var console bytes.Buffer
	l, err := New(Options{Dir: t.TempDir(), Console: &console, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(l.Path()); got != "netconfig-20261003-101500.log" {
		t.Errorf("log file name = %q", got)
	}

	l.Infof("sw1", "connected to %s", "10.0.0.1")
	l.Tracef("sw1", ">> show version")
	l.Warnf("", "careful")
	l.Errorf("sw2", "FAILED [%s]", "AUTH_FAILED")

	con := console.String()
	if !strings.Contains(con, "connected to 10.0.0.1") || !strings.Contains(con, "[sw1]") {
		t.Errorf("console missing info line:\n%s", con)
	}
	if strings.Contains(con, "show version") {
		t.Errorf("trace must stay off the console unless Verbose:\n%s", con)
	}
	if !strings.Contains(con, "WARN") || !strings.Contains(con, "ERROR") {
		t.Errorf("console missing WARN/ERROR:\n%s", con)
	}

	file := readLog(t, l)
	for _, want := range []string{
		"2026-10-03T10:15:00.000Z INFO  [sw1] connected to 10.0.0.1",
		"TRACE [sw1] >> show version",
		"WARN  careful",
		"ERROR [sw2] FAILED [AUTH_FAILED]",
	} {
		if !strings.Contains(file, want) {
			t.Errorf("log file missing %q:\n%s", want, file)
		}
	}
}

func TestVerboseShowsTraceOnConsole(t *testing.T) {
	var console bytes.Buffer
	l, err := New(Options{Console: &console, Verbose: true, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	l.Tracef("sw1", ">> show version")
	if !strings.Contains(console.String(), ">> show version") {
		t.Errorf("verbose console missing trace:\n%s", console.String())
	}
	if l.Path() != "" {
		t.Errorf("no Dir, so no file; got %q", l.Path())
	}
}

func TestColorOnlyWhenEnabled(t *testing.T) {
	var plain, colored bytes.Buffer
	lp, _ := New(Options{Console: &plain, Now: fixedNow})
	lc, _ := New(Options{Console: &colored, Color: true, Now: fixedNow})
	lp.Errorf("sw1", "boom")
	lc.Errorf("sw1", "boom")
	if strings.Contains(plain.String(), "\x1b[") {
		t.Errorf("plain output contains ANSI codes: %q", plain.String())
	}
	if !strings.Contains(colored.String(), "\x1b[31m") {
		t.Errorf("coloured output missing red: %q", colored.String())
	}
}

func TestSecretsAreMaskedEverywhere(t *testing.T) {
	var console bytes.Buffer
	l, err := New(Options{Dir: t.TempDir(), Console: &console, Verbose: true, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	l.AddSecret("hunter2-secret")
	l.AddSecret("ab") // too short to mask safely; must be ignored

	l.Infof("sw1", "login with hunter2-secret ok, about to abort")
	l.Block(LevelTrace, "sw1", "<< ", "echo hunter2-secret\nabc")
	l.Raw("summary hunter2-secret\n", "summary hunter2-secret\n")

	file := readLog(t, l)
	for name, text := range map[string]string{"console": console.String(), "file": file} {
		if strings.Contains(text, "hunter2-secret") {
			t.Errorf("%s leaked the secret:\n%s", name, text)
		}
		if !strings.Contains(text, "********") {
			t.Errorf("%s has no mask:\n%s", name, text)
		}
		if !strings.Contains(text, "about to abort") || !strings.Contains(text, "abc") {
			t.Errorf("%s: short secret must not mangle text:\n%s", name, text)
		}
	}
}

func TestBlockPrefixesEveryLine(t *testing.T) {
	l, err := New(Options{Dir: t.TempDir(), Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	l.Block(LevelTrace, "sw1", "<< ", "line1\r\nline2\n\n")
	file := readLog(t, l)
	if !strings.Contains(file, "TRACE [sw1] << line1\n") || !strings.Contains(file, "TRACE [sw1] << line2\n") {
		t.Errorf("block lines not logged individually:\n%s", file)
	}
	if got := strings.Count(file, "\n"); got != 2 {
		t.Errorf("want 2 log lines, got %d:\n%s", got, file)
	}
}

func TestConcurrentUseKeepsLinesIntact(t *testing.T) {
	l, err := New(Options{Dir: t.TempDir(), Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				l.Infof("sw", "message-complete-%d", j)
			}
		}()
	}
	wg.Wait()
	file := readLog(t, l)
	lines := strings.Split(strings.TrimSpace(file), "\n")
	if len(lines) != 1000 {
		t.Fatalf("got %d lines, want 1000", len(lines))
	}
	for _, line := range lines {
		if !strings.Contains(line, "[sw] message-complete-") {
			t.Fatalf("corrupted line: %q", line)
		}
	}
}

func TestRedactCommand(t *testing.T) {
	cases := map[string]string{
		"hostname sw1":                                                     "hostname sw1",
		"service password-encryption":                                      "service password-encryption",
		"username admin password 0 hunter2":                                "username admin password 0 <redacted>",
		"username admin secret 5 $1$abcd$xyz":                              "username admin secret 5 <redacted>",
		"enable secret s3cr3t":                                             "enable secret <redacted>",
		"snmp-server community public RO":                                  "snmp-server community <redacted> RO",
		`set system root-authentication encrypted-password "$6$salt$hash"`: "set system root-authentication encrypted-password <redacted>",
		"set psksecret topsecret":                                          "set psksecret <redacted>",
		"no password":                                                      "no password",
		"password 1234":                                                    "password <redacted>",
		"tacacs-server key 7 secretPass":                                   "tacacs-server key 7 <redacted>",
		"radius-server key secretPass":                                     "radius-server key <redacted>",
	}
	for in, want := range cases {
		if got := RedactCommand(in); got != want {
			t.Errorf("RedactCommand(%q)\n got  %q\n want %q", in, got, want)
		}
	}
}

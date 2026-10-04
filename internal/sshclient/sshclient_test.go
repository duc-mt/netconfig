package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"netconfig/internal/vendor"
)

// ---- SafeBuffer ------------------------------------------------------------

func TestSafeBufferConcurrentUse(t *testing.T) {
	b := NewSafeBuffer()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = b.Write([]byte("x"))
				_ = b.Since(0)
				_ = b.Len()
			}
		}()
	}
	wg.Wait()
	if b.Len() != 5000 || len(b.String()) != 5000 {
		t.Fatalf("lost writes: Len=%d", b.Len())
	}
}

func TestSafeBufferSinceAndNotify(t *testing.T) {
	b := NewSafeBuffer()
	_, _ = b.Write([]byte("hello "))
	_, _ = b.Write([]byte("world"))
	if got := string(b.Since(6)); got != "world" {
		t.Errorf("Since(6) = %q", got)
	}
	if got := b.Since(100); got != nil {
		t.Errorf("Since past end = %q, want nil", got)
	}
	select {
	case <-b.Notify():
	default:
		t.Error("expected a pending notification")
	}
}

// ---- terminal cleaning -----------------------------------------------------

func TestCleanTerminal(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\r\nb\r\n", "a\nb\n"},
		{"\x1b[31mred\x1b[0m text", "red text"},
		{"abc\b\bX", "aXc"},
		{"x  \nY", "x\nY"},
		{"loading\r        \rdone\r\n", "done\n"},
		{"--More--\b\b\b\b\b\b\b\b        \b\b\b\b\b\b\b\bline2\r\n", "line2\n"},
		{"Router#", "Router#"},
	}
	for _, c := range cases {
		if got := cleanTerminal(c.in); got != c.want {
			t.Errorf("cleanTerminal(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLastLineAndStripEcho(t *testing.T) {
	if lastLine("a\nb") != "b" || lastLine("abc") != "abc" || lastLine("a\n") != "" {
		t.Error("lastLine wrong")
	}
	got := stripEcho("show clock\n10:00 UTC\n", "show clock")
	if got != "10:00 UTC" {
		t.Errorf("stripEcho = %q", got)
	}
	// Leading indentation of real output must survive.
	got = stripEcho("show run\n ip address 1.1.1.1\n", "show run")
	if got != " ip address 1.1.1.1" {
		t.Errorf("stripEcho dropped indentation: %q", got)
	}
	// No echo present: nothing is removed.
	if got := stripEcho("plain output", "show clock"); got != "plain output" {
		t.Errorf("stripEcho = %q", got)
	}
}

// ---- expect loop (no network: the "device" is a goroutine) -----------------

type testStdin struct{ *SafeBuffer }

func (testStdin) Close() error { return nil }

func newTestShell(t *testing.T, vendorName string) (*Shell, *SafeBuffer) {
	t.Helper()
	prof, ok := vendor.Lookup(vendorName)
	if !ok {
		t.Fatalf("unknown vendor %s", vendorName)
	}
	in := NewSafeBuffer()
	sh := &Shell{
		stdin:       testStdin{in},
		out:         NewSafeBuffer(),
		errBuf:      NewSafeBuffer(),
		done:        make(chan struct{}),
		prof:        prof,
		settle:      10 * time.Millisecond,
		autoConfirm: true,
		logf:        func(string, ...any) {},
	}
	return sh, in
}

// waitForInput blocks until the shell has written something ending in suffix.
func waitForInput(t *testing.T, in *SafeBuffer, suffix string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.HasSuffix(in.String(), suffix) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Errorf("device never received %q (got %q)", suffix, in.String())
}

func TestSendReturnsOutputWithoutEchoOrPrompt(t *testing.T) {
	sh, in := newTestShell(t, "cisco")
	go func() {
		waitForInput(t, in, "show clock\n")
		_, _ = sh.out.Write([]byte("show clock\r\n10:00:00.000 UTC Sat Oct 3 2026\r\nRouter#"))
	}()
	out, err := sh.Send(context.Background(), "show clock", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out != "10:00:00.000 UTC Sat Oct 3 2026" {
		t.Errorf("out = %q", out)
	}
	if sh.prompt != "Router#" {
		t.Errorf("prompt = %q", sh.prompt)
	}
}

func TestPagerIsAdvancedAndErased(t *testing.T) {
	sh, in := newTestShell(t, "cisco")
	go func() {
		waitForInput(t, in, "show run\n")
		_, _ = sh.out.Write([]byte("show run\r\nline1\r\n --More-- "))
		waitForInput(t, in, "show run\n ") // the shell must answer the pager with a space
		_, _ = sh.out.Write([]byte("\r         \rline2\r\nRouter#"))
	}()
	out, err := sh.Send(context.Background(), "show run", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out != "line1\nline2" {
		t.Errorf("out = %q, want %q", out, "line1\nline2")
	}
}

func TestConfirmationIsAutoAnswered(t *testing.T) {
	sh, in := newTestShell(t, "cisco")
	var logged []string
	var mu sync.Mutex
	sh.logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, f)
	}
	go func() {
		waitForInput(t, in, "write memory\n")
		_, _ = sh.out.Write([]byte("write memory\r\nOverwrite existing config? [y/n]: "))
		waitForInput(t, in, "write memory\ny\n")
		_, _ = sh.out.Write([]byte("\r\n[OK]\r\nRouter#"))
	}()
	out, err := sh.Send(context.Background(), "write memory", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "[OK]") || !strings.Contains(out, "Overwrite existing config?") {
		t.Errorf("out = %q", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logged) != 1 || !strings.Contains(logged[0], "auto-confirmed") {
		t.Errorf("auto-confirm was not logged: %v", logged)
	}
}

func TestConfirmationRefusedWhenAutoConfirmOff(t *testing.T) {
	sh, in := newTestShell(t, "cisco")
	sh.autoConfirm = false
	go func() {
		waitForInput(t, in, "reload\n")
		_, _ = sh.out.Write([]byte("reload\r\nProceed? [confirm]"))
	}()
	_, err := sh.Send(context.Background(), "reload", 2*time.Second)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindSession {
		t.Fatalf("err = %v, want a session error", err)
	}
	if strings.Contains(in.String(), "reload\n\n") {
		t.Errorf("shell answered the dialog despite auto-confirm being off: %q", in.String())
	}
}

func TestSecretRuleReplyIsNeverLogged(t *testing.T) {
	sh, in := newTestShell(t, "cisco")
	var logged []string
	var mu sync.Mutex
	sh.logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, f)
		for _, x := range a {
			if s, ok := x.(string); ok {
				logged = append(logged, s)
			}
		}
	}
	go func() {
		waitForInput(t, in, "enable\n")
		_, _ = sh.out.Write([]byte("enable\r\nPassword: "))
		waitForInput(t, in, "enable\nen-secret-123\n")
		_, _ = sh.out.Write([]byte("\r\nRouter#"))
	}()
	pw := &rule{re: passwordPromptRe, reply: "en-secret-123", label: "enable password prompt", max: 3, secret: true}
	if _, err := sh.send(context.Background(), "enable", 2*time.Second, []*rule{pw}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range logged {
		if strings.Contains(l, "en-secret-123") {
			t.Errorf("secret reply was logged: %q", l)
		}
	}
	if len(logged) == 0 {
		t.Error("expected the answered prompt to be logged by label")
	}
}

func TestSendTimesOut(t *testing.T) {
	sh, _ := newTestShell(t, "cisco")
	start := time.Now()
	_, err := sh.Send(context.Background(), "show tech", 60*time.Millisecond)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindTimeout {
		t.Fatalf("err = %v, want a timeout error", err)
	}
	if time.Since(start) > time.Second {
		t.Error("timeout took far too long")
	}
}

func TestSendReportsClosedConnection(t *testing.T) {
	sh, in := newTestShell(t, "cisco")
	go func() {
		waitForInput(t, in, "show x\n")
		_, _ = sh.out.Write([]byte("show x\r\npartial output"))
		close(sh.done)
	}()
	out, err := sh.Send(context.Background(), "show x", 2*time.Second)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindSession || !errors.Is(err, errClosed) {
		t.Fatalf("err = %v, want a session error wrapping errClosed", err)
	}
	if !strings.Contains(out, "partial output") {
		t.Errorf("partial output not returned: %q", out)
	}
}

func TestSendHonoursContextCancellation(t *testing.T) {
	sh, _ := newTestShell(t, "cisco")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	_, err := sh.Send(ctx, "show tech", 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// ---- host key policies ------------------------------------------------------

func newKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParsePolicy(t *testing.T) {
	for in, want := range map[string]HostKeyPolicy{
		"strict": PolicyStrict, " Accept-New ": PolicyAcceptNew, "INSECURE": PolicyInsecure,
	} {
		if got, err := ParsePolicy(in); err != nil || got != want {
			t.Errorf("ParsePolicy(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParsePolicy("yolo"); err == nil {
		t.Error("expected error for unknown policy")
	}
}

func TestHostKeyPolicies(t *testing.T) {
	const host = "192.0.2.10:22"
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	path := filepath.Join(t.TempDir(), "known_hosts")
	keyA, keyB := newKey(t), newKey(t)

	// strict + missing file: configuration error.
	if _, err := NewHostKeyCallback(path, PolicyStrict); err == nil {
		t.Fatal("strict policy must fail when known_hosts does not exist")
	}

	// accept-new enrolls an unknown host and creates the file.
	accept, err := NewHostKeyCallback(path, PolicyAcceptNew)
	if err != nil {
		t.Fatal(err)
	}
	if err := accept(host, remote, keyA); err != nil {
		t.Fatalf("accept-new should enroll an unknown host: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "192.0.2.10") {
		t.Fatalf("known_hosts not written: %q err=%v", data, err)
	}

	// strict now accepts the enrolled key and rejects a different one.
	strict, err := NewHostKeyCallback(path, PolicyStrict)
	if err != nil {
		t.Fatal(err)
	}
	if err := strict(host, remote, keyA); err != nil {
		t.Errorf("strict rejected an enrolled key: %v", err)
	}
	var hk *HostKeyError
	if err := strict(host, remote, keyB); !errors.As(err, &hk) || !strings.Contains(hk.Reason, "CHANGED") {
		t.Errorf("strict must flag a changed key, got %v", err)
	}

	// even accept-new must never trust a changed key.
	accept2, err := NewHostKeyCallback(path, PolicyAcceptNew)
	if err != nil {
		t.Fatal(err)
	}
	if err := accept2(host, remote, keyB); !errors.As(err, &hk) {
		t.Errorf("accept-new accepted a changed key: %v", err)
	}

	// strict rejects an unknown host and explains how to enroll it.
	other := &net.TCPAddr{IP: net.ParseIP("192.0.2.77"), Port: 22}
	if err := strict("192.0.2.77:22", other, keyA); !errors.As(err, &hk) || !strings.Contains(hk.Reason, "accept-new") {
		t.Errorf("strict must reject unknown hosts with guidance, got %v", err)
	}

	// insecure accepts anything.
	insecure, err := NewHostKeyCallback(path, PolicyInsecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := insecure("anything:22", other, keyB); err != nil {
		t.Errorf("insecure policy rejected a key: %v", err)
	}
}

func TestConnectRequiresHostKeyVerification(t *testing.T) {
	prof, _ := vendor.Lookup("cisco")
	_, err := Connect(context.Background(), Config{Address: "192.0.2.1:22", Profile: prof})
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindHostKey {
		t.Fatalf("err = %v, want a hostkey error", err)
	}
}

func TestClassifyHandshake(t *testing.T) {
	cases := []struct {
		err  error
		kind string
	}{
		{errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain"), KindAuth},
		{errors.New("ssh: handshake failed: " + (&HostKeyError{Host: "h", Reason: "x"}).Error()), KindHostKey},
		{errors.New("ssh: handshake failed: read tcp 1.2.3.4:5->6.7.8.9:22: i/o timeout"), KindTimeout},
		{errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange"), KindConnect},
		{errors.New("ssh: handshake failed: EOF"), KindConnect},
	}
	for _, c := range cases {
		err := classifyHandshake(c.err, "admin")
		var e *Error
		if !errors.As(err, &e) || e.Kind != c.kind {
			t.Errorf("classifyHandshake(%q) kind = %v, want %s", c.err, err, c.kind)
		}
	}
	err := classifyHandshake(errors.New("ssh: unable to authenticate"), "admin")
	if strings.Contains(err.Error(), "password") {
		t.Errorf("auth error text should not mention the password: %v", err)
	}
	err = classifyHandshake(errors.New("no common algorithm"), "admin")
	if !strings.Contains(err.Error(), "-legacy-algorithms") {
		t.Errorf("algorithm mismatch should hint at -legacy-algorithms: %v", err)
	}
}

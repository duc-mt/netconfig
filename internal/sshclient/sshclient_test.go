// ==============================================================================
// Package main implements Implementation and logic for sshclient_test..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run sshclient_test.go [options]
// Notes:         Go package implementation
// ==============================================================================
package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

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
	cancel() // cancel immediately to avoid CI flakes
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
		"strict": PolicyStrict, " Accept-New ": PolicyAcceptNew, "INSECURE": PolicyInsecure, //nolint:gocritic // tests whitespace trimming
		"update": PolicyUpdate, "replace": PolicyReplace,
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

	// Calling accept again on the same host must succeed in-memory without duplicate file appends
	if err := accept(host, remote, keyA); err != nil {
		t.Fatalf("repeated accept-new call failed: %v", err)
	}
	data2, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data2), "192.0.2.10") != 1 {
		t.Fatalf("expected exactly 1 entry for host, got %d:\n%s", strings.Count(string(data2), "192.0.2.10"), data2)
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

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("user home dir not available")
	}

	if got := ExpandHome("~"); got != home {
		t.Errorf("ExpandHome(~) = %q, want %q", got, home)
	}
	wantPath := filepath.Join(home, ".ssh", "known_hosts")
	if got := ExpandHome("~/.ssh/known_hosts"); got != wantPath {
		t.Errorf("ExpandHome(~/.ssh/known_hosts) = %q, want %q", got, wantPath)
	}
	if got := ExpandHome(`~\.ssh\known_hosts`); got != wantPath {
		t.Errorf(`ExpandHome(~\\.ssh\\known_hosts) = %q, want %q`, got, wantPath)
	}
	if got := ExpandHome("/tmp/known_hosts"); got != "/tmp/known_hosts" {
		t.Errorf("ExpandHome(/tmp/known_hosts) = %q, want %q", got, "/tmp/known_hosts")
	}
}

func TestDefaultKnownHostsFile(t *testing.T) {
	path := DefaultKnownHostsFile()
	if path == "" {
		t.Fatal("DefaultKnownHostsFile returned empty string")
	}
	if !strings.HasSuffix(filepath.ToSlash(path), ".ssh/known_hosts") && path != "known_hosts" {
		t.Errorf("unexpected default path %q", path)
	}
}

func TestNewHostKeyCallbackWithSystemKnownHosts(t *testing.T) {
	dir := t.TempDir()
	fakeHome := filepath.Join(dir, "userhome")
	t.Setenv("HOME", fakeHome)
	t.Setenv("USERPROFILE", fakeHome)

	userKhPath := filepath.Join(fakeHome, ".ssh", "known_hosts")
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 22}
	key := newKey(t)

	// In accept-new mode with default user known_hosts, ensure file and parent dirs get created
	cb, err := NewHostKeyCallback(userKhPath, PolicyAcceptNew)
	if err != nil {
		t.Fatalf("NewHostKeyCallback accept-new failed: %v", err)
	}
	if err := cb("192.0.2.20:22", remote, key); err != nil {
		t.Fatalf("cb enrollment failed: %v", err)
	}

	data, err := os.ReadFile(userKhPath)
	if err != nil {
		t.Fatalf("reading user known_hosts: %v", err)
	}
	if !strings.Contains(string(data), "192.0.2.20") {
		t.Fatalf("host key not enrolled into %s: %s", userKhPath, string(data))
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

func startMockSSHServer(t *testing.T) (int, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "testuser" && string(pass) == "testpass" {
				return nil, nil
			}
			return nil, errors.New("password rejected")
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	done := make(chan struct{})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
				default:
				}
				return
			}
			go func(c net.Conn) {
				sConn, chans, reqs, err := ssh.NewServerConn(c, serverConfig)
				if err != nil {
					_ = c.Close()
					return
				}
				defer sConn.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					ch, requests, err := newChan.Accept()
					if err != nil {
						continue
					}
					go func(channel ssh.Channel, in <-chan *ssh.Request) {
						defer channel.Close()
						for req := range in {
							switch req.Type {
							case "pty-req":
								req.Reply(true, nil)
							case "shell":
								req.Reply(true, nil)
								// Write prompt and respond to commands
								_, _ = channel.Write([]byte("Router#"))
								buf := make([]byte, 1024)
								for {
									n, err := channel.Read(buf)
									if err != nil || n == 0 {
										return
									}
									_, _ = channel.Write([]byte("\r\noutput\r\nRouter#"))
								}
							default:
								req.Reply(false, nil)
							}
						}
					}(ch, requests)
				}
			}(conn)
		}
	}()

	return port, func() {
		close(done)
		_ = listener.Close()
	}
}

func startMockSSHForwarder(t *testing.T, targetAddr string) (int, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "jumpuser" && string(pass) == "jumppass" {
				return nil, nil
			}
			return nil, errors.New("password rejected")
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	done := make(chan struct{})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
				default:
				}
				return
			}
			go func(c net.Conn) {
				sConn, chans, reqs, err := ssh.NewServerConn(c, serverConfig)
				if err != nil {
					_ = c.Close()
					return
				}
				defer sConn.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "direct-tcpip" {
						newChan.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, _, err := newChan.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer ch.Close()
						target, err := net.Dial("tcp", targetAddr)
						if err != nil {
							return
						}
						defer target.Close()
						doneCh := make(chan struct{}, 2)
						copyPipe := func(dst, src interface {
							Read([]byte) (int, error)
							Write([]byte) (int, error)
						}) {
							b := make([]byte, 16*1024)
							for {
								n, rerr := src.Read(b)
								if n > 0 {
									if _, werr := dst.Write(b[:n]); werr != nil {
										break
									}
								}
								if rerr != nil {
									break
								}
							}
							doneCh <- struct{}{}
						}
						go copyPipe(target, ch)
						go copyPipe(ch, target)
						<-doneCh
					}()
				}
			}(conn)
		}
	}()

	return port, func() {
		close(done)
		_ = listener.Close()
	}
}

func TestConnectViaJump(t *testing.T) {
	targetPort, targetCleanup := startMockSSHServer(t)
	defer targetCleanup()

	targetAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", targetPort))

	bastionPort, bastionCleanup := startMockSSHForwarder(t, targetAddr)
	defer bastionCleanup()

	bastionAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", bastionPort))

	jumpClient, err := ConnectJumpHost(context.Background(), bastionAddr, "jumpuser", "jumppass", "", 2*time.Second, ssh.InsecureIgnoreHostKey(), false)
	if err != nil {
		t.Fatalf("ConnectJumpHost failed: %v", err)
	}
	defer jumpClient.Close()

	prof, _ := vendor.Lookup("cisco")
	sh, err := ConnectViaJump(context.Background(), jumpClient, Config{
		Address:        targetAddr,
		Username:       "testuser",
		Password:       "testpass",
		Profile:        prof,
		ConnectTimeout: 2 * time.Second,
		LoginTimeout:   2 * time.Second,
		HostKey:        ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("ConnectViaJump failed: %v", err)
	}
	defer sh.Close()

	out, err := sh.Send(context.Background(), "show clock", 2*time.Second)
	if err != nil {
		t.Fatalf("sh.Send failed: %v", err)
	}
	if !strings.Contains(out, "output") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestCheckKeyPermissions(t *testing.T) {
	if CheckKeyPermissions("") != "" {
		t.Errorf("expected empty string for empty path")
	}

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test_key")

	if err := os.WriteFile(keyFile, []byte("fake-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if warn := CheckKeyPermissions(keyFile); warn != "" {
		t.Errorf("expected no warning for 0600 file, got: %s", warn)
	}

	// Make permissions permissive (0644)
	_ = os.Chmod(keyFile, 0o644)
	if warn := CheckKeyPermissions(keyFile); warn == "" {
		t.Errorf("expected warning for 0644 file, got none")
	}
}

func TestKnownHostsPolicyUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPubA, err := ssh.NewPublicKey(pubA)
	if err != nil {
		t.Fatal(err)
	}

	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPubB, err := ssh.NewPublicKey(pubB)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Initial write of Key A for test-host:22
	initialLine := knownhosts.Line([]string{"test-host:22"}, sshPubA)
	if err := os.WriteFile(khPath, []byte(initialLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. Strict policy should reject Key B
	cbStrict, err := NewHostKeyCallback(khPath, PolicyStrict)
	if err != nil {
		t.Fatal(err)
	}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	err = cbStrict("test-host:22", remoteAddr, sshPubB)
	if err == nil {
		t.Fatal("expected Strict policy to reject mismatched key, but it succeeded")
	}

	// 3. Update policy should replace Key A with Key B and succeed
	cbUpdate, err := NewHostKeyCallback(khPath, PolicyUpdate)
	if err != nil {
		t.Fatal(err)
	}
	err = cbUpdate("test-host:22", remoteAddr, sshPubB)
	if err != nil {
		t.Fatalf("expected Update policy to succeed and replace key, got: %v", err)
	}

	// 4. Verify known_hosts now has Key B
	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, string(sshPubB.Marshal())) && !strings.Contains(content, strings.Fields(knownhosts.Line([]string{"test-host:22"}, sshPubB))[2]) {
		t.Errorf("expected known_hosts to contain new key B line, got: %s", content)
	}

	// 5. Connecting with Key B again should succeed immediately
	if err := cbUpdate("test-host:22", remoteAddr, sshPubB); err != nil {
		t.Fatalf("re-verification with Key B failed: %v", err)
	}
}

func TestBuildClientConfigAlgorithms(t *testing.T) {
	// Modern config
	ccModern, err := buildClientConfig("user", "pass", "", ssh.InsecureIgnoreHostKey(), false)
	if err != nil {
		t.Fatal(err)
	}

	hasGroup16 := slices.Contains(ccModern.Config.KeyExchanges, "diffie-hellman-group16-sha512")
	if !hasGroup16 {
		t.Errorf("expected modern KeyExchanges to contain diffie-hellman-group16-sha512")
	}
	hasGroupEx256 := slices.Contains(ccModern.Config.KeyExchanges, "diffie-hellman-group-exchange-sha256")
	if !hasGroupEx256 {
		t.Errorf("expected modern KeyExchanges to contain diffie-hellman-group-exchange-sha256")
	}

	// Legacy config
	ccLegacy, err := buildClientConfig("user", "pass", "", ssh.InsecureIgnoreHostKey(), true)
	if err != nil {
		t.Fatal(err)
	}

	hasGroupEx1 := slices.Contains(ccLegacy.Config.KeyExchanges, "diffie-hellman-group-exchange-sha1")
	if !hasGroupEx1 {
		t.Errorf("expected legacy KeyExchanges to contain diffie-hellman-group-exchange-sha1")
	}
	hasArcfour := slices.Contains(ccLegacy.Config.Ciphers, "arcfour")
	if !hasArcfour {
		t.Errorf("expected legacy Ciphers to contain arcfour")
	}
	hasDSA := slices.Contains(ccLegacy.HostKeyAlgorithms, ssh.KeyAlgoDSA) //nolint:staticcheck // SA1019: required for legacy network appliances
	if !hasDSA {
		t.Errorf("expected legacy HostKeyAlgorithms to contain ssh-dss")
	}
}

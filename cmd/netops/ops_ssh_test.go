// ==============================================================================
// File name:     ops_ssh_test.go
// Description:   The automation subcommands over a REAL SSH connection to an
//
//	in-process mock device: proves the post-change login test is
//	a genuine, separate SSH handshake with the new credentials.
//
// License:       MIT
// ==============================================================================
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"netops/internal/sshclient"
	"netops/internal/task"
)

// startMockDevice serves the virtual device over SSH and returns its port.
// Logins are checked against the device's account table, and every login and
// command is appended to dev.events in order.
func startMockDevice(t *testing.T, dev *opsDev) int {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			dev.mu.Lock()
			defer dev.mu.Unlock()
			hash, ok := dev.users[c.User()]
			if !ok || hash != opsHash(string(pass)) || dev.reject[c.User()] == string(pass) {
				dev.events = append(dev.events, "login:"+c.User()+":denied")
				return nil, errors.New("password rejected")
			}
			// the password itself is never recorded, only which account got in
			dev.events = append(dev.events, "login:"+c.User()+":"+opsHash(string(pass)))
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMockConn(conn, cfg, dev)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveMockConn(c net.Conn, cfg *ssh.ServerConfig, dev *opsDev) {
	sConn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, in, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			sess := &opsSess{d: dev}
			prompt := func() string {
				if sess.inCfg {
					return "sw1(config)#"
				}
				return "sw1#"
			}
			for req := range in {
				switch req.Type {
				case "pty-req":
					_ = req.Reply(true, nil)
				case "shell":
					_ = req.Reply(true, nil)
					_, _ = ch.Write([]byte(prompt()))
					var line []byte
					buf := make([]byte, 512)
					for {
						n, err := ch.Read(buf)
						if err != nil || n == 0 {
							return
						}
						for _, b := range buf[:n] {
							if b != '\r' && b != '\n' {
								line = append(line, b)
								continue
							}
							if len(line) == 0 {
								continue
							}
							out, _ := sess.Send(context.Background(), string(line), 0)
							line = line[:0]
							_, _ = ch.Write([]byte("\r\n" + strings.ReplaceAll(out, "\n", "\r\n") + prompt()))
						}
					}
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

// sshWS is a workspace whose single switch is a live SSH server.
func sshWS(t *testing.T) (*opsWS, *opsDev) {
	t.Helper()
	dev := newOpsDev()
	port := startMockDevice(t, dev)
	w := newOpsWS(t, fmt.Sprintf("hostname,address,port,vendor,credential_group\nsw1,127.0.0.1,%d,cisco,\n", port))
	// use the real SSH transport this time
	newOpsTransport = func(h sshclient.HostKeyCallback, legacy bool, pool *jumpPool, fb []task.Target, mss int) task.Transport {
		return sshTransport{hostKey: h, legacy: legacy, autoConfirm: true, pool: pool, autoFallback: fb, tcpMSS: mss}
	}
	w.base = append(w.base, "-host-key-policy", "accept-new", "-connect-timeout", "5s", "-command-timeout", "5s")
	return w, dev
}

func indexOf(events []string, prefix string) int {
	for i, e := range events {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

func TestPasswdOverRealSSHTestsNewCredentialsBeforeSaving(t *testing.T) {
	w, dev := sshWS(t)
	t.Setenv("NETOPS_NEW_PASSWORD", "N3wPassw0rd")
	code, _, stderr := w.run("config", "passwd", "-u", "bob", "-yes")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if dev.users["bob"] != opsHash("N3wPassw0rd") || dev.writes != 1 {
		t.Fatalf("rotation not applied/saved: writes=%d", dev.writes)
	}
	// ordering on the wire: change applied, then a fresh SSH login as bob with the
	// NEW password succeeded, and only then was the configuration saved
	applied := indexOf(dev.events, "cmd:username bob secret 0 ")
	login := indexOf(dev.events, "login:bob:"+opsHash("N3wPassw0rd"))
	saved := indexOf(dev.events, "cmd:write memory")
	if applied < 0 || login < 0 || saved < 0 || !(applied < login && login < saved) {
		t.Errorf("want apply < new-credential login < save, got %d %d %d in %v", applied, login, saved, dev.events)
	}
	mustNotHave(t, "stderr", stderr, "N3wPassw0rd")
	mustNotHave(t, "audit log", w.logText(), "N3wPassw0rd")
}

func TestPasswdOverRealSSHRollsBackWhenTheNewLoginIsDenied(t *testing.T) {
	w, dev := sshWS(t)
	dev.reject["bob"] = "N3wPassw0rd" // the config line is accepted but the account cannot log in
	before := dev.users["bob"]
	t.Setenv("NETOPS_NEW_PASSWORD", "N3wPassw0rd")
	code, _, stderr := w.run("config", "passwd", "-u", "bob", "-yes")
	if code != task.ExitPartial {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stderr", stderr, "VERIFY_FAILED", "was rejected")
	if dev.users["bob"] != before {
		t.Errorf("previous credential was not restored")
	}
	if dev.writes != 0 || indexOf(dev.events, "cmd:write memory") >= 0 {
		t.Error("a rotation whose login test failed was saved")
	}
	if indexOf(dev.events, "login:bob:denied") < 0 {
		t.Errorf("the denied login attempt never happened: %v", dev.events)
	}
	// and the old password still works over SSH afterwards
	if dev.users["bob"] != opsHash("oldpass") {
		t.Error("bob's old password no longer works")
	}
	mustNotHave(t, "stderr", stderr, "N3wPassw0rd")
}

func TestUserAddAndVLANOverRealSSH(t *testing.T) {
	w, dev := sshWS(t)
	t.Setenv("NETOPS_NEW_PASSWORD", "S3cretPass")
	if code, _, stderr := w.run("config", "user", "add", "-u", "alice", "-yes"); code != task.ExitOK {
		t.Fatalf("user add: exit %d\n%s", code, stderr)
	}
	if code, _, stderr := w.run("config", "vlan", "add", "--id", "30", "--name", "Servers", "-yes"); code != task.ExitOK {
		t.Fatalf("vlan add: exit %d\n%s", code, stderr)
	}
	if dev.users["alice"] != opsHash("S3cretPass") || dev.vlans[30] != "Servers" || dev.writes != 2 {
		t.Errorf("users=%v vlans=%v writes=%d", dev.users, dev.vlans, dev.writes)
	}
	// second pass over SSH is a no-op
	writes := dev.writes
	if code, _, _ := w.run("config", "user", "add", "-u", "alice", "-yes"); code != task.ExitOK || dev.writes != writes {
		t.Errorf("not idempotent over SSH: writes %d -> %d", writes, dev.writes)
	}
	// a wrong login is reported as an authentication failure, not a hang
	if err := os.WriteFile(filepath.Join(w.dir, ".env"), []byte("NETOPS_USERNAME=admin\nNETOPS_PASSWORD=wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := w.run("config", "user", "add", "-u", "zed", "-yes")
	if code != task.ExitPartial {
		t.Errorf("bad login: exit %d", code)
	}
	mustContain(t, "stderr", stderr, "AUTH_FAILED")
}

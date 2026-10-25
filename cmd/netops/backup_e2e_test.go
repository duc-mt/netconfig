// ==============================================================================
// File name:     backup_e2e_test.go
// Description:   "netops backup" against scripted devices over real SSH.
// License:       MIT
// ==============================================================================
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"netops/internal/task"
)

// scriptedDevice is a CLI over a real SSH server: it echoes what it is sent,
// answers a fixed set of commands and ends every answer with its prompt.
type scriptedDevice struct {
	user, pass string
	prompt     string
	commands   map[string]string // command -> output; others are rejected
	rejection  string

	attempts atomic.Int32 // password attempts, right or wrong
	mu       sync.Mutex
	received []string
}

func (d *scriptedDevice) log() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.received...)
}

func startScriptedDevice(t *testing.T, d *scriptedDevice) int {
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
			d.attempts.Add(1)
			if c.User() == d.user && string(pass) == d.pass {
				return nil, nil
			}
			return nil, errors.New("password rejected")
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
			go d.serve(conn, cfg)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func (d *scriptedDevice) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sconn.Close()
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
			for req := range in {
				switch req.Type {
				case "pty-req":
					_ = req.Reply(true, nil)
				case "shell":
					_ = req.Reply(true, nil)
					d.shell(ch)
					return
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

func (d *scriptedDevice) shell(ch ssh.Channel) {
	_, _ = ch.Write([]byte(d.prompt))
	var line []byte
	buf := make([]byte, 256)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		for _, b := range buf[:n] {
			if b != '\n' && b != '\r' {
				line = append(line, b)
				continue
			}
			cmd := strings.TrimSpace(string(line))
			line = line[:0]
			d.mu.Lock()
			if cmd != "" {
				d.received = append(d.received, cmd)
			}
			d.mu.Unlock()
			out, ok := d.commands[cmd]
			if cmd != "" && !ok {
				out = d.rejection
			}
			resp := cmd + "\r\n"
			if out != "" {
				resp += strings.ReplaceAll(out, "\n", "\r\n") + "\r\n"
			}
			_, _ = ch.Write([]byte(resp + d.prompt))
		}
	}
}

const asaRunningConfig = `: Saved
:
ASA Version 9.16(4)
!
hostname asa1
enable password 8Ry2YjIyt7RRXU24 encrypted
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
!
tunnel-group 198.51.100.7 ipsec-attributes
 ikev1 pre-shared-key S3cretPSKvalue
!
: end`

const sbRunningConfig = `config-file-header
sb1
CLI v1.0
set system mode switch
!
username cisco password encrypted 6b3c7f1a2d4e5f60718293a4b5c6d7e8 privilege 15
enable password level 15 encrypted 7f1a2d4e5f60718293a4b5c6d7e8aabb
vlan database
vlan 10
exit
interface gigabitethernet1
 description uplink
exit
interface gigabitethernet2
 description access
exit`

// The whole path, with nothing faked: SSH handshake, login and prompt
// detection, paging suppression, the backup command, validation of what a
// real Send returns, redaction and saving.
func TestBackupOverRealSSH(t *testing.T) {
	asa := &scriptedDevice{
		user: "admin", pass: "s3cr3t-pw", prompt: "asa1# ",
		commands:  map[string]string{"terminal pager 0": "", "show running-config": asaRunningConfig},
		rejection: "ERROR: % Invalid input detected at '^' marker.",
	}
	// SF/SG/CBS: accepts "terminal datadump", refuses "terminal length 0"
	sb := &scriptedDevice{
		user: "admin", pass: "s3cr3t-pw", prompt: "sb1# ",
		commands:  map[string]string{"terminal datadump": "", "show running-config": sbRunningConfig},
		rejection: "% Unrecognized command",
	}
	locked := &scriptedDevice{
		user: "admin", pass: "the-right-password", prompt: "locked# ",
		commands: map[string]string{"show running-config": "version 15.2\n!\nend"},
	}
	asaPort, sbPort, lockedPort := startScriptedDevice(t, asa), startScriptedDevice(t, sb), startScriptedDevice(t, locked)

	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inv := write("inventory.csv", "hostname,address,port,vendor,credential_group\n"+
		"asa1,127.0.0.1,"+strconv.Itoa(asaPort)+",cisco_asa,\n"+
		"sb1,127.0.0.1,"+strconv.Itoa(sbPort)+",sg350,\n"+
		"locked,127.0.0.1,"+strconv.Itoa(lockedPort)+",cisco,wrongpw\n")
	env := write(".env", "NETOPS_USERNAME=admin\nNETOPS_PASSWORD=s3cr3t-pw\n"+
		"NETOPS_WRONGPW_USERNAME=admin\nNETOPS_WRONGPW_PASSWORD=not-the-password\n")

	in, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out, errb strings.Builder
	code := dispatch([]string{
		"backup", "-inventory", inv, "-env-file", env, "-redact",
		"-backup-dir", filepath.Join(dir, "backups"), "-log-dir", filepath.Join(dir, "logs"),
		"-known-hosts", filepath.Join(dir, "known_hosts"), "-host-key-policy", "accept-new",
		"-memory=false", "-jump=false", "-tcp-mss", "0", "-dial-jitter", "0", "-no-color",
		"-retries", "3", "-retry-delay", "1ms",
		"-connect-timeout", "5s", "-command-timeout", "5s",
	}, in, &out, &errb)
	stderr := errb.String()
	if code != task.ExitPartial {
		t.Fatalf("exit %d, want %d (one device has the wrong password)\n%s", code, task.ExitPartial, stderr)
	}

	read := func(rel string) string {
		matches, _ := filepath.Glob(filepath.Join(dir, "backups", "backup-*", filepath.FromSlash(rel)))
		if len(matches) != 1 {
			t.Fatalf("expected exactly one %s, found %v\n%s", rel, matches, stderr)
		}
		data, err := os.ReadFile(matches[0])
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	// ASA: the backup ends in a bare ": end" once Send has stripped the prompt
	// line; it must be recognised as complete and the secrets masked.
	asaFile := read("cisco_asa/asa1.cfg")
	for _, secret := range []string{"8Ry2YjIyt7RRXU24", "S3cretPSKvalue"} {
		if strings.Contains(asaFile, secret) {
			t.Errorf("ASA backup contains the secret %q:\n%s", secret, asaFile)
		}
	}
	for _, want := range []string{"hostname asa1", "ip address 203.0.113.2", "ikev1 pre-shared-key <REDACTED>", ": end"} {
		if !strings.Contains(asaFile, want) {
			t.Errorf("ASA backup is missing %q:\n%s", want, asaFile)
		}
	}
	if got := strings.Join(asa.log(), " | "); got != "terminal pager 0 | show running-config" {
		t.Errorf("the ASA was sent %q", got)
	}

	// Small Business: the refused "terminal length 0" does not fail the backup
	sbFile := read("cisco_sb/sb1.cfg")
	for _, secret := range []string{"6b3c7f1a2d4e5f60", "7f1a2d4e5f60"} {
		if strings.Contains(sbFile, secret) {
			t.Errorf("SB backup contains the hash %q:\n%s", secret, sbFile)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(sbFile), "exit") || !strings.Contains(sbFile, "interface gigabitethernet2") {
		t.Errorf("SB backup is incomplete:\n%s", sbFile)
	}
	if got := strings.Join(sb.log(), " | "); got != "terminal datadump | terminal length 0 | show running-config" {
		t.Errorf("the SB switch was sent %q", got)
	}

	// A wrong password is tried once, however many retries were asked for:
	// every attempt counts towards an account lockout.
	if n := locked.attempts.Load(); n != 1 {
		t.Errorf("the device with the wrong password saw %d login attempts, want 1", n)
	}
	for _, want := range []string{"FAILED  locked", "AUTHENTICATION_FAILED", "Devices: 3 total, 2 succeeded, 1 failed"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("run summary is missing %q:\n%s", want, stderr)
		}
	}
	for _, secret := range []string{"s3cr3t-pw", "not-the-password", "the-right-password"} {
		if strings.Contains(stderr, secret) || strings.Contains(out.String(), secret) {
			t.Errorf("the password %q appeared in the output", secret)
		}
	}
}

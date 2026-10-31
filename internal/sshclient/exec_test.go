// ==============================================================================
// File name:     exec_test.go
// Description:   Tests for the exec-mode SSH helpers used by "netops log",
//                against in-process mock SSH servers and a bastion.
// License:       MIT
// ==============================================================================

package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// dialPW, dialJumpHostPW and dialViaJumpPW are password-only shorthands for the
// Dial*WithAuth functions.
func dialPW(ctx context.Context, address string, port int, user, pass string, opts ExecOptions) (*ssh.Client, error) {
	return DialWithAuth(ctx, address, port, AuthOptions{Username: user, Password: pass}, opts)
}

func dialJumpHostPW(ctx context.Context, address string, port int, user, pass string, opts ExecOptions) (*ssh.Client, error) {
	return DialJumpHostWithAuth(ctx, address, port, AuthOptions{Username: user, Password: pass}, opts)
}

func dialViaJumpPW(ctx context.Context, jump *ssh.Client, address string, port int, user, pass string, opts ExecOptions) (*ssh.Client, error) {
	return DialViaJumpWithAuth(ctx, jump, address, port, AuthOptions{Username: user, Password: pass}, opts)
}

func startExecMockSSHServer(t *testing.T) (int, func()) {
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
			return nil, fmt.Errorf("password rejected")
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if c.User() == "kbuser" {
				answers, err := client(c.User(), "", []string{"Password: "}, []bool{false})
				if err == nil && len(answers) == 1 && answers[0] == "kbpass" {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("keyboard interactive rejected")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "keyuser" {
				return nil, nil
			}
			return nil, fmt.Errorf("public key rejected")
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
					return
				default:
					return
				}
			}

			go handleExecSSHConn(conn, serverConfig)
		}
	}()

	return port, func() {
		close(done)
		_ = listener.Close()
	}
}

func handleExecSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	defer sConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}

		go handleExecSession(channel, requests)
	}
}

func handleExecSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "pty-req":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			// Read commands from stdin and respond
			go func() {
				buf := make([]byte, 1024)
				paged := false
				for {
					n, err := channel.Read(buf)
					if err != nil || n == 0 {
						return
					}
					input := string(buf[:n])
					switch {
					case strings.Contains(input, "page-test"):
						paged = true
						_, _ = channel.Write([]byte("hostname paged-router\n--More--"))
					case paged && strings.Contains(input, " "):
						paged = false
						_, _ = channel.Write([]byte("\ninterface gig0/2\nend\n"))
					case strings.Contains(input, "show"):
						_, _ = channel.Write([]byte("hostname router-sw-01\ninterface GigabitEthernet0/1\n"))
					default:
						_, _ = channel.Write([]byte("ok\n"))
					}
				}
			}()
		case "exec":
			cmd := ""
			if len(req.Payload) >= 4 {
				cmd = string(req.Payload[4:])
			}
			req.Reply(true, nil)
			if strings.Contains(cmd, "sleep") {
				time.Sleep(500 * time.Millisecond)
			}
			if strings.Contains(cmd, "error") {
				_, _ = channel.Stderr().Write([]byte("syntax error in command"))
				_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
			} else {
				_, _ = channel.Write([]byte("! Configuration\nhostname core-switch-01\nend\n"))
				_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			}
			return
		default:
			req.Reply(false, nil)
		}
	}
}

func TestExecDialAndPasswordAuth(t *testing.T) {
	port, cleanup := startExecMockSSHServer(t)
	defer cleanup()

	opts := ExecOptions{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  2 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 1. Successful password authentication
	client, err := dialPW(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("expected successful connect: %v", err)
	}
	defer client.Close()

	// 2. RunCommand test
	out, err := RunCommand(context.Background(), client, "show run", opts)
	if err != nil {
		t.Fatalf("expected successful command run: %v", err)
	}
	if !strings.Contains(out, "core-switch-01") {
		t.Errorf("unexpected command output: %q", out)
	}

	// 3. RunCommand error test
	_, err = RunCommand(context.Background(), client, "error cmd", opts)
	if err == nil {
		t.Fatalf("expected command error")
	}
	if !strings.Contains(err.Error(), "syntax error in command") {
		t.Errorf("expected stderr message in error, got: %v", err)
	}

	// 4. Failed authentication
	_, err = dialPW(context.Background(), "127.0.0.1", port, "testuser", "wrongpass", opts)
	if err == nil {
		t.Fatalf("expected connection to fail with wrong password")
	}
}

func TestExecKeyboardInteractiveAuth(t *testing.T) {
	port, cleanup := startExecMockSSHServer(t)
	defer cleanup()

	opts := ExecOptions{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  2 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect using keyboard-interactive credentials
	client, err := dialPW(context.Background(), "127.0.0.1", port, "kbuser", "kbpass", opts)
	if err != nil {
		t.Fatalf("expected successful connect with keyboard-interactive: %v", err)
	}
	defer client.Close()
}

func TestExecPublicKeyAuth(t *testing.T) {
	port, cleanup := startExecMockSSHServer(t)
	defer cleanup()

	// Generate client private key
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	pemBytes, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBytes), 0o600); err != nil {
		t.Fatalf("writing temp key file: %v", err)
	}

	opts := ExecOptions{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  2 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 1. Connect with private key file
	client, err := DialWithAuth(context.Background(), "127.0.0.1", port, AuthOptions{
		Username: "keyuser",
		KeyFile:  keyFile,
	}, opts)
	if err != nil {
		t.Fatalf("expected successful connect with public key: %v", err)
	}
	defer client.Close()

	// 2. Reject unknown keyuser
	_, err = DialWithAuth(context.Background(), "127.0.0.1", port, AuthOptions{
		Username: "wrongkeyuser",
		KeyFile:  keyFile,
	}, opts)
	if err == nil {
		t.Fatalf("expected connection to fail for wrong key user")
	}
}

func TestExecRunCommandTimeout(t *testing.T) {
	port, cleanup := startExecMockSSHServer(t)
	defer cleanup()

	opts := ExecOptions{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  100 * time.Millisecond,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := dialPW(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	_, err = RunCommand(context.Background(), client, "sleep 5", opts)
	if err == nil {
		t.Fatalf("expected command timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExecRunCommandContextCancellation(t *testing.T) {
	port, cleanup := startExecMockSSHServer(t)
	defer cleanup()

	opts := ExecOptions{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  5 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := dialPW(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = RunCommand(ctx, client, "sleep 5", opts)
	if err == nil {
		t.Fatalf("expected command cancellation error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("expected context cancellation error, got: %v", err)
	}
}

func TestExecRunInteractive(t *testing.T) {
	port, cleanup := startExecMockSSHServer(t)
	defer cleanup()

	opts := ExecOptions{
		ConnectTimeout:  5 * time.Second,
		CommandTimeout:  10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := dialPW(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	output, err := RunInteractive(context.Background(), client, []string{"terminal length 0", "show run"}, opts)
	if err != nil {
		t.Fatalf("RunInteractive failed: %v", err)
	}
	if !strings.Contains(output, "router-sw-01") {
		t.Errorf("unexpected output from RunInteractive: %q", output)
	}
}

func TestExecRunInteractivePager(t *testing.T) {
	port, cleanup := startExecMockSSHServer(t)
	defer cleanup()

	opts := ExecOptions{
		ConnectTimeout:  5 * time.Second,
		CommandTimeout:  10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := dialPW(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	output, err := RunInteractive(context.Background(), client, []string{"page-test"}, opts)
	if err != nil {
		t.Fatalf("RunInteractive failed with pager: %v", err)
	}
	if !strings.Contains(output, "paged-router") || !strings.Contains(output, "gig0/2") {
		t.Errorf("expected complete output across pager, got: %q", output)
	}
	if strings.Contains(output, "--More--") {
		t.Errorf("expected --More-- markers to be cleaned up, got: %q", output)
	}
}

func TestExecLegacyAlgorithmsOption(t *testing.T) {
	optsModern := ExecOptions{
		ConnectTimeout:   2 * time.Second,
		LegacyAlgorithms: false,
	}
	cfgModern, err := buildExecClientConfig(AuthOptions{Username: "u", Password: "p"}, ssh.InsecureIgnoreHostKey(), optsModern)
	if err != nil {
		t.Fatalf("buildExecClientConfig modern failed: %v", err)
	}
	for _, c := range cfgModern.Ciphers {
		if c == "3des-cbc" || c == "aes128-cbc" || c == "arcfour" {
			t.Errorf("did not expect legacy cipher %s in modern config", c)
		}
	}
	hasDH16 := false
	hasDHGEX256 := false
	for _, k := range cfgModern.KeyExchanges {
		if k == "diffie-hellman-group16-sha512" {
			hasDH16 = true
		}
		if k == "diffie-hellman-group-exchange-sha256" {
			hasDHGEX256 = true
		}
		if k == "diffie-hellman-group-exchange-sha1" || k == "diffie-hellman-group1-sha1" {
			t.Errorf("did not expect legacy kex %s in modern config", k)
		}
	}
	if !hasDH16 {
		t.Errorf("expected diffie-hellman-group16-sha512 in modern config, kex: %v", cfgModern.KeyExchanges)
	}
	if !hasDHGEX256 {
		t.Errorf("expected diffie-hellman-group-exchange-sha256 in modern config, kex: %v", cfgModern.KeyExchanges)
	}

	optsLegacy := ExecOptions{
		ConnectTimeout:   2 * time.Second,
		LegacyAlgorithms: true,
	}
	cfgLegacy, err := buildExecClientConfig(AuthOptions{Username: "u", Password: "p"}, ssh.InsecureIgnoreHostKey(), optsLegacy)
	if err != nil {
		t.Fatalf("buildExecClientConfig legacy failed: %v", err)
	}
	has3DES := false
	hasArcfour := false
	for _, c := range cfgLegacy.Ciphers {
		if c == "3des-cbc" {
			has3DES = true
		}
		if c == "arcfour" {
			hasArcfour = true
		}
	}
	if !has3DES {
		t.Errorf("expected 3des-cbc in legacy config, ciphers: %v", cfgLegacy.Ciphers)
	}
	if !hasArcfour {
		t.Errorf("expected arcfour in legacy config, ciphers: %v", cfgLegacy.Ciphers)
	}
	hasDHGEX1 := false
	hasDSA := false
	for _, k := range cfgLegacy.KeyExchanges {
		if k == "diffie-hellman-group-exchange-sha1" {
			hasDHGEX1 = true
		}
	}
	for _, hk := range cfgLegacy.HostKeyAlgorithms {
		if hk == "ssh-dss" {
			hasDSA = true
		}
	}
	if !hasDHGEX1 {
		t.Errorf("expected diffie-hellman-group-exchange-sha1 in legacy config, kex: %v", cfgLegacy.KeyExchanges)
	}
	if !hasDSA {
		t.Errorf("expected ssh-dss in legacy host keys, got: %v", cfgLegacy.HostKeyAlgorithms)
	}
}

func startExecMockForwarder(t *testing.T, targetAddr string) (int, func()) {
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
			return nil, fmt.Errorf("password rejected")
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
			go handleExecBastionConn(conn, serverConfig, targetAddr)
		}
	}()

	return port, func() {
		close(done)
		_ = listener.Close()
	}
}

// handleExecBastionConn handles SSH connections on the mock bastion, proxying
// direct-tcpip channel requests to targetAddr.
func handleExecBastionConn(conn net.Conn, config *ssh.ServerConfig, targetAddr string) {
	sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-tcpip":
			// Accept the channel and pipe it to the real target.
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
				done := make(chan struct{}, 2)
				copy := func(dst, src interface {
					Read([]byte) (int, error)
					Write([]byte) (int, error)
				}) {
					buf := make([]byte, 32*1024)
					for {
						n, err := src.Read(buf)
						if n > 0 {
							if _, werr := dst.Write(buf[:n]); werr != nil {
								break
							}
						}
						if err != nil {
							break
						}
					}
					done <- struct{}{}
				}
				go copy(target, ch)
				go copy(ch, target)
				<-done
			}()
		default:
			newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported on this bastion")
		}
	}
}

func TestExecDialViaJump(t *testing.T) {
	// Start the "real" target SSH server.
	targetPort, targetCleanup := startExecMockSSHServer(t)
	defer targetCleanup()

	targetAddr := fmt.Sprintf("127.0.0.1:%d", targetPort)

	// Start the bastion that can forward to the target.
	bastionPort, bastionCleanup := startExecMockForwarder(t, targetAddr)
	defer bastionCleanup()

	opts := ExecOptions{
		ConnectTimeout:  5 * time.Second,
		CommandTimeout:  5 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 1. Connect to bastion.
	bastionClient, err := dialJumpHostPW(context.Background(), "127.0.0.1", bastionPort, "jumpuser", "jumppass", opts)
	if err != nil {
		t.Fatalf("DialJumpHost failed: %v", err)
	}
	defer bastionClient.Close()

	// 2. Connect to target via the bastion tunnel.
	client, err := dialViaJumpPW(context.Background(), bastionClient, "127.0.0.1", targetPort, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("DialViaJump failed: %v", err)
	}
	defer client.Close()

	// 3. Run a command through the tunnelled connection.
	out, err := RunCommand(context.Background(), client, "show run", opts)
	if err != nil {
		t.Fatalf("RunCommand via jump failed: %v", err)
	}
	if !strings.Contains(out, "core-switch-01") {
		t.Errorf("unexpected output through jump: %q", out)
	}
}

func TestExecDialJumpHostBadPassword(t *testing.T) {
	bastionPort, cleanup := startExecMockForwarder(t, "127.0.0.1:22")
	defer cleanup()

	opts := ExecOptions{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  2 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	_, err := dialJumpHostPW(context.Background(), "127.0.0.1", bastionPort, "jumpuser", "wrongpass", opts)
	if err == nil {
		t.Fatal("expected auth failure for bad jump host password")
	}
}

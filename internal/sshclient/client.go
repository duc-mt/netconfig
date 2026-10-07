// Package sshclient opens an interactive CLI session on a network device over
// SSH: TCP + handshake with timeouts, host key verification, password and
// keyboard-interactive authentication, a PTY shell, and an expect-style loop
// that understands vendor prompts, pagers and confirmation dialogs.
package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"netconfig/internal/vendor"
)

// Error kinds, exposed through (*Error).ErrorKind so callers can categorise
// failures without importing this package.
const (
	KindConnect = "connect" // TCP/SSH transport problem
	KindAuth    = "auth"    // credentials rejected
	KindHostKey = "hostkey" // host key unknown or changed
	KindTimeout = "timeout"
	KindSession = "session" // anything that goes wrong inside the CLI session
)

// Error is a categorised SSH failure. Its text never contains credentials.
type Error struct {
	Kind string
	Op   string
	Err  error
}

func (e *Error) Error() string { return e.Op + ": " + e.Err.Error() }

// Unwrap exposes the cause to errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.Err }

// ErrorKind returns one of the Kind* constants.
func (e *Error) ErrorKind() string { return e.Kind }

// Config describes one device connection.
type Config struct {
	Address        string // host:port
	Username       string
	Password       string
	EnablePassword string // optional; defaults to Password where an enable step exists
	Profile        *vendor.Profile

	ConnectTimeout time.Duration // TCP connect + SSH handshake
	LoginTimeout   time.Duration // first prompt / enable / pager setup (and per-command default)

	HostKey          HostKeyCallback // required; there is deliberately no insecure default
	LegacyAlgorithms bool            // also offer SHA-1 key exchange and CBC ciphers (old IOS, VRP, ...)
	AutoConfirm      bool            // answer "[y/n]"-style dialogs
	Logf             func(format string, args ...any)
}

// Connect dials the device, authenticates, opens a PTY shell and prepares it
// for scripted use (first prompt reached, privileged mode, pager disabled).
func Connect(ctx context.Context, cfg Config) (*Shell, error) {
	if cfg.Profile == nil {
		return nil, &Error{Kind: KindSession, Op: "connect", Err: errors.New("no vendor profile")}
	}
	if cfg.HostKey == nil {
		return nil, &Error{Kind: KindHostKey, Op: "connect", Err: errors.New("no host key verification configured")}
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.LoginTimeout <= 0 {
		cfg.LoginTimeout = 30 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}

	password := cfg.Password
	cc := &ssh.ClientConfig{
		User: cfg.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			// Many network OSes only offer keyboard-interactive for passwords.
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: cfg.HostKey,
	}
	if cfg.LegacyAlgorithms {
		applyLegacy(cc)
	}

	dialer := net.Dialer{Timeout: cfg.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, wrapDial(err)
	}

	// The handshake budget is part of -connect-timeout and is enforced with a
	// connection deadline; cancelling ctx closes the connection to abort it.
	_ = conn.SetDeadline(time.Now().Add(cfg.ConnectTimeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, cfg.Address, cc)
	stop()
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("handshake: %w", ctx.Err())
		}
		return nil, classifyHandshake(err, cfg.Username)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(sshConn, chans, reqs)

	sh, err := newShell(client, cfg)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	if err := sh.login(ctx, cfg); err != nil {
		_ = sh.Close()
		return nil, err
	}
	return sh, nil
}

func newShell(client *ssh.Client, cfg Config) (*Shell, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, &Error{Kind: KindSession, Op: "open session", Err: err}
	}
	// A very wide terminal keeps devices from wrapping long config lines.
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	if err := sess.RequestPty("vt100", 50, 512, modes); err != nil {
		_ = sess.Close()
		return nil, &Error{Kind: KindSession, Op: "request pty", Err: err}
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, &Error{Kind: KindSession, Op: "open stdin", Err: err}
	}
	sh := &Shell{
		client:      client,
		session:     sess,
		stdin:       stdin,
		out:         NewSafeBuffer(),
		errBuf:      NewSafeBuffer(),
		done:        make(chan struct{}),
		prof:        cfg.Profile,
		settle:      defaultSettle,
		autoConfirm: cfg.AutoConfirm,
		logf:        cfg.Logf,
	}
	sess.Stdout = sh.out
	sess.Stderr = sh.errBuf
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		return nil, &Error{Kind: KindSession, Op: "start shell", Err: err}
	}
	go func() {
		_ = sess.Wait()
		close(sh.done)
	}()
	return sh, nil
}

// applyLegacy re-enables algorithms that current x/crypto does not offer by
// default but that older network gear still requires. The modern algorithms
// stay first in every list, so up-to-date devices never negotiate down.
func applyLegacy(cc *ssh.ClientConfig) {
	cc.KeyExchanges = []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
	}
	cc.Ciphers = []string{
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-cbc", "3des-cbc",
	}
	cc.HostKeyAlgorithms = []string{
		"ssh-ed25519",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"rsa-sha2-512", "rsa-sha2-256",
		"ssh-rsa",
		"ssh-dss",
	}
}

func wrapDial(err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("connect: %w", err)
	}
	if isTimeout(err) {
		return &Error{Kind: KindTimeout, Op: "connect", Err: err}
	}
	return &Error{Kind: KindConnect, Op: "connect", Err: err}
}

func classifyHandshake(err error, user string) error {
	msg := err.Error()
	var hk *HostKeyError
	switch {
	case errors.As(err, &hk):
		return &Error{Kind: KindHostKey, Op: "host key", Err: hk}
	case strings.Contains(msg, "host key verification failed"), strings.Contains(msg, "knownhosts:"):
		return &Error{Kind: KindHostKey, Op: "host key", Err: err}
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods remain"):
		return &Error{Kind: KindAuth, Op: "authenticate", Err: fmt.Errorf("authentication failed for user %q", user)}
	case isTimeout(err), strings.Contains(msg, "i/o timeout"):
		return &Error{Kind: KindTimeout, Op: "handshake", Err: err}
	case strings.Contains(msg, "no common algorithm"):
		return &Error{Kind: KindConnect, Op: "handshake", Err: fmt.Errorf("%w (the device may need legacy algorithms: try -legacy-algorithms)", err)}
	default:
		return &Error{Kind: KindConnect, Op: "handshake", Err: err}
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

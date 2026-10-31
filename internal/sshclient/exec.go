// ==============================================================================
// File name:     exec.go
// Description:   Exec-mode SSH helpers used by "netops log": one-shot commands
//                on a plain exec channel, short PTY sessions, jump-host
//                tunnelling and the Check Point Gaia expert-mode flow. They
//                share the dialer and algorithm configuration of the
//                vendor-profile Shell in client.go.
// License:       MIT
// ==============================================================================

package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	pagerPromptRe = regexp.MustCompile(`(?i)(?:-+\s*More(?:\s*\(?\s*\d+%\s*\)?)?\s*-+|---\(more(?:\s+\d+%)?\)---|\[More\]|Press any key to continue|<--- More --->)\s*$`)
	pagerMarkerRe = regexp.MustCompile(`(?i)(?:-+\s*More(?:\s*\(?\s*\d+%\s*\)?)?\s*-+|---\(more(?:\s+\d+%)?\)---|\[More\]|Press any key to continue|<--- More --->)`)
)

// ExecOptions controls the timeouts and algorithms applied to every exec-mode
// connection used by "netops log" (one-shot commands and short interactive
// sessions, as opposed to the vendor-profile Shell used by the other commands).
type ExecOptions struct {
	ConnectTimeout time.Duration // TCP dial + SSH handshake
	CommandTimeout time.Duration // time budget for running the command(s)

	// HostKeyCallback verifies the server's host key during the SSH
	// handshake. It is required: the Dial functions return an error if it is nil
	// rather than silently accepting any host key. Use NewHostKeyCallback to
	// build one from a known_hosts file, ssh.FixedHostKey for a single
	// pinned key, or ssh.InsecureIgnoreHostKey() as an explicit, callsite-
	// visible opt-out (never as a hidden default).
	HostKeyCallback ssh.HostKeyCallback

	// JumpHostKeyCallback, when non-nil, is used to verify the bastion /
	// jump host's own key. Falls back to HostKeyCallback when nil.
	JumpHostKeyCallback ssh.HostKeyCallback

	// TCPMSS clamps the TCP Maximum Segment Size on outgoing sockets.
	// 0 = default (1360), <0 = disabled (OS default).
	TCPMSS int

	// LegacyAlgorithms, when true, enables older ciphers (e.g. 3des-cbc, aes128-cbc),
	// key exchanges (e.g. diffie-hellman-group1-sha1, diffie-hellman-group14-sha1),
	// and legacy host keys (ssh-dss) for compatibility with older network hardware.
	LegacyAlgorithms bool
}

// ErrNoHostKeyCallback is returned by Connect when opts.HostKeyCallback is

// ErrNoHostKeyCallback is returned by the Dial functions when
// opts.HostKeyCallback is nil, so callers can't accidentally run with host key
// checking disabled.
var ErrNoHostKeyCallback = errors.New("sshclient: ExecOptions.HostKeyCallback is required")

// AuthOptions contains authentication parameters for SSH connections.
type AuthOptions struct {
	Username string
	Password string
	KeyFile  string
}

// DialWithAuth opens a TCP connection and completes the SSH handshake
// (passwords and private key files), both bounded by opts.ConnectTimeout so an
// unreachable or black-holed device can never hang the run. Cancelling ctx
// (e.g. on SIGINT/SIGTERM) aborts an in-progress dial immediately.
func DialWithAuth(ctx context.Context, address string, port int, auth AuthOptions, opts ExecOptions) (*ssh.Client, error) {
	if opts.HostKeyCallback == nil {
		return nil, ErrNoHostKeyCallback
	}

	addr := net.JoinHostPort(address, strconv.Itoa(port))

	dialer := newDialer(opts.ConnectTimeout, opts.TCPMSS)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	config, err := buildExecClientConfig(auth, opts.HostKeyCallback, opts)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("auth config: %w", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

// DialJumpHostWithAuth opens an SSH connection to a bastion / jump host. The
// returned *ssh.Client can be shared across many concurrent DialViaJumpWithAuth
// calls because (*ssh.Client).Dial is safe for concurrent use. The caller is
// responsible for calling Close() on the returned client when the run is done.
func DialJumpHostWithAuth(ctx context.Context, address string, port int, auth AuthOptions, opts ExecOptions) (*ssh.Client, error) {
	hkCb := opts.JumpHostKeyCallback
	if hkCb == nil {
		hkCb = opts.HostKeyCallback
	}
	if hkCb == nil {
		return nil, ErrNoHostKeyCallback
	}

	addr := net.JoinHostPort(address, strconv.Itoa(port))
	dialer := newDialer(opts.ConnectTimeout, opts.TCPMSS)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial jump host: %w", err)
	}

	config, err := buildExecClientConfig(auth, hkCb, opts)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("jump host auth config: %w", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("jump host handshake: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// DialViaJumpWithAuth opens a ProxyJump-style connection to address:port by
// tunnelling through an already-established jump host client (bastion). The
// tunnel is a standard SSH "direct-tcpip" channel -- exactly what OpenSSH does
// with `ssh -J bastion target`.
//
// jumpClient is safe to share across goroutines; pass the same value for all
// devices that route through the same bastion.
func DialViaJumpWithAuth(ctx context.Context, jumpClient *ssh.Client, address string, port int, auth AuthOptions, opts ExecOptions) (*ssh.Client, error) {
	if opts.HostKeyCallback == nil {
		return nil, ErrNoHostKeyCallback
	}

	targetAddr := net.JoinHostPort(address, strconv.Itoa(port))

	tunnelConn, err := jumpClient.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("jump tunnel to %s: %w", targetAddr, err)
	}

	config, err := buildExecClientConfig(auth, opts.HostKeyCallback, opts)
	if err != nil {
		_ = tunnelConn.Close()
		return nil, fmt.Errorf("auth config via jump: %w", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(tunnelConn, targetAddr, config)
	if err != nil {
		_ = tunnelConn.Close()
		return nil, fmt.Errorf("handshake via jump: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// buildExecClientConfig reuses the shared auth methods and algorithm lists of
// buildClientConfig and adds the handshake timeout the exec-mode dialers rely on.
func buildExecClientConfig(auth AuthOptions, hk HostKeyCallback, opts ExecOptions) (*ssh.ClientConfig, error) {
	cc, err := buildClientConfig(auth.Username, auth.Password, auth.KeyFile, hk, opts.LegacyAlgorithms)
	if err != nil {
		return nil, err
	}
	cc.Timeout = opts.ConnectTimeout
	return cc, nil
}

// RunCommand executes a single command on a plain (non-interactive, no PTY)
// exec channel -- the default, simplest, and most broadly compatible mode.
// It is bounded by opts.CommandTimeout: if the device never responds, the
// session is closed and a timeout error is returned instead of hanging.
// If ctx is cancelled, the session is terminated immediately and ctx.Err() is returned.
func RunCommand(ctx context.Context, client *ssh.Client, command string, opts ExecOptions) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("opening session: %w", err)
	}
	defer session.Close()

	stdout, stderr := NewSafeBuffer(), NewSafeBuffer()
	session.Stdout = stdout
	session.Stderr = stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case err := <-done:
		out := stdout.String()
		cleaned := pagerMarkerRe.ReplaceAllString(out, "")
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return cleaned, fmt.Errorf("command failed: %w (stderr: %s)", err, msg)
			}
			return cleaned, fmt.Errorf("command failed: %w", err)
		}
		return cleaned, nil

	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		session.Close()
		return "", ctx.Err()

	case <-time.After(opts.CommandTimeout):
		_ = session.Signal(ssh.SIGKILL)
		session.Close()
		return "", fmt.Errorf("command timed out after %s", opts.CommandTimeout)
	}
}

var reANSI = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// AtPrompt reports whether the output currently ends at the device prompt.
func AtPrompt(out string, prompt *regexp.Regexp) bool {
	if prompt == nil {
		return false
	}
	out = reANSI.ReplaceAllString(out, "")
	last := out
	if i := strings.LastIndexAny(out, "\r\n"); i >= 0 {
		last = out[i+1:]
	}
	return prompt.MatchString(last)
}

// RunInteractive is for platforms whose SSH login does not accept a
// one-shot exec command (e.g. a restricted console menu). It allocates a
// PTY, starts a shell, feeds each command in sequence, and collects
// output until either the shell goes quiet for a short settle period or
// the hard opts.CommandTimeout is reached.
func RunInteractive(ctx context.Context, client *ssh.Client, commands []string, opts ExecOptions) (string, error) {
	return RunInteractivePrompt(ctx, client, commands, nil, opts)
}

// RunInteractivePrompt feeds commands to a PTY shell session. If prompt is non-nil,
// it waits for the prompt after login and after each command (answering paging markers
// on the way). If prompt is nil, it falls back to a quiet/settle period. The entire
// session is bounded by ctx and opts.CommandTimeout.
func RunInteractivePrompt(ctx context.Context, client *ssh.Client, commands []string, prompt *regexp.Regexp, opts ExecOptions) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("opening session: %w", err)
	}
	defer session.Close()

	if err := session.RequestPty("vt100", 50, 512, ssh.TerminalModes{
		ssh.ECHO: 0,
	}); err != nil {
		return "", fmt.Errorf("requesting pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin pipe: %w", err)
	}

	output := NewSafeBuffer()
	session.Stdout = output
	session.Stderr = output

	if err := session.Shell(); err != nil {
		return "", fmt.Errorf("starting shell: %w", err)
	}

	deadline := time.Now().Add(opts.CommandTimeout)

	if prompt != nil {
		const poll = 40 * time.Millisecond
		// Wake prompt on connect if switch sits at login banner
		wakeTicker := time.NewTicker(600 * time.Millisecond)
		defer wakeTicker.Stop()

		waitPrompt := func(from int, what string) error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-wakeTicker.C:
					cur := output.String()
					if len(cur) > from {
						tail := cur[from:]
						if !AtPrompt(tail, prompt) {
							_, _ = fmt.Fprintf(stdin, "\n")
						}
					} else {
						_, _ = fmt.Fprintf(stdin, "\n")
					}
				default:
				}
				cur := output.String()
				if len(cur) > from {
					tail := cur[from:]
					if AtPrompt(tail, prompt) {
						wakeTicker.Stop()
						return nil
					}
					if pagerPromptRe.MatchString(tail) {
						if _, err := stdin.Write([]byte(" ")); err != nil {
							return fmt.Errorf("answering pager: %w", err)
						}
						from = len(cur)
						time.Sleep(poll)
						continue
					}
				}
				if time.Now().After(deadline) {
					return fmt.Errorf("timed out after %s waiting for the prompt %s", opts.CommandTimeout, what)
				}
				time.Sleep(poll)
			}
		}

		if err := waitPrompt(0, "after login"); err != nil {
			return reANSI.ReplaceAllString(output.String(), ""), err
		}
		for _, cmd := range commands {
			from := len(output.String())
			if _, err := fmt.Fprintf(stdin, "%s\n", cmd); err != nil {
				return reANSI.ReplaceAllString(output.String(), ""), fmt.Errorf("writing command: %w", err)
			}
			if err := waitPrompt(from, fmt.Sprintf("after %q", cmd)); err != nil {
				return reANSI.ReplaceAllString(output.String(), ""), err
			}
		}
		return reANSI.ReplaceAllString(output.String(), ""), nil
	}

	const settle = 1500 * time.Millisecond
	for _, cmd := range commands {
		if _, err := fmt.Fprintf(stdin, "%s\n", cmd); err != nil {
			return output.String(), fmt.Errorf("writing command to stdin: %w", err)
		}

		startLen := output.Len()
		lastSize := startLen
		lastChange := time.Now()

	waitLoop:
		for {
			select {
			case <-ctx.Done():
				return output.String(), ctx.Err()
			default:
			}
			if time.Now().After(deadline) {
				session.Close()
				return output.String(), fmt.Errorf("command timed out after %s", opts.CommandTimeout)
			}
			time.Sleep(150 * time.Millisecond)
			size := output.Len()
			switch {
			case size != lastSize:
				lastSize = size
				lastChange = time.Now()
			default:
				// Detect and answer interactive paging markers (--More--, ---(more)---, etc.)
				str := output.String()
				tail := str
				if len(tail) > 256 {
					tail = tail[len(tail)-256:]
				}
				if pagerPromptRe.MatchString(tail) {
					if _, err := stdin.Write([]byte(" ")); err == nil {
						lastChange = time.Now()
						time.Sleep(100 * time.Millisecond)
						continue
					}
				}

				if size > startLen && time.Since(lastChange) >= settle {
					break waitLoop // command output arrived and settled
				} else if size == startLen && time.Since(lastChange) >= settle*2 {
					// command produced no new output within quiet window (e.g. empty command or prompt wake)
					break waitLoop
				}
			}
		}
	}

	cleaned := pagerMarkerRe.ReplaceAllString(reANSI.ReplaceAllString(output.String(), ""), "")
	return cleaned, nil
}

var (
	reGaiaClishPrompt = regexp.MustCompile(`[\w.-]+(:[0-9a-zA-Z]+)?(?: \([\w./-]+\))?>\s*$`)
	reGaiaBashPrompt  = regexp.MustCompile(`(?:\[?Expert@[\w.-]+[^\]]*\]?#|[\w.-]+#)\s*$`)
	reGaiaExpPassReq  = regexp.MustCompile(`(?i)(?:enter\s+expert\s+password|password)\s*:\s*$`)
)

// RunInteractiveGaia handles Check Point Gaia SSH sessions. If the login lands
// in clish (prompt ending in '>'), it automatically sends 'expert', feeds the
// expertPassword if prompted, executes the given commands in bash, and exits.
func RunInteractiveGaia(ctx context.Context, client *ssh.Client, commands []string, expertPassword string, opts ExecOptions) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("opening session: %w", err)
	}
	defer session.Close()

	if err := session.RequestPty("vt100", 50, 512, ssh.TerminalModes{
		ssh.ECHO: 0,
	}); err != nil {
		return "", fmt.Errorf("requesting pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin pipe: %w", err)
	}

	output := NewSafeBuffer()
	session.Stdout = output
	session.Stderr = output

	if err := session.Shell(); err != nil {
		return "", fmt.Errorf("starting shell: %w", err)
	}

	deadline := time.Now().Add(opts.CommandTimeout)
	const poll = 40 * time.Millisecond

	// Send an initial newline after a brief delay if no prompt appears,
	// which wakes MOTD/banner prompts on Gaia firewalls.
	wakeTicker := time.NewTicker(600 * time.Millisecond)
	defer wakeTicker.Stop()

	// 1. Wait for initial prompt (either clish '>' or bash '#')
	inBash := false
	for !inBash {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-wakeTicker.C:
			cur := output.String()
			cleaned := reANSI.ReplaceAllString(cur, "")
			lastLine := cleaned
			if idx := strings.LastIndexAny(cleaned, "\r\n"); idx >= 0 {
				lastLine = cleaned[idx+1:]
			}
			if !reGaiaBashPrompt.MatchString(lastLine) && !reGaiaClishPrompt.MatchString(lastLine) {
				_, _ = fmt.Fprintf(stdin, "\n")
			}
		default:
		}
		if time.Now().After(deadline) {
			return reANSI.ReplaceAllString(output.String(), ""), fmt.Errorf("timed out waiting for Gaia login prompt")
		}

		cur := output.String()
		cleaned := reANSI.ReplaceAllString(cur, "")
		lastLine := cleaned
		if idx := strings.LastIndexAny(cleaned, "\r\n"); idx >= 0 {
			lastLine = cleaned[idx+1:]
		}

		if reGaiaBashPrompt.MatchString(lastLine) {
			break
		}

		if reGaiaClishPrompt.MatchString(lastLine) {
			wakeTicker.Stop()
			// At clish prompt: enter expert mode
			if _, err := fmt.Fprintf(stdin, "expert\n"); err != nil {
				return "", fmt.Errorf("sending expert command: %w", err)
			}
			// Wait for either password prompt or bash prompt
			passwordSent := false
		expertLoop:
			for {
				select {
				case <-ctx.Done():
					return "", ctx.Err()
				default:
				}
				if time.Now().After(deadline) {
					return reANSI.ReplaceAllString(output.String(), ""), fmt.Errorf("timed out waiting for expert shell")
				}
				time.Sleep(poll)

				subCur := reANSI.ReplaceAllString(output.String(), "")
				subLast := subCur
				if idx := strings.LastIndexAny(subCur, "\r\n"); idx >= 0 {
					subLast = subCur[idx+1:]
				}

				if reGaiaBashPrompt.MatchString(subLast) {
					inBash = true
					break expertLoop
				}

				if !passwordSent && reGaiaExpPassReq.MatchString(subLast) {
					if _, err := fmt.Fprintf(stdin, "%s\n", expertPassword); err != nil {
						return "", fmt.Errorf("sending expert password: %w", err)
					}
					passwordSent = true
				}
			}
		}
		time.Sleep(poll)
	}
	wakeTicker.Stop()

	// 2. Execute commands in bash shell
	var result strings.Builder
	for _, cmd := range commands {
		from := output.Len()
		if _, err := fmt.Fprintf(stdin, "%s\n", cmd); err != nil {
			return result.String(), fmt.Errorf("writing command %q: %w", cmd, err)
		}

		// Wait for command completion (bash prompt)
		for {
			select {
			case <-ctx.Done():
				return result.String(), ctx.Err()
			default:
			}
			if time.Now().After(deadline) {
				return result.String(), fmt.Errorf("timed out waiting for command %q to finish", cmd)
			}
			time.Sleep(poll)

			cur := output.String()
			if len(cur) > from {
				tail := cur[from:]
				cleanedTail := reANSI.ReplaceAllString(tail, "")
				last := cleanedTail
				if idx := strings.LastIndexAny(cleanedTail, "\r\n"); idx >= 0 {
					last = cleanedTail[idx+1:]
				}
				if reGaiaBashPrompt.MatchString(last) {
					// Command completed; strip the command echo and the trailing prompt
					lines := strings.Split(cleanedTail, "\n")
					if len(lines) > 1 {
						// Drop first line (command echo) and last line (prompt)
						bodyLines := lines[1 : len(lines)-1]
						for _, bl := range bodyLines {
							result.WriteString(strings.TrimRight(bl, "\r"))
							result.WriteString("\n")
						}
					}
					break
				}
			}
		}
	}

	_, _ = fmt.Fprintf(stdin, "exit\n")
	return result.String(), nil
}

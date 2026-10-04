package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"netconfig/internal/vendor"
)

const (
	defaultSettle = 150 * time.Millisecond // quiet period required after a prompt-looking tail
	tailWindow    = 1024                   // bytes inspected for prompt/pager/confirm detection
)

var (
	errExpectTimeout = errors.New("timed out waiting for the device prompt")
	errClosed        = errors.New("connection closed by the device")

	passwordPromptRe = regexp.MustCompile(`(?i)password:\s*$`)
)

// rule is an extra prompt answer for one operation (the enable password).
type rule struct {
	re     *regexp.Regexp
	reply  string
	label  string // what gets logged; the reply itself never is
	max    int
	used   int
	secret bool
}

// Shell is one interactive CLI session on a device. It is used by a single
// goroutine at a time (one worker owns one device).
type Shell struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser

	out    *SafeBuffer // remote stdout (a PTY merges stderr into it)
	errBuf *SafeBuffer // remote stderr, kept for diagnostics
	done   chan struct{}

	prof        *vendor.Profile
	settle      time.Duration
	autoConfirm bool
	logf        func(format string, args ...any)

	pos    int    // start of output not yet consumed
	prompt string // last prompt seen
}

// Send types one line, waits for the next prompt (answering pagers and
// confirmation dialogs on the way) and returns the output with the echo of the
// command and the final prompt removed. On error the partial output received so
// far is returned as well.
func (s *Shell) Send(ctx context.Context, line string, timeout time.Duration) (string, error) {
	return s.send(ctx, line, timeout, nil)
}

func (s *Shell) send(ctx context.Context, line string, timeout time.Duration, extra []*rule) (string, error) {
	s.pos = s.out.Len() // drop unsolicited output (syslog messages) received while idle
	if err := s.write(line + "\n"); err != nil {
		return "", s.wrapErr("send", err)
	}
	body, _, err := s.expect(ctx, timeout, extra)
	body = stripEcho(body, line)
	if err != nil {
		if errors.Is(err, errExpectTimeout) {
			err = fmt.Errorf("no device prompt within %s: %w", timeout, err)
		}
		return body, s.wrapErr("command", err)
	}
	return body, nil
}

// Close ends the session and the underlying connection.
func (s *Shell) Close() error {
	if s.stdin != nil {
		_ = s.stdin.Close()
	}
	if s.session != nil {
		_ = s.session.Close()
	}
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

func (s *Shell) write(text string) error {
	_, err := io.WriteString(s.stdin, text)
	return err
}

func (s *Shell) wrapErr(op string, err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s: %w", op, err)
	case errors.Is(err, errExpectTimeout):
		return &Error{Kind: KindTimeout, Op: op, Err: err}
	default:
		if se := strings.TrimSpace(s.errBuf.String()); se != "" && errors.Is(err, errClosed) {
			if len(se) > 200 {
				se = se[:200]
			}
			err = fmt.Errorf("%w (stderr: %s)", err, se)
		}
		return &Error{Kind: KindSession, Op: op, Err: err}
	}
}

// expect consumes output until the vendor prompt shows up and stays quiet for
// the settle period. It returns the cleaned output before the prompt and the
// prompt line itself.
func (s *Shell) expect(ctx context.Context, timeout time.Duration, extra []*rule) (string, string, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	handled := -1 // output length at which we last answered something
	for {
		raw := s.out.Since(s.pos)
		n := len(raw)
		tail := lastLine(cleanTerminal(string(tailBytes(raw, tailWindow))))

		if n != handled {
			acted, err := s.interact(tail, extra)
			if err != nil {
				return s.consumeAll(raw), "", err
			}
			if acted {
				handled = n
			}
		}

		var settle <-chan time.Time
		promptSeen := s.prof.Prompt.MatchString(tail)
		if promptSeen {
			settle = time.After(s.settle)
		}

		select {
		case <-s.out.Notify():
			// more output arrived: re-evaluate
		case <-settle:
			if s.out.Len()-s.pos == n { // quiet since we looked: the prompt is real
				body, prompt := s.consume(raw)
				s.prompt = prompt
				return body, prompt, nil
			}
		case <-s.done:
			// The remote side hung up. If the last thing it printed was a
			// prompt, the command still completed.
			raw = s.out.Since(s.pos)
			if s.prof.Prompt.MatchString(lastLine(cleanTerminal(string(tailBytes(raw, tailWindow))))) {
				body, prompt := s.consume(raw)
				s.prompt = prompt
				return body, prompt, nil
			}
			return s.consumeAll(raw), "", errClosed
		case <-timer.C:
			return s.consumeAll(raw), "", errExpectTimeout
		case <-ctx.Done():
			return s.consumeAll(raw), "", ctx.Err()
		}
	}
}

// interact answers a pager, an extra rule or a confirmation dialog visible at
// the end of the output. It reports whether it wrote anything.
func (s *Shell) interact(tail string, extra []*rule) (bool, error) {
	for _, r := range extra {
		if r.used < r.max && r.re.MatchString(tail) {
			r.used++
			if err := s.write(r.reply + "\n"); err != nil {
				return false, err
			}
			s.logf("answered %s", r.label) // never the reply: it may be a secret
			return true, nil
		}
	}
	for _, re := range s.prof.Pagers {
		if re.MatchString(tail) {
			return true, s.write(" ")
		}
	}
	for _, c := range s.prof.Confirms {
		if c.Re.MatchString(tail) {
			question := strings.TrimSpace(tail)
			if !s.autoConfirm {
				return false, fmt.Errorf("device asked for confirmation (%q) and -auto-confirm is disabled", question)
			}
			if err := s.write(c.Reply + "\n"); err != nil {
				return false, err
			}
			s.logf("auto-confirmed %q with %q", question, c.Reply)
			return true, nil
		}
	}
	return false, nil
}

// consume marks raw as read and splits it into output and the final line.
func (s *Shell) consume(raw []byte) (body, prompt string) {
	text := s.cleanConsumed(raw)
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		return text[:i], text[i+1:]
	}
	return "", text
}

// consumeAll marks raw as read and returns all of it (used on errors).
func (s *Shell) consumeAll(raw []byte) string {
	return s.cleanConsumed(raw)
}

func (s *Shell) cleanConsumed(raw []byte) string {
	s.pos += len(raw)
	text := cleanTerminal(string(raw))
	for _, re := range s.prof.Pagers {
		text = re.ReplaceAllString(text, "")
	}
	return text
}

// login waits for the first prompt, escalates privilege if the vendor needs it
// and turns the pager off.
func (s *Shell) login(ctx context.Context, cfg Config) error {
	total := cfg.LoginTimeout
	first := total / 3
	if first > 5*time.Second {
		first = 5 * time.Second
	}
	_, _, err := s.expect(ctx, first, nil)
	if errors.Is(err, errExpectTimeout) {
		// Some devices wait for a keypress before showing anything.
		if werr := s.write("\n"); werr != nil {
			return s.wrapErr("login", werr)
		}
		_, _, err = s.expect(ctx, total-first, nil)
	}
	if err != nil {
		return s.wrapErr("login", fmt.Errorf("waiting for the first prompt: %w", err))
	}

	prof := s.prof
	if prof.UserPrompt != nil && prof.EnableCommand != "" && prof.UserPrompt.MatchString(s.prompt) {
		pw := cfg.EnablePassword
		if pw == "" {
			pw = cfg.Password
		}
		pwRule := &rule{re: passwordPromptRe, reply: pw, label: "enable password prompt", max: 3, secret: true}
		if _, err := s.send(ctx, prof.EnableCommand, total, []*rule{pwRule}); err != nil {
			return err
		}
		if prof.UserPrompt.MatchString(s.prompt) {
			return &Error{Kind: KindAuth, Op: "enable", Err: errors.New("privileged mode was refused (check NETCONFIG_<GROUP>_ENABLE_PASSWORD)")}
		}
	}

	for _, cmd := range prof.DisablePaging {
		if _, err := s.send(ctx, cmd, total, nil); err != nil {
			if ctx.Err() != nil {
				return err
			}
			s.logf("warning: could not run %q: %v", cmd, err) // the --More-- handler still copes
		}
	}
	return nil
}

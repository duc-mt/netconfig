// Package logging provides the audit trail: a coloured console stream (stderr)
// plus a timestamped log file with every command sent and every device
// response, per device. Registered secrets (login passwords) are masked in
// everything that is written, and well-known secret-bearing configuration
// lines can be masked with RedactCommand.
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Level is a log severity.
type Level int

const (
	LevelTrace Level = iota // command/response traces: file always, console only with Verbose
	LevelInfo
	LevelWarn
	LevelError
)

var levelNames = [...]string{"TRACE", "INFO", "WARN", "ERROR"}

var levelColors = [...]string{"\x1b[90m", "\x1b[32m", "\x1b[33m", "\x1b[31m"}

const (
	colorReset   = "\x1b[0m"
	colorHost    = "\x1b[36m"
	fileTimeFmt  = "2006-01-02T15:04:05.000Z07:00"
	redactedMask = "********"
	minSecretLen = 4 // shorter secrets would mangle ordinary text when masked
)

func (l Level) String() string {
	if l < 0 || int(l) >= len(levelNames) {
		return "?"
	}
	return levelNames[l]
}

// Options configures New.
type Options struct {
	Dir     string    // log directory; "" disables the file
	Prefix  string    // file name prefix, default "netconfig"
	Console io.Writer // usually os.Stderr; nil disables console output
	Color   bool      // ANSI colours on the console
	Verbose bool      // also show TRACE on the console
	Now     func() time.Time
}

// Logger is safe for concurrent use; each call writes its lines atomically so
// output of concurrent devices never interleaves mid-block.
type Logger struct {
	mu      sync.Mutex
	console io.Writer
	color   bool
	verbose bool
	file    *os.File
	path    string
	now     func() time.Time
	secrets []string
}

// New creates the logger and, if Options.Dir is set, a new
// <prefix>-YYYYMMDD-HHMMSS.log (mode 0600) inside it.
func New(o Options) (*Logger, error) {
	l := &Logger{console: o.Console, color: o.Color, verbose: o.Verbose, now: o.Now}
	if l.now == nil {
		l.now = time.Now
	}
	if o.Dir != "" {
		if err := os.MkdirAll(o.Dir, 0o700); err != nil {
			return nil, fmt.Errorf("create log directory: %w", err)
		}
		prefix := o.Prefix
		if prefix == "" {
			prefix = "netconfig"
		}
		name := fmt.Sprintf("%s-%s.log", prefix, l.now().Format("20060102-150405"))
		l.path = filepath.Join(o.Dir, name)
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		l.file = f
	}
	return l, nil
}

// Path returns the log file path ("" when file logging is disabled).
func (l *Logger) Path() string { return l.path }

// Close flushes and closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// AddSecret registers a value (e.g. a login password) that must never appear
// in console or file output; it is replaced by ******** wherever it occurs.
func (l *Logger) AddSecret(s string) {
	if len(s) < minSecretLen {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.secrets {
		if existing == s {
			return
		}
	}
	l.secrets = append(l.secrets, s)
}

// Tracef, Infof, Warnf and Errorf log one (possibly multi-line) message
// tagged with host ("" for run-level messages).
func (l *Logger) Tracef(host, format string, args ...any) { l.logf(LevelTrace, host, format, args) }
func (l *Logger) Infof(host, format string, args ...any)  { l.logf(LevelInfo, host, format, args) }
func (l *Logger) Warnf(host, format string, args ...any)  { l.logf(LevelWarn, host, format, args) }
func (l *Logger) Errorf(host, format string, args ...any) { l.logf(LevelError, host, format, args) }

func (l *Logger) logf(level Level, host, format string, args []any) {
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	l.logLines(level, host, splitLines(msg))
}

// Block logs text line by line, each line prefixed (e.g. "<< " for device
// output), as one atomic unit.
func (l *Logger) Block(level Level, host, prefix, text string) {
	lines := splitLines(text)
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	l.logLines(level, host, lines)
}

// Raw writes preformatted text (the end-of-run summary) to the console and,
// separately, to the file; the two may differ (colour codes).
func (l *Logger) Raw(consoleText, fileText string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.console != nil {
		_, _ = io.WriteString(l.console, l.maskLocked(consoleText))
	}
	if l.file != nil {
		_, _ = io.WriteString(l.file, l.maskLocked(fileText))
	}
}

func (l *Logger) logLines(level Level, host string, lines []string) {
	if len(lines) == 0 {
		lines = []string{""}
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	showConsole := l.console != nil && (level >= LevelInfo || l.verbose)
	for _, line := range lines {
		line = l.maskLocked(line)
		if l.file != nil {
			tag := ""
			if host != "" {
				tag = "[" + host + "] "
			}
			fmt.Fprintf(l.file, "%s %-5s %s%s\n", now.Format(fileTimeFmt), level, tag, line)
		}
		if showConsole {
			l.writeConsoleLocked(now, level, host, line)
		}
	}
}

func (l *Logger) writeConsoleLocked(now time.Time, level Level, host, line string) {
	ts := now.Format("15:04:05")
	if !l.color {
		tag := ""
		if host != "" {
			tag = "[" + host + "] "
		}
		fmt.Fprintf(l.console, "%s %-5s %s%s\n", ts, level, tag, line)
		return
	}
	tag := ""
	if host != "" {
		tag = colorHost + "[" + host + "]" + colorReset + " "
	}
	fmt.Fprintf(l.console, "%s %s%-5s%s %s%s\n", ts, levelColors[level], level, colorReset, tag, line)
}

func (l *Logger) maskLocked(s string) string {
	for _, sec := range l.secrets {
		s = strings.ReplaceAll(s, sec, redactedMask)
	}
	return s
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// secretCommand finds "<keyword> [type] <value>" in configuration lines:
// "username a password 0 hunter2", "enable secret 5 $1$...", "snmp-server
// community public RO", "set encrypted-password \"$6$...\"", FortiOS "set psksecret x",
// Cisco "tacacs-server key 7 secret", "radius-server key secret".
var secretCommand = regexp.MustCompile(`(?i)\b((?:(?:tacacs|radius)-server\s+)?key|password|passwd|secret|psksecret|community|pre-shared-key|psk|passphrase|encrypted-password|authentication-key|auth-password|priv-password|key-string)(\s+(?:\d+|encrypted|hash)\b)?\s+("[^"]*"|\S+)`)

// RedactCommand masks the value of well-known secret-bearing configuration
// keywords so audit logs can show the exact command structure without
// leaking the secret. It only changes what is logged, never what is sent.
func RedactCommand(line string) string {
	return secretCommand.ReplaceAllString(line, "${1}${2} <redacted>")
}

package credentials

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// TerminalPrompter asks on a real terminal. Prompts go to Out (stderr, so
// stdout stays clean) and passwords are read with echo disabled.
type TerminalPrompter struct {
	In  *os.File
	Out io.Writer
}

// IsTerminal reports whether f is an interactive terminal.
func IsTerminal(f *os.File) bool {
	return f != nil && term.IsTerminal(int(f.Fd()))
}

// Username prompts for a (visible) user name.
func (p *TerminalPrompter) Username(group string) (string, error) {
	fmt.Fprintf(p.Out, "Username for credential group %q: ", group)
	return readLine(p.In)
}

// Password prompts for a password without echoing it.
func (p *TerminalPrompter) Password(group, username string) (string, error) {
	fmt.Fprintf(p.Out, "Password for %s (group %q): ", username, group)
	b, err := term.ReadPassword(int(p.In.Fd()))
	fmt.Fprintln(p.Out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// readLine reads byte-by-byte so nothing beyond the newline is consumed; a
// buffered reader could swallow input meant for the next prompt.
func readLine(r io.Reader) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			if buf[0] != '\r' {
				sb.WriteByte(buf[0])
			}
		}
		if err != nil {
			if err == io.EOF && sb.Len() > 0 {
				break
			}
			return "", err
		}
	}
	return sb.String(), nil
}

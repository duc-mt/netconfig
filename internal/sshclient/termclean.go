// ==============================================================================
// Package main implements Implementation and logic for termclean..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run termclean.go [options]
// Notes:         Go package implementation
// ==============================================================================
package sshclient

import (
	"regexp"
	"strings"
)

// ansiRe matches CSI, OSC and a few single-character escape sequences.
var ansiRe = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][0-9A-Za-z]|[=>78MDEHc])`)

// cleanTerminal turns raw terminal output into plain text: escape sequences
// are dropped, "\r" returns the cursor to column 0 and "\b" moves it back, so
// pager erasures ("--More--" followed by backspaces) and carriage-return
// overwrites resolve the way a real terminal would show them. Trailing blanks
// of completed lines are trimmed; the final, unterminated line (the prompt) is
// left exactly as received.
func cleanTerminal(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	var (
		lines []string
		cur   []rune
		col   int
	)
	for _, r := range s {
		switch r {
		case '\n':
			lines = append(lines, strings.TrimRight(string(cur), " \t"))
			cur = cur[:0]
			col = 0
		case '\r':
			col = 0
		case '\b', 0x7f:
			if col > 0 {
				col--
			}
		case 0x07, 0x00:
			// bell / NUL: ignore
		default:
			if col < len(cur) {
				cur[col] = r
			} else {
				cur = append(cur, r)
			}
			col++
		}
	}
	lines = append(lines, string(cur))
	return strings.Join(lines, "\n")
}

// lastLine returns the text after the final newline.
func lastLine(s string) string {
	return s[strings.LastIndexByte(s, '\n')+1:]
}

// tailBytes returns at most n trailing bytes of b. Prompts, pagers and
// confirmation questions are always at the very end of the output, so looking
// only at the tail keeps expect matching cheap while a large config streams in.
func tailBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}

// stripEcho drops the device's echo of the command we typed (the first
// non-blank line, if it contains the command) and surrounding blank lines.
func stripEcho(body, cmd string) string {
	want := strings.TrimSpace(cmd)
	lines := strings.Split(body, "\n")
	if want != "" {
		for i, ln := range lines {
			if strings.TrimSpace(ln) == "" {
				continue
			}
			if strings.Contains(ln, want) {
				lines = lines[i+1:]
			}
			break
		}
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n")
}

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
var (
	ansiRe    = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][0-9A-Za-z]|[=>78MDEHc])`)
	reScroll  = regexp.MustCompile(`^\x1b\[\d*[ML]$`)
	reLineCol = regexp.MustCompile(`^\x1b\[(?:(\d+);)?(\d+)?[Hf]$`)
)

// cleanTerminal turns raw terminal output into plain text: escape sequences
// are dropped, "\r" returns the cursor to column 0 and "\b" moves it back, so
// pager erasures ("--More--" followed by backspaces) and carriage-return
// overwrites resolve the way a real terminal would show them. Trailing blanks
// of completed lines are trimmed; the final, unterminated line (the prompt) is
// left exactly as received.
func cleanTerminal(s string) string {
	matches := ansiRe.FindAllStringIndex(s, -1)
	var (
		lines []string
		cur   []rune
		col   int
		last  int
	)

	processChars := func(chunk string) {
		for _, r := range chunk {
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
	}

	for _, m := range matches {
		if m[0] > last {
			processChars(s[last:m[0]])
		}
		esc := s[m[0]:m[1]]
		last = m[1]

		switch {
		case reScroll.MatchString(esc):
			// VT100 scroll up: Delete Line (\x1b[M or \x1b[1M) or Insert Line (\x1b[L or \x1b[1L).
			// When scrolling at the bottom of the screen, complete the line into lines.
			if len(cur) > 0 {
				lines = append(lines, strings.TrimRight(string(cur), " \t"))
				cur = cur[:0]
				col = 0
			}
		case esc == "\x1b[2K":
			// Erase entire line
			cur = cur[:0]
			col = 0
		case esc == "\x1b[K" || esc == "\x1b[0K":
			// Erase line from cursor to end
			if col < len(cur) {
				cur = cur[:col]
			}
		default:
			if sub := reLineCol.FindStringSubmatch(esc); sub != nil {
				// Cursor positioning: if target column is 1 (or omitted), move cursor to col 0
				targetCol := sub[2]
				if targetCol == "1" || (sub[1] == "" && targetCol == "") {
					col = 0
				}
			}
		}
	}
	if last < len(s) {
		processChars(s[last:])
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

// stripPromptPrefix removes trailing prompt lines that belong to a multi-line
// prompt prefix (such as Junos's "{master:0}" or "[edit]").
func stripPromptPrefix(body string, prefixRe *regexp.Regexp) string {
	if prefixRe == nil || body == "" {
		return body
	}
	lines := strings.Split(body, "\n")
	for len(lines) > 0 {
		last := strings.TrimRight(lines[len(lines)-1], "\r \t")
		if last == "" {
			lines = lines[:len(lines)-1]
			continue
		}
		if prefixRe.MatchString(last) {
			lines = lines[:len(lines)-1]
			continue
		}
		break
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\r\n")
}

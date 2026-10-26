// ==============================================================================
// Package backup implements terminal banner sanitization for configuration dumps.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-25
// License:       MIT
// ==============================================================================
package backup

import (
	"regexp"
	"strings"
)

var (
	// Terminal banner patterns emitted at the top of configuration dumps
	// by platforms such as Cisco IOS, Cisco IOS-XE, and Ruijie RGOS.
	reBuildingConfig = regexp.MustCompile(`(?i)^\s*building configuration(\.{1,3})?\s*$`)
	reCurrentConfig  = regexp.MustCompile(`(?i)^\s*(?:current\s+configuration|configuration\s+size|current\s+config\s+size)\s*:\s*\d+\s*bytes\b.*$`)
)

// CleanTerminalBanners strips leading non-configuration terminal progress headers
// (e.g. "Building configuration...", "Current configuration: <N> bytes")
// emitted at the start of configuration dumps by platforms such as Cisco IOS,
// IOS-XE, and Ruijie RGOS. Leading blank lines preceding or following these
// banners are also trimmed so the file starts directly with valid configuration.
// If no terminal banners are present at the beginning of the text, the original
// content is returned completely untouched.
func CleanTerminalBanners(output string) string {
	if output == "" {
		return ""
	}

	lines := strings.Split(output, "\n")
	firstRealLineIdx := -1
	hasBanner := false

	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		trimmedSpace := strings.TrimSpace(trimmed)
		if trimmedSpace == "" {
			continue
		}
		if reBuildingConfig.MatchString(trimmed) || reCurrentConfig.MatchString(trimmed) {
			hasBanner = true
			continue
		}
		firstRealLineIdx = i
		break
	}

	if !hasBanner {
		return output
	}

	if firstRealLineIdx == -1 {
		// Output contained only terminal banners and blank lines
		return ""
	}

	// Calculate the byte offset in output where line `firstRealLineIdx` begins.
	offset := 0
	for i := 0; i < firstRealLineIdx; i++ {
		offset += len(lines[i]) + 1 // +1 for the '\n'
	}
	if offset > len(output) {
		offset = len(output)
	}
	return output[offset:]
}

// SanitizeCheckPointConfig sanitizes Check Point Gaia and Gaia Embedded (Quantum Spark)
// configuration dumps so that the captured configuration can be restored via Clish
// without manual editing.
//
// Specifically, it performs two critical corrections:
//  1. Prepends "set clienv on-failure continue" (if not already present in the initial lines)
//     so that benign duplicate-object conflicts (e.g. default admin user, default loopback,
//     pre-existing routes) do not halt batch script imports.
//  2. Flattens multiline string commands (such as UserCheck templates for Threat Prevention,
//     Zero Phishing, Anti-Bot, Anti-Virus, and login banners) where embedded raw newlines
//     within quotes cause Clish syntax errors (unterminated quotes) and command-not-found failures.
func SanitizeCheckPointConfig(output string) string {
	if strings.TrimSpace(output) == "" {
		return output
	}

	hasCRLF := strings.Contains(output, "\r\n")
	lineEnding := "\n"
	if hasCRLF {
		lineEnding = "\r\n"
	}

	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))

	// 1. Ensure "set clienv on-failure continue" is present at the top.
	hasCliEnv := false
	checkLimit := 25
	if len(lines) < checkLimit {
		checkLimit = len(lines)
	}
	for i := 0; i < checkLimit; i++ {
		lineTrimmed := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
		if strings.HasPrefix(lineTrimmed, "set clienv on-failure continue") {
			hasCliEnv = true
			break
		}
	}

	if !hasCliEnv {
		result = append(result,
			"# Enable continue on failure so harmless conflicts or duplicate objects do not halt restore",
			"set clienv on-failure continue",
		)
	}

	// 2. Flatten multiline string commands.
	inQuotes := false
	var currentCmd []string

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		quoteCount := countUnescapedQuotes(line)

		if !inQuotes {
			if quoteCount%2 != 0 {
				inQuotes = true
				currentCmd = []string{line}
			} else {
				result = append(result, line)
			}
		} else {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				if strings.HasPrefix(trimmed, "\"") && len(currentCmd) > 0 {
					currentCmd[len(currentCmd)-1] += "\""
					rem := strings.TrimSpace(trimmed[1:])
					if rem != "" {
						currentCmd = append(currentCmd, rem)
					}
				} else {
					currentCmd = append(currentCmd, trimmed)
				}
			}
			if quoteCount%2 != 0 {
				inQuotes = false
				result = append(result, strings.Join(currentCmd, " "))
				currentCmd = nil
			}
		}
	}

	if len(currentCmd) > 0 {
		result = append(result, strings.Join(currentCmd, " "))
	}

	hadTrailingNewline := strings.HasSuffix(output, "\n")
	joined := strings.Join(result, lineEnding)
	if hadTrailingNewline && !strings.HasSuffix(joined, lineEnding) {
		joined += lineEnding
	}
	return joined
}

// countUnescapedQuotes counts the number of double quote characters (") that are
// not escaped by a preceding backslash (\).
func countUnescapedQuotes(s string) int {
	count := 0
	backslashCount := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '\\':
			backslashCount++
		case '"':
			if backslashCount%2 == 0 {
				count++
			}
			backslashCount = 0
		default:
			backslashCount = 0
		}
	}
	return count
}

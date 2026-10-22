// ==============================================================================
// Package backup implements diff calculation for device configurations.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package backup

import "strings"

// maxDiffLines caps the combined line count (before + after) that
// diffConfig will attempt to diff. Its LCS algorithm is O(n*m) in both
// time and memory, bounding the DP table to a sane size.
const maxDiffLines = 20000

// diffConfig compares two configuration dumps line by line with an
// LCS (longest common subsequence) diff, returning only lines that differ
// prefixed with "+" (added) or "-" (removed), plus line counts.
// Unchanged lines are omitted.
// ok is false when the input exceeds maxDiffLines.
func diffConfig(before, after string) (lines []string, added, removed int, ok bool) {
	a := splitConfigLines(before)
	b := splitConfigLines(after)
	if len(a)+len(b) > maxDiffLines {
		return nil, 0, 0, false
	}

	// lcs[i][j] = length of longest common subsequence of a[i:] and b[j:]
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			lines = append(lines, "-"+a[i])
			removed++
			i++
		default:
			lines = append(lines, "+"+b[j])
			added++
			j++
		}
	}
	for ; i < len(a); i++ {
		lines = append(lines, "-"+a[i])
		removed++
	}
	for ; j < len(b); j++ {
		lines = append(lines, "+"+b[j])
		added++
	}
	return lines, added, removed, true
}

// splitConfigLines splits configuration text into non-blank lines,
// trimming trailing \r characters.
func splitConfigLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

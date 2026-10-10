package task

import "strings"

// maxDiffLines caps the combined line count (before + after) that
// diffConfig will attempt to diff. Its LCS algorithm is O(n*m) in both
// time and memory, so an unbounded configuration dump could otherwise
// exhaust memory on a run that would otherwise have nothing unusual
// about it; 20000 lines comfortably covers any real device configuration
// while still bounding the DP table to a sane size.
const maxDiffLines = 20000

// diffConfig compares two full configuration dumps line by line with a
// classic LCS (longest common subsequence) diff, and returns only the
// lines that differ -- each prefixed "+" (present only in after) or "-"
// (present only in before), the way `git diff` marks them -- plus how
// many of each. Unchanged lines are omitted entirely: for a device's full
// configuration, an operator wants to see what changed, not the whole
// file with a few lines of context around it.
//
// ok is false when the input is too large to diff safely (see
// maxDiffLines); the caller should treat that as "diff skipped", not as
// "no difference found".
func diffConfig(before, after string) (lines []string, added, removed int, ok bool) {
	a := splitConfigLines(before)
	b := splitConfigLines(after)
	if len(a)+len(b) > maxDiffLines {
		return nil, 0, 0, false
	}

	// lcs[i][j] = length of the longest common subsequence of a[i:] and b[j:].
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

// splitConfigLines splits a configuration dump into non-blank lines,
// trimming any trailing \r so text fetched live from a device (which
// typically sends \r\n) compares equal to a backup file written with \n
// alone.
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

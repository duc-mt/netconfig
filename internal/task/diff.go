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

	// 1. Trim common prefix
	start := 0
	for start < len(a) && start < len(b) && a[start] == b[start] {
		start++
	}

	// 2. Trim common suffix
	endA := len(a)
	endB := len(b)
	for endA > start && endB > start && a[endA-1] == b[endB-1] {
		endA--
		endB--
	}

	subA := a[start:endA]
	subB := b[start:endB]

	if len(subA) == 0 && len(subB) == 0 {
		return nil, 0, 0, true
	}

	diffLines := hirschbergDiff(subA, subB)
	for _, l := range diffLines {
		if strings.HasPrefix(l, "+") {
			added++
		} else if strings.HasPrefix(l, "-") {
			removed++
		}
	}
	return diffLines, added, removed, true
}

const maxFlatDPCells = 250000

func hirschbergDiff(a, b []string) []string {
	if len(a) == 0 {
		out := make([]string, len(b))
		for i, s := range b {
			out[i] = "+" + s
		}
		return out
	}
	if len(b) == 0 {
		out := make([]string, len(a))
		for i, s := range a {
			out[i] = "-" + s
		}
		return out
	}
	if len(a) == 1 {
		idx := -1
		for i, s := range b {
			if s == a[0] {
				idx = i
				break
			}
		}
		if idx >= 0 {
			out := make([]string, 0, len(b)-1)
			for _, s := range b[:idx] {
				out = append(out, "+"+s)
			}
			for _, s := range b[idx+1:] {
				out = append(out, "+"+s)
			}
			return out
		}
		out := make([]string, 0, len(b)+1)
		out = append(out, "-"+a[0])
		for _, s := range b {
			out = append(out, "+"+s)
		}
		return out
	}
	if len(b) == 1 {
		idx := -1
		for i, s := range a {
			if s == b[0] {
				idx = i
				break
			}
		}
		if idx >= 0 {
			out := make([]string, 0, len(a)-1)
			for _, s := range a[:idx] {
				out = append(out, "-"+s)
			}
			for _, s := range a[idx+1:] {
				out = append(out, "-"+s)
			}
			return out
		}
		out := make([]string, 0, len(a)+1)
		for _, s := range a {
			out = append(out, "-"+s)
		}
		out = append(out, "+"+b[0])
		return out
	}

	// Use fast flat 1D DP for small/medium blocks
	if len(a)*len(b) <= maxFlatDPCells {
		return flatLCSDiff(a, b)
	}

	// Hirschberg divide-and-conquer for large blocks to guarantee linear O(min(N,M)) memory
	mid := len(a) / 2
	l1 := lcsLengths(a[:mid], b)
	l2 := lcsLengthsRev(a[mid:], b)

	m := len(b)
	bestK := 0
	maxSum := -1
	for k := 0; k <= m; k++ {
		sum := l1[k] + l2[m-k]
		if sum > maxSum {
			maxSum = sum
			bestK = k
		}
	}

	left := hirschbergDiff(a[:mid], b[:bestK])
	right := hirschbergDiff(a[mid:], b[bestK:])
	return append(left, right...)
}

func flatLCSDiff(a, b []string) []string {
	stride := len(b) + 1
	dp := make([]int, (len(a)+1)*stride)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				dp[i*stride+j] = dp[(i+1)*stride+j+1] + 1
			case dp[(i+1)*stride+j] >= dp[i*stride+j+1]:
				dp[i*stride+j] = dp[(i+1)*stride+j]
			default:
				dp[i*stride+j] = dp[i*stride+j+1]
			}
		}
	}

	var lines []string
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			i++
			j++
		case dp[(i+1)*stride+j] >= dp[i*stride+j+1]:
			lines = append(lines, "-"+a[i])
			i++
		default:
			lines = append(lines, "+"+b[j])
			j++
		}
	}
	for ; i < len(a); i++ {
		lines = append(lines, "-"+a[i])
	}
	for ; j < len(b); j++ {
		lines = append(lines, "+"+b[j])
	}
	return lines
}

func lcsLengths(a, b []string) []int {
	curr := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	for i := 0; i < len(a); i++ {
		copy(prev, curr)
		for j := 0; j < len(b); j++ {
			switch {
			case a[i] == b[j]:
				curr[j+1] = prev[j] + 1
			case prev[j+1] >= curr[j]:
				curr[j+1] = prev[j+1]
			default:
				curr[j+1] = curr[j]
			}
		}
	}
	return curr
}

func lcsLengthsRev(a, b []string) []int {
	curr := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	for i := len(a) - 1; i >= 0; i-- {
		copy(prev, curr)
		for j := len(b) - 1; j >= 0; j-- {
			col := len(b) - j
			switch {
			case a[i] == b[j]:
				curr[col] = prev[col-1] + 1
			case prev[col] >= curr[col-1]:
				curr[col] = prev[col]
			default:
				curr[col] = curr[col-1]
			}
		}
	}
	return curr
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

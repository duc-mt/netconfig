// ==============================================================================
// Package backup implements diff calculation for device configurations.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-12
// License:       MIT
// ==============================================================================
package backup

import (
	"slices"
	"strings"
)

const (
	// maxDiffLines bounds the combined line count (before + after) that
	// diffConfig will look at at all. It only guards memory for absurd input;
	// size is not what makes a diff expensive (see diffOps).
	maxDiffLines = 400000
)

var (
	// denseDiffCells is the largest "old lines x new lines" product (after the
	// common start is removed) for which the exact LCS table is used. 4M cells
	// is 16 MB. Larger problems use the edit-distance algorithm below.
	denseDiffCells = 4_000_000

	// maxEditDistance is the most changed lines (removed + added) the large
	// input algorithm will find a diff for. Its memory is about 4*d^2 bytes
	// (36 MB at 3000), so a configuration that was replaced wholesale is
	// reported as "too large to diff" instead of exhausting memory.
	maxEditDistance = 3000
)

// editOp is one step of an edit script: a line kept, removed or added.
type editOp byte

const (
	opEqual  editOp = '='
	opDelete editOp = '-'
	opInsert editOp = '+'
)

// diffConfig compares two configuration dumps line by line with a shortest
// edit script (an LCS diff), returning only lines that differ prefixed with
// "+" (added) or "-" (removed), plus line counts. Unchanged lines are omitted.
// ok is false when the input is too large, or the two sides too different, to
// diff within bounded memory (see maxDiffLines and maxEditDistance).
func diffConfig(before, after string) (lines []string, added, removed int, ok bool) {
	a := splitConfigLines(before)
	b := splitConfigLines(after)
	if len(a)+len(b) > maxDiffLines {
		return nil, 0, 0, false
	}
	ops, ok := diffOps(a, b)
	if !ok {
		return nil, 0, 0, false
	}

	i, j := 0, 0
	for _, op := range ops {
		switch op {
		case opEqual:
			i++
			j++
		case opDelete:
			lines = append(lines, "-"+a[i])
			removed++
			i++
		case opInsert:
			lines = append(lines, "+"+b[j])
			added++
			j++
		}
	}
	return lines, added, removed, true
}

// diffOps returns a shortest edit script turning a into b.
//
// The lines two backups share at the start (and, for large inputs, at the end)
// are set aside first: nightly configurations nearly always differ in a few
// places only. What is left goes to one of two algorithms.
//
//   - Small problems use the classic LCS table, exactly as before, so their
//     output is unchanged down to how equally short diffs of repeated lines
//     ("!", "exit", ...) are resolved. Removing the shared start first is exact:
//     the table traversal would have matched those lines first anyway.
//   - Larger ones use Myers' O(ND) algorithm, whose cost grows with the
//     number of changes D, not with the size of the file. The old table needed
//     (old lines x new lines) cells whatever had changed: 370 MB for a
//     6,400-line configuration.
//
// ok is false only when the changes exceed maxEditDistance.
func diffOps(a, b []string) (ops []editOp, ok bool) {
	p := 0
	for p < len(a) && p < len(b) && a[p] == b[p] {
		p++
	}
	ra, rb := a[p:], b[p:]

	var mid []editOp
	suffix := 0
	if len(ra)*len(rb) <= denseDiffCells {
		mid = denseOps(ra, rb)
	} else {
		for suffix < len(ra) && suffix < len(rb) && ra[len(ra)-1-suffix] == rb[len(rb)-1-suffix] {
			suffix++
		}
		if mid, ok = myersOps(ra[:len(ra)-suffix], rb[:len(rb)-suffix]); !ok {
			return nil, false
		}
	}

	ops = make([]editOp, 0, p+len(mid)+suffix)
	for i := 0; i < p; i++ {
		ops = append(ops, opEqual)
	}
	ops = append(ops, mid...)
	for i := 0; i < suffix; i++ {
		ops = append(ops, opEqual)
	}
	return ops, true
}

// denseOps is the original algorithm: lcs[i][j] is the length of the longest
// common subsequence of a[i:] and b[j:], kept in one flat table, then walked
// from the start preferring to remove a line when removing and adding are
// equally good.
func denseOps(a, b []string) []editOp {
	n, m := len(a), len(b)
	w := m + 1
	lcs := make([]int32, (n+1)*w)
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			case lcs[(i+1)*w+j] >= lcs[i*w+j+1]:
				lcs[i*w+j] = lcs[(i+1)*w+j]
			default:
				lcs[i*w+j] = lcs[i*w+j+1]
			}
		}
	}

	ops := make([]editOp, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, opEqual)
			i++
			j++
		case lcs[(i+1)*w+j] >= lcs[i*w+j+1]:
			ops = append(ops, opDelete)
			i++
		default:
			ops = append(ops, opInsert)
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, opDelete)
	}
	for ; j < m; j++ {
		ops = append(ops, opInsert)
	}
	return ops
}

// myersOps finds a shortest edit script with Myers' greedy algorithm: round d
// extends, on each diagonal k = x-y, the furthest point reachable with d
// removals/additions. It stops at the first round that reaches the end, so the
// work is O((n+m)*d). The furthest-reaching points of every round are kept to
// walk the path back, which is what bounds the memory (see maxEditDistance).
func myersOps(a, b []string) ([]editOp, bool) {
	n, m := len(a), len(b)
	maxD := min(n+m, maxEditDistance)
	off := maxD + 1
	v := make([]int, 2*maxD+3) // v[off+k]: furthest x on diagonal k
	trace := make([][]int, 0, 32)

	for d := 0; d <= maxD; d++ {
		snap := make([]int, 2*d+1) // v as it stood before this round, k in [-d, d]
		copy(snap, v[off-d:off+d+1])
		trace = append(trace, snap)

		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1] // add a line (move down)
			} else {
				x = v[off+k-1] + 1 // remove a line (move right)
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x == n && y == m {
				return myersPath(trace, d, n, m), true
			}
		}
	}
	return nil, false
}

// myersPath walks the recorded rounds back from (n, m) to the start and returns
// the script in forward order, each block of changes listing its removals
// before its additions.
func myersPath(trace [][]int, d, n, m int) []editOp {
	ops := make([]editOp, 0, n+m)
	x, y := n, m
	for ; d > 0; d-- {
		snap := trace[d] // snap[k+d] is the furthest x on diagonal k after round d-1
		k := x - y
		var prevK int
		if k == -d || (k != d && snap[k-1+d] < snap[k+1+d]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := snap[prevK+d]
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			ops = append(ops, opEqual)
			x--
			y--
		}
		if x == prevX {
			ops = append(ops, opInsert)
			y--
		} else {
			ops = append(ops, opDelete)
			x--
		}
	}
	for x > 0 && y > 0 {
		ops = append(ops, opEqual)
		x--
		y--
	}
	slices.Reverse(ops)

	// Within one block of changes the order of removals and additions is free;
	// list the removals first, as the table algorithm does.
	for i := 0; i < len(ops); {
		if ops[i] == opEqual {
			i++
			continue
		}
		j, dels := i, 0
		for j < len(ops) && ops[j] != opEqual {
			if ops[j] == opDelete {
				dels++
			}
			j++
		}
		for k := i; k < j; k++ {
			if k-i < dels {
				ops[k] = opDelete
			} else {
				ops[k] = opInsert
			}
		}
		i = j
	}
	return ops
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

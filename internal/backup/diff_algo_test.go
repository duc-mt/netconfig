// ==============================================================================
// File name:     diff_algo_test.go
// Description:   Tests for the diff algorithms against a reference.
// License:       MIT
// ==============================================================================
package backup

import (
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// referenceDiff is the original implementation: one LCS table over the whole
// input. It is quadratic in memory, which is why it was replaced for large
// inputs, but its output is what users have seen, so the new code must
// reproduce it exactly wherever the old code was cheap enough.
func referenceDiff(before, after string) (lines []string, added, removed int) {
	a := splitConfigLines(before)
	b := splitConfigLines(after)
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
	return lines, added, removed
}

// lcsLength is computed independently of the code under test (two rolling
// rows), so "minimal" can be judged against it.
func lcsLength(a, b []string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				cur[j] = prev[j+1] + 1
			case prev[j] >= cur[j+1]:
				cur[j] = prev[j]
			default:
				cur[j] = cur[j+1]
			}
		}
		prev, cur = cur, prev
		for k := range cur {
			cur[k] = 0
		}
	}
	return prev[0]
}

func randomLines(r *rand.Rand, n, alphabet int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "line-" + strconv.Itoa(r.Intn(alphabet))
	}
	return out
}

// mutate applies a few random inserts, deletes and replacements.
func mutate(r *rand.Rand, in []string, edits, alphabet int) []string {
	out := slices.Clone(in)
	for k := 0; k < edits; k++ {
		switch op := r.Intn(3); {
		case op == 0 || len(out) == 0:
			i := r.Intn(len(out) + 1)
			out = slices.Insert(out, i, "line-"+strconv.Itoa(r.Intn(alphabet)))
		case op == 1:
			i := r.Intn(len(out))
			out = slices.Delete(out, i, i+1)
		default:
			out[r.Intn(len(out))] = "line-" + strconv.Itoa(r.Intn(alphabet))
		}
	}
	return out
}

// applyOps replays an edit script on a and returns what it produces; it fails
// the test if the script does not fit the inputs.
func applyOps(t *testing.T, a, b []string, ops []editOp) []string {
	t.Helper()
	var out []string
	i, j := 0, 0
	for _, op := range ops {
		switch op {
		case opEqual:
			if i >= len(a) || j >= len(b) || a[i] != b[j] {
				t.Fatalf("an unchanged line does not match at a[%d] / b[%d]", i, j)
			}
			out = append(out, a[i])
			i++
			j++
		case opDelete:
			if i >= len(a) {
				t.Fatal("deletes past the end of the old text")
			}
			i++
		case opInsert:
			if j >= len(b) {
				t.Fatal("inserts past the end of the new text")
			}
			out = append(out, b[j])
			j++
		}
	}
	if i != len(a) || j != len(b) {
		t.Fatalf("the script consumed %d of %d old and %d of %d new lines", i, len(a), j, len(b))
	}
	return out
}

func withDenseLimit(t *testing.T, cells int) {
	t.Helper()
	old := denseDiffCells
	denseDiffCells = cells
	t.Cleanup(func() { denseDiffCells = old })
}

func withEditCap(t *testing.T, d int) {
	t.Helper()
	old := maxEditDistance
	maxEditDistance = d
	t.Cleanup(func() { maxEditDistance = old })
}

func equalLines(a, b []string) bool { return slices.Equal(a, b) }

// Wherever the old code was affordable, nothing about the output changes: the
// same lines, in the same order, with the same tie-breaking between equally
// short diffs of repeated lines ("!", "exit", ...).
func TestDenseRegimeReproducesThePreviousOutputExactly(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for n := 0; n < 3000; n++ {
		alphabet := 2 + r.Intn(6)
		a := randomLines(r, r.Intn(40), alphabet)
		b := mutate(r, a, r.Intn(8), alphabet)
		if n%5 == 0 {
			b = randomLines(r, r.Intn(40), alphabet) // unrelated texts too
		}
		before, after := strings.Join(a, "\n"), strings.Join(b, "\n")

		got, gotAdded, gotRemoved, ok := diffConfig(before, after)
		want, wantAdded, wantRemoved := referenceDiff(before, after)
		if !ok || !equalLines(got, want) || gotAdded != wantAdded || gotRemoved != wantRemoved {
			t.Fatalf("case %d differs from the previous output\n before %q\n after  %q\n got  %q\n want %q", n, a, b, got, want)
		}
	}
}

func TestDenseRegimeReproducesThePreviousOutputOnRealisticConfigurations(t *testing.T) {
	for _, n := range []int{300, 1200} {
		before := benchConfig(n, 0)
		for _, edits := range []int{0, 1, 5, 20} {
			after := benchConfig(n, edits)
			got, ga, gr, ok := diffConfig(before, after)
			want, wa, wr := referenceDiff(before, after)
			if !ok || !equalLines(got, want) || ga != wa || gr != wr {
				t.Errorf("%d lines, %d edits: output differs from the previous implementation", n, edits)
			}
		}
	}
}

// Beyond the dense regime the algorithm may break ties differently, but it
// must still be a valid script that is as short as the shortest possible one.
func TestMyersProducesAValidMinimalEditScript(t *testing.T) {
	withDenseLimit(t, 0) // force it for every input
	r := rand.New(rand.NewSource(2))
	for n := 0; n < 4000; n++ {
		alphabet := 2 + r.Intn(6)
		a := randomLines(r, r.Intn(45), alphabet)
		b := mutate(r, a, r.Intn(10), alphabet)
		if n%4 == 0 {
			b = randomLines(r, r.Intn(45), alphabet)
		}
		ops, ok := diffOps(a, b)
		if !ok {
			t.Fatalf("case %d: refused a small input: %q -> %q", n, a, b)
		}
		if got := applyOps(t, a, b, ops); !equalLines(got, b) {
			t.Fatalf("case %d: the script does not turn the old text into the new one\n a %q\n b %q\n got %q", n, a, b, got)
		}
		edits := 0
		for _, op := range ops {
			if op != opEqual {
				edits++
			}
		}
		if want := len(a) + len(b) - 2*lcsLength(a, b); edits != want {
			t.Fatalf("case %d: %d edits, the shortest script has %d\n a %q\n b %q", n, edits, want, a, b)
		}
	}
}

func TestMyersOnLargerInputsWithScatteredChanges(t *testing.T) {
	withDenseLimit(t, 0)
	r := rand.New(rand.NewSource(3))
	for n := 0; n < 40; n++ {
		a := randomLines(r, 300+r.Intn(500), 40)
		b := mutate(r, a, 5+r.Intn(40), 40)
		ops, ok := diffOps(a, b)
		if !ok {
			t.Fatalf("case %d refused", n)
		}
		if got := applyOps(t, a, b, ops); !equalLines(got, b) {
			t.Fatalf("case %d: wrong script", n)
		}
		edits := 0
		for _, op := range ops {
			if op != opEqual {
				edits++
			}
		}
		if want := len(a) + len(b) - 2*lcsLength(a, b); edits != want {
			t.Fatalf("case %d: %d edits, shortest is %d", n, edits, want)
		}
	}
}

// Inside one changed block the old output lists every removal before every
// addition, which reads naturally; the new algorithm keeps that.
func TestMyersListsRemovalsBeforeAdditionsInEachBlock(t *testing.T) {
	withDenseLimit(t, 0)
	r := rand.New(rand.NewSource(4))
	for n := 0; n < 500; n++ {
		a := randomLines(r, 5+r.Intn(30), 4)
		b := mutate(r, a, 1+r.Intn(8), 4)
		ops, _ := diffOps(a, b)
		for i := 1; i < len(ops); i++ {
			if ops[i-1] == opInsert && ops[i] == opDelete {
				t.Fatalf("an addition is followed directly by a removal in %v\n a %q\n b %q", string(editBytes(ops)), a, b)
			}
		}
	}
}

func editBytes(ops []editOp) []byte {
	out := make([]byte, len(ops))
	for i, op := range ops {
		out[i] = byte(op)
	}
	return out
}

func TestDiffOpsEdgeCases(t *testing.T) {
	for _, regime := range []int{1 << 40, 0} { // dense, then Myers
		withDenseLimit(t, regime)
		for _, tc := range []struct{ a, b []string }{
			{nil, nil},
			{nil, []string{"x"}},
			{[]string{"x"}, nil},
			{[]string{"x"}, []string{"x"}},
			{[]string{"x", "y"}, []string{"y", "x"}},
			{[]string{"a", "a", "a"}, []string{"a"}},
			{[]string{"a"}, []string{"a", "a", "a"}},
		} {
			ops, ok := diffOps(tc.a, tc.b)
			if !ok {
				t.Fatalf("regime %d: refused %q -> %q", regime, tc.a, tc.b)
			}
			if got := applyOps(t, tc.a, tc.b, ops); !equalLines(got, tc.b) {
				t.Errorf("regime %d: %q -> %q gave %q", regime, tc.a, tc.b, got)
			}
		}
	}
}

// A configuration of any size is cheap to diff when little changed: the work
// grows with the number of changes, not with the size of the file.
func TestDiffConfigHandlesHugeConfigurationsWithFewChanges(t *testing.T) {
	const n = 100000
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("line " + strconv.Itoa(i) + "\n")
	}
	before := b.String()
	after := strings.Replace(before, "line 10\n", "changed 10\n", 1)
	after = strings.Replace(after, "line 50000\n", "changed 50000\n", 1)
	after += "appended\n"

	lines, added, removed, ok := diffConfig(before, after)
	if !ok {
		t.Fatal("a 100,000-line configuration with three changes must be diffed")
	}
	if added != 3 || removed != 2 || len(lines) != 5 {
		t.Errorf("added=%d removed=%d lines=%q", added, removed, lines)
	}
	for _, want := range []string{"-line 10", "+changed 10", "-line 50000", "+changed 50000", "+appended"} {
		if !slices.Contains(lines, want) {
			t.Errorf("diff is missing %q: %q", want, lines)
		}
	}

	if lines, a, r, ok := diffConfig(before, before); !ok || len(lines) != 0 || a != 0 || r != 0 {
		t.Errorf("identical huge configurations: %v %d %d %v", lines, a, r, ok)
	}
}

// What is skipped is a rewrite too large to diff cheaply (here 5,000 changed
// lines against a cap of 3,000), not a large file.
func TestDiffConfigSkipsWholesaleRewrites(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 2500; i++ {
		a.WriteString("old line " + strconv.Itoa(i) + "\n")
		b.WriteString("new line " + strconv.Itoa(i) + "\n")
	}
	if _, _, _, ok := diffConfig(a.String(), b.String()); ok {
		t.Error("two entirely different configurations of 2,500 lines are beyond the edit-distance cap")
	}
}

func TestEditDistanceCapIsHonoured(t *testing.T) {
	withDenseLimit(t, 0)
	withEditCap(t, 6)
	a := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	within := []string{"a", "X", "c", "Y", "e", "Z", "g", "h"} // 3 replacements = 6 edits
	beyond := []string{"a", "X", "c", "Y", "e", "Z", "g", "W"} // 4 replacements = 8 edits
	if _, ok := diffOps(a, within); !ok {
		t.Error("an edit distance equal to the cap must still be diffed")
	}
	if _, ok := diffOps(a, beyond); ok {
		t.Error("an edit distance over the cap must be refused")
	}
}

func TestDiffConfigStillBoundsTheInputSize(t *testing.T) {
	n := maxDiffLines/2 + 1
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("x" + strconv.Itoa(i) + "\n")
	}
	s := b.String()
	if _, _, _, ok := diffConfig(s, s); ok {
		t.Errorf("inputs above %d lines combined must be refused", maxDiffLines)
	}
}

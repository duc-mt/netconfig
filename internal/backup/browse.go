// ==============================================================================
// File name:     browse.go
// Description:   Read-only access to a backup tree written by a backup run.
// License:       MIT
// ==============================================================================
package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// treeEntry is one saved file: <dir>/<run>/<platform>/<node><ext>. Its
// modification time is not read while scanning: listing needs none, and a
// lookup only needs those of one device's files.
type treeEntry struct {
	node string
	path string
	run  string
	diff bool // a .diff file rather than a configuration
}

// knownExtensions are the file extensions a backup run writes, taken from the
// same table that names them, so listing can never fall out of step with saving.
func knownExtensions() map[string]bool {
	exts := map[string]bool{".cfg": true}
	for _, spec := range archiveSpecs {
		exts[spec.Ext] = true
	}
	return exts
}

// scanTree reads the three directory levels of a backup tree, keeping the
// entries keep accepts (nil keeps all). Anything that is not a regular,
// non-hidden file with a recognised extension inside a "backup-*" run
// directory (stray files, atomic-write temporaries, reports) is ignored.
func scanTree(dir string, keep func(node string, diff bool) bool) ([]treeEntry, error) {
	runs, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("backups directory %q not found: %w", dir, os.ErrNotExist)
		}
		return nil, err
	}
	exts := knownExtensions()
	var out []treeEntry
	for _, run := range runs {
		if !run.IsDir() || !strings.HasPrefix(run.Name(), "backup-") {
			continue
		}
		platforms, err := os.ReadDir(filepath.Join(dir, run.Name()))
		if err != nil {
			continue
		}
		for _, platform := range platforms {
			if !platform.IsDir() {
				continue
			}
			files, err := os.ReadDir(filepath.Join(dir, run.Name(), platform.Name()))
			if err != nil {
				continue
			}
			for _, f := range files {
				name := f.Name()
				ext := filepath.Ext(name)
				if !f.Type().IsRegular() || strings.HasPrefix(name, ".") || (ext != ".diff" && !exts[ext]) {
					continue
				}
				node := strings.TrimSuffix(name, ext)
				isDiff := ext == ".diff"
				if node == "" || (keep != nil && !keep(node, isDiff)) {
					continue
				}
				out = append(out, treeEntry{
					node: node,
					path: filepath.Join(dir, run.Name(), platform.Name(), name),
					run:  run.Name(),
					diff: isDiff,
				})
			}
		}
	}
	return out, nil
}

// Tree is a backup directory read once. Listing the devices, matching a name
// and finding the newest file all answer from that single pass, which for a
// large estate (thousands of devices, many runs) is most of the cost.
type Tree struct {
	entries []treeEntry
}

// ScanTree reads the backup tree under dir.
func ScanTree(dir string) (*Tree, error) {
	entries, err := scanTree(dir, nil)
	if err != nil {
		return nil, err
	}
	return &Tree{entries: entries}, nil
}

// Nodes returns the devices that have at least one saved configuration (or,
// with diff, at least one saved diff), sorted and without duplicates.
func (t *Tree) Nodes(diff bool) []string { return nodesOf(t.entries, diff) }

// Latest returns the path of the newest saved configuration (or, with diff,
// the newest saved diff) of node, by modification time across all runs and
// platform directories. Equal times go to the later run.
func (t *Tree) Latest(node string, diff bool) (string, error) {
	return latestOf(t.entries, node, diff)
}

func nodesOf(entries []treeEntry, diff bool) []string {
	seen := make(map[string]bool)
	var nodes []string
	for _, e := range entries {
		if e.diff == diff && !seen[e.node] {
			seen[e.node] = true
			nodes = append(nodes, e.node)
		}
	}
	sort.Strings(nodes)
	return nodes
}

func latestOf(entries []treeEntry, node string, diff bool) (string, error) {
	var best *treeEntry
	var bestTime time.Time
	for i := range entries {
		e := &entries[i]
		if e.node != node || e.diff != diff {
			continue
		}
		info, err := os.Stat(e.path)
		if err != nil {
			continue
		}
		mtime := info.ModTime()
		if best == nil || mtime.After(bestTime) ||
			(mtime.Equal(bestTime) && (e.run > best.run || (e.run == best.run && e.path > best.path))) {
			best, bestTime = e, mtime
		}
	}
	if best == nil {
		kind := "configuration"
		if diff {
			kind = "diff"
		}
		return "", fmt.Errorf("no %s found for node %q: %w", kind, node, os.ErrNotExist)
	}
	return best.path, nil
}

// ListNodes returns the devices that have at least one saved configuration in
// the backup tree under dir, sorted and without duplicates.
func ListNodes(dir string) ([]string, error) { return listNodes(dir, false) }

// ListDiffNodes returns the devices that have at least one saved diff.
func ListDiffNodes(dir string) ([]string, error) { return listNodes(dir, true) }

func listNodes(dir string, diff bool) ([]string, error) {
	entries, err := scanTree(dir, func(_ string, isDiff bool) bool { return isDiff == diff })
	if err != nil {
		return nil, err
	}
	return nodesOf(entries, diff), nil
}

// MatchNodes finds the nodes whose name contains query, ignoring case. The
// query is plain text, not a pattern. exact is the node that equals the query
// (ignoring case), if any.
func MatchNodes(nodes []string, query string) (exact string, matches []string) {
	q := strings.ToLower(query)
	for _, n := range nodes {
		if !strings.Contains(strings.ToLower(n), q) {
			continue
		}
		matches = append(matches, n)
		if exact == "" && strings.EqualFold(n, query) {
			exact = n
		}
	}
	return exact, matches
}

// Latest is Tree.Latest for a one-off lookup: only that node's entries are
// kept while scanning, so nothing is read for the rest of the estate.
func Latest(dir, node string, diff bool) (string, error) {
	entries, err := scanTree(dir, func(n string, isDiff bool) bool { return n == node && isDiff == diff })
	if err != nil {
		return "", err
	}
	return latestOf(entries, node, diff)
}

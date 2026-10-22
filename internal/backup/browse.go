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

// treeEntry is one saved file: <dir>/<run>/<platform>/<node><ext>.
type treeEntry struct {
	node  string
	path  string
	run   string
	mtime time.Time
	diff  bool // a .diff file rather than a configuration
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

// scanTree reads the three directory levels of a backup tree. Anything that is
// not a regular, non-hidden file with a recognised extension inside a
// "backup-*" run directory (stray files, atomic-write temporaries, reports) is
// ignored.
func scanTree(dir string) ([]treeEntry, error) {
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
				info, err := f.Info()
				if node == "" || err != nil {
					continue
				}
				out = append(out, treeEntry{
					node:  node,
					path:  filepath.Join(dir, run.Name(), platform.Name(), name),
					run:   run.Name(),
					mtime: info.ModTime(),
					diff:  ext == ".diff",
				})
			}
		}
	}
	return out, nil
}

// ListNodes returns the devices that have at least one saved configuration in
// the backup tree under dir, sorted and without duplicates.
func ListNodes(dir string) ([]string, error) { return listNodes(dir, false) }

// ListDiffNodes returns the devices that have at least one saved diff.
func ListDiffNodes(dir string) ([]string, error) { return listNodes(dir, true) }

func listNodes(dir string, diff bool) ([]string, error) {
	entries, err := scanTree(dir)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var nodes []string
	for _, e := range entries {
		if e.diff == diff && !seen[e.node] {
			seen[e.node] = true
			nodes = append(nodes, e.node)
		}
	}
	sort.Strings(nodes)
	return nodes, nil
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

// Latest returns the path of the newest saved configuration (or, with diff,
// the newest saved diff) of node, by modification time across all runs and
// platform directories. Equal times go to the later run.
func Latest(dir, node string, diff bool) (string, error) {
	entries, err := scanTree(dir)
	if err != nil {
		return "", err
	}
	var best *treeEntry
	for i := range entries {
		e := &entries[i]
		if e.node != node || e.diff != diff {
			continue
		}
		if best == nil || e.mtime.After(best.mtime) ||
			(e.mtime.Equal(best.mtime) && (e.run > best.run || (e.run == best.run && e.path > best.path))) {
			best = e
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

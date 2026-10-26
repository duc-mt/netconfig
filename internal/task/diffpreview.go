// ==============================================================================
// File name:     diffpreview.go
// Description:   Pre-change diff preview for platforms without a candidate
//
//	configuration (the simulated path of "netconfig diff").
//
// License:       MIT
// ==============================================================================
package task

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"netops/internal/logging"
)

// DiffRow is one device's predicted change.
type DiffRow struct {
	Hostname string
	Vendor   string
	Lines    []string // "+"/"-" lines with unchanged block headers for context
	Added    int
	Removed  int
}

// DiffSink gathers simulated diffs across devices.
type DiffSink struct {
	mu   sync.Mutex
	rows []DiffRow
}

// Rows returns the previews sorted by hostname.
func (s *DiffSink) Rows() []DiffRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]DiffRow(nil), s.rows...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// Handler reads each device's running configuration (read-only), replays
// commands against it locally and prints the predicted, colored diff. The
// device is never put into configuration mode.
func (s *DiffSink) Handler(commands []string) Handler {
	return func(ctx context.Context, env *HandlerEnv) (string, error) {
		prof := env.Job.Profile
		out, err := env.RunSlow(ctx, prof.BackupCommand)
		if err != nil {
			return "", err
		}
		if line, bad := prof.FindError(out); bad {
			return "", opErrorf(CatSyntaxError, "cannot preview: the device rejected %q (%s)", prof.BackupCommand, logging.RedactCommand(line))
		}
		if err := prof.ValidateBackup(out); err != nil {
			return "", opErrorf(CatSyntaxError, "cannot preview: %v", err)
		}
		if n := len(strings.Split(out, "\n")); n > maxDiffLines {
			return "", opErrorf(CatSyntaxError, "cannot preview: configuration too large to diff safely (%d lines)", n)
		}
		lines, added, removed, ok := SimulateDiff(prof.Name, out, commands)
		if !ok {
			return "", opErrorf(CatUnsupportedOp, "no simulator for %s", prof.Display)
		}
		for i, l := range lines {
			lines[i] = redactText(logging.RedactCommand(l))
		}
		s.mu.Lock()
		s.rows = append(s.rows, DiffRow{Hostname: env.Job.Device.Hostname, Vendor: prof.Name, Lines: lines, Added: added, Removed: removed})
		s.mu.Unlock()
		if len(lines) == 0 {
			return "predicted: no change", nil
		}
		env.Log.Infof(env.Host(), "predicted change (local simulation, device untouched): +%d -%d", added, removed)
		env.Log.DiffBlock(logging.LevelInfo, env.Host(), "  | ", strings.Join(lines, "\n"))
		return fmt.Sprintf("predicted +%d -%d line(s)", added, removed), nil
	}
}

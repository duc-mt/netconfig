// ==============================================================================
// File name:     audit.go
// Description:   Read-only compliance audit of device configurations.
// License:       MIT
// ==============================================================================
package task

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"netops/internal/audit"
	"netops/internal/logging"
	"netops/internal/vendor"
)

// AuditRow is one device's audit outcome.
type AuditRow struct {
	Hostname string
	Address  string
	Vendor   string
	Checks   []audit.Check
}

// AuditSink gathers audit outcomes across devices.
type AuditSink struct {
	rules []audit.Rule
	mu    sync.Mutex
	rows  []AuditRow
}

// NewAuditSink audits against rules (see audit.Defaults / audit.ParseRules).
func NewAuditSink(rules []audit.Rule) *AuditSink { return &AuditSink{rules: rules} }

// Rows returns the outcomes sorted by hostname.
func (s *AuditSink) Rows() []AuditRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]AuditRow(nil), s.rows...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// Handler reads each device's configuration (read-only) and evaluates it. A
// response that is empty, an error, or visibly truncated fails the device: an
// incomplete configuration must never produce a verdict, since every
// "required" line would then read as missing.
func (s *AuditSink) Handler() Handler {
	return func(ctx context.Context, env *HandlerEnv) (string, error) {
		prof := env.Job.Profile
		cmd := audit.ConfigCommand(prof)
		out, err := env.RunSlow(ctx, cmd)
		if err != nil {
			return "", err
		}
		return s.Add(env.Job.Device.Hostname, env.Job.Device.Address, prof, cmd, out)
	}
}

// Add validates out, the output of cmd for one device, and records its audit
// row. It is shared by the live handler and by offline (saved-file) audits so
// both apply the same "never judge an incomplete configuration" rules. The
// returned string is a one-line outcome summary.
func (s *AuditSink) Add(host, addr string, prof *vendor.Profile, cmd, out string) (string, error) {
	if cmd == prof.BackupCommand {
		if err := prof.ValidateBackup(out); err != nil {
			return "", opErrorf(CatSyntaxError, "cannot audit: %v", err)
		}
	} else if strings.TrimSpace(out) == "" {
		return "", opErrorf(CatSyntaxError, "cannot audit: %q returned no output", cmd)
	}
	if line, bad := prof.FindError(out); bad {
		return "", opErrorf(CatSyntaxError, "cannot audit: the device rejected %q (%s)", cmd, logging.RedactCommand(line))
	}
	checks := audit.Evaluate(prof.Name, out, s.rules)
	for i := range checks {
		checks[i].Evidence = oneLine(logging.RedactCommand(checks[i].Evidence), 120)
	}
	s.mu.Lock()
	s.rows = append(s.rows, AuditRow{Hostname: host, Address: addr, Vendor: prof.Name, Checks: checks})
	s.mu.Unlock()
	sum := audit.Summarize(checks)
	return fmt.Sprintf("%d passed, %d failed, %d n/a", sum.Pass, sum.Fail, sum.NA), nil
}

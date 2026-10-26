// ==============================================================================
// File name:     facts.go
// Description:   Hardware / software facts collection.
// License:       MIT
// ==============================================================================
package task

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"netops/internal/vendor"
)

// FactsRow is one device's normalised record, in the shape exported to CSV/JSON.
type FactsRow struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Vendor   string `json:"vendor"`
	Model    string `json:"model"`
	Serial   string `json:"serial"`
	Version  string `json:"version"`
	Uptime   string `json:"uptime"`
}

// FactsCapability admits platforms with a facts collector.
func FactsCapability(p *vendor.Profile) (bool, string) {
	if _, ok := p.Facts(); !ok {
		return false, "no facts commands are defined for it"
	}
	return true, ""
}

// FactsSink gathers the rows produced by FactsHandler across devices.
type FactsSink struct {
	mu   sync.Mutex
	rows []FactsRow
}

// Rows returns the collected records sorted by hostname.
func (s *FactsSink) Rows() []FactsRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]FactsRow(nil), s.rows...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// Handler queries each device with its read-only facts commands and parses the
// answer. A device whose output yields no field at all fails loudly rather
// than producing an empty row that looks like data.
func (s *FactsSink) Handler() Handler {
	return func(ctx context.Context, env *HandlerEnv) (string, error) {
		prof := env.Job.Profile
		fc, ok := prof.Facts()
		if !ok {
			return "", opErrorf(CatUnsupportedOp, "no facts collector for %s", prof.Display)
		}
		cmds := vendor.SplitCommands(fc.FactsCommand())
		outs := make([]string, 0, len(cmds))
		for _, c := range cmds {
			out, err := env.Run(ctx, c)
			if err != nil {
				return "", err
			}
			outs = append(outs, out)
		}
		f := fc.ParseFacts(vendor.CombineOutputs(cmds, outs))
		if f.Model == "" && f.Serial == "" && f.Version == "" && f.Uptime == "" {
			return "", opErrorf(CatSyntaxError, "no facts could be parsed from the output of %s", strings.Join(cmds, "; "))
		}
		s.mu.Lock()
		s.rows = append(s.rows, FactsRow{
			Hostname: env.Job.Device.Hostname,
			IP:       env.Job.Device.Address,
			Vendor:   prof.Name,
			Model:    f.Model,
			Serial:   f.Serial,
			Version:  f.Version,
			Uptime:   f.Uptime,
		})
		s.mu.Unlock()
		return fmt.Sprintf("model %s, serial %s, version %s", dash(f.Model), dash(f.Serial), dash(f.Version)), nil
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

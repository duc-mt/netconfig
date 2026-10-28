// ==============================================================================
// File name:     facts_cmd.go
// Description:   "netops facts": hardware / software inventory.
// License:       MIT
// ==============================================================================
package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"netops/internal/report"
	"netops/internal/task"
)

const factsUsageText = `netops facts: collect model, serial number, software version and uptime from every device.

Usage:
  netops facts [--output facts.csv] [--json] [flags]

Queries every device with read-only commands, normalises the answers and prints
an ASCII table. --output also writes the records to a file for CMDB import:
CSV by default, JSON with --json (or a .json file name). --json without
--output prints JSON to stdout instead of the table.

A device whose output yields nothing recognisable fails loudly instead of
producing an empty row.
`

var factsFlagGroups = []flagGroup{
	{"Facts and output", []string{"output", "json"}},
	{"Inventory and credentials", []string{"inventory", "limit", "env-file", "key-file", "known-hosts", "host-key-policy", "update-known-hosts", "jump", "jump-host", "jump-user", "jump-key-file", "mesh-fallback"}},
	{"Connection", []string{"concurrency", "max-retries", "connect-timeout", "command-timeout", "timeout", "legacy-algorithms", "tcp-mss", "memory", "memory-file"}},
	{"Logging and run reports", []string{"log-dir", "verbose", "no-color", "json-report", "csv-report"}},
}

var factsHeader = []string{"hostname", "ip", "vendor", "model", "serial", "version", "uptime"}

func factsRecord(r task.FactsRow) []string {
	return []string{
		report.SanitizeCSV(r.Hostname),
		report.SanitizeCSV(r.IP),
		report.SanitizeCSV(r.Vendor),
		report.SanitizeCSV(r.Model),
		report.SanitizeCSV(r.Serial),
		report.SanitizeCSV(r.Version),
		report.SanitizeCSV(r.Uptime),
	}
}

// renderTable prints rows as a bordered ASCII table sized to the content.
func renderTable(w io.Writer, header []string, rows [][]string) {
	const maxCell = 48
	clip := func(s string) string {
		if utf8.RuneCountInString(s) <= maxCell {
			return s
		}
		r := []rune(s)
		return string(r[:maxCell-1]) + "…"
	}
	width := make([]int, len(header))
	cells := make([][]string, len(rows))
	for i, h := range header {
		width[i] = utf8.RuneCountInString(strings.ToUpper(h))
	}
	for i, row := range rows {
		cells[i] = make([]string, len(row))
		for j, c := range row {
			if c == "" {
				c = "-"
			}
			cells[i][j] = clip(c)
			if n := utf8.RuneCountInString(cells[i][j]); n > width[j] {
				width[j] = n
			}
		}
	}
	sep := "+"
	for _, n := range width {
		sep += strings.Repeat("-", n+2) + "+"
	}
	line := func(vals []string) {
		var b strings.Builder
		b.WriteString("|")
		for j, v := range vals {
			b.WriteString(" " + v + strings.Repeat(" ", width[j]-utf8.RuneCountInString(v)) + " |")
		}
		fmt.Fprintln(w, b.String())
	}
	up := make([]string, len(header))
	for i, h := range header {
		up[i] = strings.ToUpper(h)
	}
	fmt.Fprintln(w, sep)
	line(up)
	fmt.Fprintln(w, sep)
	for _, row := range cells {
		line(row)
	}
	fmt.Fprintln(w, sep)
}

func writeFactsFile(path string, asJSON bool, rows []task.FactsRow) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) // #nosec G304 -- operator supplied output path
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	cw := csv.NewWriter(f)
	_ = cw.Write(factsHeader)
	for _, r := range rows {
		_ = cw.Write(factsRecord(r))
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func runFacts(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var o opsFlags
	var output string
	var asJSON bool
	fs := flag.NewFlagSet("netops facts", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, factsUsageText); printFlagGroups(stderr, fs, factsFlagGroups) }
	fs.StringVar(&output, "output", "", "also write the records to this file (CSV, or JSON with --json)")
	fs.BoolVar(&asJSON, "json", false, "JSON instead of CSV (to --output, or to stdout when --output is not given)")
	o.registerReadOnly(fs)
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(stdout, factsUsageText)
		printFlagGroups(stdout, fs, factsFlagGroups)
		return task.ExitOK
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return task.ExitOK
		}
		hintPasswordFlag(args, stderr)
		return task.ExitFatal
	}
	o.noteSetFlags(fs)
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "netops facts: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return task.ExitFatal
	}
	if strings.HasSuffix(strings.ToLower(output), ".json") {
		asJSON = true
	}

	env, code := newOpsEnv("facts", &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()

	sink := &task.FactsSink{}
	jobs := task.BuildCapabilityJobs(env.devs, "facts", task.FactsCapability)
	results := env.readOnlyRun(jobs, sink.Handler())
	rows := sink.Rows()

	switch {
	case asJSON && output == "":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if rows == nil {
			rows = []task.FactsRow{}
		}
		_ = enc.Encode(rows)
	case len(rows) > 0:
		table := make([][]string, len(rows))
		for i, r := range rows {
			table[i] = factsRecord(r)
		}
		renderTable(stdout, factsHeader, table)
	}
	if output != "" {
		if err := writeFactsFile(output, asJSON, rows); err != nil {
			env.log.Errorf("", "writing %s: %v", output, err)
			env.finish(results)
			return task.ExitFatal
		}
		env.log.Infof("", "facts for %d device(s) written to %s", len(rows), output)
	}
	return env.finish(results)
}

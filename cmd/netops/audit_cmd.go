// ==============================================================================
// File name:     audit_cmd.go
// Description:   "netops audit": baseline security / compliance check.
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
	"path/filepath"
	"sort"
	"strings"

	"netops/internal/audit"
	"netops/internal/report"
	"netops/internal/task"
	"netops/internal/vendor"
)

// exitNonCompliant: every device was audited, at least one check failed.
const exitNonCompliant = 3

const auditUsageText = `netops audit: check device configurations against a security baseline.

Usage:
  netops audit [--rules compliance.yaml] [--output-dir audit_reports/] [flags]
  netops audit --file router.config --vendor cisco [flags]
  netops audit --from-backups backups/ [flags]
  netops audit --print-defaults > compliance.yaml

Reads each device's configuration (read-only: nothing is ever changed) and
prints a PASS / FAIL / N/A matrix with a remediation for every failure. The
built-in baseline checks: NTP server, remote syslog, Telnet disabled, no
default SNMP communities, idle session timeout of at most 5 minutes,
RADIUS/TACACS+ configured, encrypted passwords, no plain HTTP management, SSH
version 2 only, and a login banner. A platform a check has no rule for is N/A, never a
guess. --rules replaces the built-in baseline with your own file (a small YAML
subset; --print-defaults writes the built-in rules in that format as a start).

--file audits one saved configuration (--vendor names its platform) and
--from-backups audits the saved *.config files of a "netops backup" run (a
backup-<stamp> directory, or the root holding them: the newest run is used).
Both work offline: no inventory, credentials or SSH are needed.

--generate-fix writes the remediation of every failed check to a file, grouped
by device. It is review guidance written as comments, not an apply-ready script.

--output-dir additionally writes audit-<time>.{csv,json,txt} there.
A configuration that is empty, an error, or visibly truncated fails the device
rather than producing a verdict.

Exit codes: 3 when every device was audited but a check failed; 2 when some
device could not be audited; 0 when everything passed (or is N/A).

Flags:
`

func runAudit(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var o opsFlags
	var rulesPath, outDir, file, vendorName, fromBackups, fixPath string
	var printDefaults bool
	fs := flag.NewFlagSet("netops audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, auditUsageText); fs.PrintDefaults() }
	fs.StringVar(&rulesPath, "rules", "", "rules file (YAML subset); default: the built-in baseline")
	fs.StringVar(&outDir, "output-dir", "", "also write audit-<time>.csv, .json and .txt into this directory")
	fs.StringVar(&file, "file", "", "audit this saved configuration file offline (needs --vendor)")
	fs.StringVar(&vendorName, "vendor", "", "platform of --file (e.g. cisco, junos, fortinet)")
	fs.StringVar(&fromBackups, "from-backups", "", "audit the saved configs of a backup run (or the newest run under this root) offline")
	fs.StringVar(&fixPath, "generate-fix", "", "write the remediation of every failed check to this file (guidance, as comments)")
	fs.BoolVar(&printDefaults, "print-defaults", false, "print the built-in rules in the rules-file format and exit")
	o.registerReadOnly(fs)
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(stdout, auditUsageText)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
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
	fatal := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "netops audit: "+format+"\n", a...)
		return task.ExitFatal
	}
	if fs.NArg() > 0 {
		return fatal("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if printDefaults {
		if err := audit.WriteRules(stdout, audit.Defaults()); err != nil {
			return fatal("%v", err)
		}
		return task.ExitOK
	}

	rules := audit.Defaults()
	if rulesPath != "" {
		f, err := os.Open(rulesPath) // #nosec G304 -- operator supplied rules file
		if err != nil {
			return fatal("%v", err)
		}
		rules, err = audit.ParseRules(f)
		_ = f.Close()
		if err != nil {
			return fatal("%s: %v", rulesPath, err)
		}
	}

	switch {
	case file != "" && fromBackups != "":
		return fatal("--file and --from-backups are mutually exclusive")
	case file != "" && vendorName == "":
		return fatal("--file needs --vendor to pick the rules")
	case file == "" && vendorName != "":
		return fatal("--vendor only applies together with --file")
	case file != "" || fromBackups != "":
		return auditOfflineRun(rules, file, vendorName, fromBackups, outDir, fixPath, stdout, stderr)
	}

	env, code := newOpsEnv("audit", &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()
	if rulesPath != "" {
		env.log.Infof("", "auditing against %d rule(s) from %s", len(rules), rulesPath)
	} else {
		env.log.Infof("", "auditing against the built-in baseline (%d rules)", len(rules))
	}

	sink := task.NewAuditSink(rules)
	jobs := task.BuildCapabilityJobs(env.devs, "audit", func(*vendor.Profile) (bool, string) { return true, "" })
	results := env.readOnlyRun(jobs, sink.Handler())
	rows := sink.Rows()

	renderAuditMatrix(stdout, rows)
	failures := renderRemediations(stdout, rows)
	code = env.finish(results)

	if outDir != "" {
		if err := writeAuditReports(outDir, env.started.Format("20060102-150405"), rows); err != nil {
			env.log.Errorf("", "audit reports: %v", err)
			return task.ExitFatal
		}
		env.log.Infof("", "audit reports written to %s", outDir)
	}
	if fixPath != "" {
		if err := reportFixScript(fixPath, rows, stderr); err != nil {
			return task.ExitFatal
		}
	}
	if failures > 0 {
		return exitNonCompliant
	}
	return code
}

// checkIDs lists the check IDs in report order (every row carries the same list).
func checkIDs(rows []task.AuditRow) []string {
	if len(rows) == 0 {
		return nil
	}
	var ids []string
	for _, c := range rows[0].Checks {
		ids = append(ids, c.ID)
	}
	return ids
}

func renderAuditMatrix(w io.Writer, rows []task.AuditRow) {
	if len(rows) == 0 {
		return
	}
	header := append([]string{"device", "vendor"}, checkIDs(rows)...)
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		row := []string{r.Hostname, r.Vendor}
		for _, c := range r.Checks {
			row = append(row, string(c.Status))
		}
		table = append(table, row)
	}
	fmt.Fprintln(w)
	renderTable(w, header, table)
}

type finding struct {
	host  string
	check audit.Check
}

func sevRank(s string) int {
	switch s {
	case audit.SevHigh:
		return 0
	case audit.SevMedium:
		return 1
	}
	return 2
}

// renderRemediations prints one block per failed check and returns how many failed.
func renderRemediations(w io.Writer, rows []task.AuditRow) int {
	var fails []finding
	var pass, na int
	for _, r := range rows {
		for _, c := range r.Checks {
			switch c.Status {
			case audit.Fail:
				fails = append(fails, finding{r.Hostname, c})
			case audit.Pass:
				pass++
			default:
				na++
			}
		}
	}
	sort.SliceStable(fails, func(i, j int) bool {
		if a, b := sevRank(fails[i].check.Severity), sevRank(fails[j].check.Severity); a != b {
			return a < b
		}
		return fails[i].host < fails[j].host
	})
	fmt.Fprintf(w, "\n%d check(s) passed, %d failed, %d not applicable across %d device(s)\n", pass, len(fails), na, len(rows))
	if len(fails) == 0 {
		return 0
	}
	fmt.Fprintln(w, "\nRemediation:")
	for _, f := range fails {
		fmt.Fprintf(w, "  [%s] %s: %s\n        %s\n        fix: %s\n",
			strings.ToUpper(f.check.Severity), f.host, f.check.Title, f.check.Evidence, f.check.Remediation)
	}
	return len(fails)
}

func writeAuditReports(dir, stamp string, rows []task.AuditRow) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	base := filepath.Join(dir, "audit-"+stamp)

	// CSV: one line per device and check
	cf, err := os.Create(base + ".csv") // #nosec G304 -- operator supplied output directory
	if err != nil {
		return err
	}
	cw := csv.NewWriter(cf)
	_ = cw.Write([]string{"hostname", "ip", "vendor", "check", "title", "severity", "status", "evidence", "remediation"})
	for _, r := range rows {
		for _, c := range r.Checks {
			_ = cw.Write([]string{
				report.SanitizeCSV(r.Hostname),
				report.SanitizeCSV(r.Address),
				report.SanitizeCSV(r.Vendor),
				report.SanitizeCSV(c.ID),
				report.SanitizeCSV(c.Title),
				report.SanitizeCSV(c.Severity),
				report.SanitizeCSV(string(c.Status)),
				report.SanitizeCSV(c.Evidence),
				report.SanitizeCSV(c.Remediation),
			})
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		_ = cf.Close()
		return err
	}
	if err := cf.Close(); err != nil {
		return err
	}

	// JSON
	type jsonCheck struct {
		ID          string `json:"id"`
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		Status      string `json:"status"`
		Evidence    string `json:"evidence,omitempty"`
		Remediation string `json:"remediation,omitempty"`
	}
	type jsonDevice struct {
		Hostname string      `json:"hostname"`
		IP       string      `json:"ip"`
		Vendor   string      `json:"vendor"`
		Checks   []jsonCheck `json:"checks"`
	}
	out := make([]jsonDevice, 0, len(rows))
	for _, r := range rows {
		d := jsonDevice{Hostname: r.Hostname, IP: r.Address, Vendor: r.Vendor}
		for _, c := range r.Checks {
			jc := jsonCheck{ID: c.ID, Title: c.Title, Severity: c.Severity, Status: string(c.Status), Evidence: c.Evidence}
			if c.Status == audit.Fail {
				jc.Remediation = c.Remediation
			}
			d.Checks = append(d.Checks, jc)
		}
		out = append(out, d)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(base+".json", append(data, '\n'), 0o600); err != nil {
		return err
	}

	// TXT: the console view
	var b strings.Builder
	renderAuditMatrix(&b, rows)
	renderRemediations(&b, rows)
	return os.WriteFile(base+".txt", []byte(b.String()), 0o600)
}

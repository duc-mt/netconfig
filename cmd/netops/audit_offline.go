// ==============================================================================
// File name:     audit_offline.go
// Description:   "netops audit --file / --from-backups" and "--generate-fix".
// License:       MIT
// ==============================================================================
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netops/internal/audit"
	"netops/internal/task"
	"netops/internal/vendor"
)

// maxOfflineConfig bounds one saved configuration read into memory.
const maxOfflineConfig = 32 << 20

// offlineConfig is one saved device configuration to audit.
type offlineConfig struct {
	host string
	prof *vendor.Profile
	path string
}

// backupExt is the extension of the configuration files "netops backup" saves
// (the .diff files next to them are not configurations).
const backupExt = ".config"

// collectBackupConfigs finds the saved configurations under dir. dir is either
// one backup run ("<dir>/<vendor>/<host>.config") or a root holding several
// runs ("<dir>/backup-<stamp>/..."), in which case the newest run is used.
func collectBackupConfigs(dir string) (cfgs []offlineConfig, warns []string, err error) {
	run, err := resolveBackupRun(dir)
	if err != nil {
		return nil, nil, err
	}
	vendors, err := os.ReadDir(run)
	if err != nil {
		return nil, nil, err
	}
	for _, vd := range vendors {
		if !vd.IsDir() {
			continue
		}
		prof, ok := vendor.Lookup(vd.Name())
		if !ok {
			warns = append(warns, fmt.Sprintf("%s: unknown vendor directory, skipped", filepath.Join(run, vd.Name())))
			continue
		}
		files, err := os.ReadDir(filepath.Join(run, vd.Name()))
		if err != nil {
			return nil, warns, err
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), backupExt) {
				continue
			}
			cfgs = append(cfgs, offlineConfig{
				host: strings.TrimSuffix(f.Name(), backupExt),
				prof: prof,
				path: filepath.Join(run, vd.Name(), f.Name()),
			})
		}
	}
	if len(cfgs) == 0 {
		return nil, warns, fmt.Errorf("%s: no *%s files found under a <vendor>/ directory", run, backupExt)
	}
	return cfgs, warns, nil
}

// resolveBackupRun returns dir itself when it holds vendor directories, else
// its lexically newest "backup-*" sub-directory (the timestamps sort).
func resolveBackupRun(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var runs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, ok := vendor.Lookup(e.Name()); ok {
			return dir, nil
		}
		if strings.HasPrefix(e.Name(), "backup-") {
			runs = append(runs, e.Name())
		}
	}
	if len(runs) == 0 {
		return "", fmt.Errorf("%s: neither a backup run (<vendor>/ directories) nor a root of backup-* runs", dir)
	}
	sort.Strings(runs)
	return filepath.Join(dir, runs[len(runs)-1]), nil
}

// readOfflineConfig loads and sanity-checks one saved configuration.
func readOfflineConfig(c offlineConfig) (string, error) {
	st, err := os.Stat(c.path)
	if err != nil {
		return "", err
	}
	if st.Size() > maxOfflineConfig {
		return "", fmt.Errorf("%s is larger than %d MiB", c.path, maxOfflineConfig>>20)
	}
	data, err := os.ReadFile(c.path) // #nosec G304 -- operator supplied path
	if err != nil {
		return "", err
	}
	text := string(data)
	// The Junos rules read the "display set" form; a curly-brace backup would
	// fail every rule, which is a wrong verdict rather than a finding.
	if c.prof.Name == vendor.Junos && !strings.Contains("\n"+text, "\nset ") {
		return "", fmt.Errorf("%s is not in 'display set' form, which the Junos rules need", c.path)
	}
	return text, nil
}

// auditOffline evaluates saved configurations into sink. It returns how many
// could not be audited.
func auditOffline(sink *task.AuditSink, cfgs []offlineConfig, stderr io.Writer) (failed int) {
	for _, c := range cfgs {
		text, err := readOfflineConfig(c)
		if err == nil {
			_, err = sink.Add(c.host, c.path, c.prof, audit.ConfigCommand(c.prof), text)
		}
		if err != nil {
			fmt.Fprintf(stderr, "netops audit: %s: %v\n", c.host, err)
			failed++
		}
	}
	return failed
}

// writeFixScript writes the remediation guidance for every failed check,
// grouped by device. The file is deliberately all comments: the remediation
// text is guidance with site specific values to fill in (<address>, secrets)
// and some entries span several steps, so none of it can be applied as is.
func writeFixScript(path string, rows []task.AuditRow) (int, error) {
	var b strings.Builder
	b.WriteString("# netops audit: remediation guidance for failed checks.\n")
	b.WriteString("# Review each entry, replace <placeholders>, and apply by hand or with\n")
	b.WriteString("# netops config (uncomment the lines you want). Nothing here is applied automatically.\n")
	n := 0
	for _, r := range rows {
		var fails []audit.Check
		for _, c := range r.Checks {
			if c.Status == audit.Fail {
				fails = append(fails, c)
			}
		}
		if len(fails) == 0 {
			continue
		}
		sort.SliceStable(fails, func(i, j int) bool { return sevRank(fails[i].Severity) < sevRank(fails[j].Severity) })
		fmt.Fprintf(&b, "\n# ==== %s (%s) ====\n", r.Hostname, r.Vendor)
		for _, c := range fails {
			fmt.Fprintf(&b, "# [%s] %s\n", strings.ToUpper(c.Severity), c.Title)
			for _, line := range strings.Split(c.Remediation, "\n") {
				fmt.Fprintf(&b, "#   %s\n", strings.TrimSpace(line))
			}
			n++
		}
	}
	if n == 0 {
		b.WriteString("\n# every audited check passed or is not applicable: nothing to fix\n")
	}
	return n, os.WriteFile(path, []byte(b.String()), 0o600)
}

// auditOfflineRun audits saved configurations (--file or --from-backups): no
// inventory, credentials or network access are involved.
func auditOfflineRun(rules []audit.Rule, file, vendorName, fromBackups, outDir, fixPath string, stdout, stderr io.Writer) int {
	var cfgs []offlineConfig
	if file != "" {
		prof, ok := vendor.Lookup(vendorName)
		if !ok {
			fmt.Fprintf(stderr, "netops audit: unknown --vendor %q (supported: %s)\n", vendorName, strings.Join(vendor.Names(), ", "))
			return task.ExitFatal
		}
		base := filepath.Base(file)
		cfgs = []offlineConfig{{host: strings.TrimSuffix(base, filepath.Ext(base)), prof: prof, path: file}}
	} else {
		var warns []string
		var err error
		if cfgs, warns, err = collectBackupConfigs(fromBackups); err != nil {
			fmt.Fprintf(stderr, "netops audit: %v\n", err)
			return task.ExitFatal
		}
		for _, w := range warns {
			fmt.Fprintf(stderr, "netops audit: warning: %s\n", w)
		}
	}

	sink := task.NewAuditSink(rules)
	unaudited := auditOffline(sink, cfgs, stderr)
	rows := sink.Rows()
	renderAuditMatrix(stdout, rows)
	failures := renderRemediations(stdout, rows)

	if outDir != "" {
		if err := writeAuditReports(outDir, time.Now().Format("20060102-150405"), rows); err != nil {
			fmt.Fprintf(stderr, "netops audit: audit reports: %v\n", err)
			return task.ExitFatal
		}
		fmt.Fprintf(stderr, "audit reports written to %s\n", outDir)
	}
	if fixPath != "" {
		if err := reportFixScript(fixPath, rows, stderr); err != nil {
			return task.ExitFatal
		}
	}
	switch {
	case unaudited > 0:
		return task.ExitPartial
	case failures > 0:
		return exitNonCompliant
	}
	return task.ExitOK
}

// reportFixScript writes the --generate-fix file and tells the operator.
func reportFixScript(path string, rows []task.AuditRow, stderr io.Writer) error {
	n, err := writeFixScript(path, rows)
	if err != nil {
		fmt.Fprintf(stderr, "netops audit: --generate-fix: %v\n", err)
		return err
	}
	fmt.Fprintf(stderr, "remediation guidance for %d failed check(s) written to %s\n", n, path)
	return nil
}

// ==============================================================================
// File name:     cve_cmd.go
// Description:   "netops cve": check device software versions against known
//
//	CVEs, with an offline cache and Telegram alerts.
//
// License:       MIT
// ==============================================================================
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"netops/internal/credentials"
	"netops/internal/cve"
	"netops/internal/inventory"
	"netops/internal/notifier"
	"netops/internal/report"
	"netops/internal/task"
)

// exitVulnerable: every device was checked and at least one advisory at or
// above -min-severity applies. Like "netops audit", it is distinct from the
// runner's 2 (some device could not be checked), which takes precedence.
const exitVulnerable = 3

const cveUsageText = `netops cve: check device software versions against known CVEs.

Usage:
  netops cve -os <platform> -version <version> [flags]   one OS and version; no device is contacted
  netops cve -from-facts facts.json [flags]              a 'netops facts --json' export; no device is contacted
  netops cve [-inventory inventory.csv] [flags]          collect versions over SSH (read-only), then check
  netops cve -update-db [-os <platform> [-version <v>] | -from-facts f.json | -inventory i.csv]

Matches each version against the advisories published for its platform and
lists the CVEs that apply, with the release that fixes them. Platforms: a
platform name as in the inventory's vendor column or a specific OS name:
cisco-ios-xe, cisco-ios, cisco-asa, cisco-ftd, junos, fortios, eos, routeros,
pan-os, checkpoint, vyos, pfsense, sophos. A bare 'cisco' is told apart by its
version (15.2(7)E3 is IOS, 17.06.01 is IOS XE). Platforms without a reliable
CVE product mapping (cisco_sb, huawei, aruba, ruijie) are reported, never guessed.

Sources: NIST NVD API 2.0 for every platform (NVD_API_KEY in .env raises its
rate limit); the Cisco PSIRT openVuln API for Cisco platforms, which often lists
advisories before NVD does (CISCO_PSIRT_CLIENT_ID and CISCO_PSIRT_CLIENT_SECRET
in .env enable it); OSV.dev for platforms that map to an OSV package (none of
the built-in platforms do today).

Offline use: every successful lookup is stored in the cache file (-db, default
.cve_cache.json.gz, git-ignored). If the network fails, the cache answers
instead and advisories are labelled CACHE. -offline never touches the network.
To prepare an air-gapped host, run 'netops cve -update-db' on a connected one
(with -os, -from-facts or -inventory to say which platforms) and copy the
cache file across. -update-db needs no -version for NVD data, which covers
every version; Cisco PSIRT answers are per version, so they are cached only
for the versions that -version or -from-facts name.

A platform for which neither a live source nor the cache has data is reported
as an error and is never shown as clean: no data does not mean no CVEs.

-min-severity (default HIGH) hides lower-rated advisories; advisories that have
no score yet are always listed. The table has one row per device and CVE.
--output writes CSV (or JSON for a .json name or --json) with every field;
--json without --output prints JSON to stdout instead of the table.
--notify sends the findings to Telegram (TELEGRAM_ENABLED, TELEGRAM_BOT_TOKEN
and TELEGRAM_CHAT_ID in .env), only when there are any.

Matching uses the version ranges the advisories publish and does not evaluate
hardware or feature qualifiers, so a result means "this software version is in
an affected range": check the advisory before acting. Nothing is ever changed
on a device. -dry-run, -yes and -backup have no effect here.

Exit codes: 3 when every device was checked and at least one advisory applies;
2 when some device could not be checked or a requested alert was not delivered;
0 when nothing at or above -min-severity applies; 1 for usage or setup errors.
`

var cveFlagGroups = []flagGroup{
	{"CVE check", []string{"os", "version", "from-facts", "min-severity", "notify", "output", "json"}},
	{"Offline cache and sources", []string{"offline", "db", "update-db", "http-timeout"}},
	{"Inventory and credentials", []string{"inventory", "limit", "env-file", "key-file", "known-hosts", "host-key-policy", "update-known-hosts", "jump", "jump-host", "jump-user", "jump-key-file", "mesh-fallback"}},
	{"Connection", []string{"concurrency", "max-retries", "connect-timeout", "command-timeout", "timeout", "legacy-algorithms", "tcp-mss", "memory", "memory-file"}},
	{"Logging and run reports", []string{"log-dir", "verbose", "no-color", "json-report", "csv-report"}},
	{"Accepted for wrapper-script compatibility (no effect: this command never changes a device)", []string{"dry-run", "yes", "force", "backup", "backup-dir", "rollback-on-fail", "strict-safety", "allow-dangerous", "canary", "batch-size", "max-fail-percent"}},
}

// cveSources builds the online sources. Tests replace it to point at mock servers.
var cveSources = func(setting func(string) string, timeout time.Duration) []cve.Source {
	client := &http.Client{Timeout: timeout}
	return []cve.Source{
		&cve.NVD{APIKey: setting("NVD_API_KEY"), Client: client},
		&cve.CiscoPSIRT{ClientID: setting("CISCO_PSIRT_CLIENT_ID"), ClientSecret: setting("CISCO_PSIRT_CLIENT_SECRET"), Client: client},
		&cve.OSV{Client: client},
	}
}

// cveSendAlert delivers the Telegram alert. Tests replace it.
var cveSendAlert = notifier.SendCVEAlert

var cveHeader = []string{"hostname", "ip", "vendor", "os", "version", "cve_id", "severity", "cvss", "fixed_in", "affected", "source", "published", "url", "title", "error"}
var cveTableHeader = []string{"hostname", "ip", "os", "version", "cve-id", "severity", "cvss", "fixed in"}

func cveScore(a cve.Advisory) string {
	if a.CVSS <= 0 {
		return ""
	}
	return fmt.Sprintf("%.1f", a.CVSS)
}

// cveRecord is one CSV row: a device/advisory pair, or (a == nil) a device that
// could not be checked, so a CMDB import can tell "unknown" from "clean".
func cveRecord(r cve.DeviceCVEResult, a *cve.Advisory) []string {
	row := []string{r.Hostname, r.IP, r.Vendor, r.OS, r.Version, "", "", "", "", "", "", "", "", "", r.Error}
	if a != nil {
		published := ""
		if !a.Published.IsZero() {
			published = a.Published.Format("2006-01-02")
		}
		row[5], row[6], row[7], row[8], row[9] = a.ID, string(a.Severity), cveScore(*a), a.FixedVer, a.AffectedVer
		row[10], row[11], row[12], row[13] = a.Source, published, a.URL, a.Title
	}
	for i := range row {
		row[i] = report.SanitizeCSV(row[i])
	}
	return row
}

func writeCVEFile(path string, asJSON bool, results []cve.DeviceCVEResult) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) // #nosec G304 -- operator supplied output path
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	cw := csv.NewWriter(f)
	_ = cw.Write(cveHeader)
	for _, r := range results {
		for i := range r.Advisories {
			_ = cw.Write(cveRecord(r, &r.Advisories[i]))
		}
		if r.Error != "" {
			_ = cw.Write(cveRecord(r, nil))
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// filterSeverity returns copies of the results holding only the advisories that
// pass the threshold (unscored ones always do).
func filterSeverity(results []cve.DeviceCVEResult, min cve.Severity) []cve.DeviceCVEResult {
	out := make([]cve.DeviceCVEResult, len(results))
	for i, r := range results {
		kept := []cve.Advisory{}
		for _, a := range r.Advisories {
			if a.Severity.Meets(min) {
				kept = append(kept, a)
			}
		}
		r.Advisories = kept
		out[i] = r
	}
	return out
}

// cveReporter writes progress and problems to the audit log in inventory mode
// and straight to stderr otherwise.
type cveReporter struct {
	env    *opsEnv
	stderr io.Writer
}

func (r cveReporter) infof(format string, a ...any) {
	if r.env != nil {
		r.env.log.Infof("", format, a...)
		return
	}
	fmt.Fprintf(r.stderr, "netops cve: "+format+"\n", a...)
}

func (r cveReporter) warnf(format string, a ...any) {
	if r.env != nil {
		r.env.log.Warnf("", format, a...)
		return
	}
	fmt.Fprintf(r.stderr, "netops cve: warning: "+format+"\n", a...)
}

func (r cveReporter) errorf(format string, a ...any) {
	if r.env != nil {
		r.env.log.Errorf("", format, a...)
		return
	}
	fmt.Fprintf(r.stderr, "netops cve: "+format+"\n", a...)
}

type cveArgs struct {
	osName, version, fromFacts, minSeverity, dbPath, output string
	offline, updateDB, notify, asJSON                       bool
	httpTimeout                                             time.Duration
	minSev                                                  cve.Severity
	inventoryGiven                                          bool
}

func newCVEFlagSet(o *opsFlags, a *cveArgs, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("netops cve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, cveUsageText); printFlagGroups(stderr, fs, cveFlagGroups) }
	fs.StringVar(&a.osName, "os", "", "OS or platform to check, e.g. cisco-ios-xe, fortios, junos (needs -version)")
	fs.StringVar(&a.version, "version", "", "software version to check, e.g. 17.6.1 (with -os)")
	fs.StringVar(&a.fromFacts, "from-facts", "", "check the devices in a 'netops facts --json' export instead of contacting them")
	fs.StringVar(&a.minSeverity, "min-severity", "HIGH", "hide advisories below this severity: LOW, MEDIUM, HIGH or CRITICAL")
	fs.BoolVar(&a.offline, "offline", false, "make no network calls; answer only from the cache (-db)")
	fs.StringVar(&a.dbPath, "db", cve.DefaultCacheFile, "offline cache file (gzip JSON; refreshed by every successful online lookup)")
	fs.BoolVar(&a.updateDB, "update-db", false, "refresh the cache for the selected platforms from the online sources, then exit")
	fs.BoolVar(&a.notify, "notify", false, "send the findings to Telegram (needs TELEGRAM_* in the env file)")
	fs.DurationVar(&a.httpTimeout, "http-timeout", cve.DefaultHTTPTimeout, "timeout of each request to an online source (raise it for slow NVD responses)")
	fs.StringVar(&a.output, "output", "", "also write the findings to this file (CSV, or JSON for a .json name or --json)")
	fs.BoolVar(&a.asJSON, "json", false, "JSON instead of CSV (to --output, or to stdout when --output is not given)")
	o.register(fs)
	return fs
}

// validate checks the flag combination. It returns a message, or "" when fine.
func (a *cveArgs) validate() string {
	sev, ok := cve.ParseSeverity(a.minSeverity)
	if !ok {
		return fmt.Sprintf("-min-severity must be LOW, MEDIUM, HIGH or CRITICAL (got %q)", a.minSeverity)
	}
	a.minSev = sev
	switch {
	case a.osName != "" && a.fromFacts != "":
		return "-os and -from-facts are alternatives: give one of them"
	case a.inventoryGiven && (a.osName != "" || a.fromFacts != ""):
		return "-inventory cannot be combined with -os or -from-facts"
	case a.osName == "" && a.version != "":
		return "-version needs -os"
	case a.osName != "" && a.version == "" && !a.updateDB:
		return "-os needs -version"
	case a.offline && a.updateDB:
		return "-offline and -update-db contradict each other: refreshing the cache needs the network"
	case a.updateDB && (a.notify || a.output != "" || a.asJSON):
		return "-notify, --output and --json do not apply to -update-db"
	case a.httpTimeout <= 0:
		return "-http-timeout must be positive"
	case strings.TrimSpace(a.dbPath) == "":
		return "-db must not be empty"
	}
	return ""
}

func runCVE(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var o opsFlags
	var a cveArgs
	fs := newCVEFlagSet(&o, &a, stderr)
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(stdout, cveUsageText)
		printFlagGroups(stdout, fs, cveFlagGroups)
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
	fatal := func(format string, v ...any) int {
		fmt.Fprintf(stderr, "netops cve: "+format+"\n", v...)
		return task.ExitFatal
	}
	if fs.NArg() > 0 {
		return fatal("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	a.inventoryGiven = isFlagSet(fs, "inventory")
	if msg := a.validate(); msg != "" {
		return fatal("%s", msg)
	}
	adhoc, fromFacts := a.osName != "", a.fromFacts != ""
	if (adhoc || fromFacts) && o.limit != "" {
		return fatal("-limit selects inventory devices; it cannot be used with -os or -from-facts")
	}
	if strings.HasSuffix(strings.ToLower(a.output), ".json") {
		a.asJSON = true
	}
	if adhoc && !a.updateDB {
		if _, err := cve.Resolve(a.osName, a.version); err != nil {
			return fatal("%v", err)
		}
	}

	// ---- environment: logging, credentials, signal handling ----------------------
	var (
		env      *opsEnv
		resolver *credentials.Resolver
		ctx      context.Context
	)
	// Only a live SSH collection needs the full environment (inventory, SSH
	// transport, audit log); everything else needs just the settings file.
	if !adhoc && !fromFacts && !a.updateDB {
		var code int
		if env, code = newOpsEnv("cve", &o, stdin, stdout, stderr); env == nil {
			return code
		}
		defer env.close()
		resolver, ctx = env.resolver, env.ctx
	} else {
		dot, err := credentials.LoadDotEnv(o.envFile)
		if err != nil {
			return fatal("%v", err)
		}
		rep := cveReporter{stderr: stderr}
		for _, w := range dot.Warnings {
			rep.warnf("%s", w)
		}
		resolver = &credentials.Resolver{DotEnv: dot.Values, LookupEnv: os.LookupEnv}
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
	}
	rep := cveReporter{env: env, stderr: stderr}
	setting := func(key string) string {
		if v := strings.TrimSpace(resolver.DotEnv[key]); v != "" {
			return v
		}
		if resolver.LookupEnv != nil {
			if v, ok := resolver.LookupEnv(key); ok {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}

	// ---- cache ---------------------------------------------------------------------
	cache, err := cve.OpenCache(a.dbPath)
	switch {
	case err != nil && a.offline:
		return fatal("offline cache: %v", err)
	case err != nil:
		rep.warnf("ignoring the unreadable cache: %v (a new one replaces it)", err)
		cache = cve.NewCache(a.dbPath)
	case a.offline && !cache.Exists():
		return fatal("offline cache %s does not exist; create it on a connected host with: netops cve -update-db -os <platform> (or -from-facts / -inventory)", a.dbPath)
	}
	if a.offline {
		scopes, records, newest := cache.Stats()
		rep.infof("offline: answering from %s (%d cached scope(s), %d advisory record(s), last updated %s)", a.dbPath, scopes, records, newest.Local().Format("2006-01-02 15:04"))
	}

	checker := &cve.Checker{
		Sources: cveSources(setting, a.httpTimeout),
		Cache:   cache,
		Offline: a.offline,
		Warnf:   rep.warnf,
	}

	if a.updateDB {
		return runCVEUpdate(ctx, &a, &o, checker, cache, rep, stdout)
	}

	// ---- targets ---------------------------------------------------------------------
	var targets []cve.Target
	var collectResults []task.Result
	switch {
	case adhoc:
		targets = []cve.Target{{OS: a.osName, Version: a.version}}
	case fromFacts:
		rows, err := readFactsFile(a.fromFacts)
		if err != nil {
			return fatal("%v", err)
		}
		targets = factsTargets(rows)
	default:
		sink := &task.FactsSink{}
		jobs := task.BuildCapabilityJobs(env.devs, "facts", task.FactsCapability)
		collectResults = env.readOnlyRun(jobs, sink.Handler())
		targets = factsTargets(sink.Rows())
	}

	// ---- evaluation ------------------------------------------------------------------
	results := make([]cve.DeviceCVEResult, 0, len(targets))
	for _, t := range targets {
		results = append(results, checker.Check(ctx, t))
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Hostname != results[j].Hostname {
			return results[i].Hostname < results[j].Hostname
		}
		return results[i].IP < results[j].IP
	})
	results = filterSeverity(results, a.minSev)

	// Devices the live collection could not query never reach the evaluation
	// (inventory mode); they must not make a fleet look clean.
	unqueried := 0
	for _, r := range collectResults {
		if r.Status != task.StatusSucceeded {
			unqueried++
		}
	}
	findings, unchecked, flagged := 0, 0, 0
	for _, r := range results {
		findings += len(r.Advisories)
		if len(r.Advisories) > 0 {
			flagged++
		}
		if r.Error != "" {
			unchecked++
			who := r.Hostname
			if who == "" {
				who = "(ad hoc)"
			}
			rep.errorf("%s: %s", who, r.Error)
		}
	}

	// ---- output -----------------------------------------------------------------------
	fileFailed := false
	switch {
	case a.asJSON && a.output == "":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	case findings > 0:
		var table [][]string
		for _, r := range results {
			for _, adv := range r.Advisories {
				table = append(table, []string{r.Hostname, r.IP, r.OS, r.Version, adv.ID, string(adv.Severity), cveScore(adv), adv.FixedVer})
			}
		}
		renderTable(stdout, cveTableHeader, table)
	case unchecked == 0 && unqueried == 0 && len(results) > 0:
		fmt.Fprintf(stdout, "No CVEs at or above %s found for %d device(s).\n", a.minSev, len(results))
	}
	if a.output != "" {
		if err := writeCVEFile(a.output, a.asJSON, results); err != nil {
			rep.errorf("writing %s: %v", a.output, err)
			fileFailed = true
		} else {
			rep.infof("findings for %d device(s) written to %s", len(results), a.output)
		}
	}
	summary := fmt.Sprintf("checked %d device(s): %d with findings (%d advisories at or above %s), %d could not be checked",
		len(results), flagged, findings, a.minSev, unchecked)
	if unqueried > 0 {
		summary += fmt.Sprintf("; %d device(s) could not be queried", unqueried)
	}
	rep.infof("%s", summary)

	// ---- alert -------------------------------------------------------------------------
	notifyFailed := false
	if a.notify {
		switch {
		case findings == 0:
			rep.infof("no findings at or above %s: no Telegram alert sent", a.minSev)
		default:
			sendCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			err := cveSendAlert(sendCtx, notifier.ConfigFromResolver(resolver), results)
			cancel()
			switch {
			case errors.Is(err, notifier.ErrTelegramNotConfigured):
				notifyFailed = true
				rep.errorf("Telegram alert not sent: set TELEGRAM_ENABLED=true, TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in %s", o.envFile)
			case err != nil:
				notifyFailed = true
				rep.errorf("Telegram alert not delivered: %v", err)
			default:
				rep.infof("Telegram alert sent for %d device(s)", flagged)
			}
		}
	}

	// ---- cache ---------------------------------------------------------------------------
	if !a.offline && cache.Dirty() {
		if err := cache.Save(); err != nil {
			rep.warnf("could not save the offline cache: %v", err)
		} else {
			rep.infof("offline cache updated: %s", a.dbPath)
		}
	}

	// ---- exit code -----------------------------------------------------------------------
	code := task.ExitOK
	if env != nil {
		code = env.finish(collectResults)
	}
	switch {
	case fileFailed:
		return task.ExitFatal
	case code == task.ExitOK && (unchecked > 0 || notifyFailed):
		return task.ExitPartial
	case code == task.ExitOK && findings > 0:
		return exitVulnerable
	}
	return code
}

// readFactsFile reads the JSON that "netops facts --json" writes.
func readFactsFile(path string) ([]task.FactsRow, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator supplied path
	if err != nil {
		return nil, err
	}
	var rows []task.FactsRow
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("%s: not a facts export (a JSON array of device records): %w", path, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: no devices in the facts export", path)
	}
	return rows, nil
}

func factsTargets(rows []task.FactsRow) []cve.Target {
	out := make([]cve.Target, len(rows))
	for i, r := range rows {
		out[i] = cve.Target{Hostname: r.Hostname, IP: r.IP, OS: r.Vendor, Version: r.Version}
	}
	return out
}

// ---- -update-db -----------------------------------------------------------------------

type cveUpdateEntry struct {
	product  cve.Product
	versions []string
}

// cveUpdatePlan collects, per product, the versions known for it.
type cveUpdatePlan struct {
	byKey map[string]*cveUpdateEntry
}

func (p *cveUpdatePlan) add(prod cve.Product, version string) {
	if p.byKey == nil {
		p.byKey = map[string]*cveUpdateEntry{}
	}
	e := p.byKey[prod.Key()]
	if e == nil {
		e = &cveUpdateEntry{product: prod}
		p.byKey[prod.Key()] = e
	}
	if version != "" {
		e.versions = append(e.versions, version)
	}
}

// addPlatform adds the product(s) a platform name stands for. With a version
// the product is decided by it; without, every candidate is added.
func (p *cveUpdatePlan) addPlatform(osName, version string, rep cveReporter, warned map[string]bool) {
	if strings.TrimSpace(version) != "" {
		if pl, err := cve.Resolve(osName, version); err == nil {
			p.add(pl.Product, version)
			return
		}
	}
	cands, err := cve.Candidates(osName)
	if err != nil {
		if !warned[osName] {
			warned[osName] = true
			rep.warnf("skipping %q: %v", osName, err)
		}
		return
	}
	for _, c := range cands {
		p.add(c.Product, "")
	}
}

func runCVEUpdate(ctx context.Context, a *cveArgs, o *opsFlags, checker *cve.Checker, cache *cve.Cache, rep cveReporter, stdout io.Writer) int {
	fatal := func(format string, v ...any) int {
		rep.errorf(format, v...)
		return task.ExitFatal
	}
	var plan cveUpdatePlan
	warned := map[string]bool{}
	switch {
	case a.osName != "":
		plan.addPlatform(a.osName, a.version, rep, warned)
	case a.fromFacts != "":
		rows, err := readFactsFile(a.fromFacts)
		if err != nil {
			return fatal("%v", err)
		}
		for _, r := range rows {
			plan.addPlatform(r.Vendor, r.Version, rep, warned)
		}
	default:
		all, err := inventory.Load(o.inventory)
		if err != nil {
			return fatal("%v", err)
		}
		devs, err := inventory.Filter(all, strings.Split(o.limit, ","))
		if err != nil {
			return fatal("%v", err)
		}
		for _, d := range devs {
			plan.addPlatform(d.Vendor, "", rep, warned)
		}
	}
	if len(plan.byKey) == 0 {
		return fatal("nothing to update: no selected platform has a CVE product mapping")
	}

	keys := make([]string, 0, len(plan.byKey))
	for k := range plan.byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var table [][]string
	failed := false
	for _, k := range keys {
		e := plan.byKey[k]
		for _, r := range checker.Refresh(ctx, e.product, e.versions) {
			status := "ok"
			switch {
			case r.Err != nil:
				status, failed = "FAILED: "+r.Err.Error(), true
			case r.Skipped != "":
				status = "skipped: " + r.Skipped
			}
			table = append(table, []string{e.product.OS, r.Source, r.Scope, fmt.Sprint(r.CVEs), status})
		}
	}
	renderTable(stdout, []string{"platform", "source", "scope", "advisories", "status"}, table)

	if err := cache.Save(); err != nil {
		return fatal("saving the cache: %v", err)
	}
	scopes, records, _ := cache.Stats()
	rep.infof("cache %s: %d scope(s), %d advisory record(s)", a.dbPath, scopes, records)
	if failed {
		return task.ExitPartial
	}
	return task.ExitOK
}

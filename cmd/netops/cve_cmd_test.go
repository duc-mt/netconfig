// ==============================================================================
// File name:     cve_cmd_test.go
// Description:   End-to-end tests of "netops cve" through dispatch(): every
//
//	mode, online / fallback / offline behaviour, outputs, alerts
//	and exit codes, against a fake NVD server and a fake network.
//
// License:       MIT
// ==============================================================================
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netops/internal/cve"
	"netops/internal/notifier"
	"netops/internal/task"
)

// ---- fixtures: NVD 2.0 pages ---------------------------------------------------------

func cveItem(id, desc, metric string, matches ...string) string {
	d, _ := json.Marshal(desc)
	return `{"cve":{"id":"` + id + `","published":"2023-10-16T15:15:12.690","vulnStatus":"Analyzed",` +
		`"descriptions":[{"lang":"en","value":` + string(d) + `}],` + metric +
		`"configurations":[{"nodes":[{"cpeMatch":[` + strings.Join(matches, ",") + `]}]}]}}`
}

func cveMetric(score float64, sev string) string {
	return fmt.Sprintf(`"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":%v,"baseSeverity":"%s"}}]},`, score, sev)
}

func cveRange(vendor, product, start, endExcl string) string {
	return fmt.Sprintf(`{"vulnerable":true,"criteria":"cpe:2.3:o:%s:%s:*:*:*:*:*:*:*:*","versionStartIncluding":"%s","versionEndExcluding":"%s"}`, vendor, product, start, endExcl)
}

func cvePage(items ...string) string {
	return fmt.Sprintf(`{"totalResults":%d,"vulnerabilities":[%s]}`, len(items), strings.Join(items, ","))
}

var cvePages = map[string]string{
	"cisco:ios_xe": cvePage(
		cveItem("CVE-2023-20198", "Cisco IOS XE web UI privilege escalation. More.", cveMetric(10.0, "CRITICAL"),
			cveRange("cisco", "ios_xe", "17.6.0", "17.6.6a"), cveRange("cisco", "ios_xe", "17.9.0", "17.9.4a")),
		cveItem("CVE-2022-20000", "A high severity flaw.", cveMetric(8.1, "HIGH"), cveRange("cisco", "ios_xe", "17.6.0", "17.6.4")),
		cveItem("CVE-2021-1000", "A medium severity flaw.", cveMetric(5.5, "MEDIUM"), cveRange("cisco", "ios_xe", "17.0.0", "17.7.0")),
		// not scored yet, and a description a spreadsheet would run as a formula
		cveItem("CVE-2099-0001", `=cmd|' /C calc'!A0 is awaiting analysis.`, "", cveRange("cisco", "ios_xe", "17.6.0", "17.6.3")),
	),
	"cisco:ios:": cvePage(
		cveItem("CVE-2018-0171", "Smart Install remote code execution.", cveMetric(9.8, "CRITICAL"),
			`{"vulnerable":true,"criteria":"cpe:2.3:o:cisco:ios:15.2\\(4\\)e10:*:*:*:*:*:*:*"}`,
			`{"vulnerable":true,"criteria":"cpe:2.3:o:cisco:ios:15.2\\(7\\)e3:*:*:*:*:*:*:*"}`),
	),
	"juniper:junos": cvePage(
		cveItem("CVE-2023-36845", "J-Web PHP variable modification.", cveMetric(9.8, "CRITICAL"), cveRange("juniper", "junos", "21.2", "21.2R3-S5")),
	),
	"fortinet:fortios": cvePage(
		cveItem("CVE-2023-27997", "FortiOS SSL-VPN heap overflow.", cveMetric(9.8, "CRITICAL"),
			`{"vulnerable":true,"criteria":"cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*","versionStartIncluding":"7.2.0","versionEndIncluding":"7.2.4"}`),
	),
}

// fakeNVD serves cvePages by the product in virtualMatchString.
type fakeNVD struct {
	srv  *httptest.Server
	hits int32
	fail int32 // an HTTP status to answer with instead; 0 = serve normally
}

func newFakeNVD(t *testing.T) *fakeNVD {
	t.Helper()
	f := &fakeNVD{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.hits, 1)
		if st := atomic.LoadInt32(&f.fail); st != 0 {
			w.WriteHeader(int(st))
			return
		}
		match := r.URL.Query().Get("virtualMatchString")
		for key, page := range cvePages {
			if strings.Contains(match, ":"+key) {
				_, _ = w.Write([]byte(page))
				return
			}
		}
		w.Header().Set("message", "no such product in the fake")
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNVD) requests() int { return int(atomic.LoadInt32(&f.hits)) }

// cveStub is an extra Source for tests.
type cveStub struct {
	name  string
	scope cve.Scope
	recs  []cve.Record
	err   error
	mu    sync.Mutex
	calls []string
}

func (s *cveStub) Name() string                { return s.name }
func (s *cveStub) Scope() cve.Scope            { return s.scope }
func (s *cveStub) Supports(p cve.Product) bool { return p.Vendor == "cisco" }
func (s *cveStub) Fetch(_ context.Context, p cve.Product, v string) ([]cve.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, p.Name+"@"+v)
	return s.recs, s.err
}

// cveWS is a scratch directory with the fake sources installed.
type cveWS struct {
	t    *testing.T
	dir  string
	db   string
	env  string
	nvd  *fakeNVD
	seen map[string]string // settings the sources builder was asked for
}

func newCVEWS(t *testing.T, envLines string, extra ...cve.Source) *cveWS {
	t.Helper()
	for _, k := range []string{"TELEGRAM_ENABLED", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "NVD_API_KEY", "CISCO_PSIRT_CLIENT_ID", "CISCO_PSIRT_CLIENT_SECRET"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	w := &cveWS{t: t, dir: dir, db: filepath.Join(dir, "cache.json.gz"), env: filepath.Join(dir, ".env"), nvd: newFakeNVD(t), seen: map[string]string{}}
	if err := os.WriteFile(w.env, []byte(envLines), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := cveSources
	cveSources = func(setting func(string) string, timeout time.Duration) []cve.Source {
		for _, k := range []string{"NVD_API_KEY", "CISCO_PSIRT_CLIENT_ID", "CISCO_PSIRT_CLIENT_SECRET"} {
			w.seen[k] = setting(k)
		}
		nvd := &cve.NVD{BaseURL: w.nvd.srv.URL, Client: &http.Client{Timeout: timeout}, Backoff: time.Nanosecond, PageGap: time.Nanosecond, MaxRetries: -1}
		return append([]cve.Source{nvd}, extra...)
	}
	t.Cleanup(func() { cveSources = orig })
	return w
}

// run invokes "netops cve" with the workspace's cache and env file.
func (w *cveWS) run(args ...string) (int, string, string) {
	w.t.Helper()
	return dispatchOut(w.t, append([]string{"cve", "-db", w.db, "-env-file", w.env}, args...)...)
}

func (w *cveWS) writeFacts(rows ...task.FactsRow) string {
	w.t.Helper()
	data, _ := json.Marshal(rows)
	p := filepath.Join(w.dir, "facts.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

const telegramEnv = "TELEGRAM_ENABLED=true\nTELEGRAM_BOT_TOKEN=123:abc\nTELEGRAM_CHAT_ID=-100\n"

type alertCall struct {
	cfg     notifier.TelegramConfig
	results []cve.DeviceCVEResult
}

func hookAlerts(t *testing.T, ret error) *[]alertCall {
	t.Helper()
	var calls []alertCall
	orig := cveSendAlert
	cveSendAlert = func(_ context.Context, cfg notifier.TelegramConfig, res []cve.DeviceCVEResult) error {
		calls = append(calls, alertCall{cfg, res})
		return ret
	}
	t.Cleanup(func() { cveSendAlert = orig })
	return &calls
}

func decodeResults(t *testing.T, s string) []cve.DeviceCVEResult {
	t.Helper()
	var res []cve.DeviceCVEResult
	if err := json.Unmarshal([]byte(s), &res); err != nil {
		t.Fatalf("not a JSON array of results: %v\n%s", err, s)
	}
	return res
}

func ids(a []cve.Advisory) string {
	var s []string
	for _, x := range a {
		s = append(s, x.ID)
	}
	return strings.Join(s, ",")
}

// ---- ad-hoc mode ----------------------------------------------------------------------------

func TestCVEAdHocTableUsesTheSpecifiedColumns(t *testing.T) {
	w := newCVEWS(t, "")
	code, stdout, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.06.01")
	if code != exitVulnerable {
		t.Fatalf("exit %d, want %d (checked, findings present)\n%s", code, exitVulnerable, stderr)
	}
	mustContain(t, "stdout", stdout,
		"| HOSTNAME | IP | OS           | VERSION  | CVE-ID         | SEVERITY | CVSS | FIXED IN |",
		"| CVE-2023-20198 | CRITICAL | 10.0 | 17.6.6a  |",
		"| CVE-2022-20000 | HIGH     | 8.1  | 17.6.4   |",
		"| CVE-2099-0001  | UNKNOWN  | -    | 17.6.3   |")
	if !strings.Contains(stdout, "| - ") { // an ad-hoc check has no hostname / IP
		t.Errorf("empty cells render as -:\n%s", stdout)
	}
	// MEDIUM is below the default threshold; unscored advisories are never hidden
	mustNotHave(t, "stdout", stdout, "CVE-2021-1000")
	if strings.Index(stdout, "CVE-2023-20198") > strings.Index(stdout, "CVE-2022-20000") {
		t.Error("most severe first")
	}
	mustContain(t, "stderr", stderr, "checked 1 device(s): 1 with findings (3 advisories at or above HIGH), 0 could not be checked", "offline cache updated")
	if _, err := os.Stat(w.db); err != nil {
		t.Errorf("a successful online lookup must write the cache: %v", err)
	}
}

func TestCVEMinSeverity(t *testing.T) {
	w := newCVEWS(t, "")
	for _, tc := range []struct {
		min       string
		want, not []string
	}{
		{"LOW", []string{"CVE-2021-1000", "CVE-2022-20000", "CVE-2023-20198"}, nil},
		{"medium", []string{"CVE-2021-1000", "CVE-2023-20198"}, nil},
		{"CRITICAL", []string{"CVE-2023-20198", "CVE-2099-0001"}, []string{"CVE-2022-20000", "CVE-2021-1000"}},
	} {
		code, stdout, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.6.1", "-min-severity", tc.min)
		if code != exitVulnerable {
			t.Errorf("%s: exit %d\n%s", tc.min, code, stderr)
		}
		mustContain(t, tc.min+" stdout", stdout, tc.want...)
		mustNotHave(t, tc.min+" stdout", stdout, tc.not...)
	}
}

func TestCVENoFindingsExitsZero(t *testing.T) {
	w := newCVEWS(t, "")
	code, stdout, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.12.1")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stdout", stdout, "No CVEs at or above HIGH found for 1 device(s).")
	mustNotHave(t, "stdout", stdout, "| CVE-ID")
}

func TestCVEBareCiscoUsesTheVersionToTellIOSFromIOSXE(t *testing.T) {
	w := newCVEWS(t, "")
	_, stdout, stderr := w.run("-os", "cisco", "-version", "15.2(4)E10", "--json")
	res := decodeResults(t, stdout)
	if len(res) != 1 || res[0].OS != "cisco-ios" || ids(res[0].Advisories) != "CVE-2018-0171" {
		t.Errorf("classic IOS: %+v\n%s", res, stderr)
	}
	_, stdout, _ = w.run("-os", "cisco", "-version", "17.06.01", "--json")
	if res := decodeResults(t, stdout); res[0].OS != "cisco-ios-xe" || res[0].Version != "17.06.01" {
		t.Errorf("IOS XE: %+v", res)
	}
}

func TestCVEJSONOnStdoutIsOnlyJSON(t *testing.T) {
	w := newCVEWS(t, "")
	code, stdout, _ := w.run("-os", "cisco-ios-xe", "-version", "17.6.1", "--json")
	if code != exitVulnerable {
		t.Errorf("exit %d", code)
	}
	res := decodeResults(t, stdout)
	if len(res) != 1 || res[0].Vendor != "cisco" || res[0].OS != "cisco-ios-xe" || res[0].Version != "17.6.1" || len(res[0].Advisories) != 3 {
		t.Fatalf("results = %+v", res)
	}
	a := res[0].Advisories[0]
	if a.ID != "CVE-2023-20198" || a.Source != "NVD" || a.Severity != cve.SeverityCritical || a.CVSS != 10 || a.FixedVer != "17.6.6a" ||
		a.AffectedVer != ">=17.6.0, <17.6.6a" || a.Published.IsZero() || !strings.Contains(a.URL, "nvd.nist.gov") || a.Title == "" || a.Description == "" {
		t.Errorf("advisory = %+v", a)
	}
	mustNotHave(t, "JSON stdout", stdout, "| HOSTNAME")
}

// ---- output files -------------------------------------------------------------------------------

func TestCVECSVOutputIsSanitisedAndCarriesEveryField(t *testing.T) {
	w := newCVEWS(t, "")
	facts := w.writeFacts(
		task.FactsRow{Hostname: "+evil-host", IP: "10.0.0.1", Vendor: "cisco", Version: "17.06.01"},
		task.FactsRow{Hostname: "unsupported", IP: "10.0.0.2", Vendor: "cisco_sb", Version: "3.1.1.7"},
	)
	out := filepath.Join(w.dir, "cves.csv")
	code, stdout, stderr := w.run("-from-facts", facts, "--output", out)
	if code != task.ExitPartial {
		t.Fatalf("exit %d, want %d (one device could not be checked)\n%s", code, task.ExitPartial, stderr)
	}
	mustContain(t, "stdout", stdout, "| +evil-host") // the table is for people; only the CSV is sanitised
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(recs[0], ",") != "hostname,ip,vendor,os,version,cve_id,severity,cvss,fixed_in,affected,source,published,url,title,error" {
		t.Errorf("header = %v", recs[0])
	}
	if len(recs) != 5 { // header + 3 findings + the unchecked device
		t.Fatalf("%d rows: %v", len(recs), recs)
	}
	first := recs[1]
	if first[0] != "'+evil-host" {
		t.Errorf("a hostname starting with + must be defused against formula injection: %q", first[0])
	}
	if first[5] != "CVE-2023-20198" || first[6] != "CRITICAL" || first[7] != "10.0" || first[8] != "17.6.6a" || first[9] != ">=17.6.0, <17.6.6a" ||
		first[10] != "NVD" || first[11] != "2023-10-16" || !strings.HasPrefix(first[12], "https://nvd.nist.gov/") || first[14] != "" {
		t.Errorf("row = %v", first)
	}
	var formula []string
	for _, r := range recs[1:4] {
		if r[5] == "CVE-2099-0001" {
			formula = r
		}
	}
	if formula == nil || !strings.HasPrefix(formula[13], "'=cmd") {
		t.Errorf("a title starting with = must be defused: %v", formula)
	}
	last := recs[4]
	if last[0] != "unsupported" || last[5] != "" || !strings.Contains(last[14], "no CVE product mapping") {
		t.Errorf("a device that could not be checked is a row of its own with the error: %v", last)
	}
}

func TestCVEJSONFileByExtensionAndFlag(t *testing.T) {
	w := newCVEWS(t, "")
	for _, tc := range []struct {
		name  string
		extra []string
	}{{"a.json", nil}, {"b.out", []string{"--json"}}} {
		out := filepath.Join(w.dir, tc.name)
		code, stdout, stderr := w.run(append([]string{"-os", "junos", "-version", "21.2R3", "--output", out}, tc.extra...)...)
		if code != exitVulnerable {
			t.Fatalf("%s: exit %d\n%s", tc.name, code, stderr)
		}
		mustContain(t, "stdout", stdout, "CVE-2023-36845") // the table still goes to stdout when a file is written
		data, _ := os.ReadFile(out)
		if res := decodeResults(t, string(data)); len(res) != 1 || res[0].Advisories[0].FixedVer != "21.2R3-S5" {
			t.Errorf("%s: %s", tc.name, data)
		}
	}
}

func TestCVEOutputFileFailureIsFatal(t *testing.T) {
	w := newCVEWS(t, "")
	code, _, stderr := w.run("-os", "junos", "-version", "21.2R3", "--output", filepath.Join(w.dir, "no", "such", "dir", "x.csv"))
	if code != task.ExitFatal {
		t.Errorf("exit %d", code)
	}
	mustContain(t, "stderr", stderr, "writing")
}

// ---- -from-facts ---------------------------------------------------------------------------------

func TestCVEFromFactsMixedFleet(t *testing.T) {
	w := newCVEWS(t, "")
	facts := w.writeFacts(
		task.FactsRow{Hostname: "r1", IP: "10.0.0.1", Vendor: "cisco", Version: "17.06.01"},
		task.FactsRow{Hostname: "sw-j", IP: "10.0.0.3", Vendor: "junos", Version: "21.2R3"},
		task.FactsRow{Hostname: "fw", IP: "10.0.0.4", Vendor: "fortinet", Version: "v7.2.4"},
		task.FactsRow{Hostname: "ok-fw", IP: "10.0.0.5", Vendor: "fortinet", Version: "v7.4.1"},
		task.FactsRow{Hostname: "sb", IP: "10.0.0.6", Vendor: "cisco_sb", Version: "3.1.1.7"},
		task.FactsRow{Hostname: "nover", IP: "10.0.0.7", Vendor: "cisco"},
	)
	code, stdout, stderr := w.run("-from-facts", facts, "--json")
	if code != task.ExitPartial {
		t.Errorf("exit %d: some devices could not be checked, which outranks the findings (%d)\n%s", code, exitVulnerable, stderr)
	}
	res := decodeResults(t, stdout)
	by := map[string]cve.DeviceCVEResult{}
	var order []string
	for _, r := range res {
		by[r.Hostname] = r
		order = append(order, r.Hostname)
	}
	if strings.Join(order, ",") != "fw,nover,ok-fw,r1,sb,sw-j" {
		t.Errorf("results are sorted by hostname: %v", order)
	}
	if ids(by["fw"].Advisories) != "CVE-2023-27997" || by["fw"].OS != "fortios" || by["fw"].Vendor != "fortinet" {
		t.Errorf("fw = %+v", by["fw"])
	}
	if by["ok-fw"].Error != "" || by["ok-fw"].Advisories == nil || len(by["ok-fw"].Advisories) != 0 {
		t.Errorf("a fixed FortiOS is clean, with [] and not null: %+v", by["ok-fw"])
	}
	if ids(by["sw-j"].Advisories) != "CVE-2023-36845" || ids(by["r1"].Advisories) != "CVE-2023-20198,CVE-2022-20000,CVE-2099-0001" {
		t.Errorf("sw-j=%+v r1=%+v", by["sw-j"], by["r1"])
	}
	if !strings.Contains(by["sb"].Error, "no CVE product mapping") || !strings.Contains(by["nover"].Error, "no software version") {
		t.Errorf("sb=%q nover=%q", by["sb"].Error, by["nover"].Error)
	}
	mustContain(t, "stderr", stderr, "sb: no CVE product mapping", "nover: no software version", "2 could not be checked")
	if !strings.Contains(stdout, `"advisories": []`) {
		t.Error("clean devices carry an empty advisories array")
	}
	// the three products are each fetched once, however many devices use them
	if got := w.nvd.requests(); got != 3 {
		t.Errorf("NVD requests = %d, want 3 (ios_xe, junos, fortios)", got)
	}
}

func TestCVEFromFactsFileProblems(t *testing.T) {
	w := newCVEWS(t, "")
	bad := filepath.Join(w.dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"not":"an array"}`), 0o600)
	empty := filepath.Join(w.dir, "empty.json")
	_ = os.WriteFile(empty, []byte(`[]`), 0o600)
	for name, tc := range map[string]struct{ path, want string }{
		"missing": {filepath.Join(w.dir, "nope.json"), "no such file"},
		"object":  {bad, "not a facts export"},
		"empty":   {empty, "no devices in the facts export"},
	} {
		code, _, stderr := w.run("-from-facts", tc.path)
		if code != task.ExitFatal || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr)
		}
	}
}

// ---- offline cache and fallback -------------------------------------------------------------------

func TestCVEOfflineAnswersFromTheCacheWithoutTheNetwork(t *testing.T) {
	w := newCVEWS(t, "")
	if code, _, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.6.1"); code != exitVulnerable {
		t.Fatalf("priming run: exit %d\n%s", code, stderr)
	}
	before := w.nvd.requests()

	// a version that was never looked up: the cache holds the product's ranges
	code, stdout, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.9.2", "-offline", "--json")
	if code != exitVulnerable {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if w.nvd.requests() != before {
		t.Errorf("-offline made %d request(s)", w.nvd.requests()-before)
	}
	res := decodeResults(t, stdout)
	if len(res[0].Advisories) != 1 || res[0].Advisories[0].ID != "CVE-2023-20198" || res[0].Advisories[0].Source != "CACHE" || res[0].Advisories[0].FixedVer != "17.9.4a" {
		t.Errorf("results = %+v", res[0].Advisories)
	}
	mustContain(t, "stderr", stderr, "offline: answering from "+w.db)
	mustNotHave(t, "stderr", stderr, "offline cache updated") // an offline run never rewrites the cache
}

func TestCVEOfflineWithoutACacheIsFatal(t *testing.T) {
	w := newCVEWS(t, "")
	code, _, stderr := w.run("-os", "junos", "-version", "21.2R3", "-offline")
	if code != task.ExitFatal {
		t.Errorf("exit %d", code)
	}
	mustContain(t, "stderr", stderr, "does not exist", "netops cve -update-db")
	if w.nvd.requests() != 0 {
		t.Error("offline must not call the network")
	}
}

func TestCVEOfflineWithACacheLackingThePlatformIsAnErrorNotClean(t *testing.T) {
	w := newCVEWS(t, "")
	w.run("-os", "junos", "-version", "21.2R3") // caches junos only
	code, stdout, stderr := w.run("-os", "fortios", "-version", "7.2.4", "-offline")
	if code != task.ExitPartial {
		t.Errorf("exit %d", code)
	}
	mustContain(t, "stderr", stderr, "no cached advisory data for fortios", "-update-db")
	mustNotHave(t, "stdout", stdout, "No CVEs") // never claim clean
}

func TestCVEFallsBackToTheCacheWhenTheNetworkFails(t *testing.T) {
	w := newCVEWS(t, "")
	w.run("-os", "cisco-ios-xe", "-version", "17.6.1") // prime
	atomic.StoreInt32(&w.nvd.fail, http.StatusServiceUnavailable)

	code, stdout, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.6.1", "--json")
	if code != exitVulnerable {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stderr", stderr, "NVD:", "HTTP 503", "using cached data from")
	res := decodeResults(t, stdout)
	if len(res[0].Advisories) != 3 || res[0].Advisories[0].Source != "CACHE" {
		t.Errorf("results = %+v", res[0].Advisories)
	}
}

func TestCVENetworkFailureWithoutACacheIsADeviceError(t *testing.T) {
	w := newCVEWS(t, "")
	atomic.StoreInt32(&w.nvd.fail, http.StatusInternalServerError)
	code, stdout, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.6.1")
	if code != task.ExitPartial {
		t.Errorf("exit %d", code)
	}
	mustContain(t, "stderr", stderr, "(ad hoc): no advisory data for cisco-ios-xe", "HTTP 500", "1 could not be checked")
	mustNotHave(t, "stdout", stdout, "No CVEs")
	if _, err := os.Stat(w.db); err == nil {
		t.Error("nothing was fetched, so no cache file may be written")
	}
}

func TestCVEUnreadableCacheIsReplacedOnlineAndFatalOffline(t *testing.T) {
	w := newCVEWS(t, "")
	if err := os.WriteFile(w.db, []byte("not a cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.6.1", "-offline")
	if code != task.ExitFatal || !strings.Contains(stderr, "offline cache:") {
		t.Errorf("offline: exit %d, stderr %q", code, stderr)
	}
	code, _, stderr = w.run("-os", "cisco-ios-xe", "-version", "17.6.1")
	if code != exitVulnerable {
		t.Fatalf("online: exit %d\n%s", code, stderr)
	}
	mustContain(t, "stderr", stderr, "ignoring the unreadable cache", "a new one replaces it")
	if c, err := cve.OpenCache(w.db); err != nil || !c.Exists() {
		t.Errorf("the corrupt file must have been replaced by a valid cache: %v", err)
	}
}

func TestCVEStaleCacheIsFlagged(t *testing.T) {
	w := newCVEWS(t, "")
	c := cve.NewCache(w.db)
	c.Put("NVD", "o:cisco:ios_xe", cve.Entry{Updated: time.Now().Add(-30 * 24 * time.Hour), Records: []cve.Record{
		{Advisory: cve.Advisory{ID: "CVE-OLD", Source: "NVD", Severity: cve.SeverityHigh, CVSS: 8},
			Affects: []cve.Affect{{Vendor: "cisco", Product: "ios_xe"}}},
	}})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.6.1", "-offline")
	if code != exitVulnerable {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stderr", stderr, "30 day(s) old", "-update-db")
	mustContain(t, "stdout", stdout, "CVE-OLD")
}

// ---- -update-db -------------------------------------------------------------------------------------

func TestCVEUpdateDBPreWarmsTheCacheForOfflineUse(t *testing.T) {
	w := newCVEWS(t, "")
	code, stdout, stderr := w.run("-update-db", "-os", "cisco-ios-xe")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stdout", stdout, "| PLATFORM", "| cisco-ios-xe", "| NVD", "o:cisco:ios_xe", "| ok")
	mustContain(t, "stderr", stderr, "1 scope(s), 4 advisory record(s)")

	// the cache now answers for any version, with no network at all
	atomic.StoreInt32(&w.nvd.fail, http.StatusServiceUnavailable)
	code, stdout, _ = w.run("-os", "cisco-ios-xe", "-version", "17.6.5", "-offline")
	if code != exitVulnerable || !strings.Contains(stdout, "CVE-2023-20198") {
		t.Errorf("offline after update: exit %d\n%s", code, stdout)
	}
}

func TestCVEUpdateDBForABareVendorCoversEveryCandidateProduct(t *testing.T) {
	w := newCVEWS(t, "")
	code, stdout, stderr := w.run("-update-db", "-os", "cisco")
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stdout", stdout, "o:cisco:ios_xe", "o:cisco:ios ")
	if w.nvd.requests() != 2 {
		t.Errorf("requests = %d, want one per candidate product", w.nvd.requests())
	}
}

func TestCVEUpdateDBCachesVersionScopedSourcesForKnownVersionsOnly(t *testing.T) {
	stub := &cveStub{name: "CISCO", scope: cve.ScopeVersion, recs: []cve.Record{
		{Advisory: cve.Advisory{ID: "CVE-2099-7", Source: "CISCO", Severity: cve.SeverityHigh, CVSS: 8},
			Affects: []cve.Affect{{Vendor: "cisco", Product: "ios_xe", Version: "17.06.01"}}},
	}}
	w := newCVEWS(t, "", stub)

	// without a version the Cisco source is skipped, and says why
	_, stdout, _ := w.run("-update-db", "-os", "cisco-ios-xe")
	mustContain(t, "stdout", stdout, "skipped: needs a version")
	if len(stub.calls) != 0 {
		t.Errorf("calls = %v", stub.calls)
	}
	// a facts export names versions: those are cached
	facts := w.writeFacts(task.FactsRow{Hostname: "r1", Vendor: "cisco", Version: "17.06.01"}, task.FactsRow{Hostname: "r2", Vendor: "cisco", Version: "17.6.1"},
		task.FactsRow{Hostname: "sb", Vendor: "cisco_sb", Version: "3.1"})
	code, stdout, stderr := w.run("-update-db", "-from-facts", facts)
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stdout", stdout, "o:cisco:ios_xe@17.6.1", "| CISCO")
	mustContain(t, "stderr", stderr, `skipping "cisco_sb"`)
	if len(stub.calls) != 1 || stub.calls[0] != "ios_xe@17.06.01" {
		t.Errorf("the same version in two spellings is fetched once: %v", stub.calls)
	}
	// and an offline check of that exact version sees the Cisco-only advisory
	_, out, _ := w.run("-os", "cisco-ios-xe", "-version", "17.6.1", "-offline", "--json")
	if got := decodeResults(t, out)[0].Advisories; !strings.Contains(ids(got), "CVE-2099-7") {
		t.Errorf("advisories = %s", ids(got))
	}
}

func TestCVEUpdateDBFromAnInventoryNeedsNoDeviceAccess(t *testing.T) {
	w := newCVEWS(t, "")
	inv := filepath.Join(w.dir, "inventory.csv")
	body := "hostname,address,port,vendor,credential_group\nr1,10.0.0.1,22,junos,\nr2,10.0.0.2,22,junos,\nsw,10.0.0.3,22,huawei,\nfw,10.0.0.4,22,fortinet,\n"
	if err := os.WriteFile(inv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := w.run("-update-db", "-inventory", inv)
	if code != task.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	mustContain(t, "stdout", stdout, "o:juniper:junos", "o:fortinet:fortios")
	mustContain(t, "stderr", stderr, `skipping "huawei"`)
	if w.nvd.requests() != 2 {
		t.Errorf("requests = %d, want 2 (junos once for two devices, fortios once)", w.nvd.requests())
	}
	// -limit applies
	code, stdout, _ = w.run("-update-db", "-inventory", inv, "-limit", "fw")
	if code != task.ExitOK || strings.Contains(stdout, "junos") {
		t.Errorf("-limit: exit %d\n%s", code, stdout)
	}
}

func TestCVEUpdateDBReportsFailuresAndKeepsGoing(t *testing.T) {
	w := newCVEWS(t, "")
	atomic.StoreInt32(&w.nvd.fail, http.StatusInternalServerError)
	code, stdout, _ := w.run("-update-db", "-os", "junos", "-version", "21.2R3")
	if code != task.ExitPartial {
		t.Errorf("exit %d", code)
	}
	mustContain(t, "stdout", stdout, "FAILED:", "HTTP 500")
}

func TestCVEUpdateDBProblems(t *testing.T) {
	w := newCVEWS(t, "")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"nothing mappable":  {[]string{"-update-db", "-os", "cisco_sb"}, "nothing to update"},
		"missing inventory": {[]string{"-update-db", "-inventory", filepath.Join(w.dir, "nope.csv")}, "no such file"},
		"bad facts":         {[]string{"-update-db", "-from-facts", filepath.Join(w.dir, "nope.json")}, "no such file"},
		"bad limit":         {[]string{"-update-db", "-inventory", filepath.Join(w.dir, "inv.csv"), "-limit", "@nogroup"}, ""},
	} {
		if name == "bad limit" {
			_ = os.WriteFile(filepath.Join(w.dir, "inv.csv"), []byte("hostname,address,port,vendor,credential_group\nr1,10.0.0.1,22,junos,\n"), 0o600)
		}
		code, _, stderr := w.run(tc.args...)
		if code != task.ExitFatal || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr)
		}
	}
	// the cache directory cannot be created
	blocker := filepath.Join(w.dir, "file")
	_ = os.WriteFile(blocker, []byte("x"), 0o600)
	code, _, stderr := dispatchOut(t, "cve", "-update-db", "-os", "junos", "-version", "21.2R3", "-db", filepath.Join(blocker, "sub", "c.gz"), "-env-file", w.env)
	if code != task.ExitFatal {
		t.Errorf("exit %d, want fatal: the refreshed data could not be saved\n%s", code, stderr)
	}
	mustContain(t, "stderr", stderr, "ignoring the unreadable cache", "saving the cache")
}

// ---- Telegram ------------------------------------------------------------------------------------------

func TestCVENotifySendsTheFindings(t *testing.T) {
	w := newCVEWS(t, telegramEnv)
	calls := hookAlerts(t, nil)
	code, _, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.6.1", "-notify")
	if code != exitVulnerable {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if len(*calls) != 1 {
		t.Fatalf("alerts sent: %d", len(*calls))
	}
	c := (*calls)[0]
	if !c.cfg.Enabled || c.cfg.BotToken != "123:abc" || c.cfg.ChatID != "-100" {
		t.Errorf("the Telegram settings must come from the env file: %+v", c.cfg)
	}
	if len(c.results) != 1 || ids(c.results[0].Advisories) != "CVE-2023-20198,CVE-2022-20000,CVE-2099-0001" {
		t.Errorf("the alert carries the filtered findings: %+v", c.results)
	}
	mustContain(t, "stderr", stderr, "Telegram alert sent for 1 device(s)")
}

func TestCVENotifyWithoutFindingsSendsNothing(t *testing.T) {
	w := newCVEWS(t, telegramEnv)
	calls := hookAlerts(t, nil)
	code, _, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.12.1", "-notify")
	if code != task.ExitOK || len(*calls) != 0 {
		t.Errorf("exit %d, alerts %d", code, len(*calls))
	}
	mustContain(t, "stderr", stderr, "no findings at or above HIGH: no Telegram alert sent")
}

func TestCVENotifyDeliveryFailureRaisesTheExitCode(t *testing.T) {
	w := newCVEWS(t, telegramEnv)
	hookAlerts(t, errors.New("telegram api error 400: chat not found"))
	code, _, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.6.1", "-notify")
	if code != task.ExitPartial {
		t.Errorf("exit %d: a lost alert must not look like a normal findings run", code)
	}
	mustContain(t, "stderr", stderr, "Telegram alert not delivered: telegram api error 400")
}

func TestCVENotifyExplainsMissingTelegramSettings(t *testing.T) {
	w := newCVEWS(t, "") // no TELEGRAM_* anywhere; the real sender is in place
	code, stdout, stderr := w.run("-os", "cisco-ios-xe", "-version", "17.6.1", "-notify")
	if code != task.ExitPartial {
		t.Errorf("exit %d", code)
	}
	mustContain(t, "stderr", stderr, "Telegram alert not sent: set TELEGRAM_ENABLED=true, TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in "+w.env)
	mustContain(t, "stdout", stdout, "CVE-2023-20198") // the report itself is unaffected
}

// ---- inventory mode (live collection over SSH) -------------------------------------------------------------

func TestCVEInventoryModeCollectsVersionsThenChecks(t *testing.T) {
	ws := factsWS(t) // sw-a, sw-b: classic IOS 15.2(4)E10; fw: unreachable
	w := newCVEWS(t, "")
	code, stdout, stderr := ws.run("cve", "-db", w.db, "-min-severity", "LOW")
	if code != task.ExitPartial {
		t.Errorf("exit %d: the unreachable device outranks the findings\n%s", code, stderr)
	}
	mustContain(t, "stderr", stderr, "CONNECT_FAILED")
	mustContain(t, "stdout", stdout, "| HOSTNAME", "| sw-a", "| sw-b", "| cisco-ios | 15.2(4)E10 | CVE-2018-0171 | CRITICAL | 9.8")
	if strings.Index(stdout, "sw-a") > strings.Index(stdout, "sw-b") {
		t.Error("rows sorted by hostname")
	}
	mustContain(t, "audit log", ws.logText(), "checked 2 device(s): 2 with findings (2 advisories at or above LOW), 0 could not be checked; 1 device(s) could not be queried")
	// read-only: only the facts commands ran
	for _, c := range ws.dev("sw-a").cmds {
		if strings.HasPrefix(c, "configure") || c == "write memory" {
			t.Errorf("a configuration command was sent: %q", c)
		}
	}
}

func TestCVEInventoryModeExitCodeWhenEverythingWasChecked(t *testing.T) {
	ws := newOpsWS(t, oneSwitch, "sw1")
	ws.dev("sw1").answers["show version"] = "Cisco IOS XE Software, Version 17.06.01\nsw1 uptime is 1 week\n"
	w := newCVEWS(t, "")
	code, stdout, stderr := ws.run("cve", "-db", w.db)
	if code != exitVulnerable {
		t.Fatalf("exit %d, want %d\n%s", code, exitVulnerable, stderr)
	}
	mustContain(t, "stdout", stdout, "| sw1", "| cisco-ios-xe", "17.06.01", "CVE-2023-20198", "17.6.6a")

	// the same device on a fixed release: exit 0
	ws.dev("sw1").answers["show version"] = "Cisco IOS XE Software, Version 17.12.01\nsw1 uptime is 1 week\n"
	code, stdout, _ = ws.run("cve", "-db", w.db)
	if code != task.ExitOK || !strings.Contains(stdout, "No CVEs at or above HIGH found for 1 device(s).") {
		t.Errorf("exit %d\n%s", code, stdout)
	}
}

func TestCVEInventoryModeWritesProblemsToTheAuditLog(t *testing.T) {
	ws := newOpsWS(t, oneSwitch, "sw1")
	ws.dev("sw1").answers["show version"] = "Cisco IOS XE Software, Version 17.06.01\nsw1 uptime is 1 week\n"
	w := newCVEWS(t, "")

	// NVD down and nothing cached: the device is reported as unchecked, in the log too
	atomic.StoreInt32(&w.nvd.fail, http.StatusServiceUnavailable)
	code, stdout, _ := ws.run("cve", "-db", w.db)
	if code != task.ExitPartial {
		t.Errorf("exit %d", code)
	}
	mustNotHave(t, "stdout", stdout, "No CVEs")
	mustContain(t, "audit log", ws.logText(), "ERROR", "sw1: no advisory data for cisco-ios-xe", "1 could not be checked")

	// primed cache and NVD down: the fallback is a warning in the log, and the run still reports
	atomic.StoreInt32(&w.nvd.fail, 0)
	if code, _, stderr := ws.run("cve", "-db", w.db); code != exitVulnerable {
		t.Fatalf("priming: exit %d\n%s", code, stderr)
	}
	atomic.StoreInt32(&w.nvd.fail, http.StatusServiceUnavailable)
	code, _, _ = ws.run("cve", "-db", w.db)
	if code != exitVulnerable {
		t.Errorf("fallback: exit %d", code)
	}
	mustContain(t, "audit log", ws.logText(), "WARN", "using cached data from")
}

func TestCVEInventoryModeNotify(t *testing.T) {
	ws := newOpsWS(t, oneSwitch, "sw1")
	ws.dev("sw1").answers["show version"] = "Cisco IOS XE Software, Version 17.06.01\nsw1 uptime is 1 week\n"
	w := newCVEWS(t, "")
	calls := hookAlerts(t, nil)
	code, _, stderr := ws.run("cve", "-db", w.db, "-notify")
	if code != exitVulnerable || len(*calls) != 1 || (*calls)[0].results[0].Hostname != "sw1" {
		t.Errorf("exit %d, alerts %+v\n%s", code, *calls, stderr)
	}
}

// ---- settings --------------------------------------------------------------------------------------------------

func TestCVESettingsComeFromTheEnvFileThenTheEnvironment(t *testing.T) {
	w := newCVEWS(t, "NVD_API_KEY=from-file\n")
	t.Setenv("NVD_API_KEY", "from-env")              // the file wins, as for the Telegram settings
	t.Setenv("CISCO_PSIRT_CLIENT_ID", "id-from-env") // only in the environment
	w.run("-os", "junos", "-version", "21.2R3")
	if w.seen["NVD_API_KEY"] != "from-file" || w.seen["CISCO_PSIRT_CLIENT_ID"] != "id-from-env" || w.seen["CISCO_PSIRT_CLIENT_SECRET"] != "" {
		t.Errorf("settings seen by the source builder: %v", w.seen)
	}
}

func TestCVEDefaultSourcesAreWiredWithTheirSettings(t *testing.T) {
	cfg := map[string]string{"NVD_API_KEY": "k1", "CISCO_PSIRT_CLIENT_ID": "id", "CISCO_PSIRT_CLIENT_SECRET": "sec"}
	srcs := cveSources(func(k string) string { return cfg[k] }, 3*time.Second)
	if len(srcs) != 3 {
		t.Fatalf("sources = %d", len(srcs))
	}
	nvd, ok1 := srcs[0].(*cve.NVD)
	psirt, ok2 := srcs[1].(*cve.CiscoPSIRT)
	osv, ok3 := srcs[2].(*cve.OSV)
	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("source types: %T %T %T", srcs[0], srcs[1], srcs[2])
	}
	if nvd.APIKey != "k1" || nvd.Client.Timeout != 3*time.Second || psirt.ClientID != "id" || psirt.ClientSecret != "sec" || psirt.Client.Timeout != 3*time.Second || osv.Client.Timeout != 3*time.Second {
		t.Errorf("nvd=%+v psirt=%+v osv=%+v", nvd, psirt, osv)
	}
}

// ---- flags, help and dispatch --------------------------------------------------------------------------------------

func TestCVEFlagValidation(t *testing.T) {
	w := newCVEWS(t, "")
	facts := w.writeFacts(task.FactsRow{Hostname: "r1", Vendor: "junos", Version: "21.2R3"})
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"bad severity":        {[]string{"-os", "junos", "-version", "1", "-min-severity", "SEVERE"}, "-min-severity must be LOW, MEDIUM, HIGH or CRITICAL"},
		"unknown severity":    {[]string{"-os", "junos", "-version", "1", "-min-severity", "UNKNOWN"}, "-min-severity must be"},
		"os without version":  {[]string{"-os", "junos"}, "-os needs -version"},
		"version without os":  {[]string{"-version", "1.0"}, "-version needs -os"},
		"os and facts":        {[]string{"-os", "junos", "-version", "1", "-from-facts", facts}, "alternatives"},
		"os and inventory":    {[]string{"-os", "junos", "-version", "1", "-inventory", "x.csv"}, "-inventory cannot be combined"},
		"facts and inventory": {[]string{"-from-facts", facts, "-inventory", "x.csv"}, "-inventory cannot be combined"},
		"os and limit":        {[]string{"-os", "junos", "-version", "1", "-limit", "r1"}, "-limit selects inventory devices"},
		"facts and limit":     {[]string{"-from-facts", facts, "-limit", "r1"}, "-limit selects inventory devices"},
		"offline and update":  {[]string{"-update-db", "-os", "junos", "-offline"}, "contradict"},
		"update and notify":   {[]string{"-update-db", "-os", "junos", "-notify"}, "do not apply to -update-db"},
		"update and output":   {[]string{"-update-db", "-os", "junos", "--output", "x.csv"}, "do not apply to -update-db"},
		"update and json":     {[]string{"-update-db", "-os", "junos", "--json"}, "do not apply to -update-db"},
		"zero timeout":        {[]string{"-os", "junos", "-version", "1", "-http-timeout", "0s"}, "-http-timeout must be positive"},
		"empty db":            {[]string{"-os", "junos", "-version", "1", "-db", " "}, "-db must not be empty"},
		"unknown os":          {[]string{"-os", "plan9", "-version", "1"}, "unknown OS/platform"},
		"unsupported os":      {[]string{"-os", "huawei", "-version", "1"}, "no CVE product mapping"},
		"stray argument":      {[]string{"-os", "junos", "-version", "1", "extra"}, "unexpected arguments: extra"},
		"unknown flag":        {[]string{"-bogus"}, "flag provided but not defined"},
	} {
		code, _, stderr := dispatchOut(t, append([]string{"cve", "-db", w.db, "-env-file", w.env}, tc.args...)...)
		if code != task.ExitFatal || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: exit %d, stderr:\n%s\nwant %q", name, code, stderr, tc.want)
		}
	}
	if code, _, stderr := dispatchOut(t, "cve", "-password", "x"); code != task.ExitFatal || !strings.Contains(stderr, "passwords are never accepted as command-line flags") {
		t.Errorf("password flag: exit %d\n%s", code, stderr)
	}
	if w.nvd.requests() != 0 {
		t.Error("invalid invocations must not touch the network")
	}
}

func TestCVEHelpListsTheGroupedFlags(t *testing.T) {
	for _, form := range []string{"-h", "--help", "help"} {
		code, stdout, _ := dispatchOut(t, "cve", form)
		if code != task.ExitOK {
			t.Errorf("%s: exit %d", form, code)
		}
		mustContain(t, form+" output", stdout, "netops cve: check device software versions against known CVEs.",
			"CVE check:", "Offline cache and sources:", "Inventory and credentials:", "-min-severity", "-update-db", "-from-facts", "Exit codes: 3")
		mustNotHave(t, form+" output", stdout, "Other flags:")
	}
	// the usage printed for a parse error goes to stderr
	code, _, stderr := dispatchOut(t, "cve", "-bogus")
	if code != task.ExitFatal || !strings.Contains(stderr, "netops cve:") {
		t.Errorf("exit %d\n%s", code, stderr)
	}
}

func TestCVEIsListedInTheRootUsage(t *testing.T) {
	_, stdout, stderr := dispatchOut(t, "-h")
	mustContain(t, "root usage", stdout+stderr, "cve            check software versions against known CVEs")
}

// ---- helpers ----------------------------------------------------------------------------------------------------------

func TestFilterSeverityKeepsDevicesAndUnscoredAdvisories(t *testing.T) {
	in := []cve.DeviceCVEResult{
		{Hostname: "a", Advisories: []cve.Advisory{{ID: "1", Severity: cve.SeverityLow}, {ID: "2", Severity: cve.SeverityHigh}, {ID: "3", Severity: cve.SeverityUnknown}}},
		{Hostname: "b", Error: "boom", Advisories: []cve.Advisory{}},
	}
	out := filterSeverity(in, cve.SeverityHigh)
	if len(out) != 2 || ids(out[0].Advisories) != "2,3" || out[1].Error != "boom" || out[1].Advisories == nil {
		t.Errorf("out = %+v", out)
	}
	if len(in[0].Advisories) != 3 {
		t.Error("the input must not be modified")
	}
}

func TestCVERecordForADeviceThatCouldNotBeChecked(t *testing.T) {
	row := cveRecord(cve.DeviceCVEResult{Hostname: "=h", Error: "+boom"}, nil)
	if len(row) != len(cveHeader) || row[0] != "'=h" || row[14] != "'+boom" || row[5] != "" {
		t.Errorf("row = %q", row)
	}
	if cveScore(cve.Advisory{CVSS: 0}) != "" || cveScore(cve.Advisory{CVSS: 7.55}) != "7.5" && cveScore(cve.Advisory{CVSS: 7.55}) != "7.6" {
		t.Error("cveScore")
	}
}

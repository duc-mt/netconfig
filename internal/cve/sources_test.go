// ==============================================================================
// File name:     sources_test.go
// Description:   Tests of the NVD, Cisco PSIRT and OSV clients against mock
//                servers, and of the aggregator that merges them.
// License:       MIT
// ==============================================================================

package cve

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// nvdPage is a realistic NVD 2.0 page: an IOS XE CVE with a Primary metric next
// to a Secondary one, a rejected CVE, a CVE where IOS XE is only the platform
// something runs on, and a Junos CVE whose release sits in the CPE update field.
const nvdPage = `{
 "resultsPerPage": 500, "startIndex": 0, "totalResults": 4, "format": "NVD_CVE", "version": "2.0",
 "vulnerabilities": [
  {"cve": {
    "id": "CVE-2023-20198", "published": "2023-10-16T15:15:12.690", "vulnStatus": "Modified",
    "descriptions": [
      {"lang": "es", "value": "Descripción en español."},
      {"lang": "en", "value": "Cisco is aware of active exploitation of a vulnerability in the web UI of Cisco IOS XE Software. It allows a remote attacker to create an account. More text follows."}
    ],
    "metrics": {
      "cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 9.9, "baseSeverity": "CRITICAL"}},
        {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL"}}
      ],
      "cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]
    },
    "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [
      {"vulnerable": true, "criteria": "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", "versionStartIncluding": "17.9.0", "versionEndExcluding": "17.9.4a"},
      {"vulnerable": true, "criteria": "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", "versionStartIncluding": "17.9.0", "versionEndExcluding": "17.9.4a"},
      {"vulnerable": true, "criteria": "cpe:2.3:o:cisco:ios_xe:17.3.1:*:*:*:*:*:*:*"},
      {"vulnerable": true, "criteria": "cpe:2.3:o:cisco:ios:15.2\\(4\\)m11:*:*:*:*:*:*:*"},
      {"vulnerable": false, "criteria": "cpe:2.3:h:cisco:asr_1001-x:-:*:*:*:*:*:*:*"}
    ]}]}],
    "references": [{"url": "https://example.com/ref"}]
  }},
  {"cve": {
    "id": "CVE-2000-0001", "published": "2000-01-01T00:00:00.000", "vulnStatus": "Rejected",
    "descriptions": [{"lang": "en", "value": "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER."}],
    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*"}]}]}]
  }},
  {"cve": {
    "id": "CVE-2022-9999", "published": "2022-02-02T00:00:00.000", "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "A third-party app that runs on IOS XE is vulnerable."}],
    "configurations": [{"operator": "AND", "nodes": [
      {"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:thirdparty:app:1.0:*:*:*:*:*:*:*"}]},
      {"cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*"}]}
    ]}]
  }},
  {"cve": {
    "id": "CVE-2023-36845", "published": "2023-08-17T21:15:09.000", "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "PHP external variable modification in J-Web of Junos OS."}],
    "metrics": {"cvssMetricV30": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
    "configurations": [{"nodes": [{"cpeMatch": [
      {"vulnerable": true, "criteria": "cpe:2.3:o:juniper:junos:20.4:r3-s2:*:*:*:*:*:*"},
      {"vulnerable": true, "criteria": "cpe:2.3:o:juniper:junos:20.4:-:*:*:*:*:*:*"}
    ]}]}]
  }}
 ]}`

// oneJSON serves body with status 200 for every request and counts them.
func oneJSON(t *testing.T, body string, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fastNVD(base string) *NVD {
	return &NVD{BaseURL: base, Backoff: time.Nanosecond, PageGap: time.Nanosecond}
}

func TestNVDFetchParsesRecordsAndRequestShape(t *testing.T) {
	var gotQuery, gotKey, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery, gotKey, gotUA = r.URL.RawQuery, r.Header.Get("apiKey"), r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(nvdPage))
	}))
	defer srv.Close()

	n := fastNVD(srv.URL)
	n.APIKey = "secret-key"
	recs, err := n.Fetch(context.Background(), ciscoIOSXE, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if gotKey != "secret-key" || gotUA == "" {
		t.Errorf("apiKey header %q, user agent %q", gotKey, gotUA)
	}
	for _, want := range []string{"virtualMatchString=cpe%3A2.3%3Ao%3Acisco%3Aios_xe%3A%2A", "resultsPerPage=500", "startIndex=0"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q lacks %q", gotQuery, want)
		}
	}
	// Rejected, "runs on" and other-product CVEs are dropped; the Junos CVE has no IOS XE range.
	if len(recs) != 1 {
		t.Fatalf("got %d records: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.ID != "CVE-2023-20198" || r.Source != "NVD" || r.CVSS != 10.0 || r.Severity != SeverityCritical {
		t.Errorf("record = %+v", r.Advisory)
	}
	if r.URL != "https://nvd.nist.gov/vuln/detail/CVE-2023-20198" {
		t.Errorf("URL = %q", r.URL)
	}
	if !strings.HasPrefix(r.Title, "Cisco is aware") || !strings.HasSuffix(r.Title, "Cisco IOS XE Software.") {
		t.Errorf("title should be the first English sentence, got %q", r.Title)
	}
	if !strings.Contains(r.Description, "More text follows.") {
		t.Errorf("description is the full English text, got %q", r.Description)
	}
	if want := time.Date(2023, 10, 16, 15, 15, 12, 690000000, time.UTC); !r.Published.Equal(want) {
		t.Errorf("published = %v", r.Published)
	}
	want := []Affect{
		{Vendor: "cisco", Product: "ios_xe", StartIncluding: "17.9.0", EndExcluding: "17.9.4a", Fixed: "17.9.4a"},
		{Vendor: "cisco", Product: "ios_xe", Version: "17.3.1"},
	}
	if len(r.Affects) != len(want) || r.Affects[0] != want[0] || r.Affects[1] != want[1] {
		t.Errorf("affects = %+v, want %+v (duplicates collapsed, other products ignored)", r.Affects, want)
	}
}

func TestNVDFetchJunosUpdateFieldBecomesPartOfTheVersion(t *testing.T) {
	var hits int32
	srv := oneJSON(t, nvdPage, &hits)
	junos := Product{Part: "o", Vendor: "juniper", Name: "junos", OS: "junos"}
	recs, err := fastNVD(srv.URL).Fetch(context.Background(), junos, "")
	if err != nil || len(recs) != 1 {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
	if got := Match(recs, junos, "20.4R3-S2"); len(got) != 1 {
		t.Errorf("20.4R3-S2 must match junos:20.4:r3-s2, got %v", got)
	}
	// "20.4" with update "-" (not applicable) is the bare release 20.4
	if got := Match(recs, junos, "20.4"); len(got) != 1 {
		t.Errorf("20.4 must match junos:20.4:-, got %v", got)
	}
	if got := Match(recs, junos, "20.4R3-S1"); len(got) != 0 {
		t.Errorf("20.4R3-S1 is not enumerated, got %v", got)
	}
}

func TestNVDFetchPanOSHotfixInUpdateField(t *testing.T) {
	page := `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-3400","descriptions":[{"lang":"en","value":"x"}],
	 "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:h4:*:*:*:*:*:*"}]}]}]}}]}`
	var hits int32
	srv := oneJSON(t, page, &hits)
	pan := Product{Part: "o", Vendor: "paloaltonetworks", Name: "pan-os", OS: "pan-os"}
	recs, err := fastNVD(srv.URL).Fetch(context.Background(), pan, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(Match(recs, pan, "10.2.3-h4")) != 1 || len(Match(recs, pan, "10.2.3-h5")) != 0 {
		t.Errorf("PAN-OS hotfix matching is wrong: %+v", recs)
	}
}

func TestNVDFetchPaginates(t *testing.T) {
	var starts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := r.URL.Query().Get("startIndex")
		starts = append(starts, start+"/"+r.URL.Query().Get("resultsPerPage"))
		item := func(id string) string {
			return `{"cve":{"id":"` + id + `","descriptions":[{"lang":"en","value":"d"}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*"}]}]}]}}`
		}
		switch start {
		case "0":
			_, _ = w.Write([]byte(`{"totalResults":3,"vulnerabilities":[` + item("CVE-1") + `,` + item("CVE-2") + `]}`))
		case "2":
			_, _ = w.Write([]byte(`{"totalResults":3,"vulnerabilities":[` + item("CVE-3") + `]}`))
		default:
			http.Error(w, "unexpected startIndex", http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	n := fastNVD(srv.URL)
	n.PageSize = 2
	recs, err := n.Fetch(context.Background(), ciscoIOSXE, "")
	if err != nil || len(recs) != 3 {
		t.Fatalf("recs=%d err=%v", len(recs), err)
	}
	if strings.Join(starts, ",") != "0/2,2/2" {
		t.Errorf("requests = %v", starts)
	}
}

func TestNVDFetchStopsOnAnEmptyPageEvenIfTotalIsLarger(t *testing.T) {
	var hits int32
	srv := oneJSON(t, `{"totalResults":99,"vulnerabilities":[]}`, &hits)
	_, err := fastNVD(srv.URL).Fetch(context.Background(), ciscoIOSXE, "")
	if err != nil {
		t.Fatalf("an empty page with a non-zero total must end the loop, not error: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("hits = %d, want 1 (no infinite paging)", n)
	}
}

func TestNVDFetchPageGapContextCancel(t *testing.T) {
	var hits int32
	srv := oneJSON(t, `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-1","descriptions":[{"lang":"en","value":"d"}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*"}]}]}]}}]}`, &hits)
	n := &NVD{BaseURL: srv.URL, PageGap: time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := n.Fetch(ctx, ciscoIOSXE, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the page gap must be interruptible")
	}
}

func TestNVDRetriesRateLimitsWithRetryAfter(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		var hits int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&hits, 1) <= 2 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(code)
				return
			}
			_, _ = w.Write([]byte(nvdPage))
		}))
		recs, err := fastNVD(srv.URL).Fetch(context.Background(), ciscoIOSXE, "")
		srv.Close()
		if err != nil || len(recs) != 1 {
			t.Errorf("HTTP %d: recs=%d err=%v", code, len(recs), err)
		}
		if n := atomic.LoadInt32(&hits); n != 3 {
			t.Errorf("HTTP %d: %d requests, want 3 (two rate-limited, one good)", code, n)
		}
	}
}

func TestNVDBackoffDoublesWithoutRetryAfter(t *testing.T) {
	var times []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		times = append(times, time.Now())
		if len(times) < 4 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(nvdPage))
	}))
	defer srv.Close()
	n := fastNVD(srv.URL)
	n.Backoff = 20 * time.Millisecond
	if _, err := n.Fetch(context.Background(), ciscoIOSXE, ""); err != nil {
		t.Fatal(err)
	}
	g1, g2, g3 := times[1].Sub(times[0]), times[2].Sub(times[1]), times[3].Sub(times[2])
	if g1 < 20*time.Millisecond || g2 < 40*time.Millisecond || g3 < 80*time.Millisecond {
		t.Errorf("gaps %v %v %v, want at least 20ms, 40ms, 80ms (exponential)", g1, g2, g3)
	}
}

func TestNVDGivesUpAfterMaxRetries(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	n := fastNVD(srv.URL)
	n.MaxRetries = 2
	_, err := n.Fetch(context.Background(), ciscoIOSXE, "")
	if err == nil || !strings.Contains(err.Error(), "HTTP 429") {
		t.Fatalf("err = %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 3 {
		t.Errorf("hits = %d, want 3 (1 try + 2 retries)", n)
	}

	atomic.StoreInt32(&hits, 0)
	n.MaxRetries = -1 // no retries at all
	if _, err := n.Fetch(context.Background(), ciscoIOSXE, ""); err == nil || atomic.LoadInt32(&hits) != 1 {
		t.Errorf("negative MaxRetries: err=%v hits=%d, want one request", err, atomic.LoadInt32(&hits))
	}
}

func TestNVDRetryWaitIsInterruptible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := fastNVD(srv.URL).Fetch(ctx, ciscoIOSXE, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline exceeded", err)
	}
}

func TestNVDErrorsCarryTheServersExplanation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("message", "Invalid apiKey")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	_, err := fastNVD(srv.URL).Fetch(context.Background(), ciscoIOSXE, "")
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "Invalid apiKey") {
		t.Errorf("err = %v", err)
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv2.Close()
	if _, err := fastNVD(srv2.URL).Fetch(context.Background(), ciscoIOSXE, ""); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("err = %v", err)
	}
}

func TestNVDRefusesAnEmptyAnswer(t *testing.T) {
	var hits int32
	srv := oneJSON(t, `{"totalResults":0,"vulnerabilities":[]}`, &hits)
	_, err := fastNVD(srv.URL).Fetch(context.Background(), ciscoIOSXE, "")
	if err == nil || !strings.Contains(err.Error(), "not vulnerable") || !strings.Contains(err.Error(), "cpe:2.3:o:cisco:ios_xe") {
		t.Errorf("an empty answer must be an error naming the CPE, got %v", err)
	}
}

func TestNVDMalformedAndUnreachable(t *testing.T) {
	var hits int32
	srv := oneJSON(t, `{not json`, &hits)
	if _, err := fastNVD(srv.URL).Fetch(context.Background(), ciscoIOSXE, ""); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("err = %v", err)
	}
	srv.Close()
	if _, err := fastNVD(srv.URL).Fetch(context.Background(), ciscoIOSXE, ""); err == nil || !strings.Contains(err.Error(), "NVD request") {
		t.Errorf("unreachable server: err = %v", err)
	}
	if _, err := fastNVD("http://bad host/").Fetch(context.Background(), ciscoIOSXE, ""); err == nil {
		t.Error("an invalid URL must fail")
	}
}

func TestNVDTimeoutIsNotRetried(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()
	n := fastNVD(srv.URL)
	n.Client = &http.Client{Timeout: 50 * time.Millisecond}
	start := time.Now()
	if _, err := n.Fetch(context.Background(), ciscoIOSXE, ""); err == nil {
		t.Fatal("a timeout must be an error")
	}
	if n := atomic.LoadInt32(&hits); n != 1 || time.Since(start) > 2*time.Second {
		t.Errorf("hits=%d after %v: a timeout falls back to the cache instead of retrying", n, time.Since(start))
	}
}

func TestNVDDefaults(t *testing.T) {
	n := &NVD{}
	if n.baseURL() != NVDBaseURL || n.pageSize() != 500 || n.retries() != 4 || n.backoff() != 2*time.Second {
		t.Errorf("defaults: %s %d %d %v", n.baseURL(), n.pageSize(), n.retries(), n.backoff())
	}
	if n.pageGap() != 6*time.Second {
		t.Errorf("page gap without a key = %v", n.pageGap())
	}
	n.APIKey = "k"
	if n.pageGap() != 700*time.Millisecond {
		t.Errorf("page gap with a key = %v", n.pageGap())
	}
	if n.Name() != "NVD" || n.Scope() != ScopeProduct || !n.Supports(Product{}) {
		t.Error("NVD identity is wrong")
	}
	if clientOrDefault(nil).Timeout != DefaultHTTPTimeout || DefaultHTTPTimeout != 8*time.Second {
		t.Error("the default HTTP timeout must be 8s")
	}
}

func TestNVDScorePreference(t *testing.T) {
	m := func(typ string, score float64, sev string) nvdMetric {
		x := nvdMetric{Type: typ}
		x.CVSSData.BaseScore, x.CVSSData.BaseSeverity = score, sev
		return x
	}
	v2 := nvdMetric{Type: "Primary", BaseSeverity: "HIGH"}
	v2.CVSSData.BaseScore = 7.5

	tests := []struct {
		name  string
		in    nvdMetrics
		score float64
		sev   Severity
	}{
		{"v3.1 beats everything", nvdMetrics{V31: []nvdMetric{m("Primary", 9.8, "CRITICAL")}, V30: []nvdMetric{m("Primary", 5, "MEDIUM")}, V2: []nvdMetric{v2}}, 9.8, SeverityCritical},
		{"primary beats secondary", nvdMetrics{V31: []nvdMetric{m("Secondary", 5.0, "MEDIUM"), m("Primary", 8.1, "HIGH")}}, 8.1, SeverityHigh},
		{"first when none is primary", nvdMetrics{V31: []nvdMetric{m("Secondary", 5.0, "MEDIUM"), m("Secondary", 8.1, "HIGH")}}, 5.0, SeverityMedium},
		{"falls to v3.0", nvdMetrics{V30: []nvdMetric{m("Primary", 7.2, "HIGH")}}, 7.2, SeverityHigh},
		{"falls to v4.0", nvdMetrics{V40: []nvdMetric{m("Secondary", 9.3, "CRITICAL")}}, 9.3, SeverityCritical},
		{"v2 keeps severity at metric level", nvdMetrics{V2: []nvdMetric{v2}}, 7.5, SeverityHigh},
		{"severity derived from score when absent", nvdMetrics{V31: []nvdMetric{m("Primary", 5.5, "")}}, 5.5, SeverityMedium},
		{"no metrics", nvdMetrics{}, 0, SeverityUnknown},
	}
	for _, tc := range tests {
		score, sev := nvdScore(tc.in)
		if score != tc.score || sev != tc.sev {
			t.Errorf("%s: got %v %s, want %v %s", tc.name, score, sev, tc.score, tc.sev)
		}
	}
}

func TestParseCPE23(t *testing.T) {
	tests := []struct {
		in                    string
		part, vend, prod, ver string
		upd                   string
		ok                    bool
	}{
		{"cpe:2.3:o:cisco:ios_xe:17.6.1:*:*:*:*:*:*:*", "o", "cisco", "ios_xe", "17.6.1", "*", true},
		{`cpe:2.3:o:cisco:ios:15.2\(4\)m11:*:*:*:*:*:*:*`, "o", "cisco", "ios", "15.2(4)m11", "*", true},
		{"cpe:2.3:o:juniper:junos:20.4:r3-s2:*:*:*:*:*:*", "o", "juniper", "junos", "20.4", "r3-s2", true},
		{`cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:*:*:*`, "a", "vendor", "prod:uct", "1.0", "*", true},
		{"cpe:2.3:o:cisco:ios_xe:*", "o", "cisco", "ios_xe", "*", "", true},
		{"cpe:2.2:o:cisco", "", "", "", "", "", false},
		{"not a cpe", "", "", "", "", "", false},
		{"", "", "", "", "", "", false},
	}
	for _, tc := range tests {
		part, vend, prod, ver, upd, ok := parseCPE23(tc.in)
		if ok != tc.ok || part != tc.part || vend != tc.vend || prod != tc.prod || ver != tc.ver || upd != tc.upd {
			t.Errorf("parseCPE23(%q) = %q %q %q %q %q %v", tc.in, part, vend, prod, ver, upd, ok)
		}
	}
	if got := splitCPE(`a\`); len(got) != 1 || got[0] != `a\` {
		t.Errorf("a dangling backslash must survive: %q", got)
	}
}

func TestHeadlineAndParseTime(t *testing.T) {
	if got := headline("  One   sentence. Two."); got != "One sentence." {
		t.Errorf("headline = %q", got)
	}
	if got := headline("no stop"); got != "no stop" {
		t.Errorf("headline = %q", got)
	}
	long := strings.Repeat("é", 400)
	if got := headline(long); len([]rune(got)) != 160 || !strings.HasSuffix(got, "…") {
		t.Errorf("long headline has %d runes", len([]rune(got)))
	}
	for _, in := range []string{"2023-10-16T15:15:12.690", "2023-10-16T15:15:12", "2023-10-16T15:15:12Z", "2023-10-16T17:15:12+02:00", "2023-10-16"} {
		if parseTime(in).IsZero() {
			t.Errorf("parseTime(%q) failed", in)
		}
	}
	if !parseTime("garbage").IsZero() || !parseTime("").IsZero() {
		t.Error("unparseable times must be the zero time")
	}
}

func TestRetryAfterAndSleep(t *testing.T) {
	h := http.Header{}
	if _, ok := retryAfter(h); ok {
		t.Error("absent header")
	}
	h.Set("Retry-After", "7")
	if d, ok := retryAfter(h); !ok || d != 7*time.Second {
		t.Errorf("seconds: %v %v", d, ok)
	}
	h.Set("Retry-After", time.Now().Add(90*time.Second).UTC().Format(http.TimeFormat))
	if d, ok := retryAfter(h); !ok || d < 60*time.Second || d > 91*time.Second {
		t.Errorf("date: %v %v", d, ok)
	}
	h.Set("Retry-After", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	if d, ok := retryAfter(h); !ok || d != 0 {
		t.Errorf("past date: %v %v", d, ok)
	}
	h.Set("Retry-After", "soon")
	if _, ok := retryAfter(h); ok {
		t.Error("junk header")
	}
	if err := sleepCtx(context.Background(), 0); err != nil {
		t.Error(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, 0); err == nil {
		t.Error("an already cancelled context must report its error even for a zero wait")
	}
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Error("cancelled")
	}
}

// ---- Cisco PSIRT -------------------------------------------------------------------

const ciscoAdvisoriesJSON = `{"advisories": [
 {"advisoryId": "cisco-sa-iosxe-webui-privesc-j22SaA4z", "advisoryTitle": "Cisco IOS XE Software Web UI Privilege Escalation Vulnerability",
  "cves": ["CVE-2023-20198", "cve-2023-20273"], "cvssBaseScore": "10.0", "firstFixed": ["17.9.4a", "17.6.6a", "17.3.8a"],
  "firstPublished": "2023-10-16T16:00:00", "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
  "sir": "Critical", "summary": "Cisco is aware of active exploitation."},
 {"advisoryId": "cisco-sa-noc-1", "advisoryTitle": "No CVE yet", "cves": ["NA"], "cvssBaseScore": "NA", "firstFixed": [],
  "firstPublished": "2024-01-02T00:00:00", "publicationUrl": "https://example.com/noc", "sir": "Informational", "summary": "s"}
]}`

type ciscoFake struct {
	srv       *httptest.Server
	tokens    int32
	data      int32
	lastPath  string
	lastQuery string
	lastAuth  string
	form      map[string]string
}

func newCiscoFake(t *testing.T, dataHandler func(w http.ResponseWriter, r *http.Request, n int32)) *ciscoFake {
	t.Helper()
	f := &ciscoFake{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.tokens, 1)
		_ = r.ParseForm()
		f.form = map[string]string{"grant_type": r.PostForm.Get("grant_type"), "client_id": r.PostForm.Get("client_id"), "client_secret": r.PostForm.Get("client_secret"), "ct": r.Header.Get("Content-Type")}
		_, _ = w.Write([]byte(`{"access_token":"tok-` + string(rune('0'+atomic.LoadInt32(&f.tokens))) + `","token_type":"Bearer","expires_in":3599}`))
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&f.data, 1)
		f.lastPath, f.lastQuery, f.lastAuth = r.URL.Path, r.URL.Query().Get("version"), r.Header.Get("Authorization")
		dataHandler(w, r, n)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *ciscoFake) client() *CiscoPSIRT {
	return &CiscoPSIRT{BaseURL: f.srv.URL + "/api", TokenURL: f.srv.URL + "/token", ClientID: "id-1", ClientSecret: "sec-1"}
}

func TestCiscoPSIRTFetch(t *testing.T) {
	f := newCiscoFake(t, func(w http.ResponseWriter, r *http.Request, _ int32) { _, _ = w.Write([]byte(ciscoAdvisoriesJSON)) })
	c := f.client()
	recs, err := c.Fetch(context.Background(), ciscoIOSXE, "17.06.01")
	if err != nil {
		t.Fatal(err)
	}
	if f.lastPath != "/api/OSType/iosxe" || f.lastQuery != "17.6.1" || f.lastAuth != "Bearer tok-1" {
		t.Errorf("request: path %q version %q auth %q", f.lastPath, f.lastQuery, f.lastAuth)
	}
	if f.form["grant_type"] != "client_credentials" || f.form["client_id"] != "id-1" || f.form["client_secret"] != "sec-1" || !strings.HasPrefix(f.form["ct"], "application/x-www-form-urlencoded") {
		t.Errorf("token request form = %v", f.form)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3 (two CVEs of the first advisory + the CVE-less one by advisory ID): %+v", len(recs), recs)
	}
	r := recs[0]
	if r.ID != "CVE-2023-20198" || r.Source != "CISCO" || r.CVSS != 10.0 || r.Severity != SeverityCritical ||
		!strings.HasPrefix(r.Title, "Cisco IOS XE Software Web UI") || r.Published.IsZero() || !strings.Contains(r.URL, "cisco-sa-iosxe") {
		t.Errorf("record = %+v", r.Advisory)
	}
	if recs[1].ID != "CVE-2023-20273" {
		t.Errorf("CVE ids are upper-cased: %q", recs[1].ID)
	}
	// the fix of the device's own train (17.6) is chosen out of all trains' fixes
	if len(r.Affects) != 1 || r.Affects[0].Fixed != "17.6.6a" || r.Affects[0].Version != "17.06.01" || r.Affects[0].Product != "ios_xe" {
		t.Errorf("affects = %+v", r.Affects)
	}
	if recs[2].ID != "cisco-sa-noc-1" || recs[2].Severity != SeverityLow || recs[2].CVSS != 0 {
		t.Errorf("CVE-less advisory = %+v", recs[2].Advisory)
	}
	// pinned to the queried version: matches it (zero-padding insensitive), nothing else
	if len(Match(recs, ciscoIOSXE, "17.6.1")) != 3 || len(Match(recs, ciscoIOSXE, "17.6.2")) != 0 {
		t.Error("Cisco answers are only valid for the queried version")
	}
}

func TestCiscoPSIRTTokenIsCachedAndRenewedOn401(t *testing.T) {
	f := newCiscoFake(t, func(w http.ResponseWriter, r *http.Request, n int32) {
		if n == 2 { // the second data call finds the token revoked
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"advisories":[]}`))
	})
	c := f.client()
	for i := 0; i < 2; i++ {
		if _, err := c.Fetch(context.Background(), ciscoIOS, "15.2(7)E3"); err != nil {
			t.Fatal(err)
		}
	}
	// call 1: token 1; call 2: reuses token 1, gets 401, fetches token 2 and retries
	if f.tokens != 2 || f.data != 3 {
		t.Errorf("tokens=%d data=%d, want 2 and 3", f.tokens, f.data)
	}
	if f.lastAuth != "Bearer tok-2" || f.lastPath != "/api/OSType/ios" || f.lastQuery != "15.2(7)E3" {
		t.Errorf("after renewal: %q %q %q", f.lastAuth, f.lastPath, f.lastQuery)
	}
}

func TestCiscoPSIRTSecond401IsAnError(t *testing.T) {
	f := newCiscoFake(t, func(w http.ResponseWriter, r *http.Request, _ int32) { w.WriteHeader(http.StatusUnauthorized) })
	if _, err := f.client().Fetch(context.Background(), ciscoIOS, "15.2(7)E3"); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("err = %v", err)
	}
}

func TestCiscoPSIRTStatusHandling(t *testing.T) {
	f := newCiscoFake(t, func(w http.ResponseWriter, r *http.Request, _ int32) { w.WriteHeader(http.StatusNotFound) })
	recs, err := f.client().Fetch(context.Background(), ciscoIOSXE, "17.6.1")
	if err != nil || len(recs) != 0 {
		t.Errorf("404 means no advisory lists the version: recs=%v err=%v", recs, err)
	}
	f2 := newCiscoFake(t, func(w http.ResponseWriter, r *http.Request, _ int32) { w.WriteHeader(http.StatusBadGateway) })
	if _, err := f2.client().Fetch(context.Background(), ciscoIOSXE, "17.6.1"); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Errorf("err = %v", err)
	}
	f3 := newCiscoFake(t, func(w http.ResponseWriter, r *http.Request, _ int32) { _, _ = w.Write([]byte("{oops")) })
	if _, err := f3.client().Fetch(context.Background(), ciscoIOSXE, "17.6.1"); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("err = %v", err)
	}
}

func TestCiscoPSIRTNeedsCredentialsAndASupportedProduct(t *testing.T) {
	c := &CiscoPSIRT{}
	_, err := c.Fetch(context.Background(), ciscoIOSXE, "17.6.1")
	if !errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), "CISCO_PSIRT_CLIENT_ID") {
		t.Errorf("err = %v", err)
	}
	c.ClientID, c.ClientSecret = "a", "b"
	if _, err := c.Fetch(context.Background(), Product{Vendor: "juniper", Name: "junos"}, "1"); err == nil || errors.Is(err, ErrNotConfigured) {
		t.Errorf("an unsupported product is a plain error: %v", err)
	}
	if c.Name() != "CISCO" || c.Scope() != ScopeVersion {
		t.Error("identity")
	}
	for _, p := range []Product{ciscoIOS, ciscoIOSXE, ciscoASA, ciscoFTD} {
		if !c.Supports(p) {
			t.Errorf("must support %s", p.Name)
		}
	}
	if c.Supports(Product{Vendor: "juniper", Name: "junos"}) || c.Supports(Product{Vendor: "cisco", Name: "sg350"}) {
		t.Error("must not support other products")
	}
}

func TestCiscoPSIRTTokenFailures(t *testing.T) {
	mk := func(h http.HandlerFunc) *CiscoPSIRT {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		return &CiscoPSIRT{BaseURL: srv.URL, TokenURL: srv.URL, ClientID: "a", ClientSecret: "b"}
	}
	if _, err := mk(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }).Fetch(context.Background(), ciscoIOS, "15.2(7)E3"); err == nil || !strings.Contains(err.Error(), "token request: HTTP 401") {
		t.Errorf("err = %v", err)
	}
	if _, err := mk(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"expires_in":1}`)) }).Fetch(context.Background(), ciscoIOS, "15.2(7)E3"); err == nil || !strings.Contains(err.Error(), "no access_token") {
		t.Errorf("err = %v", err)
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	c := &CiscoPSIRT{BaseURL: dead.URL, TokenURL: dead.URL, ClientID: "a", ClientSecret: "b"}
	if _, err := c.Fetch(context.Background(), ciscoIOS, "15.2(7)E3"); err == nil || !strings.Contains(err.Error(), "token request") {
		t.Errorf("err = %v", err)
	}
}

func TestCiscoVersionAndTrainFix(t *testing.T) {
	for _, tc := range []struct {
		p       Product
		in, out string
	}{
		{ciscoIOSXE, "17.06.01", "17.6.1"},
		{ciscoIOSXE, "16.12.4a", "16.12.4a"},
		{ciscoIOSXE, "03.07.04.E", "3.7.4.E"},
		{ciscoIOSXE, "17.00.0", "17.0.0"},
		{ciscoIOS, "15.2(7)E3", "15.2(7)E3"},
		{ciscoASA, "9.16(2)", "9.16.2"},
		{ciscoASA, "9.12(4.47)", "9.12.4.47"}, // interim builds keep the dot inside the parentheses
		{ciscoFTD, " 7.2.4 ", "7.2.4"},
	} {
		if got := ciscoVersion(tc.p, tc.in); got != tc.out {
			t.Errorf("ciscoVersion(%s, %q) = %q, want %q", tc.p.Name, tc.in, got, tc.out)
		}
	}
	fixes := []string{"17.9.4a", "17.6.6a", "", "17.6.7"}
	if got := trainFix(fixes, "17.6.1"); got != "17.6.6a, 17.6.7" {
		t.Errorf("same train: %q", got)
	}
	if got := trainFix(fixes, "16.12.4"); got != "17.9.4a, 17.6.6a, 17.6.7" {
		t.Errorf("no same train lists every fix: %q", got)
	}
	if got := trainFix(nil, "17.6.1"); got != "" {
		t.Errorf("no fixes: %q", got)
	}
	if got := trainFix([]string{"17.6.6a"}, "x"); got != "17.6.6a" {
		t.Errorf("unparseable device version: %q", got)
	}
}

func TestFlexFloat(t *testing.T) {
	var v struct {
		A, B, C, D, E flexFloat
	}
	if err := json.Unmarshal([]byte(`{"A":"9.8","B":7.5,"C":"NA","D":null,"E":""}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.A != 9.8 || v.B != 7.5 || v.C != 0 || v.D != 0 || v.E != 0 {
		t.Errorf("flexFloat = %+v", v)
	}
	var inf struct{ A flexFloat }
	if err := json.Unmarshal([]byte(`{"A":"Infinity"}`), &inf); err != nil || inf.A != 0 {
		t.Errorf("Infinity must read as 0: %v %v", inf, err)
	}
}

// ---- OSV -----------------------------------------------------------------------------

func TestOSVFetchPaginatesAndParses(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		if r.URL.Path != "/v1/query" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if b["page_token"] == nil {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-xxxx-1","aliases":["CVE-2024-1111"],"summary":"Heap overflow in parser","details":"Long details.",
			 "published":"2024-03-01T10:00:00Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			 "references":[{"url":"https://github.com/advisories/GHSA-xxxx-1"}],
			 "affected":[{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}],"next_page_token":"p2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[{"id":"OSV-2024-5","details":"Only details here. Second sentence.","database_specific":{"severity":"MODERATE"}}]}`))
	}))
	defer srv.Close()

	o := &OSV{BaseURL: srv.URL, Packages: map[string]OSVPackage{"o:vyos:vyos": {Name: "vyos-1x", Ecosystem: "GitHub Actions"}}}
	vyos := Product{Part: "o", Vendor: "vyos", Name: "vyos", OS: "vyos"}
	if !o.Supports(vyos) || o.Supports(ciscoIOS) || o.Name() != "OSV" || o.Scope() != ScopeVersion {
		t.Error("identity / support")
	}
	recs, err := o.Fetch(context.Background(), vyos, "1.3.4")
	if err != nil || len(recs) != 2 {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
	pkg := bodies[0]["package"].(map[string]any)
	if bodies[0]["version"] != "1.3.4" || pkg["name"] != "vyos-1x" || pkg["ecosystem"] != "GitHub Actions" || bodies[1]["page_token"] != "p2" {
		t.Errorf("request bodies = %v", bodies)
	}
	a := recs[0]
	if a.ID != "CVE-2024-1111" || a.Source != "OSV" || a.CVSS != 9.8 || a.Severity != SeverityCritical || a.Title != "Heap overflow in parser" ||
		a.URL != "https://github.com/advisories/GHSA-xxxx-1" || a.Published.IsZero() {
		t.Errorf("record 0 = %+v", a.Advisory)
	}
	if a.Affects[0].Fixed != "1.2.3" || a.Affects[0].Version != "1.3.4" || a.Affects[0].Vendor != "vyos" {
		t.Errorf("affects = %+v", a.Affects)
	}
	b := recs[1]
	if b.ID != "OSV-2024-5" || b.Severity != SeverityMedium || b.CVSS != 0 || b.Title != "Only details here." || b.URL != "https://osv.dev/vulnerability/OSV-2024-5" {
		t.Errorf("record 1 = %+v", b.Advisory)
	}
}

func TestOSVErrors(t *testing.T) {
	o := &OSV{Packages: map[string]OSVPackage{"o:vyos:vyos": {Name: "x", Ecosystem: "y"}}}
	vyos := Product{Part: "o", Vendor: "vyos", Name: "vyos"}
	if _, err := o.Fetch(context.Background(), ciscoIOS, "1"); err == nil {
		t.Error("an unmapped product is an error")
	}
	for name, h := range map[string]http.HandlerFunc{
		"http error": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"malformed":  func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{")) },
	} {
		srv := httptest.NewServer(h)
		o.BaseURL = srv.URL
		if _, err := o.Fetch(context.Background(), vyos, "1"); err == nil {
			t.Errorf("%s must fail", name)
		}
		srv.Close()
	}
	if _, err := o.Fetch(context.Background(), vyos, "1"); err == nil || !strings.Contains(err.Error(), "OSV request") {
		t.Errorf("unreachable: %v", err)
	}
}

func TestOSVStopsAServerThatNeverEndsPaging(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"vulns":[],"next_page_token":"again"}`))
	}))
	defer srv.Close()
	o := &OSV{BaseURL: srv.URL, Packages: map[string]OSVPackage{"o:vyos:vyos": {Name: "x", Ecosystem: "y"}}}
	if _, err := o.Fetch(context.Background(), Product{Part: "o", Vendor: "vyos", Name: "vyos"}, "1"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&hits); n != 50 {
		t.Errorf("hits = %d, want the 50-page cap", n)
	}
}

func TestCVSS3Score(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
		ok     bool
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, true}, // CVE-2023-20198
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, true},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, true}, // the classic reflected XSS
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, true}, // scope changed raises the PR weight
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, true},   // no impact
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 0, false},
		{"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0, false},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H", 0, false},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A", 0, false},
		{"CVSS:3.1/AV:N", 0, false},
		{"", 0, false},
	}
	for _, tc := range tests {
		got, ok := cvss3Score(tc.vector)
		if ok != tc.ok || got != tc.want {
			t.Errorf("cvss3Score(%q) = %v, %v; want %v, %v", tc.vector, got, ok, tc.want, tc.ok)
		}
	}
	if roundUp1(4.0) != 4.0 || roundUp1(4.02) != 4.1 || roundUp1(4.000000001) != 4.0 || roundUp1(9.99) != 10.0 {
		t.Errorf("roundUp1: %v %v %v %v", roundUp1(4.0), roundUp1(4.02), roundUp1(4.000000001), roundUp1(9.99))
	}
}

// ---- Merge ---------------------------------------------------------------------------

func TestMergeCombinesSourcesByCVEID(t *testing.T) {
	t1 := time.Date(2023, 10, 16, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2023, 10, 14, 0, 0, 0, 0, time.UTC)
	nvd := []Record{
		{Advisory: Advisory{ID: "CVE-2023-20198", Source: "NVD", Title: "Derived headline.", Description: "short", Severity: SeverityHigh, CVSS: 8.8, Published: t1, URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-20198"},
			Affects: []Affect{{Vendor: "cisco", Product: "ios_xe", EndExcluding: "17.9.4a", Fixed: "17.9.4a"}}},
		{Advisory: Advisory{ID: "CVE-2023-0001", Source: "NVD", Severity: SeverityLow, CVSS: 2.0}},
	}
	cisco := []Record{
		{Advisory: Advisory{ID: "cve-2023-20198", Source: "CISCO", Title: "Cisco IOS XE Web UI Privilege Escalation", Description: "a much longer description from the vendor", Severity: SeverityCritical, CVSS: 10.0, Published: t2, URL: "https://sec.cloudapps.cisco.com/x"},
			Affects: []Affect{{Vendor: "cisco", Product: "ios_xe", Version: "17.6.1", Fixed: "17.6.6a"}, {Vendor: "cisco", Product: "ios_xe", EndExcluding: "17.9.4a", Fixed: "17.9.4a"}}},
		{Advisory: Advisory{ID: "", Source: "CISCO"}}, // no ID: ignored
	}
	osv := []Record{{Advisory: Advisory{ID: "CVE-2023-20198", Source: "OSV", Severity: SeverityHigh, CVSS: 8.8, URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-20198"}}}

	got := Merge(nvd, cisco, osv)
	if len(got) != 2 || got[0].ID != "CVE-2023-0001" || got[1].ID != "CVE-2023-20198" {
		t.Fatalf("merge result = %+v", got)
	}
	m := got[1]
	if m.Source != "NVD+CISCO+OSV" {
		t.Errorf("Source = %q", m.Source)
	}
	if m.CVSS != 10.0 || m.Severity != SeverityCritical {
		t.Errorf("highest CVSS must win: %v %s", m.CVSS, m.Severity)
	}
	if m.Title != "Cisco IOS XE Web UI Privilege Escalation" {
		t.Errorf("a Cisco title replaces NVD's derived headline: %q", m.Title)
	}
	if m.Description != "a much longer description from the vendor" {
		t.Errorf("description = %q", m.Description)
	}
	if !m.Published.Equal(t2) {
		t.Errorf("earliest publication date wins: %v", m.Published)
	}
	if m.URL != "https://nvd.nist.gov/vuln/detail/CVE-2023-20198 https://sec.cloudapps.cisco.com/x" {
		t.Errorf("reference URLs must be merged without duplicates: %q", m.URL)
	}
	if len(m.Affects) != 2 {
		t.Errorf("affects must be united without duplicates: %+v", m.Affects)
	}
	// inputs are not mutated
	if len(nvd[0].Affects) != 1 || nvd[0].Source != "NVD" {
		t.Errorf("Merge modified its input: %+v", nvd[0])
	}
}

func TestMergeTieBreaksAndGaps(t *testing.T) {
	a := Record{Advisory: Advisory{ID: "CVE-1", Source: "NVD", Severity: SeverityUnknown}}
	b := Record{Advisory: Advisory{ID: "CVE-1", Source: "OSV", Severity: SeverityMedium, Title: "from osv"}}
	m := Merge([]Record{a}, []Record{b})[0]
	if m.Severity != SeverityMedium || m.Title != "from osv" {
		t.Errorf("equal scores keep the more severe rating and fill missing titles: %+v", m.Advisory)
	}
	// a later source never replaces an existing non-Cisco title
	c := Record{Advisory: Advisory{ID: "CVE-1", Source: "OSV", Title: "other"}}
	if got := Merge([]Record{b}, []Record{c})[0].Title; got != "from osv" {
		t.Errorf("title = %q", got)
	}
	if len(Merge()) != 0 || len(Merge(nil, nil)) != 0 {
		t.Error("nothing in, nothing out")
	}
	if got := joinSources("CACHE", "NVD"); got != "NVD+CACHE" {
		t.Errorf("sources are ordered NVD, CISCO, OSV, CACHE: %q", got)
	}
	if got := joinSources("ZED", "NVD+ZED"); got != "NVD+ZED" {
		t.Errorf("unknown sources sort last: %q", got)
	}
	if got := joinURLs("", ""); got != "" {
		t.Errorf("joinURLs = %q", got)
	}
}

func TestMergeIsOrderIndependentForTheScore(t *testing.T) {
	mk := func(src string, cvss float64, sev Severity) Record {
		return Record{Advisory: Advisory{ID: "CVE-1", Source: src, CVSS: cvss, Severity: sev}}
	}
	x := Merge([]Record{mk("NVD", 5, SeverityMedium)}, []Record{mk("CISCO", 9, SeverityCritical)})[0]
	y := Merge([]Record{mk("CISCO", 9, SeverityCritical)}, []Record{mk("NVD", 5, SeverityMedium)})[0]
	if x.CVSS != y.CVSS || x.Severity != y.Severity || x.Source != y.Source {
		t.Errorf("order matters: %+v vs %+v", x.Advisory, y.Advisory)
	}
}

// ---- fault injection, defaults and the remaining branches ---------------------------------

// rtFunc is an http.RoundTripper made of a function.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("connection reset by peer") }
func (errBody) Close() error             { return nil }

func respond(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestSourcesUseTheirDocumentedDefaultEndpoints(t *testing.T) {
	var urls []string
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		urls = append(urls, r.Method+" "+r.URL.Scheme+"://"+r.URL.Host+r.URL.Path)
		if strings.Contains(r.URL.Host, "id.cisco.com") {
			return respond(200, `{"access_token":"t","expires_in":3600}`), nil
		}
		if strings.Contains(r.URL.Host, "nvd.nist.gov") {
			return respond(200, nvdPage), nil
		}
		return respond(200, `{"advisories":[],"vulns":[]}`), nil
	})}
	ctx := context.Background()
	if _, err := (&NVD{Client: client}).Fetch(ctx, ciscoIOSXE, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := (&CiscoPSIRT{Client: client, ClientID: "a", ClientSecret: "b"}).Fetch(ctx, ciscoIOSXE, "17.6.1"); err != nil {
		t.Fatal(err)
	}
	o := &OSV{Client: client, Packages: map[string]OSVPackage{ciscoIOSXE.Key(): {Name: "n", Ecosystem: "e"}}}
	if _, err := o.Fetch(ctx, ciscoIOSXE, "17.6.1"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET https://services.nvd.nist.gov/rest/json/cves/2.0",
		"POST https://id.cisco.com/oauth2/default/v1/token",
		"GET https://apix.cisco.com/security/advisories/v2/OSType/iosxe",
		"POST https://api.osv.dev/v1/query",
	}
	if strings.Join(urls, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n%s\nwant:\n%s", strings.Join(urls, "\n"), strings.Join(want, "\n"))
	}
}

func TestSourcesReportBodyReadFailures(t *testing.T) {
	broken := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: errBody{}}, nil
	})}
	ctx := context.Background()
	if _, err := (&NVD{Client: broken}).Fetch(ctx, ciscoIOSXE, ""); err == nil || !strings.Contains(err.Error(), "NVD: reading response") {
		t.Errorf("NVD: %v", err)
	}
	// a broken token body and a broken data body
	if _, err := (&CiscoPSIRT{Client: broken, ClientID: "a", ClientSecret: "b"}).Fetch(ctx, ciscoIOSXE, "17.6.1"); err == nil || !strings.Contains(err.Error(), "token response") {
		t.Errorf("Cisco token: %v", err)
	}
	dataBroken := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return respond(200, `{"access_token":"t","expires_in":3600}`), nil
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: errBody{}}, nil
	})}
	if _, err := (&CiscoPSIRT{Client: dataBroken, ClientID: "a", ClientSecret: "b"}).Fetch(ctx, ciscoIOSXE, "17.6.1"); err == nil || !strings.Contains(err.Error(), "Cisco PSIRT: reading response") {
		t.Errorf("Cisco data: %v", err)
	}
	o := &OSV{Client: broken, Packages: map[string]OSVPackage{ciscoIOSXE.Key(): {Name: "n", Ecosystem: "e"}}}
	if _, err := o.Fetch(ctx, ciscoIOSXE, "1"); err == nil || !strings.Contains(err.Error(), "OSV: reading response") {
		t.Errorf("OSV: %v", err)
	}
}

func TestSourcesRefuseAbsurdlyLargeResponses(t *testing.T) {
	old := maxResponseBytes
	maxResponseBytes = 1024
	defer func() { maxResponseBytes = old }()
	var hits int32
	srv := oneJSON(t, `{"totalResults":1,"vulnerabilities":[],"pad":"`+strings.Repeat("x", 4096)+`"}`, &hits)
	_, err := fastNVD(srv.URL).Fetch(context.Background(), ciscoIOSXE, "")
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
}

func TestSourcesRejectInvalidURLs(t *testing.T) {
	ctx := context.Background()
	c := &CiscoPSIRT{BaseURL: "http://bad host/", TokenURL: "http://bad host/", ClientID: "a", ClientSecret: "b"}
	if _, err := c.Fetch(ctx, ciscoIOSXE, "17.6.1"); err == nil {
		t.Error("Cisco with an invalid token URL must fail")
	}
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	defer good.Close()
	c2 := &CiscoPSIRT{BaseURL: "http://bad host/", TokenURL: good.URL, ClientID: "a", ClientSecret: "b"}
	if _, err := c2.Fetch(ctx, ciscoIOSXE, "17.6.1"); err == nil {
		t.Error("Cisco with an invalid base URL must fail")
	}
	o := &OSV{BaseURL: "http://bad host/", Packages: map[string]OSVPackage{ciscoIOSXE.Key(): {Name: "n", Ecosystem: "e"}}}
	if _, err := o.Fetch(ctx, ciscoIOSXE, "1"); err == nil {
		t.Error("OSV with an invalid URL must fail")
	}
}

func TestCiscoRequestFailureAfterAToken(t *testing.T) {
	var tokenHits int32
	c := &CiscoPSIRT{ClientID: "a", ClientSecret: "b", Client: &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(&tokenHits, 1)
			return respond(200, `{"access_token":"t","expires_in":3600}`), nil
		}
		return nil, errors.New("network is unreachable")
	})}}
	if _, err := c.Fetch(context.Background(), ciscoIOSXE, "17.6.1"); err == nil || !strings.Contains(err.Error(), "Cisco PSIRT request") {
		t.Errorf("err = %v", err)
	}
}

func TestNVDDropsNegatedNodesAndRejectTextEvenWithoutARejectedStatus(t *testing.T) {
	page := `{"totalResults":3,"vulnerabilities":[
	 {"cve":{"id":"CVE-A","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"** REJECT ** duplicate of CVE-B"}],
	   "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*"}]}]}]}},
	 {"cve":{"id":"CVE-B","descriptions":[{"lang":"fr","value":"seulement en français"}],
	   "configurations":[{"nodes":[{"negate":true,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:cisco:ios_xe:1.0:*:*:*:*:*:*:*"}]},
	                               {"negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:cisco:ios_xe:2.0:*:*:*:*:*:*:*"}]}]}]}},
	 {"cve":{"id":"","descriptions":[],"configurations":[]}}]}`
	var hits int32
	srv := oneJSON(t, page, &hits)
	recs, err := fastNVD(srv.URL).Fetch(context.Background(), ciscoIOSXE, "")
	if err != nil || len(recs) != 1 {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
	r := recs[0]
	if r.ID != "CVE-B" || len(r.Affects) != 1 || r.Affects[0].Version != "2.0" {
		t.Errorf("a negated node must not contribute: %+v", r)
	}
	if r.Description != "seulement en français" {
		t.Errorf("without an English text the first one is used: %q", r.Description)
	}
}

func TestCiscoSeverityFallsBackToTheScore(t *testing.T) {
	f := newCiscoFake(t, func(w http.ResponseWriter, r *http.Request, _ int32) {
		_, _ = w.Write([]byte(`{"advisories":[{"advisoryId":"cisco-sa-x","cves":["CVE-2024-1"],"cvssBaseScore":8.6,"sir":"","firstFixed":["17.6.7"]}]}`))
	})
	recs, err := f.client().Fetch(context.Background(), ciscoIOSXE, "17.6.1")
	if err != nil || len(recs) != 1 || recs[0].Severity != SeverityHigh || recs[0].CVSS != 8.6 {
		t.Errorf("recs=%+v err=%v (a numeric cvssBaseScore must work too)", recs, err)
	}
}

func TestOSVWithoutAnySeverityIsUnknown(t *testing.T) {
	rec := osvRecord(osvVuln{ID: "OSV-1", Details: "x"}, Product{Vendor: "v", Name: "n"}, "1.0")
	if rec.Severity != SeverityUnknown || rec.CVSS != 0 {
		t.Errorf("record = %+v", rec.Advisory)
	}
	// an unparseable vector falls back to the database's rating
	rec = osvRecord(osvVuln{ID: "OSV-2", Severity: []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N"}}, DatabaseSpecific: struct {
		Severity string `json:"severity"`
	}{Severity: "HIGH"}}, Product{Vendor: "v", Name: "n"}, "1.0")
	if rec.Severity != SeverityHigh || rec.CVSS != 0 {
		t.Errorf("record = %+v", rec.Advisory)
	}
}

func TestMatchBreaksScoreTiesBySeverity(t *testing.T) {
	all := Affect{Vendor: "cisco", Product: "ios_xe"}
	got := Match([]Record{
		rec("CVE-1", 0, SeverityUnknown, all),
		rec("CVE-2", 0, SeverityHigh, all), // same (zero) score, rated by the vendor
	}, ciscoIOSXE, "17.6.1")
	if got[0].ID != "CVE-2" {
		t.Errorf("order = %s, %s; a rated advisory outranks an unrated one at equal score", got[0].ID, got[1].ID)
	}
}

func TestCheckSkipsSourcesThatDoNotCoverTheProduct(t *testing.T) {
	nvd := nvdFake([]Record{{Advisory: Advisory{ID: "CVE-1", Source: "NVD", CVSS: 5, Severity: SeverityMedium}, Affects: []Affect{{Vendor: "juniper", Product: "junos"}}}})
	ciscoOnly := &fakeSource{name: "CISCO", scope: ScopeVersion, only: func(p Product) bool { return p.Vendor == "cisco" }}
	c := &Checker{Sources: []Source{nvd, ciscoOnly}, Cache: newCache(t)}
	res := c.Check(context.Background(), Target{OS: "junos", Version: "21.2R3"})
	if res.Error != "" || len(res.Advisories) != 1 || ciscoOnly.callCount() != 0 {
		t.Errorf("result=%+v cisco calls=%d", res, ciscoOnly.callCount())
	}
}

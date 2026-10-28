// ==============================================================================
// File name:     cache_test.go
// Description:   Tests of the offline cache file and of the Checker's online,
//                fallback and offline behaviour.
// License:       MIT
// ==============================================================================

package cve

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func sampleRecords() []Record {
	return []Record{
		{Advisory: Advisory{ID: "CVE-2023-20198", Source: "NVD", Title: "t", Description: "d", Severity: SeverityCritical, CVSS: 10, Published: t0, URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-20198"},
			Affects: []Affect{{Vendor: "cisco", Product: "ios_xe", StartIncluding: "17.6.0", EndExcluding: "17.6.6a", Fixed: "17.6.6a"}}},
	}
}

// ---- Cache file ------------------------------------------------------------------------

func TestCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".cve_cache.json.gz")
	c, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Exists() || c.Dirty() || c.Path() != path {
		t.Fatalf("a missing file opens as an empty cache: exists=%v dirty=%v", c.Exists(), c.Dirty())
	}
	if _, ok := c.Get("NVD", "o:cisco:ios_xe"); ok {
		t.Error("empty cache has no entries")
	}
	c.Put("NVD", "o:cisco:ios_xe", Entry{Updated: t0, Records: sampleRecords()})
	c.Put("CISCO", "o:cisco:ios_xe@17.6.1", Entry{Updated: t0.Add(time.Hour)})
	if !c.Dirty() {
		t.Error("Put must mark the cache dirty")
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if c.Dirty() || !c.Exists() {
		t.Errorf("after Save: dirty=%v exists=%v", c.Dirty(), c.Exists())
	}

	// the file really is gzip-compressed JSON
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Fatalf("not a gzip file: %v", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.NewDecoder(zr).Decode(&doc); err != nil || doc["format"] != float64(1) {
		t.Fatalf("document = %v, err %v", doc, err)
	}

	c2, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c2.Exists() {
		t.Error("Exists after reopening")
	}
	e, ok := c2.Get("NVD", "o:cisco:ios_xe")
	if !ok || !e.Updated.Equal(t0) || len(e.Records) != 1 {
		t.Fatalf("entry = %+v ok=%v", e, ok)
	}
	got := e.Records[0]
	if got.ID != "CVE-2023-20198" || got.CVSS != 10 || got.Severity != SeverityCritical || !got.Published.Equal(t0) ||
		len(got.Affects) != 1 || got.Affects[0].Fixed != "17.6.6a" || got.Affects[0].StartIncluding != "17.6.0" {
		t.Errorf("record did not survive the round trip: %+v", got)
	}
	scopes, records, newest := c2.Stats()
	if scopes != 2 || records != 1 || !newest.Equal(t0.Add(time.Hour)) {
		t.Errorf("Stats = %d %d %v", scopes, records, newest)
	}
}

func TestCacheSaveIsANoOpWhenNothingChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.gz")
	c, _ := OpenCache(path)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Save of an untouched cache must not create a file (err=%v)", err)
	}
}

func TestCacheSaveIsAtomicAndLeavesNoTemporaryFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir") // does not exist yet
	path := filepath.Join(dir, ".cve_cache.json.gz")
	c, _ := OpenCache(path)
	c.Put("NVD", "k", Entry{Updated: t0})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	// overwrite an existing cache
	c.Put("NVD", "k2", Entry{Updated: t0})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != ".cve_cache.json.gz" {
		t.Errorf("directory holds %v, want only the cache file", ents)
	}
	c2, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c2.Get("NVD", "k2"); !ok {
		t.Error("the second save was lost")
	}
}

func TestCacheSaveFailureKeepsTheOldFileAndReportsIt(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "afile")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCache(filepath.Join(blocker, "sub", "c.gz")); err == nil {
		t.Error("opening a path below a regular file is an error (ENOTDIR), not an empty cache")
	}
	c, _ := OpenCache(filepath.Join(dir, "ok.gz"))
	c.path = filepath.Join(blocker, "sub", "c.gz") // a directory cannot be created below a file
	c.Put("NVD", "k", Entry{})
	if err := c.Save(); err == nil || !strings.Contains(err.Error(), "cache directory") {
		t.Errorf("err = %v", err)
	}
	if !c.Dirty() {
		t.Error("a failed save must leave the cache dirty so it can be retried")
	}

	// the destination is a directory: rename fails, the temp file is cleaned up
	target := filepath.Join(dir, "isadir")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, _ := OpenCache(filepath.Join(dir, "other.gz"))
	c2.path = target
	c2.Put("NVD", "k", Entry{})
	if err := c2.Save(); err == nil {
		t.Error("renaming over a non-empty directory must fail")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestOpenCacheRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gz := func(s string) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		_, _ = w.Write([]byte(s))
		_ = w.Close()
		return b.Bytes()
	}
	good := gz(`{"format":1,"sources":{}}`)

	tests := []struct {
		name    string
		path    string
		wantSub string
	}{
		{"empty path", "", "path is empty"},
		{"plain text", write("plain", []byte("hello")), "not a gzip file"},
		{"empty file", write("empty", nil), "not a gzip file"},
		{"truncated gzip", write("trunc", good[:len(good)-6]), "read cache"},
		{"corrupt checksum", write("crc", func() []byte { b := append([]byte(nil), good...); b[len(b)-5] ^= 0xff; return b }()), "read cache"},
		{"bad json", write("badjson", gz("{nope")), "read cache"},
		{"future format", write("future", gz(`{"format":99,"sources":{}}`)), "format 99"},
		{"missing format", write("noformat", gz(`{"sources":{}}`)), "format 0"},
		{"a directory", dir, "read cache"},
	}
	for _, tc := range tests {
		c, err := OpenCache(tc.path)
		if err == nil || c != nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: cache=%v err=%v, want an error containing %q", tc.name, c, err, tc.wantSub)
		}
	}

	// a cache without a "sources" key is valid and empty
	c, err := OpenCache(write("nosources", gz(`{"format":1}`)))
	if err != nil {
		t.Fatal(err)
	}
	c.Put("NVD", "k", Entry{}) // must not panic on a nil map
	if !c.Exists() {
		t.Error("exists")
	}
}

func TestNewCacheReplacesABadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.gz")
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCache(path); err == nil {
		t.Fatal("the garbage must be rejected")
	}
	c := NewCache(path)
	if c.Exists() || c.Dirty() || c.Path() != path {
		t.Errorf("NewCache must be empty: exists=%v dirty=%v", c.Exists(), c.Dirty())
	}
	c.Put("NVD", "k", Entry{Updated: t0})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if c2, err := OpenCache(path); err != nil || !c2.Exists() {
		t.Errorf("the replacement must be a valid cache: %v", err)
	}
}

func TestOpenCacheUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	p := filepath.Join(t.TempDir(), "locked.gz")
	if err := os.WriteFile(p, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCache(p); err == nil || !strings.Contains(err.Error(), "open cache") {
		t.Errorf("err = %v", err)
	}
}

func TestCacheIsSafeForConcurrentUse(t *testing.T) {
	c, _ := OpenCache(filepath.Join(t.TempDir(), "c.gz"))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := string(rune('a' + i%5))
			c.Put("NVD", key, Entry{Updated: t0})
			c.Get("NVD", key)
			c.Stats()
			c.Dirty()
		}(i)
	}
	wg.Wait()
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
}

// ---- Checker ----------------------------------------------------------------------------

// fakeSource is a controllable Source.
type fakeSource struct {
	name  string
	scope Scope
	only  func(Product) bool // nil: supports everything
	mu    sync.Mutex
	recs  []Record
	err   error
	calls []string // "product@version" per Fetch
	block chan struct{}
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Scope() Scope { return f.scope }
func (f *fakeSource) Supports(p Product) bool {
	return f.only == nil || f.only(p)
}
func (f *fakeSource) Fetch(ctx context.Context, p Product, version string) ([]Record, error) {
	f.mu.Lock()
	f.calls = append(f.calls, p.Name+"@"+version)
	recs, err := f.recs, f.err
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return recs, err
}
func (f *fakeSource) set(recs []Record, err error) {
	f.mu.Lock()
	f.recs, f.err = recs, err
	f.mu.Unlock()
}
func (f *fakeSource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func nvdFake(recs []Record) *fakeSource {
	return &fakeSource{name: "NVD", scope: ScopeProduct, recs: recs}
}

type warnings struct {
	mu   sync.Mutex
	list []string
}

func (w *warnings) add(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.list = append(w.list, strings.TrimSpace(strings.Join(strings.Fields(fmt.Sprintf(format, args...)), " ")))
}
func (w *warnings) joined() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Join(w.list, "\n")
}

func newCache(t *testing.T) *Cache {
	t.Helper()
	c, err := OpenCache(filepath.Join(t.TempDir(), "c.gz"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var xeTarget = Target{Hostname: "r1", IP: "10.0.0.1", OS: "cisco", Version: "17.06.01"}

func TestCheckOnlineMatchesAndFillsTheCache(t *testing.T) {
	src := nvdFake(sampleRecords())
	cache := newCache(t)
	c := &Checker{Sources: []Source{src}, Cache: cache, Now: func() time.Time { return t0 }}
	res := c.Check(context.Background(), xeTarget)
	if res.Error != "" || len(res.Advisories) != 1 {
		t.Fatalf("result = %+v", res)
	}
	a := res.Advisories[0]
	if a.ID != "CVE-2023-20198" || a.Source != "NVD" || a.FixedVer != "17.6.6a" || a.AffectedVer != ">=17.6.0, <17.6.6a" {
		t.Errorf("advisory = %+v", a)
	}
	if res.Hostname != "r1" || res.IP != "10.0.0.1" || res.Vendor != "cisco" || res.OS != "cisco-ios-xe" || res.Version != "17.06.01" {
		t.Errorf("identity fields = %+v", res)
	}
	e, ok := cache.Get("NVD", "o:cisco:ios_xe")
	if !ok || !e.Updated.Equal(t0) || len(e.Records) != 1 {
		t.Errorf("a successful fetch must be cached with a timestamp: %+v ok=%v", e, ok)
	}
	if !cache.Dirty() {
		t.Error("the cache must be marked for saving")
	}
}

func TestCheckAsksEachScopeOnlyOnce(t *testing.T) {
	nvd := nvdFake(sampleRecords())
	ver := &fakeSource{name: "CISCO", scope: ScopeVersion}
	c := &Checker{Sources: []Source{nvd, ver}, Cache: newCache(t)}
	for _, v := range []string{"17.06.01", "17.6.1", " 17.6.1 ", "17.9.4", "16.12.4a"} {
		c.Check(context.Background(), Target{OS: "cisco", Version: v})
	}
	if nvd.callCount() != 1 {
		t.Errorf("NVD is product-scoped: %d fetches for 5 devices, want 1", nvd.callCount())
	}
	if ver.callCount() != 3 {
		t.Errorf("a version-scoped source is asked once per distinct version (17.6.1, 17.9.4, 16.12.4a), got %v", ver.calls)
	}
}

func TestCheckFallsBackToTheCacheWhenTheSourceFails(t *testing.T) {
	cache := newCache(t)
	prime := &Checker{Sources: []Source{nvdFake(sampleRecords())}, Cache: cache, Now: func() time.Time { return t0 }}
	prime.Check(context.Background(), xeTarget)

	down := nvdFake(nil)
	down.set(nil, errors.New("NVD request: dial tcp: connection refused"))
	var w warnings
	c := &Checker{Sources: []Source{down}, Cache: cache, Warnf: w.add, Now: func() time.Time { return t0.Add(time.Hour) }}
	res := c.Check(context.Background(), xeTarget)
	if res.Error != "" || len(res.Advisories) != 1 {
		t.Fatalf("a network failure must fall back to the cache without failing: %+v", res)
	}
	if res.Advisories[0].Source != "CACHE" {
		t.Errorf("Source = %q, want CACHE", res.Advisories[0].Source)
	}
	if !strings.Contains(w.joined(), "connection refused") || !strings.Contains(w.joined(), "using cached data from 2026-10-27") {
		t.Errorf("the fallback must be announced with its cause: %q", w.joined())
	}
}

func TestCheckFallbackWorksForAnyVersionOfACachedProduct(t *testing.T) {
	// The point of caching ranges instead of per-version answers.
	cache := newCache(t)
	(&Checker{Sources: []Source{nvdFake(sampleRecords())}, Cache: cache}).Check(context.Background(), Target{OS: "cisco", Version: "17.9.9"})
	off := &Checker{Sources: []Source{nvdFake(nil)}, Cache: cache, Offline: true}
	res := off.Check(context.Background(), Target{OS: "cisco", Version: "17.6.2"}) // never queried before
	if res.Error != "" || len(res.Advisories) != 1 {
		t.Errorf("offline evaluation of a never-seen version failed: %+v", res)
	}
}

func TestCheckOfflineNeverCallsASource(t *testing.T) {
	cache := newCache(t)
	cache.Put("NVD", "o:cisco:ios_xe", Entry{Updated: t0, Records: sampleRecords()})
	src := nvdFake(nil)
	src.set(nil, errors.New("must not be called"))
	c := &Checker{Sources: []Source{src}, Cache: cache, Offline: true, Now: func() time.Time { return t0 }}
	res := c.Check(context.Background(), xeTarget)
	if src.callCount() != 0 {
		t.Fatalf("offline mode made %d fetches", src.callCount())
	}
	if res.Error != "" || len(res.Advisories) != 1 || res.Advisories[0].Source != "CACHE" {
		t.Errorf("result = %+v", res)
	}
}

func TestCheckNoDataIsAnErrorNeverClean(t *testing.T) {
	// offline with an empty cache
	cache := newCache(t)
	off := &Checker{Sources: []Source{nvdFake(nil)}, Cache: cache, Offline: true}
	res := off.Check(context.Background(), xeTarget)
	if res.Error == "" || !strings.Contains(res.Error, "netops cve -update-db") || !strings.Contains(res.Error, cache.Path()) || len(res.Advisories) != 0 {
		t.Errorf("offline without data: %+v", res)
	}
	if res.Advisories == nil {
		t.Error("Advisories must be an empty slice (JSON []), not nil")
	}

	// online, source down, nothing cached: the cause is reported
	down := nvdFake(nil)
	down.set(nil, errors.New("NVD: HTTP 503"))
	on := &Checker{Sources: []Source{down}, Cache: newCache(t)}
	res = on.Check(context.Background(), xeTarget)
	if !strings.Contains(res.Error, "nothing is cached") || !strings.Contains(res.Error, "HTTP 503") {
		t.Errorf("online without data: %+v", res)
	}

	// no cache object at all
	if res := (&Checker{Sources: []Source{down}}).Check(context.Background(), xeTarget); res.Error == "" {
		t.Error("no cache and a failing source must be an error")
	}
	if res := (&Checker{Sources: []Source{down}, Offline: true}).Check(context.Background(), xeTarget); !strings.Contains(res.Error, "needs a cache file") {
		t.Errorf("offline without a cache object: %q", res.Error)
	}
	// no NVD source configured at all
	other := &fakeSource{name: "OSV", scope: ScopeVersion}
	if res := (&Checker{Sources: []Source{other}}).Check(context.Background(), xeTarget); !strings.Contains(res.Error, "no NVD source") {
		t.Errorf("no baseline source: %q", res.Error)
	}
}

func TestCheckAnOptionalSourceFailingDoesNotHideTheBaseline(t *testing.T) {
	nvd := nvdFake(sampleRecords())
	cisco := &fakeSource{name: "CISCO", scope: ScopeVersion, err: errors.New("Cisco PSIRT: HTTP 502")}
	var w warnings
	c := &Checker{Sources: []Source{nvd, cisco}, Cache: newCache(t), Warnf: w.add}
	res := c.Check(context.Background(), xeTarget)
	if res.Error != "" || len(res.Advisories) != 1 {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(w.joined(), "HTTP 502") || !strings.Contains(w.joined(), "continuing without it") {
		t.Errorf("the failure must be visible: %q", w.joined())
	}
	// asking again does not repeat the warning
	c.Check(context.Background(), xeTarget)
	if strings.Count(w.joined(), "HTTP 502") != 1 {
		t.Errorf("warned more than once: %q", w.joined())
	}
}

func TestCheckASourceThatIsNotConfiguredIsSkippedSilently(t *testing.T) {
	nvd := nvdFake(sampleRecords())
	cisco := &fakeSource{name: "CISCO", scope: ScopeVersion, err: ErrNotConfigured}
	var w warnings
	c := &Checker{Sources: []Source{nvd, cisco}, Cache: newCache(t), Warnf: w.add}
	if res := c.Check(context.Background(), xeTarget); res.Error != "" || len(res.Advisories) != 1 {
		t.Fatalf("result = %+v", res)
	}
	if w.joined() != "" {
		t.Errorf("an unconfigured optional source is not worth a warning: %q", w.joined())
	}
}

func TestCheckMergesBaselineAndVendorAdvisories(t *testing.T) {
	nvd := nvdFake(sampleRecords())
	cisco := &fakeSource{name: "CISCO", scope: ScopeVersion, recs: []Record{
		{Advisory: Advisory{ID: "CVE-2023-20198", Source: "CISCO", Title: "Cisco IOS XE Web UI", Severity: SeverityCritical, CVSS: 10, URL: "https://sec.cloudapps.cisco.com/x"},
			Affects: []Affect{{Vendor: "cisco", Product: "ios_xe", Version: "17.06.01", Fixed: "17.6.6a"}}},
		{Advisory: Advisory{ID: "CVE-2099-0001", Source: "CISCO", Title: "Not yet in NVD", Severity: SeverityHigh, CVSS: 8.1},
			Affects: []Affect{{Vendor: "cisco", Product: "ios_xe", Version: "17.06.01", Fixed: "17.6.7"}}},
	}}
	c := &Checker{Sources: []Source{nvd, cisco}, Cache: newCache(t)}
	res := c.Check(context.Background(), xeTarget)
	if len(res.Advisories) != 2 {
		t.Fatalf("want the NVD CVE and the Cisco-only early disclosure: %+v", res.Advisories)
	}
	if res.Advisories[0].ID != "CVE-2023-20198" || res.Advisories[0].Source != "NVD+CISCO" || res.Advisories[1].ID != "CVE-2099-0001" || res.Advisories[1].Source != "CISCO" {
		t.Errorf("advisories = %+v", res.Advisories)
	}
}

func TestCheckVersionScopedCacheIsOnlyValidForItsVersion(t *testing.T) {
	cache := newCache(t)
	nvd := nvdFake([]Record{{Advisory: Advisory{ID: "CVE-0", Source: "NVD"}, Affects: []Affect{{Vendor: "cisco", Product: "ios_xe", Version: "1.0"}}}})
	cisco := &fakeSource{name: "CISCO", scope: ScopeVersion, recs: []Record{
		{Advisory: Advisory{ID: "CVE-2099-0001", Source: "CISCO", Severity: SeverityHigh, CVSS: 8},
			Affects: []Affect{{Vendor: "cisco", Product: "ios_xe", Version: "17.6.1"}}},
	}}
	(&Checker{Sources: []Source{nvd, cisco}, Cache: cache}).Check(context.Background(), Target{OS: "cisco", Version: "17.6.1"})

	off := &Checker{Sources: []Source{nvd, cisco}, Cache: cache, Offline: true}
	if res := off.Check(context.Background(), Target{OS: "cisco", Version: "17.06.01"}); len(res.Advisories) != 1 || res.Advisories[0].ID != "CVE-2099-0001" {
		t.Errorf("same version, other spelling: %+v", res)
	}
	if res := off.Check(context.Background(), Target{OS: "cisco", Version: "17.6.2"}); res.Error != "" || len(res.Advisories) != 0 {
		t.Errorf("another version has no Cisco cache entry: that is silently fine for an optional source: %+v", res)
	}
}

func TestCheckWarnsAboutStaleCaches(t *testing.T) {
	cache := newCache(t)
	cache.Put("NVD", "o:cisco:ios_xe", Entry{Updated: t0, Records: sampleRecords()})
	var w warnings
	c := &Checker{Sources: []Source{nvdFake(nil)}, Cache: cache, Offline: true, Warnf: w.add, Now: func() time.Time { return t0.Add(10 * 24 * time.Hour) }}
	c.Check(context.Background(), xeTarget)
	if !strings.Contains(w.joined(), "10 day(s) old") || !strings.Contains(w.joined(), "-update-db") {
		t.Errorf("stale warning missing: %q", w.joined())
	}

	var w2 warnings
	c2 := &Checker{Sources: []Source{nvdFake(nil)}, Cache: cache, Offline: true, Warnf: w2.add, StaleAfter: 30 * 24 * time.Hour, Now: func() time.Time { return t0.Add(10 * 24 * time.Hour) }}
	c2.Check(context.Background(), xeTarget)
	if w2.joined() != "" {
		t.Errorf("not stale under a 30 day limit: %q", w2.joined())
	}
}

func TestCheckAbortedRunDoesNotFallBackToStaleData(t *testing.T) {
	cache := newCache(t)
	cache.Put("NVD", "o:cisco:ios_xe", Entry{Updated: t0, Records: sampleRecords()})
	src := nvdFake(sampleRecords())
	src.block = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	res := (&Checker{Sources: []Source{src}, Cache: cache}).Check(ctx, xeTarget)
	if res.Error == "" || len(res.Advisories) != 0 {
		t.Errorf("Ctrl-C must not be answered with cached data: %+v", res)
	}
}

func TestCheckRejectsWhatCannotBeEvaluated(t *testing.T) {
	c := &Checker{Sources: []Source{nvdFake(sampleRecords())}, Cache: newCache(t)}
	for name, tc := range map[string]struct {
		t       Target
		wantSub string
	}{
		"no version":  {Target{Hostname: "h", OS: "cisco"}, "no software version"},
		"blank":       {Target{Hostname: "h", OS: "cisco", Version: "  "}, "no software version"},
		"unknown os":  {Target{Hostname: "h", OS: "plan9", Version: "1.0"}, "unknown OS/platform"},
		"unsupported": {Target{Hostname: "h", OS: "cisco_sb", Version: "3.1.1.7"}, "no CVE product mapping"},
	} {
		res := c.Check(context.Background(), tc.t)
		if !strings.Contains(res.Error, tc.wantSub) || res.Advisories == nil || len(res.Advisories) != 0 || res.Hostname != "h" {
			t.Errorf("%s: %+v", name, res)
		}
	}
}

func TestCheckWorksWithoutACache(t *testing.T) {
	res := (&Checker{Sources: []Source{nvdFake(sampleRecords())}}).Check(context.Background(), xeTarget)
	if res.Error != "" || len(res.Advisories) != 1 {
		t.Errorf("result = %+v", res)
	}
}

func TestCheckIsSafeForConcurrentUse(t *testing.T) {
	nvd := nvdFake(sampleRecords())
	c := &Checker{Sources: []Source{nvd}, Cache: newCache(t)}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res := c.Check(context.Background(), xeTarget); len(res.Advisories) != 1 {
				t.Errorf("result = %+v", res)
			}
		}()
	}
	wg.Wait()
	if nvd.callCount() != 1 {
		t.Errorf("fetches = %d, want 1", nvd.callCount())
	}
}

// ---- Refresh -----------------------------------------------------------------------------

func TestRefreshStoresEveryScope(t *testing.T) {
	nvd := nvdFake(sampleRecords())
	cisco := &fakeSource{name: "CISCO", scope: ScopeVersion, only: func(p Product) bool { return p.Vendor == "cisco" }, recs: sampleRecords()}
	osv := &fakeSource{name: "OSV", scope: ScopeVersion, only: func(Product) bool { return false }}
	cache := newCache(t)
	c := &Checker{Sources: []Source{osv, cisco, nvd}, Cache: cache, Now: func() time.Time { return t0 }}

	res := c.Refresh(context.Background(), ciscoIOSXE, []string{"17.06.01", "17.6.1", "", "17.9.4"})
	var got []string
	for _, r := range res {
		if r.Err != nil || r.Skipped != "" {
			t.Errorf("unexpected: %+v", r)
		}
		got = append(got, r.Source+" "+r.Scope)
	}
	want := "NVD o:cisco:ios_xe,CISCO o:cisco:ios_xe@17.6.1,CISCO o:cisco:ios_xe@17.9.4"
	if strings.Join(got, ",") != want {
		t.Errorf("refreshed %v, want %s (NVD first, versions de-duplicated, OSV unsupported)", got, want)
	}
	if res[0].CVEs != 1 {
		t.Errorf("CVEs = %d", res[0].CVEs)
	}
	if _, ok := cache.Get("CISCO", "o:cisco:ios_xe@17.9.4"); !ok {
		t.Error("version-scoped entries must be stored")
	}
	if e, _ := cache.Get("NVD", "o:cisco:ios_xe"); !e.Updated.Equal(t0) {
		t.Errorf("timestamp = %v", e.Updated)
	}
}

func TestRefreshReportsSkipsAndFailuresAndKeepsOldData(t *testing.T) {
	cache := newCache(t)
	cache.Put("NVD", "o:cisco:ios_xe", Entry{Updated: t0, Records: sampleRecords()})
	nvd := nvdFake(nil)
	nvd.set(nil, errors.New("NVD: HTTP 503"))
	cisco := &fakeSource{name: "CISCO", scope: ScopeVersion, err: ErrNotConfigured}
	osv := &fakeSource{name: "OSV", scope: ScopeVersion}
	c := &Checker{Sources: []Source{nvd, cisco, osv}, Cache: cache}

	res := c.Refresh(context.Background(), ciscoIOSXE, nil)
	if len(res) != 3 {
		t.Fatalf("results = %+v", res)
	}
	if res[0].Source != "NVD" || res[0].Err == nil {
		t.Errorf("NVD failure not reported: %+v", res[0])
	}
	if res[1].Source != "CISCO" || !strings.Contains(res[1].Skipped, "needs a version") {
		t.Errorf("without versions a version-scoped source is skipped: %+v", res[1])
	}
	if e, _ := cache.Get("NVD", "o:cisco:ios_xe"); len(e.Records) != 1 {
		t.Error("a failed refresh must keep the previous entry")
	}

	res = c.Refresh(context.Background(), ciscoIOSXE, []string{"17.6.1"})
	var notConf bool
	for _, r := range res {
		if r.Source == "CISCO" && strings.Contains(r.Skipped, "not configured") {
			notConf = true
		}
	}
	if !notConf {
		t.Errorf("an unconfigured source is reported as skipped: %+v", res)
	}

	// without a cache object Refresh still reports counts
	nvd.set(sampleRecords(), nil)
	res = (&Checker{Sources: []Source{nvd}}).Refresh(context.Background(), ciscoIOSXE, nil)
	if len(res) != 1 || res[0].CVEs != 1 {
		t.Errorf("results = %+v", res)
	}
}

func TestCanonicalVersionAndScopeKey(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"17.06.01", "17.6.1"}, {" 17.6.1 ", "17.6.1"}, {"15.2(7)E3", "15.2.7.e.3"}, {"v7.2.4", "7.2.4"}, {"", ""},
	} {
		if got := canonicalVersion(tc.in); got != tc.want {
			t.Errorf("canonicalVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	prod, ver := nvdFake(nil), &fakeSource{name: "CISCO", scope: ScopeVersion}
	if scopeKey(prod, ciscoIOSXE, "17.6.1") != "o:cisco:ios_xe" || scopeKey(ver, ciscoIOSXE, "17.06.01") != "o:cisco:ios_xe@17.6.1" {
		t.Error("scope keys")
	}
}

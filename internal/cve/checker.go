// ==============================================================================
// File name:     checker.go
// Description:   Checker: evaluates devices against the online sources, falls
//                back to the offline cache, and refreshes the cache.
// License:       MIT
// ==============================================================================

package cve

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// BaselineSource is the source every platform is checked against. A result
	// without baseline data would read as "no vulnerabilities" while really
	// meaning "unknown", so a device without it is an error, never clean.
	BaselineSource = SourceNVD

	// DefaultStaleAfter is the age after which cached data triggers a warning.
	DefaultStaleAfter = 7 * 24 * time.Hour
)

// errNoCache marks "offline, and the cache holds nothing for this scope".
var errNoCache = errors.New("not in the offline cache")

// Target is one device (or an ad-hoc OS/version pair) to evaluate.
type Target struct {
	Hostname string
	IP       string
	OS       string // platform as the operator or the facts collector names it
	Version  string
}

// Checker evaluates targets. Sources are tried when online; every successful
// answer is stored in Cache; a source that fails (or is skipped with Offline)
// is answered from Cache instead. The zero value is not usable: set Sources
// (even when Offline, where they only define what the cache holds).
type Checker struct {
	Sources    []Source
	Cache      *Cache // may be nil: no persistence and no fallback
	Offline    bool   // never call a source
	StaleAfter time.Duration
	Now        func() time.Time
	Warnf      func(format string, args ...any) // diagnostics; may be nil

	mu     sync.Mutex
	scopes map[string]*scopeLookup
}

type scopeLookup struct {
	once   sync.Once
	recs   []Record
	cached bool
	err    error
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) warnf(format string, args ...any) {
	if c.Warnf != nil {
		c.Warnf(format, args...)
	}
}

func (c *Checker) staleAfter() time.Duration {
	if c.StaleAfter > 0 {
		return c.StaleAfter
	}
	return DefaultStaleAfter
}

// canonicalVersion makes spelling variants of one version share a cache key:
// "17.06.01", "17.6.1" and " 17.6.1 " are the same; "15.2(7)E3" is "15.2.7.e.3".
func canonicalVersion(v string) string {
	toks := tokenize(v)
	parts := make([]string, len(toks))
	for i, t := range toks {
		parts[i] = t.s
	}
	return strings.Join(parts, ".")
}

// scopeKey is the cache key of what a source returns for a product: the product
// itself for product-scoped sources, product plus version for version-scoped.
func scopeKey(s Source, p Product, version string) string {
	if s.Scope() == ScopeProduct {
		return p.Key()
	}
	return p.Key() + "@" + canonicalVersion(version)
}

// Check evaluates one target. It never returns an error: a target that cannot
// be evaluated comes back with DeviceCVEResult.Error set and no advisories.
func (c *Checker) Check(ctx context.Context, t Target) DeviceCVEResult {
	res := DeviceCVEResult{Hostname: t.Hostname, IP: t.IP, Vendor: t.OS, OS: t.OS, Version: t.Version, Advisories: []Advisory{}}
	if strings.TrimSpace(t.Version) == "" {
		res.Error = "no software version known; cannot evaluate CVEs"
		return res
	}
	pl, err := Resolve(t.OS, t.Version)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Vendor, res.OS = pl.Vendor, pl.Product.OS
	recs, err := c.gather(ctx, pl.Product, t.Version)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Advisories = Match(recs, pl.Product, t.Version)
	return res
}

// gather collects and merges what every supporting source knows about the
// product (at this version, for version-scoped sources).
func (c *Checker) gather(ctx context.Context, p Product, version string) ([]Record, error) {
	var sets [][]Record
	var baselineErr error
	baseline := false
	for _, s := range c.Sources {
		if !s.Supports(p) {
			continue
		}
		recs, cached, err := c.scope(ctx, s, p, version)
		if err != nil {
			if s.Name() == BaselineSource {
				baselineErr = err
			}
			continue
		}
		if s.Name() == BaselineSource {
			baseline = true
		}
		if cached {
			recs = markCache(recs)
		}
		sets = append(sets, recs)
	}
	if !baseline {
		return nil, c.baselineError(p, baselineErr)
	}
	return Merge(sets...), nil
}

func (c *Checker) baselineError(p Product, err error) error {
	switch {
	case c.Offline && c.Cache == nil:
		return fmt.Errorf("no advisory data for %s: offline mode needs a cache file", p.OS)
	case c.Offline:
		return fmt.Errorf("no cached advisory data for %s in %s; run \"netops cve -update-db\" on a connected host to create it", p.OS, c.Cache.Path())
	case err != nil:
		return fmt.Errorf("no advisory data for %s: lookup failed and nothing is cached: %w", p.OS, err)
	}
	return fmt.Errorf("no advisory data for %s: no %s source is available", p.OS, BaselineSource)
}

// markCache relabels records that were served from the cache.
func markCache(recs []Record) []Record {
	out := make([]Record, len(recs))
	for i, r := range recs {
		r.Source = SourceCache
		out[i] = r
	}
	return out
}

// scope returns what one source knows for one scope, asking the source at most
// once per Checker no matter how many devices share the product.
func (c *Checker) scope(ctx context.Context, s Source, p Product, version string) ([]Record, bool, error) {
	key := s.Name() + "|" + scopeKey(s, p, version)
	c.mu.Lock()
	if c.scopes == nil {
		c.scopes = map[string]*scopeLookup{}
	}
	l := c.scopes[key]
	if l == nil {
		l = &scopeLookup{}
		c.scopes[key] = l
	}
	c.mu.Unlock()
	l.once.Do(func() { l.recs, l.cached, l.err = c.load(ctx, s, p, version) })
	return l.recs, l.cached, l.err
}

// load is scope without the memoisation: live fetch first (unless Offline),
// then the cache.
func (c *Checker) load(ctx context.Context, s Source, p Product, version string) ([]Record, bool, error) {
	key := scopeKey(s, p, version)
	var fetchErr error
	if !c.Offline {
		recs, err := s.Fetch(ctx, p, version)
		if err == nil {
			if c.Cache != nil {
				c.Cache.Put(s.Name(), key, Entry{Updated: c.now().UTC(), Records: recs})
			}
			return recs, false, nil
		}
		if ctx.Err() != nil { // the operator aborted; do not paper over it with stale data
			return nil, false, ctx.Err()
		}
		fetchErr = err
	}
	if c.Cache != nil {
		if e, ok := c.Cache.Get(s.Name(), key); ok {
			if fetchErr != nil && !errors.Is(fetchErr, ErrNotConfigured) {
				c.warnf("%s: %v; using cached data from %s", s.Name(), fetchErr, e.Updated.Format("2006-01-02 15:04 MST"))
			}
			if age := c.now().Sub(e.Updated); age > c.staleAfter() {
				c.warnf("cached %s data for %s is %d day(s) old (updated %s); refresh it with \"netops cve -update-db\"",
					s.Name(), p.OS, int(age.Hours()/24), e.Updated.Format("2006-01-02"))
			}
			return e.Records, true, nil
		}
	}
	if fetchErr != nil {
		if s.Name() != BaselineSource && !errors.Is(fetchErr, ErrNotConfigured) {
			c.warnf("%s: %v (nothing cached); continuing without it", s.Name(), fetchErr)
		}
		return nil, false, fetchErr
	}
	return nil, false, errNoCache
}

// RefreshResult reports what Refresh did for one source and scope.
type RefreshResult struct {
	Source  string
	Scope   string // the cache key that was refreshed
	CVEs    int
	Err     error  // the fetch failed; the previous cache entry (if any) is kept
	Skipped string // why the source was not queried
}

// Refresh fetches fresh data for a product from every source that covers it and
// stores it in the cache, ignoring what is cached. Product-scoped sources are
// queried once; version-scoped sources once per version in versions (and are
// skipped when none is known). The caller saves the cache.
func (c *Checker) Refresh(ctx context.Context, p Product, versions []string) []RefreshResult {
	seen := map[string]bool{}
	var vers []string
	for _, v := range versions {
		if cv := canonicalVersion(v); cv != "" && !seen[cv] {
			seen[cv] = true
			vers = append(vers, v)
		}
	}
	var out []RefreshResult
	for _, s := range c.Sources {
		if !s.Supports(p) {
			continue
		}
		if s.Scope() == ScopeProduct {
			out = append(out, c.refreshOne(ctx, s, p, ""))
			continue
		}
		if len(vers) == 0 {
			out = append(out, RefreshResult{Source: s.Name(), Scope: p.Key(), Skipped: "needs a version (give -os with -version, or -from-facts)"})
			continue
		}
		for _, v := range vers {
			out = append(out, c.refreshOne(ctx, s, p, v))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return sourceRank(out[i].Source) < sourceRank(out[j].Source) })
	return out
}

func (c *Checker) refreshOne(ctx context.Context, s Source, p Product, version string) RefreshResult {
	r := RefreshResult{Source: s.Name(), Scope: scopeKey(s, p, version)}
	recs, err := s.Fetch(ctx, p, version)
	switch {
	case errors.Is(err, ErrNotConfigured):
		r.Skipped = err.Error()
	case err != nil:
		r.Err = err
	default:
		r.CVEs = len(recs)
		if c.Cache != nil {
			c.Cache.Put(s.Name(), r.Scope, Entry{Updated: c.now().UTC(), Records: recs})
		}
	}
	return r
}

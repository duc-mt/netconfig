// ==============================================================================
// File name:     cache.go
// Description:   Offline advisory cache: a gzip-compressed JSON file that holds
//                the records every source returned, with timestamps.
// License:       MIT
// ==============================================================================

package cve

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultCacheFile is where advisories are cached unless -db says otherwise.
	// It is git-ignored (.cve_cache*).
	DefaultCacheFile = ".cve_cache.json.gz"

	cacheFormat   = 1
	maxCacheBytes = 512 << 20
)

// Entry is what one source returned for one scope (a product, or a product at
// one version), and when.
type Entry struct {
	Updated time.Time `json:"updated"`
	Records []Record  `json:"records"`
}

// cacheFile is the on-disk document: entries[source][scope].
type cacheFile struct {
	Format  int                         `json:"format"`
	Saved   time.Time                   `json:"saved"`
	Sources map[string]map[string]Entry `json:"sources"`
}

// Cache is the in-memory view of the offline cache file. It is safe for
// concurrent use. Nothing reaches disk until Save.
type Cache struct {
	path   string
	mu     sync.Mutex
	data   cacheFile
	exists bool
	dirty  bool
}

// NewCache returns an empty cache that Save will write to path, replacing
// whatever is there. Use it to carry on after OpenCache rejected a bad file.
func NewCache(path string) *Cache {
	return &Cache{path: path, data: cacheFile{Format: cacheFormat, Sources: map[string]map[string]Entry{}}}
}

// OpenCache loads the cache at path. A missing file is not an error: the
// returned Cache is empty and Exists reports false. A file that is not a valid
// cache (not gzip, truncated, corrupt JSON, newer format) is an error.
func OpenCache(path string) (*Cache, error) {
	if path == "" {
		return nil, errors.New("cache path is empty")
	}
	c := NewCache(path)
	f, err := os.Open(path) // #nosec G304 -- the path is operator supplied (-db)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open cache %s: %w", path, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("read cache %s: not a gzip file: %w", path, err)
	}
	defer gz.Close()
	var data cacheFile
	if err := json.NewDecoder(io.LimitReader(gz, maxCacheBytes)).Decode(&data); err != nil {
		return nil, fmt.Errorf("read cache %s: %w", path, err)
	}
	// Draining the stream is what makes gzip verify its checksum.
	if _, err := io.Copy(io.Discard, io.LimitReader(gz, maxCacheBytes)); err != nil {
		return nil, fmt.Errorf("read cache %s: %w", path, err)
	}
	if data.Format != cacheFormat {
		return nil, fmt.Errorf("cache %s has format %d; this netops reads format %d", path, data.Format, cacheFormat)
	}
	if data.Sources == nil {
		data.Sources = map[string]map[string]Entry{}
	}
	c.data, c.exists = data, true
	return c, nil
}

// Path is the file the cache was opened from and is saved to.
func (c *Cache) Path() string { return c.path }

// Exists reports whether the cache file existed when it was opened (or has been
// saved since).
func (c *Cache) Exists() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exists
}

// Dirty reports whether there are changes that Save would write.
func (c *Cache) Dirty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dirty
}

// Get returns the entry a source stored for a scope. The records must not be
// modified.
func (c *Cache) Get(source, scope string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data.Sources[source][scope]
	return e, ok
}

// Put stores (replacing) the entry of a source for a scope.
func (c *Cache) Put(source, scope string, e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data.Sources[source] == nil {
		c.data.Sources[source] = map[string]Entry{}
	}
	c.data.Sources[source][scope] = e
	c.dirty = true
}

// Stats counts the cached scopes and records, and returns the time of the most
// recent update (zero for an empty cache).
func (c *Cache) Stats() (scopes, records int, newest time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, byScope := range c.data.Sources {
		for _, e := range byScope {
			scopes++
			records += len(e.Records)
			if e.Updated.After(newest) {
				newest = e.Updated
			}
		}
	}
	return scopes, records, newest
}

// Save writes the cache if it changed. The file is written to a temporary file
// next to the destination and renamed into place, so an interrupted run or a
// concurrent reader never sees a half-written cache.
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return nil
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".cve_cache.*.tmp")
	if err != nil {
		return fmt.Errorf("create cache file: %w", err)
	}
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write cache %s: %w", c.path, err)
	}
	c.data.Format, c.data.Saved = cacheFormat, time.Now().UTC()
	gz := gzip.NewWriter(tmp)
	if err := json.NewEncoder(gz).Encode(c.data); err != nil {
		return fail(err)
	}
	if err := gz.Close(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp.Name(), c.path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write cache %s: %w", c.path, err)
	}
	c.dirty, c.exists = false, true
	return nil
}

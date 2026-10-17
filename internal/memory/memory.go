// ==============================================================================
// Package memory implements persistent route memory and auto-discovery caching
// for netconfig so that devices requiring jump host fallback are remembered
// across invocations without requiring manual modifications to inventory.csv.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-17
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package memory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultFile is the default persistent memory filename.
const DefaultFile = ".netconfig_memory.json"

// RouteRecord stores learned routing decisions for a single device.
type RouteRecord struct {
	TargetHost   string    `json:"target_host"`
	TargetIP     string    `json:"target_ip"`
	JumpHost     string    `json:"jump_host"`     // Jump host hostname (e.g. "NHG-TRANSIT-GW-01")
	JumpEndpoint string    `json:"jump_endpoint"` // Jump host address:port (e.g. "10.255.255.4:22")
	Reason       string    `json:"reason"`        // why direct failed (e.g. "timeout", "pmtu-drop")
	LearnedAt    time.Time `json:"learned_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
	SuccessCount int       `json:"success_count"`
}

// Store holds persistent memory for device routes.
type Store struct {
	mu     sync.RWMutex
	path   string
	routes map[string]RouteRecord // indexed by target address (IP) and hostname
}

// Load reads the memory file from disk. If the file does not exist,
// an empty store is returned.
func Load(path string) (*Store, error) {
	if path == "" {
		path = DefaultFile
	}
	s := &Store{
		path:   path,
		routes: make(map[string]RouteRecord),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, fmt.Errorf("read memory file %q: %w", path, err)
	}
	if len(data) == 0 {
		return s, nil
	}

	var raw []RouteRecord
	if err := json.Unmarshal(data, &raw); err != nil {
		// Fallback for map representation
		var rawMap map[string]RouteRecord
		if errMap := json.Unmarshal(data, &rawMap); errMap == nil {
			for k, v := range rawMap {
				s.routes[k] = v
			}
			return s, nil
		}
		return s, fmt.Errorf("parse memory file %q: %w", path, err)
	}

	for _, r := range raw {
		if r.TargetIP != "" {
			s.routes[r.TargetIP] = r
		}
		if r.TargetHost != "" {
			s.routes[r.TargetHost] = r
		}
	}
	return s, nil
}

// Get finds a learned route by device address or hostname.
func (s *Store) Get(addrOrHost string) (RouteRecord, bool) {
	if s == nil {
		return RouteRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.routes[addrOrHost]
	return r, ok
}

// Record saves a learned route into memory and flushes to disk.
func (s *Store) Record(targetHost, targetIP, jumpHost, jumpEndpoint, reason string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.routes[targetIP]
	if !ok && targetHost != "" {
		rec, ok = s.routes[targetHost]
	}
	if !ok {
		rec = RouteRecord{
			TargetHost: targetHost,
			TargetIP:   targetIP,
			LearnedAt:  time.Now(),
		}
	}
	rec.TargetHost = targetHost
	rec.TargetIP = targetIP
	rec.JumpHost = jumpHost
	rec.JumpEndpoint = jumpEndpoint
	rec.Reason = reason
	rec.LastUsedAt = time.Now()
	rec.SuccessCount++

	if targetIP != "" {
		s.routes[targetIP] = rec
	}
	if targetHost != "" {
		s.routes[targetHost] = rec
	}

	return s.saveLocked()
}

// Forget removes a learned route (e.g. if the jump host is no longer valid).
func (s *Store) Forget(targetIP, targetHost string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.routes, targetIP)
	delete(s.routes, targetHost)
	return s.saveLocked()
}

// Clear wipes all learned routes.
func (s *Store) Clear() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.routes = make(map[string]RouteRecord)
	if s.path != "" {
		_ = os.Remove(s.path)
	}
	return nil
}

// List returns a deduplicated list of all learned routes.
func (s *Store) List() []RouteRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listLocked()
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	list := s.listLocked()
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0700)
	}
	tmp := fmt.Sprintf("%s.tmp.%d", s.path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) listLocked() []RouteRecord {
	seen := make(map[string]bool)
	var result []RouteRecord
	for _, r := range s.routes {
		key := r.TargetIP
		if key == "" {
			key = r.TargetHost
		}
		if !seen[key] {
			seen[key] = true
			result = append(result, r)
		}
	}
	return result
}

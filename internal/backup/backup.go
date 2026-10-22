// ==============================================================================
// Package backup implements the "backup" subcommand's engine, merged from the
// standalone netbackup tool.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Package backup ties inventory, credentials, vendor profiles and the SSH
// engine together: for each device, open a session, run the right backup
// command, write the result to disk, and report what happened -- without ever
// letting one device's failure stop the others.
//
// Connecting is delegated to a task.Transport (netconfig's SSH engine), so
// jump hosts, host-key policy, legacy algorithms, learned routes and the
// vendor-specific login/paging/enable handling are the same as for a
// configuration run.
package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netconfig/internal/compliance"
	"netconfig/internal/errcat"
	"netconfig/internal/inventory"
	"netconfig/internal/redact"
	"netconfig/internal/task"
	"netconfig/internal/vendor"
)

// Config holds everything a backup run needs besides the device list.
type Config struct {
	// Transport opens the CLI sessions. Required.
	Transport task.Transport

	// Target returns the connection details for a device (credentials, jump
	// host, ...). The package fills in Device, Profile, the timeouts and the
	// trace hook itself. Required.
	Target func(dev inventory.Device, prof *vendor.Profile) (task.Target, error)

	// Logf, when set, receives per-device connection traces.
	Logf func(host, format string, args ...any)

	OutputDir      string
	RunName        string
	Concurrency    int
	Redact         bool
	RetentionCount int
	RetentionDays  int
	SaveUnchanged  bool
	Retries        int           // number of retry attempts per device upon failure (default: 0)
	RetryDelay     time.Duration // pause between retries (default: 2s)
	DialJitter     time.Duration // random jitter delay up to this value applied before connection (default: 0)

	ConnectTimeout time.Duration // TCP dial + SSH handshake (default: 10s)
	CommandTimeout time.Duration // per-command budget; the backup command gets 3x (default: 30s)

	// DryRun tests connection, authentication and login without executing the
	// backup command or saving anything.
	DryRun bool

	// ShowDiff controls whether configuration diffs are calculated and logged
	ShowDiff bool

	// OnDiff callback is invoked when a diff is detected against the latest backup
	OnDiff func(dev inventory.Device, lines []string, added, removed int)

	// OnProgress callback is invoked each time a device backup finishes.
	OnProgress func(completed, total int, res Result)

	// IgnoreVolatile makes change detection compare the "before" and "after"
	// configurations with volatile lines (clock stamps, "last changed"
	// comments, size counters, uptime banners) removed, so noise alone is
	// not reported as a change. The file written to disk is never filtered.
	IgnoreVolatile bool

	// VolatileFilter supplies the volatile-line rules used when
	// IgnoreVolatile is set. Nil means the built-in rules.
	VolatileFilter *VolatileFilter

	// Baseline holds the golden-config rules every device is checked
	// against. Nil disables compliance checking.
	Baseline *compliance.Baseline
}

func (c Config) connectTimeout() time.Duration {
	if c.ConnectTimeout > 0 {
		return c.ConnectTimeout
	}
	return 10 * time.Second
}

func (c Config) commandTimeout() time.Duration {
	if c.CommandTimeout > 0 {
		return c.CommandTimeout
	}
	return 30 * time.Second
}

// Result is what came of trying to back up one device.
type Result struct {
	Device       inventory.Device
	Success      bool
	DryRun       bool
	Unchanged    bool
	DiffLines    []string
	DiffAdded    int
	DiffRemoved  int
	HasDiff      bool
	Category     errcat.Category
	Err          error
	OutputPath   string
	DiffPath     string
	Duration     time.Duration
	Checksum     string // SHA-256 hash of configuration
	BytesWritten int64  // bytes written to disk (0 if skipped or failed)

	// VolatileOnly is set when the raw output differs from the previous
	// backup but only in volatile (or whitespace-only) lines, so the device
	// counts as Unchanged. Only possible with Config.IgnoreVolatile.
	VolatileOnly bool

	// Risk is the classification of DiffLines; Risk.Level is the highest
	// risk detected (RiskNone when nothing noteworthy changed).
	Risk RiskAssessment

	// Compliance is the golden-config check of the fetched configuration.
	// Compliance.Checked is false when no baseline applies.
	Compliance compliance.Report

	// Warnings lists non-fatal problems met while processing this device
	// (a filter, classifier or compliance failure, a diff skipped as too
	// large). They degrade the extra analysis only; the backup itself
	// still succeeds.
	Warnings []string
}

// DefaultRunName is the run directory name RunAll uses when Config.RunName
// is empty. Callers that need to know the name before the run starts (for
// example to put it in a report path) can set Config.RunName from it.
func DefaultRunName(t time.Time) string {
	return "backup-" + t.Format("2006-01-02-1504")
}

func calcJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// ipLocker serializes backup operations per target IP address, preventing
// parallel workers from overwhelming per-device limits such as JunOS
// connection-limit (default: 10) or rate-limit (default: 5).
type ipLocker struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newIPLocker() *ipLocker {
	return &ipLocker{
		locks: make(map[string]*sync.Mutex),
	}
}

func (l *ipLocker) lock(ip string) func() {
	if ip == "" {
		return func() {}
	}
	l.mu.Lock()
	m, ok := l.locks[ip]
	if !ok {
		m = &sync.Mutex{}
		l.locks[ip] = m
	}
	l.mu.Unlock()

	m.Lock()
	return func() {
		m.Unlock()
	}
}

// RunAll backs up every device in the inventory using a bounded pool of
// workers, so a handful of unreachable devices can't serialise the whole
// run behind their timeouts, while a reasonable concurrency cap keeps the
// tool from hammering dozens of devices at once.
func RunAll(ctx context.Context, devices []inventory.Device, cfg Config) []Result {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.RunName == "" {
		cfg.RunName = DefaultRunName(time.Now())
	}

	locker := newIPLocker()
	results := make([]Result, len(devices))
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	var completed atomic.Int32

	for i, dev := range devices {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, dev inventory.Device) {
			defer wg.Done()
			defer func() { <-sem }()

			unlock := locker.lock(dev.Address)
			defer unlock()

			if cfg.DialJitter > 0 {
				jitter := calcJitter(cfg.DialJitter)
				select {
				case <-ctx.Done():
					results[i] = Result{
						Device:   dev,
						Success:  false,
						Category: errcat.CategoryUnknown,
						Err:      ctx.Err(),
					}
					if cfg.OnProgress != nil {
						cfg.OnProgress(int(completed.Add(1)), len(devices), results[i])
					}
					return
				case <-time.After(jitter):
				}
			}
			res := runOne(ctx, dev, cfg)
			results[i] = res
			if cfg.OnProgress != nil {
				cfg.OnProgress(int(completed.Add(1)), len(devices), res)
			}
		}(i, dev)
	}

	wg.Wait()
	return results
}

// runOne performs a single device's backup. The recover() is defense in
// depth on top of the already-careful error handling below: a bug in a
// dependency, or an unexpected nil somewhere, still must not crash the
// whole batch -- it should surface as one failed device instead.
func runOne(ctx context.Context, dev inventory.Device, cfg Config) (result Result) {
	start := time.Now()
	result = Result{Device: dev}

	defer func() {
		if r := recover(); r != nil {
			result.Success = false
			result.Category = errcat.CategoryUnknown
			result.Err = fmt.Errorf("recovered from panic: %v", r)
		}
		result.Duration = time.Since(start)
	}()

	profile, ok := vendor.Lookup(dev.Vendor)
	if !ok {
		result.Err = fmt.Errorf("unsupported vendor %q (supported: %s)", dev.Vendor, strings.Join(vendor.Names(), ", "))
		result.Category = errcat.CategoryUnknown
		return result
	}
	dev.Vendor = profile.Name

	maxAttempts := cfg.Retries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	baseDelay := cfg.RetryDelay
	if baseDelay <= 0 {
		baseDelay = 2 * time.Second
	}

	var output string
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		output, err = fetchConfig(ctx, dev, profile, cfg)
		if err == nil {
			break
		}

		// If cancelled, do not retry
		if ctx.Err() != nil {
			break
		}

		// Some failures cannot be cured by trying again, and trying again can
		// do harm: see retryable.
		if !retryable(err) {
			break
		}

		// If we encountered a transient rate-limit / connection-limit drop (e.g. JunOS handshake EOF
		// or connection reset), dynamically allow 1 automatic retry even if cfg.Retries is 0,
		// and use an extended jittered backoff (3.0s - 4.5s) to allow device token buckets to replenish
		// and half-closed sockets to drain.
		isRateLimit := isTransientRateLimitDrop(err)
		if isRateLimit && attempt == maxAttempts && cfg.Retries == 0 && maxAttempts == 1 {
			maxAttempts = 2
		}

		if attempt < maxAttempts {
			delay := baseDelay
			if isRateLimit {
				delay = rateLimitBackoff + calcJitter(rateLimitBackoff/2)
			}
			select {
			case <-ctx.Done():
			case <-time.After(delay):
			}
			if ctx.Err() != nil {
				break
			}
		}
	}

	if err != nil {
		if cerr, ok := err.(*errcat.Error); ok {
			result.Err = cerr
			result.Category = cerr.Category
		} else {
			result.Err = err
			result.Category = errcat.CategoryUnknown
		}
		return result
	}

	if cfg.DryRun {
		result.Success = true
		result.DryRun = true
		return result
	}

	return processConfig(dev, profile, output, cfg, result)
}

// processConfig does everything that happens locally once a device's
// configuration has been fetched: redaction, golden-config compliance,
// change detection (volatile-aware), risk classification, saving and
// retention. It is separate from runOne so it can be exercised without an
// SSH connection.
//
// The analysis steps (volatile filtering, diffing, risk classification,
// compliance) are best effort: if one fails it is recorded in
// Result.Warnings and the backup carries on, because a problem in an extra
// feature must never cost the operator the backup itself.
func processConfig(dev inventory.Device, profile *vendor.Profile, output string, cfg Config, result Result) Result {
	spec := archiveFor(profile)
	if cfg.Redact {
		output = redact.Config(output)
	}

	report, warn := checkCompliance(cfg.Baseline, profile.Name, output)
	result.Compliance = report
	if warn != "" {
		result.Warnings = append(result.Warnings, warn)
	}

	// Change Detection against latest backup
	latestPath, latestHash, found := findLatestBackup(cfg.OutputDir, dev, spec.Ext)
	currHash := sha256.Sum256([]byte(output))
	result.Checksum = hex.EncodeToString(currHash[:])
	if found && latestHash == currHash {
		result.Unchanged = true
		if !cfg.SaveUnchanged {
			result.Success = true
			result.OutputPath = latestPath
			result.BytesWritten = 0
			return result
		}
	}

	if found && latestHash != currHash {
		beforeData, err := os.ReadFile(latestPath)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("change detection skipped: reading previous backup %s: %v", latestPath, err))
		} else {
			dLines, added, removed, ok, warn := compareConfigs(cfg, profile.Name, string(beforeData), output)
			if warn != "" {
				result.Warnings = append(result.Warnings, warn)
			}
			switch {
			case !ok:
				// No diff available: treat as changed and save the new file.
			case len(dLines) == 0 && cfg.IgnoreVolatile:
				// The raw text differs but nothing meaningful does.
				result.Unchanged = true
				result.VolatileOnly = true
				if !cfg.SaveUnchanged {
					result.Success = true
					result.OutputPath = latestPath
					result.BytesWritten = 0
					return result
				}
			case len(dLines) > 0:
				result.DiffLines = dLines
				result.DiffAdded = added
				result.DiffRemoved = removed
				result.HasDiff = true

				risk, warn := assessRiskSafe(dLines)
				result.Risk = risk
				if warn != "" {
					result.Warnings = append(result.Warnings, warn)
				}

				if cfg.OnDiff != nil {
					cfg.OnDiff(dev, dLines, added, removed)
				}
			}
		}
	}

	// The saved file is always the real configuration (redacted if
	// requested) -- never the volatile-filtered comparison text.
	path, err := save(dev, profile, output, cfg)
	if err != nil {
		cerr := errcat.New(errcat.CategoryIOError, dev.Hostname, "write", err)
		result.Err = cerr
		result.Category = cerr.Category
		return result
	}
	result.BytesWritten = int64(len(output))

	if result.HasDiff && len(result.DiffLines) > 0 {
		diffPath := strings.TrimSuffix(path, spec.Ext) + ".diff"
		if err := WriteFileAtomic(diffPath, []byte(strings.Join(result.DiffLines, "\n")+"\n"), 0o600); err == nil {
			result.DiffPath = diffPath
		}
	}

	if cfg.RetentionCount > 0 || cfg.RetentionDays > 0 {
		_ = pruneBackups(cfg.OutputDir, dev, spec.Ext, cfg.RetentionCount, cfg.RetentionDays)
	}

	result.Success = true
	result.OutputPath = path
	return result
}

// compareConfigs diffs the previous and the new configuration. With
// cfg.IgnoreVolatile both sides first pass through the volatile filter, so
// lines such as "! Last configuration change at ..." cannot produce a
// diff. ok is false (with a warning) when no diff could be produced, either
// because the input is too large or because something panicked.
func compareConfigs(cfg Config, vendorKey, before, after string) (lines []string, added, removed int, ok bool, warn string) {
	defer func() {
		if r := recover(); r != nil {
			lines, added, removed, ok = nil, 0, 0, false
			warn = fmt.Sprintf("change detection failed: %v", r)
		}
	}()

	if cfg.IgnoreVolatile {
		f := cfg.VolatileFilter
		if f == nil {
			f = sharedDefaultFilter()
		}
		before = f.Apply(vendorKey, before)
		after = f.Apply(vendorKey, after)
	}

	lines, added, removed, ok = diffConfig(before, after)
	if !ok {
		warn = "change detection skipped: configuration too large to diff"
	}
	return lines, added, removed, ok, warn
}

// assessRiskSafe classifies a diff, converting a panic into a warning.
func assessRiskSafe(lines []string) (a RiskAssessment, warn string) {
	defer func() {
		if r := recover(); r != nil {
			a = RiskAssessment{}
			warn = fmt.Sprintf("risk classification failed: %v", r)
		}
	}()
	return AssessRisk(lines), ""
}

// checkCompliance runs the golden-config check, converting a panic into a
// warning. A nil baseline yields an unchecked (zero) report.
func checkCompliance(b *compliance.Baseline, vendorKey, config string) (rep compliance.Report, warn string) {
	if b == nil {
		return compliance.Report{}, ""
	}
	defer func() {
		if r := recover(); r != nil {
			rep = compliance.Report{}
			warn = fmt.Sprintf("compliance check failed: %v", r)
		}
	}()
	return b.Check(vendorKey, config), ""
}

// rateLimitBackoff is the pause before retrying a connection that a device's
// connection or rate limit dropped (plus up to half as much jitter), long
// enough for its token bucket to refill and half-closed sockets to drain.
var rateLimitBackoff = 3 * time.Second

// retryable reports whether trying a device again after err could help.
//
// A rejected password (or enable secret) is never retried: every attempt
// counts against the account's lockout threshold, so -retries 3 would turn one
// wrong password into four failed logins per device. A changed host key is a
// security failure that retrying only repeats, and a command the device
// refused will be refused again. Everything else (unreachable, timeouts,
// dropped sessions, a truncated backup) may be transient.
func retryable(err error) bool {
	var ce *errcat.Error
	if errors.As(err, &ce) {
		switch ce.Category {
		case errcat.CategoryAuthFailed, errcat.CategoryCommandFailed:
			return false
		}
	}
	var typed interface{ ErrorKind() string }
	if errors.As(err, &typed) && typed.ErrorKind() == "hostkey" {
		return false
	}
	return true
}

// isTransientRateLimitDrop reports whether an error looks like a transient connection
// termination caused by network device connection-limit or rate-limit exhaustion
// (e.g. JunOS "connection-limit 10" or "rate-limit 5" terminating the handshake with EOF
// or TCP reset).
func isTransientRateLimitDrop(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "handshake failed: eof") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe")
}

// fetchConfig opens a session, runs the platform's backup command and
// validates the output. With cfg.DryRun it stops after the session is open
// (connection, authentication, enable and paging setup all succeeded).
func fetchConfig(ctx context.Context, dev inventory.Device, profile *vendor.Profile, cfg Config) (string, error) {
	if cfg.Transport == nil || cfg.Target == nil {
		return "", errcat.New(errcat.CategoryUnknown, dev.Hostname, "connect", fmt.Errorf("backup: no transport configured"))
	}
	tgt, err := cfg.Target(dev, profile)
	if err != nil {
		return "", errcat.Classify(dev.Hostname, "connect", err)
	}
	tgt.Device = dev
	tgt.Profile = profile
	tgt.ConnectTimeout = cfg.connectTimeout()
	tgt.LoginTimeout = cfg.commandTimeout()
	if cfg.Logf != nil {
		host := dev.Hostname
		tgt.Logf = func(format string, args ...any) { cfg.Logf(host, format, args...) }
	}

	sess, err := cfg.Transport.Open(ctx, tgt)
	if err != nil {
		return "", errcat.Classify(dev.Hostname, "connect", err)
	}
	defer sess.Close()
	if cfg.DryRun {
		return "", nil
	}

	command := archiveFor(profile).Command
	out, err := sess.Send(ctx, command, 3*cfg.commandTimeout())
	if err != nil {
		return "", errcat.Classify(dev.Hostname, "command", err)
	}
	if line, bad := profile.FindError(out); bad {
		return "", errcat.New(errcat.CategoryCommandFailed, dev.Hostname, "command",
			fmt.Errorf("device rejected %q: %s", command, line))
	}
	if err := profile.ValidateBackup(out); err != nil {
		return "", errcat.Classify(dev.Hostname, "validate", err)
	}
	return out, nil
}

// save writes the captured config to <outputDir>/<runName>/<archive dir>/<hostname><ext>.
func save(dev inventory.Device, profile *vendor.Profile, content string, cfg Config) (string, error) {
	spec := archiveFor(profile)
	vendorDir := filepath.Join(cfg.OutputDir, cfg.RunName, spec.Dir)
	if err := os.MkdirAll(vendorDir, 0o700); err != nil {
		return "", fmt.Errorf("creating vendor dir: %w", err)
	}

	filename := sanitize(dev.Hostname) + spec.Ext
	path := filepath.Join(vendorDir, filename)

	if _, err := os.Stat(path); err == nil {
		// Collision fallback
		filename = fmt.Sprintf("%s_%s%s", sanitize(dev.Hostname), sanitize(dev.Address), spec.Ext)
		path = filepath.Join(vendorDir, filename)
	}

	if err := WriteFileAtomic(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("writing backup file: %w", err)
	}
	return path, nil
}

type fileEntry struct {
	path    string
	modTime time.Time
}

func findMatchingBackups(outputDir string, dev inventory.Device, ext string) ([]fileEntry, error) {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, err
	}

	var matching []fileEntry
	filename := sanitize(dev.Hostname) + ext
	filenameAltPrefix := sanitize(dev.Hostname) + "_"
	vCandidates := vendorCandidates(dev)

	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "backup-") {
			continue
		}

		for _, vName := range vCandidates {
			vendorDir := filepath.Join(outputDir, entry.Name(), vName)
			ventries, err := os.ReadDir(vendorDir)
			if err != nil {
				continue
			}

			for _, v := range ventries {
				if v.IsDir() {
					continue
				}
				if v.Name() == filename || (strings.HasPrefix(v.Name(), filenameAltPrefix) && strings.HasSuffix(v.Name(), ext)) {
					info, err := v.Info()
					if err == nil {
						matching = append(matching, fileEntry{
							path:    filepath.Join(vendorDir, v.Name()),
							modTime: info.ModTime(),
						})
					}
				}
			}
		}
	}

	if len(matching) == 0 {
		return nil, nil
	}

	// Sort newest first
	slices.SortFunc(matching, func(a, b fileEntry) int {
		return b.modTime.Compare(a.modTime)
	})

	return matching, nil
}

func findLatestBackup(outputDir string, dev inventory.Device, ext string) (string, [32]byte, bool) {
	matching, err := findMatchingBackups(outputDir, dev, ext)
	if err != nil || len(matching) == 0 {
		return "", [32]byte{}, false
	}

	latestPath := matching[0].path
	data, err := os.ReadFile(latestPath)
	if err != nil {
		return "", [32]byte{}, false
	}

	return latestPath, sha256.Sum256(data), true
}

func pruneBackups(outputDir string, dev inventory.Device, ext string, keepCount, keepDays int) int {
	matching, err := findMatchingBackups(outputDir, dev, ext)
	if err != nil || len(matching) == 0 {
		return 0
	}

	now := time.Now()
	cutoff := now.Add(-time.Duration(keepDays) * 24 * time.Hour)
	pruned := 0

	for i, f := range matching {
		deleteFile := false
		// Keep at least the latest backup even if expired by days
		if i > 0 && keepDays > 0 && f.modTime.Before(cutoff) {
			deleteFile = true
		}
		if keepCount > 0 && i >= keepCount {
			deleteFile = true
		}

		if deleteFile {
			if err := os.Remove(f.path); err == nil {
				pruned++
				// Also clean up accompanying .diff file if present
				diffPath := strings.TrimSuffix(f.path, ext) + ".diff"
				_ = os.Remove(diffPath)

				// Attempt to clean up empty directories
				dir := filepath.Dir(f.path)
				if removeEmptyDir(dir) {
					parentDir := filepath.Dir(dir)
					removeEmptyDir(parentDir)
				}
			}
		}
	}

	return pruned
}

func removeEmptyDir(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	_, readErr := f.Readdirnames(1)
	_ = f.Close()
	if readErr == nil {
		return false
	}
	_ = os.Remove(dir)
	return true
}

func sanitize(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// vendorCandidates lists the directory names under a run directory in which a
// device's backups may live: the netbackup-compatible archive directory, and
// the profile's own name (for trees written under that name).
func vendorCandidates(dev inventory.Device) []string {
	p, ok := vendor.Lookup(dev.Vendor)
	if !ok {
		return []string{dev.Vendor}
	}
	keys := []string{archiveFor(p).Dir}
	if p.Name != keys[0] {
		keys = append(keys, p.Name)
	}
	return keys
}

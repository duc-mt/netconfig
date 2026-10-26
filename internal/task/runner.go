// ==============================================================================
// Package main implements Implementation and logic for runner..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run runner.go [options]
// Notes:         Go package implementation
// ==============================================================================
package task

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/internal/credentials"
	"netops/internal/inventory"
	"netops/internal/logging"
	"netops/internal/parser"
	"netops/internal/vendor"
)

// Target is what a Transport needs to open a session.
type Target struct {
	Device         inventory.Device
	Profile        *vendor.Profile
	Cred           credentials.Credential
	JumpCred       credentials.JumpCredentials // optional jump host credentials
	ConnectTimeout time.Duration               // TCP + SSH handshake
	LoginTimeout   time.Duration               // first prompt, enable, pager setup
	Logf           func(format string, args ...any)
	TCPMSS         int // optional TCP MSS clamping
}

// Session is an open, ready-to-use CLI session.
type Session interface {
	// Send types one line, waits for the next prompt and returns the output.
	// On error the partial output received so far is returned too.
	Send(ctx context.Context, line string, timeout time.Duration) (string, error)
	Close() error
}

// Transport opens sessions. Errors may implement ErrorKind() string
// ("auth", "hostkey", "connect", "timeout", "session") to be categorised.
type Transport interface {
	Open(ctx context.Context, t Target) (Session, error)
}

// StatusObserver receives execution lifecycle events for live reporting.
type StatusObserver interface {
	OnBatchStart(batch int, totalBatches int, count int, isCanary bool)
	OnDeviceStart(dev inventory.Device)
	OnDeviceStep(dev inventory.Device, step vendor.StepKind, line string)
	OnDeviceDone(res Result)
}

// Options tunes a run.
type Options struct {
	Concurrency    int
	MaxRetries     int
	ConnectTimeout time.Duration
	CommandTimeout time.Duration
	SlowFactor     int // commit/save/backup get CommandTimeout*SlowFactor (default 3)
	DryRun         bool
	OpMode         bool // run commands in operational shell; no configure/commit/save
	Backup         bool
	BackupDir      string
	RollbackOnFail bool   // restore from pre-change backup if a device fails (requires -backup)
	OutputDir      string // write per-device command output to <OutputDir>/<hostname>.txt
	ShowDiff       bool   // after a successful change, diff post-change config against the pre-change backup (requires -backup)

	CommitConfirm       int          // minutes; > 0 arms an on-box deadman timer where the platform has one
	AllowRebootRollback bool         // permit a timed reload as the deadman on platforms without a hitless one
	Verify              []VerifyRule // post-change health checks, filtered per device

	// Canary & Phased Rollout
	Canary           int  // run N devices first as canary; abort run if any canary fails
	BatchSize        int  // execute remaining devices in sequential batches of N (0 = all at once)
	MaxFailPercent   int  // abort subsequent batches if failure rate exceeds this % (0-100, default 100)
	FailThresholdSet bool // true if MaxFailPercent was explicitly configured (allows 0% threshold)

	// Pre-Commit Candidate Diff
	PreDiff     bool // stage and inspect candidate diff before commit on supported platforms
	ConfirmDiff bool // prompt operator confirmation before committing candidate diff

	// Output format
	Format string // "text" (default) or "json" for structured operational output
}

// Runner executes jobs.
type Runner struct {
	Transport   Transport
	Log         *logging.Logger
	Opts        Options
	Observer    StatusObserver
	ConfirmFunc func(host string, diff string) bool
	Now         func() time.Time // for backup file names; defaults to time.Now

	// Handler, when set, replaces the configuration plan: each device is
	// connected and the handler runs on the open session (see handler.go).
	Handler Handler
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) slow() time.Duration {
	if r.Opts.SlowFactor > 0 {
		return time.Duration(r.Opts.SlowFactor)
	}
	return 3
}

// ipLocker serializes execution per target IP address, preventing
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

// Run processes all jobs according to canary, batch size, and concurrency options.
// It returns one Result per job, in job order. A failure (or panic) on one device
// never affects others within the same batch.
func (r *Runner) Run(ctx context.Context, jobs []Job) []Result {
	results := make([]Result, len(jobs))
	if len(jobs) == 0 {
		return results
	}

	maxFail := r.Opts.MaxFailPercent
	if maxFail <= 0 && !r.Opts.FailThresholdSet {
		maxFail = 100
	}

	// Partition job indices into batches.
	type batch struct {
		indices  []int
		isCanary bool
	}
	var batches []batch

	startIdx := 0
	if r.Opts.Canary > 0 {
		canarySize := r.Opts.Canary
		if canarySize > len(jobs) {
			canarySize = len(jobs)
		}
		var canaryIdx []int
		for i := 0; i < canarySize; i++ {
			canaryIdx = append(canaryIdx, i)
		}
		batches = append(batches, batch{indices: canaryIdx, isCanary: true})
		startIdx = canarySize
	}

	if startIdx < len(jobs) {
		if r.Opts.BatchSize > 0 {
			for i := startIdx; i < len(jobs); i += r.Opts.BatchSize {
				end := i + r.Opts.BatchSize
				if end > len(jobs) {
					end = len(jobs)
				}
				var bIdx []int
				for j := i; j < end; j++ {
					bIdx = append(bIdx, j)
				}
				batches = append(batches, batch{indices: bIdx, isCanary: false})
			}
		} else {
			var bIdx []int
			for j := startIdx; j < len(jobs); j++ {
				bIdx = append(bIdx, j)
			}
			batches = append(batches, batch{indices: bIdx, isCanary: false})
		}
	}

	skipRemaining := func(fromBatch int, cat Category, detail string) {
		for b := fromBatch; b < len(batches); b++ {
			for _, i := range batches[b].indices {
				results[i] = Result{
					Device:   jobs[i].Device,
					Status:   StatusSkipped,
					Category: cat,
					Detail:   detail,
				}
				r.Log.Warnf(jobs[i].Device.Hostname, "SKIPPED [%s]: %s", cat, detail)
				if r.Observer != nil {
					r.Observer.OnDeviceDone(results[i])
				}
			}
		}
	}

	cumulativeCompleted := 0
	cumulativeFailed := 0
	locker := newIPLocker()

	for bIdx, b := range batches {
		if ctx.Err() != nil {
			skipRemaining(bIdx, CatCancelled, "run was interrupted before this device started")
			break
		}

		if r.Observer != nil {
			r.Observer.OnBatchStart(bIdx+1, len(batches), len(b.indices), b.isCanary)
		}
		if b.isCanary {
			r.Log.Infof("", "CANARY BATCH starting: %d device(s)", len(b.indices))
		} else if len(batches) > 1 {
			r.Log.Infof("", "BATCH %d/%d starting: %d device(s)", bIdx+1, len(batches), len(b.indices))
		}

		workers := r.Opts.Concurrency
		if workers < 1 {
			workers = 1
		}
		if workers > len(b.indices) {
			workers = len(b.indices)
		}

		idxChan := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range idxChan {
					unlock := locker.lock(jobs[i].Device.Address)
					results[i] = r.runGuarded(ctx, jobs[i])
					unlock()
				}
			}()
		}
		for _, i := range b.indices {
			idxChan <- i
		}
		close(idxChan)
		wg.Wait()

		// Evaluate batch outcomes
		batchFailed := 0
		batchCompleted := 0
		for _, i := range b.indices {
			switch results[i].Status {
			case StatusFailed:
				batchFailed++
				batchCompleted++
			case StatusSucceeded:
				batchCompleted++
			}
		}
		cumulativeCompleted += batchCompleted
		cumulativeFailed += batchFailed

		if b.isCanary {
			if batchFailed > 0 {
				r.Log.Errorf("", "CANARY FAILED: %d of %d canary device(s) failed; aborting subsequent batches", batchFailed, len(b.indices))
				skipRemaining(bIdx+1, CatCanaryFailed, "canary device failed; subsequent batches aborted")
				break
			}
			r.Log.Infof("", "CANARY PASSED: all %d canary device(s) succeeded", len(b.indices))
		} else {
			if cumulativeCompleted > 0 {
				failPercent := (cumulativeFailed * 100) / cumulativeCompleted
				if failPercent > maxFail {
					r.Log.Errorf("", "FAILURE THRESHOLD EXCEEDED: %d%% failed (%d/%d), threshold is %d%%; aborting subsequent batches",
						failPercent, cumulativeFailed, cumulativeCompleted, maxFail)
					skipRemaining(bIdx+1, CatThresholdExceeded,
						fmt.Sprintf("failure rate (%d%%) exceeded threshold (%d%%); subsequent batches aborted", failPercent, maxFail))
					break
				}
			}
			if len(batches) > 1 && bIdx < len(batches)-1 {
				r.Log.Infof("", "BATCH %d/%d completed (%d succeeded, %d failed)", bIdx+1, len(batches), batchCompleted-batchFailed, batchFailed)
			}
		}
	}

	return results
}

func (r *Runner) runGuarded(ctx context.Context, job Job) (res Result) {
	start := time.Now()
	res = Result{Device: job.Device}
	host := job.Device.Hostname

	if r.Observer != nil {
		r.Observer.OnDeviceStart(job.Device)
	}

	defer func() {
		if rec := recover(); rec != nil {
			res.Status = StatusFailed
			res.Category = CatPanic
			res.Detail = oneLine(fmt.Sprintf("internal error: %v", rec), 160)
			r.Log.Errorf(host, "PANIC while processing device: %v\n%s", rec, debug.Stack())
		}
		res.Duration = time.Since(start)
		if r.Observer != nil {
			r.Observer.OnDeviceDone(res)
		}
	}()

	switch {
	case job.Skip != "":
		res.Status, res.Category, res.Detail = StatusSkipped, job.Skip, job.SkipDetail
		r.Log.Warnf(host, "SKIPPED [%s]: %s", job.Skip, job.SkipDetail)
	case ctx.Err() != nil:
		res.Status, res.Category, res.Detail = StatusSkipped, CatCancelled, "run was interrupted before this device started"
		r.Log.Warnf(host, "SKIPPED [%s]: %s", CatCancelled, res.Detail)
	default:
		r.execute(ctx, job, &res)
	}
	return res
}

// isTransientRateLimitDrop reports whether an error detail indicates a transient
// connection drop caused by device connection-limit or rate-limit exhaustion
// (e.g. JunOS "connection-limit 10" or "rate-limit 5" terminating the handshake with EOF
// or TCP reset).
func isTransientRateLimitDrop(detail string) bool {
	s := strings.ToLower(detail)
	return strings.Contains(s, "handshake failed: eof") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe")
}

func (r *Runner) execute(ctx context.Context, job Job, res *Result) {
	for attempt := 0; ; attempt++ {
		r.executeAttempt(ctx, job, res)

		isRateLimit := isTransientRateLimitDrop(res.Detail)
		maxRetries := r.Opts.MaxRetries
		if isRateLimit && maxRetries == 0 {
			maxRetries = 1
		}

		if res.Status != StatusFailed || maxRetries <= 0 || attempt >= maxRetries {
			break
		}
		if res.Category != CatConnectFailed && res.Category != CatSessionError && res.Category != CatTimeout {
			break
		}
		if ctx.Err() != nil {
			break
		}

		delay := time.Duration(1<<attempt) * time.Second
		if isRateLimit {
			delay = 3*time.Second + time.Duration(attempt)*time.Second
		}
		r.Log.Warnf(job.Device.Hostname, "transient error (%s): %s; retrying %d/%d in %v...", res.Category, res.Detail, attempt+1, maxRetries, delay)

		res.Status = StatusUnknown
		res.Category = ""
		res.Detail = ""
		res.BackupPath = ""
		res.CommandsApplied = 0
		res.Rollback = RollbackNone
		res.SafetyRating = ""
		res.VerifyPassed, res.VerifyTotal = 0, 0

		select {
		case <-time.After(delay):
		case <-ctx.Done():
		}
	}
}

func (r *Runner) executeAttempt(ctx context.Context, job Job, res *Result) {
	if r.Handler != nil {
		r.executeHandler(ctx, job, res)
		return
	}
	host := job.Device.Hostname
	prof := job.Profile
	res.CommandsTotal = len(job.Commands)

	rules := r.rulesFor(job)
	commitConfirm := r.Opts.CommitConfirm
	if job.CommitConfirm > 0 {
		commitConfirm = job.CommitConfirm
	}
	var plan vendor.Plan
	if r.Opts.OpMode {
		plan = prof.BuildOpPlan(job.Commands)
	} else {
		plan = prof.BuildPlan(job.Commands, vendor.PlanOptions{
			DryRun:        r.Opts.DryRun,
			Token:         strconv.FormatInt(r.now().Unix(), 36),
			CommitConfirm: commitConfirm,
			AllowReboot:   r.Opts.AllowRebootRollback,
			Verify:        len(rules) > 0,
			PreDiff:       r.Opts.PreDiff,
			PreVerify:     job.PreCommitCheck != nil,
		})
		res.SafetyRating = prof.Safety().String()
		r.announceSafety(host, prof, plan, commitConfirm)
	}

	r.Log.Infof(host, "connecting to %s (%s)", job.Device.Endpoint(), prof.Display)
	sess, err := r.Transport.Open(ctx, Target{
		Device:         job.Device,
		Profile:        prof,
		Cred:           job.Cred,
		JumpCred:       job.JumpCred,
		ConnectTimeout: r.Opts.ConnectTimeout,
		LoginTimeout:   r.Opts.CommandTimeout,
		Logf:           func(format string, args ...any) { r.Log.Tracef(host, format, args...) },
	})
	if err != nil {
		r.fail(res, host, classify(err, CatConnectFailed), err)
		return
	}
	defer sess.Close()
	r.Log.Infof(host, "session established (user %s)", job.Cred.Username)

	if r.Opts.OpMode {
		r.Log.Infof(host, "OPERATIONAL-MODE: commands run in operational shell; no configure/commit/save")
	} else if r.Opts.DryRun {
		if plan.Validates {
			r.Log.Infof(host, "DRY-RUN: validating on the device; the candidate configuration is discarded afterwards")
		} else {
			r.Log.Infof(host, "DRY-RUN: this platform has no candidate configuration; running a read-only probe only")
		}
	}

	if r.Opts.Backup {
		path, err := r.backup(ctx, sess, job)
		if err != nil {
			cat := CatBackupFailed
			if errors.Is(err, context.Canceled) {
				cat = CatCancelled
			}
			r.fail(res, host, cat, fmt.Errorf("backup failed, no changes were made: %w", err))
			return
		}
		res.BackupPath = path
	}

	// outputLines accumulates all StepBody responses for -output-dir.
	var outputLines strings.Builder

	// applied counts StepBody steps (one per user command) that were sent
	// and accepted, so a mid-plan failure still reports how far it got.
	applied := 0

	// armed is true while an on-box deadman timer may be running: the device
	// reverts the change by itself unless it is confirmed in time.
	armed := false
	var armedAt time.Time
	window := time.Duration(plan.Window) * time.Minute
	confirmChecked := false

	announced := false
	for _, step := range plan.Steps {
		if r.Observer != nil {
			r.Observer.OnDeviceStep(job.Device, step.Kind, step.Line)
		}
		if step.Kind == vendor.StepVerify {
			if !r.verifyStep(ctx, sess, job, rules, step, armed, res, &outputLines) {
				res.CommandsApplied = applied
				r.afterFailure(ctx, sess, job, plan, res, armed)
				return
			}
			continue
		}
		if step.Kind == vendor.StepConfirm && armed && !confirmChecked {
			confirmChecked = true
			if window-r.now().Sub(armedAt) < confirmMargin {
				res.CommandsApplied = applied
				r.fail(res, host, CatConfirmFailed, fmt.Errorf(
					"commit-confirm window (%d min) ran out before the change could be confirmed; the device is reverting on its own", plan.Window))
				r.afterFailure(ctx, sess, job, plan, res, armed)
				return
			}
		}
		if step.Kind == vendor.StepBody {
			if !announced {
				announced = true
				if r.Opts.OpMode {
					r.Log.Infof(host, "sending %d operational command(s)", len(job.Commands))
				} else {
					r.Log.Infof(host, "sending %d configuration command(s)", len(job.Commands))
				}
			}
		} else {
			r.Log.Infof(host, "%s: %s", step.Kind, logging.RedactCommand(step.Line))
		}
		out, cat, err := r.runStep(ctx, stepContext{sess: sess, prof: prof, host: host, step: step})
		if step.Kind == vendor.StepBody && strings.TrimSpace(out) != "" {
			// Accumulate for -output-dir; also print for -op with -verbose.
			fmt.Fprintf(&outputLines, "=== %s ===\n%s\n", logging.RedactCommand(step.Line), redactText(out))
			if r.Opts.OpMode {
				r.Log.Block(logging.LevelInfo, host, "  | ", redactText(out))
				if r.Opts.Format == "json" {
					if res.ParsedOutput == nil {
						res.ParsedOutput = make(map[string]any)
					}
					res.ParsedOutput[step.Line] = parser.ParseCommandOutput(step.Line, out)
				}
			}
		}
		if step.Kind == vendor.StepInspect && strings.TrimSpace(out) != "" {
			// The device's own compare/diff command (Junos "show | compare",
			// Arista "show session-config diffs"): highlight it the same
			// way as the before/after diff below, since it's the same kind
			// of content.
			res.CandidateDiff = out
			r.Log.DiffBlock(logging.LevelInfo, host, "  | ", redactText(out))
			if r.Opts.ConfirmDiff {
				confirmed := true
				if r.ConfirmFunc != nil {
					confirmed = r.ConfirmFunc(host, out)
				}
				if !confirmed {
					res.CommandsApplied = applied
					r.fail(res, host, CatCancelled, fmt.Errorf("candidate configuration diff was rejected by operator"))
					r.afterFailure(ctx, sess, job, plan, res, armed)
					return
				}
				r.Log.Infof(host, "candidate configuration diff confirmed by operator")
			}
		}
		if err != nil {
			res.CommandsApplied = applied
			r.fail(res, host, cat, err)
			if step.Kind == vendor.StepPersist && cat == CatTimeout {
				r.Log.Warnf(host, "the outcome of %q is unknown; verify the device state before retrying", step.Line)
			}
			if step.Timed && (cat == CatTimeout || cat == CatSessionError) && !armed {
				// The timed commit may have taken effect right before the
				// session died (the classic lockout): assume the deadman runs.
				armed = true
			}
			if !r.Opts.OpMode {
				r.afterFailure(ctx, sess, job, plan, res, armed)
			}
			return
		}
		if step.Kind == vendor.StepBody {
			applied++
		}
		if step.Timed {
			armed, armedAt = true, r.now()
		}
	}

	// Write per-device output file if requested.
	if r.Opts.OutputDir != "" {
		if outputLines.Len() > 0 {
			if err := r.writeOutput(host, outputLines.String()); err != nil {
				r.Log.Warnf(host, "could not write output file: %v", err)
			}
		}
		if r.Opts.Format == "json" && len(res.ParsedOutput) > 0 {
			if err := r.writeJSONOutput(host, res.ParsedOutput); err != nil {
				r.Log.Warnf(host, "could not write JSON output file: %v", err)
			}
		}
	}

	if len(plan.Simulated) > 0 {
		r.Log.Infof(host, "DRY-RUN: would send %d command(s) (not executed):", len(plan.Simulated))
		for _, st := range plan.Simulated {
			r.Log.Infof(host, "  would run: %s", logging.RedactCommand(st.Line))
		}
	}

	// Diff the post-change configuration against the pre-change backup.
	// Only meaningful for a real, non-dry-run change to a device that was
	// actually backed up; best-effort, so it can never turn an otherwise-
	// successful change into a failed result (see reportDiff).
	if r.Opts.ShowDiff && !r.Opts.OpMode && !r.Opts.DryRun && res.BackupPath != "" {
		r.reportDiff(ctx, sess, job, res)
	}

	res.CommandsApplied = applied
	res.Status = StatusSucceeded
	switch {
	case r.Opts.OpMode:
		res.Detail = fmt.Sprintf("%d operational command(s) executed", len(job.Commands))
	case !r.Opts.DryRun:
		res.Detail = fmt.Sprintf("%d command(s) applied", len(job.Commands))
		if plan.Confirm != vendor.ConfirmNone {
			res.Detail += fmt.Sprintf(", commit-confirm (%d min) confirmed", plan.Window)
		}
		if res.VerifyTotal > 0 {
			res.Detail += fmt.Sprintf(", %d/%d check(s) passed", res.VerifyPassed, res.VerifyTotal)
		}
	case plan.Validates:
		res.Detail = fmt.Sprintf("dry-run: %d command(s) validated on device, nothing kept", len(job.Commands))
	default:
		res.Detail = fmt.Sprintf("dry-run: connectivity OK, %d command(s) not sent", len(job.Commands))
	}
	r.Log.Infof(host, "OK: %s", res.Detail)
}

type stepContext struct {
	sess Session
	prof *vendor.Profile
	host string
	step vendor.Step
}

// runStep sends one step and classifies a failure. The returned category is
// only meaningful when err != nil.
func (r *Runner) runStep(ctx context.Context, sc stepContext) (string, Category, error) {
	timeout := r.Opts.CommandTimeout
	if sc.step.Slow {
		timeout *= r.slow()
	}
	shown := logging.RedactCommand(sc.step.Line)

	r.Log.Tracef(sc.host, ">> %s", shown)
	out, err := sc.sess.Send(ctx, sc.step.Line, timeout)
	if out != "" {
		r.Log.Block(logging.LevelTrace, sc.host, "<< ", redactText(out))
	}
	if err != nil {
		return out, classify(err, CatSessionError), fmt.Errorf("%s: %w", shown, err)
	}
	if !sc.step.IgnoreError {
		if bad, ok := sc.prof.FindError(out); ok {
			return out, categoryForStep(sc.step.Kind), fmt.Errorf("device rejected %q: %s", shown, bad)
		}
		if sc.step.Timed {
			// A safety net that silently did not start is worse than none.
			if bad, ok := vendor.LooksLikeFailure(out); ok {
				return out, categoryForStep(sc.step.Kind), fmt.Errorf("could not arm %q: %s", shown, bad)
			}
		}
	}
	return out, "", nil
}

// confirmMargin is how close to the end of a commit-confirm window the runner
// still dares to confirm: past that, the device may already be reverting.
const confirmMargin = 15 * time.Second

// rulesFor returns the verification rules that apply to one device. Nothing
// is verified on a dry run (nothing was changed) or in operational mode.
func (r *Runner) rulesFor(job Job) []VerifyRule {
	if r.Opts.OpMode || r.Opts.DryRun {
		return nil
	}
	var out []VerifyRule
	for _, rule := range r.Opts.Verify {
		if rule.AppliesTo(job.Device, job.Profile) {
			out = append(out, rule)
		}
	}
	return out
}

// announceSafety logs how this device's change is protected, including the
// hazard warning when the platform has no on-box rollback.
func (r *Runner) announceSafety(host string, prof *vendor.Profile, plan vendor.Plan, commitConfirm int) {
	if r.Opts.DryRun {
		if commitConfirm > 0 || len(r.Opts.Verify) > 0 {
			r.Log.Infof(host, "DRY-RUN: commit-confirm and post-change verification are not exercised (nothing is applied)")
		}
		return
	}
	if commitConfirm <= 0 {
		return
	}
	switch {
	case plan.Confirm == vendor.ConfirmNative:
		r.Log.Infof(host, "commit-confirm: the change is applied with a native %d-minute deadman timer and confirmed only after verification", plan.Window)
	case plan.Confirm == vendor.ConfirmReload:
		r.Log.Warnf(host, "commit-confirm: arming 'reload in %d'; unless the change is confirmed the device will RELOAD to revert it", plan.Window)
	case prof.Safety() == vendor.RollbackRebootOnly:
		r.Log.Warnf(host, "commit-confirm needs a timed reload on this platform and -allow-reboot-rollback is not set; "+
			"falling back to client-side rollback only (-rollback-on-fail)")
	default:
		r.Log.Warnf(host, "%s", vendor.HazardClientOnly)
	}
}

// afterFailure leaves the device in the safest state it can after a failed
// change: native immediate revert when asked and available, else a clean exit
// from configuration mode, then (without an on-box timer) the backup rollback.
func (r *Runner) afterFailure(ctx context.Context, sess Session, job Job, plan vendor.Plan, res *Result, armed bool) {
	host := job.Device.Hostname
	if armed && r.Opts.RollbackOnFail && len(plan.Abort) > 0 {
		err := r.abortConfirm(sess, job, plan)
		if err == nil {
			res.Rollback = RollbackOK
			r.Log.Infof(host, "pending change reverted immediately through the platform's native rollback")
			return
		}
		r.Log.Warnf(host, "native rollback failed (%v); leaving it to the deadman timer", err)
	}
	r.cleanup(sess, host, plan)
	if armed {
		if plan.Confirm == vendor.ConfirmReload {
			r.Log.Warnf(host, "the change was NOT confirmed: the device will RELOAD in about %d min to revert it "+
				"(run 'reload cancel' on the device to stop that)", plan.Window)
		} else {
			r.Log.Warnf(host, "the change was NOT confirmed: the device rolls back by itself within %d min", plan.Window)
		}
		if r.Opts.RollbackOnFail && res.BackupPath != "" {
			r.Log.Warnf(host, "backup rollback skipped: the on-box deadman timer owns the revert")
		}
		return
	}
	// A job that knows how to put back exactly what it changed does so first:
	// it is precise, where the backup replay below re-applies a whole config.
	if len(job.Undo) > 0 {
		if err := r.undo(sess, job); err != nil {
			res.Rollback = RollbackFailed
			r.Log.Errorf(host, "restoring the previous state failed: %v; the device may hold the new settings", err)
		} else {
			res.Rollback = RollbackOK
			r.Log.Infof(host, "previous state restored (the change was never saved)")
			return
		}
	}
	// Attempt rollback if we took a backup and the option is set.
	if r.Opts.RollbackOnFail && res.BackupPath != "" {
		r.Log.Warnf(host, "attempting rollback from backup: %s", res.BackupPath)
		if rbErr := r.rollback(ctx, sess, job, res.BackupPath); rbErr != nil {
			res.Rollback = RollbackFailed
			r.Log.Errorf(host, "rollback failed: %v", rbErr)
		} else {
			res.Rollback = RollbackOK
			r.Log.Infof(host, "rollback succeeded; device restored to pre-change state")
		}
	}
}

// abortConfirm reverts an armed change right away (plan.Abort), on a fresh
// context so it still happens after an interrupt.
func (r *Runner) abortConfirm(sess Session, job Job, plan vendor.Plan) error {
	host := job.Device.Hostname
	ctx, cancel := context.WithTimeout(context.Background(), r.Opts.CommandTimeout*r.slow()*time.Duration(len(plan.Abort)+1))
	defer cancel()
	r.Log.Warnf(host, "reverting the pending change now")
	for _, st := range plan.Abort {
		if _, _, err := r.runStep(ctx, stepContext{sess: sess, prof: job.Profile, host: host, step: st}); err != nil {
			return err
		}
	}
	return nil
}

// verifyStep runs the post-change checks. With a deadman timer armed it first
// proves, with a brand-new session, that the device is still manageable.
// It returns false (with res filled in) when the change must not be confirmed.
func (r *Runner) verifyStep(ctx context.Context, sess Session, job Job, rules []VerifyRule, step vendor.Step,
	armed bool, res *Result, out *strings.Builder) bool {
	host := job.Device.Hostname
	var failures []string
	if armed {
		r.Log.Infof(host, "checking management reachability with a fresh session before confirming")
		if err := r.probeReachability(ctx, job); err != nil {
			failures = append(failures, "management reachability lost: "+err.Error())
		}
	}
	if len(rules) > 0 {
		res.VerifyTotal = len(rules)
		if len(failures) == 0 {
			var passed int
			passed, failures = r.runChecks(ctx, sess, job, rules, step.Line, out)
			res.VerifyPassed = passed
		}
	}
	if job.PreCommitCheck != nil {
		res.VerifyTotal++
		if err := job.PreCommitCheck(ctx, job); err != nil {
			failures = append(failures, err.Error())
		} else {
			res.VerifyPassed++
			r.Log.Infof(host, "verify OK: pre-commit check")
		}
	}
	if len(failures) == 0 {
		if res.VerifyTotal > 0 {
			r.Log.Infof(host, "verification passed: %d/%d check(s)", res.VerifyPassed, res.VerifyTotal)
		}
		return true
	}
	cat := CatVerifyFailed
	if ctx.Err() != nil {
		cat = CatCancelled
	}
	r.fail(res, host, cat, fmt.Errorf("VERIFY FAILED: %s", strings.Join(failures, " | ")))
	return false
}

// probeReachability opens a new session and runs the platform's probe command.
// An established session survives many lockout causes (changed SSH port, new
// ACL, removed route); a new one does not.
func (r *Runner) probeReachability(ctx context.Context, job Job) error {
	host := job.Device.Hostname
	pctx, cancel := context.WithTimeout(ctx, r.Opts.ConnectTimeout+r.Opts.CommandTimeout*2)
	defer cancel()
	cred := job.Cred
	if job.PostCred != nil {
		cred = *job.PostCred // the change rotated the login account's credentials
	}
	sess, err := r.Transport.Open(pctx, Target{
		Device:         job.Device,
		Profile:        job.Profile,
		Cred:           cred,
		JumpCred:       job.JumpCred,
		ConnectTimeout: r.Opts.ConnectTimeout,
		LoginTimeout:   r.Opts.CommandTimeout,
		Logf:           func(format string, args ...any) { r.Log.Tracef(host, "(reachability) "+format, args...) },
	})
	if err != nil {
		return fmt.Errorf("new session failed: %w", err)
	}
	defer sess.Close()
	if _, err := sess.Send(pctx, job.Profile.ProbeCommand(), r.Opts.CommandTimeout); err != nil {
		return fmt.Errorf("probe on new session failed: %w", err)
	}
	return nil
}

// runChecks evaluates every rule and returns how many passed plus one message
// per failure. One failing check never stops the others from running.
func (r *Runner) runChecks(ctx context.Context, sess Session, job Job, rules []VerifyRule, prefix string, out *strings.Builder) (int, []string) {
	host := job.Device.Hostname
	passed := 0
	var failures []string
	for _, rule := range rules {
		if msg := r.runCheck(ctx, sess, job, rule, prefix, out); msg == "" {
			passed++
			r.Log.Infof(host, "verify OK: %s", rule.Command)
		} else {
			failures = append(failures, msg)
			r.Log.Errorf(host, "VERIFY FAILED: %s", msg)
		}
	}
	return passed, failures
}

// runCheck runs one rule, retrying while its conditions do not hold yet. It
// returns "" on success or a description of the last failure.
func (r *Runner) runCheck(ctx context.Context, sess Session, job Job, rule VerifyRule, prefix string, out *strings.Builder) string {
	host := job.Device.Hostname
	cmd := prefix + rule.Command
	for attempt := 0; ; attempt++ {
		output, err := sess.Send(ctx, cmd, r.Opts.CommandTimeout)
		fmt.Fprintf(out, "=== verify: %s ===\n%s\n", logging.RedactCommand(cmd), redactText(output))
		var problems []string
		switch {
		case err != nil:
			problems = []string{"command failed: " + err.Error()}
		default:
			if bad, ok := job.Profile.FindError(output); ok {
				problems = []string{"device rejected the command: " + bad}
			} else {
				problems = rule.Evaluate(output)
			}
		}
		if len(problems) == 0 {
			return ""
		}
		msg := fmt.Sprintf("%q: %s", rule.Command, strings.Join(problems, "; "))
		if err != nil || attempt >= rule.Retries || ctx.Err() != nil {
			return msg
		}
		r.Log.Warnf(host, "verify %q not satisfied yet (%s); retry %d/%d in %v", rule.Command, strings.Join(problems, "; "), attempt+1, rule.Retries, rule.Interval)
		select {
		case <-time.After(rule.Interval):
		case <-ctx.Done():
			return msg
		}
	}
}

// cleanup leaves configuration mode (and discards candidate changes where the
// platform supports it) after a failure. It never persists anything, and it
// runs on a fresh context so it still happens after an interrupt.
func (r *Runner) cleanup(sess Session, host string, plan vendor.Plan) {
	if len(plan.Cleanup) == 0 {
		return
	}
	timeout := r.Opts.CommandTimeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(len(plan.Cleanup)+1))
	defer cancel()

	r.Log.Warnf(host, "leaving configuration mode without saving")
	for _, st := range plan.Cleanup {
		r.Log.Tracef(host, ">> %s (cleanup)", st.Line)
		out, err := sess.Send(ctx, st.Line, timeout)
		if out != "" {
			r.Log.Block(logging.LevelTrace, host, "<< ", redactText(out))
		}
		if err != nil {
			r.Log.Warnf(host, "cleanup step %q failed: %v", st.Line, err)
			if classify(err, CatSessionError) == CatTimeout || ctx.Err() != nil {
				return // the session is probably gone
			}
		}
	}
}

// backup stores the running configuration before anything is changed.
func (r *Runner) backup(ctx context.Context, sess Session, job Job) (string, error) {
	host := job.Device.Hostname
	prof := job.Profile
	dir := r.Opts.BackupDir
	if dir == "" {
		dir = "backups"
	}

	cmds := prof.BackupCommands
	if len(cmds) == 0 && prof.BackupCommand != "" {
		cmds = []string{prof.BackupCommand}
	}
	var sections []string
	for _, cmd := range cmds {
		r.Log.Infof(host, "backing up configuration (%s)", cmd)
		out, err := sess.Send(ctx, cmd, r.Opts.CommandTimeout*r.slow())
		if err != nil {
			return "", fmt.Errorf("run %q: %w", cmd, err)
		}
		if bad, ok := prof.FindError(out); ok {
			return "", fmt.Errorf("device rejected %q: %s", cmd, bad)
		}
		if len(cmds) > 1 {
			sections = append(sections, fmt.Sprintf("=== %s ===\n%s", cmd, strings.TrimSpace(out)))
		} else {
			sections = append(sections, out)
		}
	}
	allOut := strings.Join(sections, "\n\n")
	if err := prof.ValidateBackup(allOut); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s_%s.cfg", unsafeFileChars.ReplaceAllString(job.Device.Hostname, "_"), r.now().Format("20060102-150405"))
	dst := filepath.Join(dir, name)
	if err := writeFileAtomic(dst, []byte(allOut+"\n"), 0o600); err != nil {
		return "", err
	}
	r.Log.Infof(host, "backup saved: %s (%d bytes)", dst, len(allOut))
	return dst, nil
}

// reportDiff re-reads the device's configuration after a successful change
// and diffs it against the pre-change backup at res.BackupPath, logging
// the result the way `git diff` would (see Logger.DiffBlock) and recording
// res.DiffAdded/DiffRemoved for the result table and JSON/CSV reports.
//
// This is best-effort and never fails the result: the change already
// happened, so a problem reading or diffing the "after" state (a timeout,
// a device that rejects the read-only command for some reason) is logged
// as a warning and otherwise ignored, the same way a failed rollback
// attempt doesn't retroactively succeed the device it's attached to.
func (r *Runner) reportDiff(ctx context.Context, sess Session, job Job, res *Result) {
	host := job.Device.Hostname
	prof := job.Profile

	before, err := os.ReadFile(res.BackupPath)
	if err != nil {
		r.Log.Warnf(host, "diff: could not read pre-change backup %s: %v", res.BackupPath, err)
		return
	}

	cmds := prof.BackupCommands
	if len(cmds) == 0 && prof.BackupCommand != "" {
		cmds = []string{prof.BackupCommand}
	}
	var postSections []string
	var fetchErr error
	for _, cmd := range cmds {
		part, err := sess.Send(ctx, cmd, r.Opts.CommandTimeout*r.slow())
		if err != nil {
			fetchErr = err
			break
		}
		if bad, ok := prof.FindError(part); ok {
			fetchErr = fmt.Errorf("device rejected %q: %s", cmd, bad)
			break
		}
		if len(cmds) > 1 {
			postSections = append(postSections, fmt.Sprintf("=== %s ===\n%s", cmd, strings.TrimSpace(part)))
		} else {
			postSections = append(postSections, part)
		}
	}
	if fetchErr != nil {
		r.Log.Warnf(host, "diff: could not read post-change configuration: %v", fetchErr)
		return
	}
	after := strings.Join(postSections, "\n\n")
	if err := prof.ValidateBackup(after); err != nil {
		r.Log.Warnf(host, "diff: backup output after the change does not look like a complete configuration (%v); skipping diff", err)
		return
	}

	lines, added, removed, ok := diffConfig(string(before), after)
	if !ok {
		r.Log.Warnf(host, "diff: configuration too large to diff safely (over %d lines); skipped", maxDiffLines)
		return
	}
	res.DiffAdded, res.DiffRemoved = added, removed
	if len(lines) == 0 {
		return // no textual difference -- e.g. a no-op change, or a backup command whose output doesn't reflect it
	}

	r.Log.DiffBlock(logging.LevelInfo, host, "  ", redactText(strings.Join(lines, "\n")))
	if r.Opts.OutputDir != "" {
		if err := r.writeDiff(host, lines); err != nil {
			r.Log.Warnf(host, "diff: could not write diff file: %v", err)
		}
	}
}

// writeDiff saves the +/- diff lines for one device to
// <OutputDir>/<hostname>.diff, alongside its command output file.
func (r *Runner) writeDiff(host string, lines []string) error {
	dir := r.Opts.OutputDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := unsafeFileChars.ReplaceAllString(host, "_") + ".diff"
	dst := filepath.Join(dir, name)
	return writeFileAtomic(dst, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// rollback re-opens a fresh session and re-applies the saved backup content as
// configuration commands, effectively reverting the device to its pre-change
// state. It is best-effort: failures are logged but never propagate back to the
// main result (which already reflects the original failure).
func (r *Runner) rollback(ctx context.Context, _ Session, job Job, backupPath string) error {
	host := job.Device.Hostname
	prof := job.Profile

	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup %s: %w", backupPath, err)
	}
	cmds := parseRawConfig(string(data))
	if len(cmds) == 0 {
		return fmt.Errorf("backup file %s is empty or unparseable", backupPath)
	}

	// Open a new session; the old one was already handed to cleanup().
	rbCtx, cancel := context.WithTimeout(ctx, r.Opts.ConnectTimeout+r.Opts.CommandTimeout*time.Duration(len(cmds)+5))
	defer cancel()
	sess, err := r.Transport.Open(rbCtx, Target{
		Device:         job.Device,
		Profile:        prof,
		Cred:           job.Cred,
		JumpCred:       job.JumpCred,
		ConnectTimeout: r.Opts.ConnectTimeout,
		LoginTimeout:   r.Opts.CommandTimeout,
		Logf:           func(format string, args ...any) { r.Log.Tracef(host, "(rollback) "+format, args...) },
	})
	if err != nil {
		return fmt.Errorf("open rollback session: %w", err)
	}
	defer sess.Close()

	plan := prof.BuildPlan(cmds, vendor.PlanOptions{})
	for _, step := range plan.Steps {
		out, _, stepErr := r.runStep(rbCtx, stepContext{sess: sess, prof: prof, host: host, step: step})
		if out != "" {
			r.Log.Block(logging.LevelTrace, host, "(rollback) << ", redactText(out))
		}
		if stepErr != nil && step.Kind != vendor.StepPersist {
			return fmt.Errorf("rollback step %q: %w", step.Line, stepErr)
		}
	}
	return nil
}

// parseRawConfig extracts non-empty, non-comment lines from a raw config dump
// for use as rollback commands.
func parseRawConfig(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// undo re-applies job.Undo on the live session, without ever saving: the
// change being undone was never persisted, so putting the running state back
// leaves the device exactly as it was. It runs on a fresh context so it still
// happens after an interrupt.
func (r *Runner) undo(sess Session, job Job) error {
	host := job.Device.Hostname
	plan := job.Profile.BuildPlan(job.Undo, vendor.PlanOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), r.Opts.CommandTimeout*r.slow()*time.Duration(len(plan.Steps)+1))
	defer cancel()
	r.Log.Warnf(host, "restoring the previous state")
	for _, st := range plan.Steps {
		if st.Kind == vendor.StepPersist || st.Kind == vendor.StepVerify {
			continue
		}
		if _, _, err := r.runStep(ctx, stepContext{sess: sess, prof: job.Profile, host: host, step: st}); err != nil {
			r.cleanup(sess, host, plan)
			return err
		}
	}
	return nil
}

// writeOutput saves the accumulated command output for one device to
// <OutputDir>/<hostname>.txt, creating the directory if needed.
func (r *Runner) writeOutput(host, content string) error {
	dir := r.Opts.OutputDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := unsafeFileChars.ReplaceAllString(host, "_") + ".txt"
	dst := filepath.Join(dir, name)
	return writeFileAtomic(dst, []byte(content), 0o600)
}

// writeJSONOutput saves the structured parsed output for one device to
// <OutputDir>/<hostname>.json, creating the directory if needed.
func (r *Runner) writeJSONOutput(host string, data any) error {
	dir := r.Opts.OutputDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := unsafeFileChars.ReplaceAllString(host, "_") + ".json"
	dst := filepath.Join(dir, name)
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, append(bytes, '\n'), 0o600)
}

// writeFileAtomic writes via a temporary file and rename so a crash never
// leaves a truncated backup that looks valid.
func writeFileAtomic(dst string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".netops-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, perm); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, dst); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func (r *Runner) fail(res *Result, host string, cat Category, err error) {
	res.Status = StatusFailed
	res.Category = cat
	res.Detail = oneLine(err.Error(), 160)
	r.Log.Errorf(host, "FAILED [%s]: %v", cat, err)
}

// classify maps a transport/session error to a category; fallback is used for
// errors it cannot place.
func classify(err error, fallback Category) Category {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return CatCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return CatTimeout
	}
	var k interface{ ErrorKind() string }
	if errors.As(err, &k) {
		switch k.ErrorKind() {
		case "auth":
			return CatAuthFailed
		case "hostkey":
			return CatHostKeyFailed
		case "connect":
			return CatConnectFailed
		case "timeout":
			return CatTimeout
		case "session":
			return CatSessionError
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return CatTimeout
	}
	return fallback
}

// categoryForStep names the failure when the device itself rejected a step.
func categoryForStep(k vendor.StepKind) Category {
	switch k {
	case vendor.StepBody:
		return CatSyntaxError
	case vendor.StepEnter, vendor.StepExit:
		return CatModeError
	case vendor.StepValidate, vendor.StepPersist:
		return CatCommitFailed
	case vendor.StepArm, vendor.StepConfirm:
		return CatConfirmFailed
	}
	return CatSessionError
}

// redactText masks secret-bearing configuration lines in device output, one
// line at a time (the pattern must not run across line breaks).
func redactText(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = logging.RedactCommand(l)
	}
	return strings.Join(lines, "\n")
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		return string(r[:max-3]) + "..."
	}
	return s
}

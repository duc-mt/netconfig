package task

import (
	"context"
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

	"netconfig/internal/credentials"
	"netconfig/internal/inventory"
	"netconfig/internal/logging"
	"netconfig/internal/vendor"
)

// Target is what a Transport needs to open a session.
type Target struct {
	Device         inventory.Device
	Profile        *vendor.Profile
	Cred           credentials.Credential
	ConnectTimeout time.Duration // TCP + SSH handshake
	LoginTimeout   time.Duration // first prompt, enable, pager setup
	Logf           func(format string, args ...any)
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

// Options tunes a run.
type Options struct {
	Concurrency    int
	ConnectTimeout time.Duration
	CommandTimeout time.Duration
	SlowFactor     int // commit/save/backup get CommandTimeout*SlowFactor (default 3)
	DryRun         bool
	OpMode         bool   // run commands in operational shell; no configure/commit/save
	Backup         bool
	BackupDir      string
	RollbackOnFail bool   // restore from pre-change backup if a device fails (requires -backup)
	OutputDir      string // write per-device command output to <OutputDir>/<hostname>.txt
}

// Runner executes jobs.
type Runner struct {
	Transport Transport
	Log       *logging.Logger
	Opts      Options
	Now       func() time.Time // for backup file names; defaults to time.Now
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

// Run processes all jobs with at most Opts.Concurrency devices in flight and
// returns one Result per job, in job order. A failure (or panic) on one device
// never affects the others.
func (r *Runner) Run(ctx context.Context, jobs []Job) []Result {
	results := make([]Result, len(jobs))

	workers := r.Opts.Concurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}

	idx := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				results[i] = r.runGuarded(ctx, jobs[i]) // each index is written by exactly one worker
			}
		}()
	}
	for i := range jobs {
		idx <- i
	}
	close(idx)
	wg.Wait()
	return results
}

func (r *Runner) runGuarded(ctx context.Context, job Job) (res Result) {
	start := time.Now()
	res = Result{Device: job.Device}
	host := job.Device.Hostname

	defer func() {
		if rec := recover(); rec != nil {
			res.Status = StatusFailed
			res.Category = CatPanic
			res.Detail = oneLine(fmt.Sprintf("internal error: %v", rec), 160)
			r.Log.Errorf(host, "PANIC while processing device: %v\n%s", rec, debug.Stack())
		}
		res.Duration = time.Since(start)
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

func (r *Runner) execute(ctx context.Context, job Job, res *Result) {
	host := job.Device.Hostname
	prof := job.Profile

	var plan vendor.Plan
	if r.Opts.OpMode {
		plan = prof.BuildOpPlan(job.Commands)
	} else {
		plan = prof.BuildPlan(job.Commands, vendor.PlanOptions{
			DryRun: r.Opts.DryRun,
			Token:  strconv.FormatInt(r.now().Unix(), 36),
		})
	}

	r.Log.Infof(host, "connecting to %s (%s)", job.Device.Endpoint(), prof.Display)
	sess, err := r.Transport.Open(ctx, Target{
		Device:         job.Device,
		Profile:        prof,
		Cred:           job.Cred,
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

	announced := false
	for _, step := range plan.Steps {
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
		out, cat, err := r.runStep(ctx, sess, prof, host, step)
		if step.Kind == vendor.StepBody && strings.TrimSpace(out) != "" {
			// Accumulate for -output-dir; also print for -op with -verbose.
			fmt.Fprintf(&outputLines, "=== %s ===\n%s\n", logging.RedactCommand(step.Line), redactText(out))
			if r.Opts.OpMode {
				r.Log.Block(logging.LevelInfo, host, "  | ", redactText(out))
			}
		}
		if step.Kind == vendor.StepInspect && strings.TrimSpace(out) != "" {
			r.Log.Block(logging.LevelInfo, host, "  | ", redactText(out))
		}
		if err != nil {
			r.fail(res, host, cat, err)
			if step.Kind == vendor.StepPersist && cat == CatTimeout {
				r.Log.Warnf(host, "the outcome of %q is unknown; verify the device state before retrying", step.Line)
			}
			if !r.Opts.OpMode {
				r.cleanup(sess, host, plan)
				// Attempt rollback if we took a backup and the option is set.
				if r.Opts.RollbackOnFail && res.BackupPath != "" {
					r.Log.Warnf(host, "attempting rollback from backup: %s", res.BackupPath)
					if rbErr := r.rollback(ctx, sess, job, res.BackupPath); rbErr != nil {
						r.Log.Errorf(host, "rollback failed: %v", rbErr)
					} else {
						r.Log.Infof(host, "rollback succeeded; device restored to pre-change state")
					}
				}
			}
			return
		}
	}

	// Write per-device output file if requested.
	if r.Opts.OutputDir != "" && outputLines.Len() > 0 {
		if err := r.writeOutput(host, outputLines.String()); err != nil {
			r.Log.Warnf(host, "could not write output file: %v", err)
		}
	}

	if len(plan.Simulated) > 0 {
		r.Log.Infof(host, "DRY-RUN: would send %d command(s) (not executed):", len(plan.Simulated))
		for _, st := range plan.Simulated {
			r.Log.Infof(host, "  would run: %s", logging.RedactCommand(st.Line))
		}
	}

	res.Status = StatusSucceeded
	switch {
	case r.Opts.OpMode:
		res.Detail = fmt.Sprintf("%d operational command(s) executed", len(job.Commands))
	case !r.Opts.DryRun:
		res.Detail = fmt.Sprintf("%d command(s) applied", len(job.Commands))
	case plan.Validates:
		res.Detail = fmt.Sprintf("dry-run: %d command(s) validated on device, nothing kept", len(job.Commands))
	default:
		res.Detail = fmt.Sprintf("dry-run: connectivity OK, %d command(s) not sent", len(job.Commands))
	}
	r.Log.Infof(host, "OK: %s", res.Detail)
}

// runStep sends one step and classifies a failure. The returned category is
// only meaningful when err != nil.
func (r *Runner) runStep(ctx context.Context, sess Session, prof *vendor.Profile, host string, step vendor.Step) (string, Category, error) {
	timeout := r.Opts.CommandTimeout
	if step.Slow {
		timeout *= r.slow()
	}
	shown := logging.RedactCommand(step.Line)

	r.Log.Tracef(host, ">> %s", shown)
	out, err := sess.Send(ctx, step.Line, timeout)
	if out != "" {
		r.Log.Block(logging.LevelTrace, host, "<< ", redactText(out))
	}
	if err != nil {
		return out, classify(err, CatSessionError), fmt.Errorf("%s: %w", shown, err)
	}
	if !step.IgnoreError {
		if bad, ok := prof.FindError(out); ok {
			return out, categoryForStep(step.Kind), fmt.Errorf("device rejected %q: %s", shown, bad)
		}
	}
	return out, "", nil
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

	r.Log.Infof(host, "backing up configuration (%s)", prof.BackupCommand)
	out, err := sess.Send(ctx, prof.BackupCommand, r.Opts.CommandTimeout*r.slow())
	if err != nil {
		return "", fmt.Errorf("run %q: %w", prof.BackupCommand, err)
	}
	if bad, ok := prof.FindError(out); ok {
		return "", fmt.Errorf("device rejected %q: %s", prof.BackupCommand, bad)
	}
	if strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("%q returned no output", prof.BackupCommand)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s_%s.cfg", unsafeFileChars.ReplaceAllString(job.Device.Hostname, "_"), r.now().Format("20060102-150405"))
	dst := filepath.Join(dir, name)
	if err := writeFileAtomic(dst, []byte(out+"\n"), 0o600); err != nil {
		return "", err
	}
	r.Log.Infof(host, "backup saved: %s (%d bytes)", dst, len(out))
	return dst, nil
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
		out, _, stepErr := r.runStep(rbCtx, sess, prof, host, step)
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


// writeFileAtomic writes via a temporary file and rename so a crash never
// leaves a truncated backup that looks valid.
func writeFileAtomic(dst string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".netconfig-*.tmp")
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

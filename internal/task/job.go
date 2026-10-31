// ==============================================================================
// Package main implements Implementation and logic for job..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run job.go [options]
// Notes:         Go package implementation
// ==============================================================================
// Package task runs a configuration change across many devices: it prepares
// one job per device, executes them on a bounded worker pool with per-device
// failure isolation, and summarises the outcome.
package task

import (
	"context"
	"fmt"
	"strings"
	"time"

	"netops/internal/credentials"
	"netops/internal/inventory"
	"netops/internal/vendor"
)

// Process exit codes.
const (
	ExitOK      = 0 // every selected device succeeded
	ExitFatal   = 1 // configuration/usage error, or the operator declined; nothing was changed
	ExitPartial = 2 // at least one device failed or was skipped
)

// Category names why a device failed or was skipped.
type Category string

// Failure categories (Status == StatusFailed).
const (
	CatAuthFailed    Category = "AUTH_FAILED"    // credentials rejected (SSH or enable)
	CatConnectFailed Category = "CONNECT_FAILED" // unreachable, refused, handshake error
	CatHostKeyFailed Category = "HOSTKEY_FAILED" // host key unknown or changed
	CatTimeout       Category = "TIMEOUT"        // connect, prompt or command exceeded its budget
	CatSyntaxError   Category = "SYNTAX_ERROR"   // device rejected a configuration command
	CatModeError     Category = "MODE_ERROR"     // could not enter/leave configuration mode
	CatCommitFailed  Category = "COMMIT_FAILED"  // commit / save / commit-check failed
	CatBackupFailed  Category = "BACKUP_FAILED"  // pre-change snapshot failed; nothing was changed
	CatSessionError  Category = "SESSION_ERROR"  // connection dropped or unexpected CLI behaviour
	CatPanic         Category = "PANIC"          // internal error, isolated to this device
	CatCancelled     Category = "CANCELLED"      // interrupted by the operator while running
	CatConfirmFailed Category = "CONFIRM_FAILED" // commit-confirm safety net could not be armed or confirmed
	CatVerifyFailed  Category = "VERIFY_FAILED"  // post-change health check failed (shown as VERIFY FAILED)
)

// Skip categories (Status == StatusSkipped): the device was never touched.
const (
	CatUnsupportedVendor Category = "UNSUPPORTED_VENDOR"
	CatNoCredentials     Category = "NO_CREDENTIALS"
	CatNoCommands        Category = "NO_COMMANDS"
	CatUnsupportedOp     Category = "UNSUPPORTED_OPERATION" // the platform has no safe CLI form of the requested operation
	CatCanaryFailed      Category = "CANARY_FAILED"
	CatThresholdExceeded Category = "THRESHOLD_EXCEEDED"
	// CatCancelled is also used for devices not started before an interrupt.
)

// Status is the outcome class of one device.
type Status int

const (
	StatusUnknown Status = iota
	StatusSucceeded
	StatusFailed
	StatusSkipped
)

func (s Status) String() string {
	switch s {
	case StatusUnknown:
		return "UNKNOWN"
	case StatusSucceeded:
		return "SUCCEEDED"
	case StatusFailed:
		return "FAILED"
	case StatusSkipped:
		return "SKIPPED"
	}
	return "UNKNOWN"
}

// Job is everything needed to process one device.
type Job struct {
	Device   inventory.Device
	Profile  *vendor.Profile
	Commands []string
	Cred     credentials.Credential
	JumpCred credentials.JumpCredentials // optional jump host credentials

	// Skip, when set, means the device is not processed (and why).
	Skip       Category
	SkipDetail string

	// PreCommitCheck, when set, runs once the change is applied but before it
	// is saved or confirmed (see vendor.PlanOptions.PreVerify). A non-nil error
	// fails the device and triggers Undo / the platform's rollback.
	PreCommitCheck func(ctx context.Context, job Job) error

	// Undo are configuration commands that restore the pre-change state when
	// the job fails after the device was modified. They run on the live
	// session and are never saved. Not used on commit-confirm platforms, which
	// revert on their own.
	Undo []string

	// CommitConfirm, when > 0, overrides Options.CommitConfirm (minutes) for
	// this device only.
	CommitConfirm int

	// PostCred, when set, are the credentials that work once the change has
	// been applied (a rotated password of the login account). Sessions opened
	// after the change, such as the commit-confirm reachability probe, use it.
	PostCred *credentials.Credential
}

// Result is the outcome for one device.
type Result struct {
	Device     inventory.Device
	Status     Status
	Category   Category
	Detail     string
	Duration   time.Duration
	BackupPath string

	// CommandsTotal is the number of commands the job was given.
	// CommandsApplied is how many of those were actually sent to the
	// device and accepted before the job finished -- whether it finished
	// by succeeding or by failing partway through. Both are 0 for a
	// skipped device, or for one that never got past connecting.
	CommandsTotal   int
	CommandsApplied int

	// Rollback reports the outcome of an automatic post-failure rollback
	// (-rollback-on-fail). It is RollbackNone unless one was attempted.
	Rollback RollbackOutcome

	// DiffAdded and DiffRemoved count the configuration lines added and
	// removed by the change (see Options.ShowDiff in runner.go), comparing
	// the pre-change backup against the post-change configuration. Both
	// are 0 unless ShowDiff was used on a successful, non-dry-run change.
	DiffAdded   int
	DiffRemoved int

	// SafetyRating is the platform's rollback safety class ("SAFE",
	// "REBOOT REQUIRED", "UNSAFE / OOB REQUIRED"); empty for devices that
	// were not rated (skipped, or operational-mode runs).
	SafetyRating string

	// VerifyPassed and VerifyTotal count post-change health checks (see
	// Options.Verify). Both are 0 when no check applied to the device.
	VerifyPassed int
	VerifyTotal  int

	// CandidateDiff contains the candidate configuration diff inspected
	// before committing on supported platforms (-pre-diff).
	CandidateDiff string

	// ParsedOutput contains structured data extracted from operational
	// command responses (e.g. -op -format json). Keyed by command string.
	ParsedOutput map[string]any

	// RawOutput contains raw text output of operational commands.
	RawOutput map[string]string
}

// RollbackOutcome is the outcome of an automatic rollback attempted after a
// failed change (see Options.RollbackOnFail in runner.go).
type RollbackOutcome int

const (
	RollbackNone   RollbackOutcome = iota // not attempted: no failure, -rollback-on-fail unset, or no backup to restore from
	RollbackOK                            // the pre-change backup was re-applied successfully
	RollbackFailed                        // rollback was attempted but did not complete; the device may be left mid-change
)

// String renders the outcome the way the result table and reports show it.
// It is empty for RollbackNone so callers can treat "" as "not applicable"
// without a special case.
func (r RollbackOutcome) String() string {
	switch r {
	case RollbackOK:
		return "ROLLED_BACK"
	case RollbackFailed:
		return "ROLLBACK_FAILED"
	default:
		return ""
	}
}

// BuildJobs renders the commands for every device and resolves its vendor
// profile. Template errors are fatal (nothing has been touched yet); devices
// with an unknown vendor or an empty command list become skipped jobs.
func BuildJobs(devs []inventory.Device, src CommandSource) ([]Job, error) {
	jobs := make([]Job, 0, len(devs))
	for _, d := range devs {
		cmds, err := src(d)
		if err != nil {
			return nil, err
		}
		job := Job{Device: d}
		prof, ok := vendor.Lookup(d.Vendor)
		switch {
		case !ok:
			job.Skip = CatUnsupportedVendor
			job.SkipDetail = fmt.Sprintf("unsupported vendor %q (supported: %s)", d.Vendor, strings.Join(vendor.Names(), ", "))
		case len(cmds) == 0:
			job.Skip = CatNoCommands
			job.SkipDetail = "no commands apply to this device"
		default:
			job.Profile = prof
			job.Commands = cmds
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

// ResolveCredentials fills in each runnable job's credential. A group that
// cannot be resolved skips its devices (NO_CREDENTIALS) instead of aborting the
// run, so one misconfigured site does not block the others. Calls happen
// sequentially in inventory order, which keeps interactive prompts orderly.
func ResolveCredentials(jobs []Job, resolve func(group string) (credentials.Credential, error)) {
	for i := range jobs {
		if jobs[i].Skip != "" {
			continue
		}
		cred, err := resolve(jobs[i].Device.Group)
		if err != nil {
			jobs[i].Skip = CatNoCredentials
			jobs[i].SkipDetail = err.Error()
			continue
		}
		jobs[i].Cred = cred
	}
}

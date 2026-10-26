// ==============================================================================
// File name:     change.go
// Description:   Idempotent changes: read each device's state first, apply
//
//	only where the state differs, through the normal apply path.
//
// License:       MIT
// ==============================================================================
package task

import (
	"context"
	"sync"

	"netops/internal/credentials"
)

// Decision is what a Decider concluded about one device.
type Decision struct {
	// Commands to apply. Empty means the device is already in the wanted state.
	Commands []string
	// Undo, PreCommitCheck and PostCred are copied onto the apply job (see Job).
	Undo           []string
	PreCommitCheck func(ctx context.Context, job Job) error
	PostCred       *credentials.Credential
	CommitConfirm  int
	// Detail is the skip reason when Commands is empty, else a short summary.
	Detail string
}

// Decider reads one device's state through env (read-only commands only) and
// says what, if anything, must change.
type Decider func(ctx context.Context, env *HandlerEnv) (Decision, error)

func decisionKey(j Job) string { return j.Device.Hostname + "\x00" + j.Device.Address }

// Decide is phase one: it runs d on every runnable job and returns the
// decisions plus a result per job. Nothing is changed. Canary and batch
// settings are for the apply phase and do not apply to this read-only pass.
func (r *Runner) Decide(ctx context.Context, jobs []Job, d Decider) (map[string]Decision, []Result) {
	var mu sync.Mutex
	decisions := make(map[string]Decision, len(jobs))

	opts := r.Opts
	opts.Canary, opts.BatchSize, opts.MaxFailPercent, opts.FailThresholdSet = 0, 0, 100, false
	opts.DryRun, opts.OpMode, opts.Backup = false, false, false
	check := &Runner{
		Transport: r.Transport,
		Log:       r.Log,
		Opts:      opts,
		Now:       r.Now,
		Handler: func(ctx context.Context, env *HandlerEnv) (string, error) {
			dec, err := d(ctx, env)
			if err != nil {
				return "", err
			}
			mu.Lock()
			decisions[decisionKey(env.Job)] = dec
			mu.Unlock()
			if len(dec.Commands) == 0 {
				return env.Skipped(dec.Detail), nil
			}
			return "to apply: " + dec.Detail, nil
		},
	}
	return decisions, check.Run(ctx, jobs)
}

// BuildApplyJobs is phase two's input: a copy of every job whose check passed
// and whose decision carries commands, plus the index of each in jobs.
func BuildApplyJobs(jobs []Job, checked []Result, decisions map[string]Decision) (apply []Job, index []int) {
	for i, j := range jobs {
		if j.Skip != "" || checked[i].Status != StatusSucceeded {
			continue
		}
		dec, ok := decisions[decisionKey(j)]
		if !ok || len(dec.Commands) == 0 {
			continue
		}
		j.Commands = dec.Commands
		j.Undo = dec.Undo
		j.PreCommitCheck = dec.PreCommitCheck
		j.PostCred = dec.PostCred
		j.CommitConfirm = dec.CommitConfirm
		apply = append(apply, j)
		index = append(index, i)
	}
	return apply, index
}

// MergeResults overlays the apply results onto the check results: a device
// that was applied reports the apply outcome, every other device keeps the
// outcome of its check (skipped as already compliant, failed to connect, ...).
func MergeResults(checked []Result, index []int, applied []Result) []Result {
	out := make([]Result, len(checked))
	copy(out, checked)
	for k, i := range index {
		if k < len(applied) {
			out[i] = applied[k]
		}
	}
	return out
}

// ==============================================================================
// File name:     diff_cmd.go
// Description:   "netops diff": preview what a command file would change.
// License:       MIT
// ==============================================================================
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"netops/internal/task"
	"netops/internal/vendor"
)

const diffUsageText = `netops diff: preview what a command file would change, before anything is applied.

Usage:
  netops diff -commands commands.txt [--apply] [flags]

Per platform:
  Junos, VyOS, Arista   the device's own candidate-configuration compare
                        ("show | compare"), validated and then discarded.
  Cisco IOS, Huawei,    the running configuration is downloaded (read-only),
  Aruba, Fortinet, ...  the commands are replayed against it locally, and the
                        predicted +/- diff is shown under the block it belongs to.
Anything else is reported as unsupported.

The local diff is a PREDICTION, not the device's answer: it does not know a
platform's defaults or side effects. Use it as a review aid.

By default nothing is changed. With --apply, once the previews are shown you are
asked to confirm (skipped with -yes), and the change is applied to the devices
that have one through the normal apply path (-backup, -rollback-on-fail,
-canary, --commit-confirm, ...).

Flags:
`

// hasNativeDiff reports whether the platform can compare a candidate configuration.
func hasNativeDiff(p *vendor.Profile) bool {
	for _, s := range p.BuildPlan([]string{"x"}, vendor.PlanOptions{DryRun: true}).Steps {
		if s.Kind == vendor.StepInspect {
			return true
		}
	}
	return false
}

func runDiff(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var o opsFlags
	var cmdsPath string
	var apply bool
	var commitConfirm int
	fs := flag.NewFlagSet("netops diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, diffUsageText); fs.PrintDefaults() }
	fs.StringVar(&cmdsPath, "commands", "", "plain text file with one configuration command per line")
	fs.BoolVar(&apply, "apply", false, "after the preview, confirm and apply the change")
	fs.IntVar(&commitConfirm, "commit-confirm", 0, "with --apply: arm an on-box deadman timer of `minutes` (0 = off)")
	o.register(fs)
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(stdout, diffUsageText)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return task.ExitOK
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return task.ExitOK
		}
		hintPasswordFlag(args, stderr)
		return task.ExitFatal
	}
	o.noteSetFlags(fs)
	fatal := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "netops diff: "+format+"\n", a...)
		return task.ExitFatal
	}
	if fs.NArg() > 0 && cmdsPath == "" && fs.NArg() == 1 {
		cmdsPath = fs.Arg(0) // netops diff commands.txt
	} else if fs.NArg() > 0 {
		return fatal("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if cmdsPath == "" {
		return fatal("-commands is required")
	}
	if commitConfirm < 0 || commitConfirm > 60 {
		return fatal("--commit-confirm must be between 0 and 60 minutes")
	}
	cmds, err := task.ReadCommandsFile(cmdsPath)
	if err != nil {
		return fatal("%v", err)
	}

	env, code := newOpsEnv("diff", &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()

	jobs, err := task.BuildJobs(env.devs, task.StaticCommands(cmds))
	if err != nil {
		return env.die("%v", err)
	}
	env.prepare(jobs)

	// Route each device to its comparison method.
	var nativeIdx, otherIdx []int
	for i := range jobs {
		j := &jobs[i]
		switch {
		case j.Skip != "":
			otherIdx = append(otherIdx, i)
		case hasNativeDiff(j.Profile):
			nativeIdx = append(nativeIdx, i)
		default:
			if ok, why := task.SimulationCapability(j.Profile); !ok {
				j.Skip = task.CatUnsupportedOp
				j.SkipDetail = fmt.Sprintf("diff is not available on %s: %s", j.Profile.Display, why)
			}
			otherIdx = append(otherIdx, i)
		}
	}
	pick := func(idx []int) []task.Job {
		out := make([]task.Job, 0, len(idx))
		for _, i := range idx {
			out = append(out, jobs[i])
		}
		return out
	}
	env.log.Infof("", "%d device(s): %d with a native candidate diff, %d previewed locally; nothing will be changed by the preview",
		len(jobs), len(nativeIdx), len(otherIdx))

	results := make([]task.Result, len(jobs))
	sim := &task.DiffSink{}
	if len(otherIdx) > 0 {
		opts := env.options()
		opts.DryRun, opts.Backup, opts.RollbackOnFail = false, false, false
		r := &task.Runner{Transport: env.tr, Log: env.log, Opts: opts, Handler: sim.Handler(cmds)}
		for k, res := range r.Run(env.ctx, pick(otherIdx)) {
			results[otherIdx[k]] = res
		}
	}
	if len(nativeIdx) > 0 {
		opts := env.options()
		opts.DryRun, opts.Backup, opts.RollbackOnFail = true, false, false
		r := &task.Runner{Transport: env.tr, Log: env.log, Opts: opts}
		for k, res := range r.Run(env.ctx, pick(nativeIdx)) {
			results[nativeIdx[k]] = res
		}
	}

	// Which devices would actually change?
	changed := map[int]bool{}
	for _, i := range nativeIdx {
		if results[i].Status == task.StatusSucceeded && strings.TrimSpace(results[i].CandidateDiff) != "" {
			changed[i] = true
		}
	}
	bySim := map[string]task.DiffRow{}
	for _, row := range sim.Rows() {
		bySim[row.Hostname] = row
	}
	for _, i := range otherIdx {
		if row, ok := bySim[jobs[i].Device.Hostname]; ok && results[i].Status == task.StatusSucceeded && row.Added+row.Removed > 0 {
			changed[i] = true
		}
	}

	if !apply {
		code := env.finish(results)
		switch {
		case len(changed) == 0 && code == task.ExitOK:
			fmt.Fprintln(stdout, "No changes would be made: every device already matches.")
		case len(changed) > 0:
			fmt.Fprintf(stdout, "%d device(s) would change. Preview only: nothing was modified. Re-run with --apply to apply.\n", len(changed))
		}
		return code
	}

	// --apply: continue only for devices whose preview succeeded and showed a change.
	var toApply []task.Job
	for i, j := range jobs {
		if changed[i] {
			toApply = append(toApply, j)
		}
	}
	failedPreview := 0
	for _, r := range results {
		if r.Status == task.StatusFailed {
			failedPreview++
		}
	}
	if len(toApply) == 0 {
		env.finish(results)
		fmt.Fprintln(stdout, "Nothing to apply: no device has a pending change.")
		if failedPreview > 0 {
			return task.ExitPartial
		}
		return task.ExitOK
	}
	if failedPreview > 0 {
		env.log.Warnf("", "%d device(s) could not be previewed and will NOT be changed", failedPreview)
	}
	if code, ok := env.vet("Apply this change", toApply); !ok {
		return code
	}
	runner := env.runner(nil)
	runner.Opts.CommitConfirm = commitConfirm
	applied := runner.Run(env.ctx, toApply)
	return env.finish(applied)
}

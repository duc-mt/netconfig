// ==============================================================================
// File name:     exec_cmd.go
// Description:   "netops exec": run operational (show) commands on devices.
// License:       MIT
// ==============================================================================
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"netops/internal/task"
)

const execUsageText = `netops exec: run operational commands on devices (no configuration changes).

Usage:
  netops exec -limit <device> [flags] "show arp"
  netops exec -limit <device> [flags] -- show arp
  netops exec -commands cmds.txt [flags]

Commands run in each platform's operational shell: no configure mode, no
commit, no save. Positional words are joined into ONE command; use -commands
for several. Output is shown per device and recorded in the audit log.
-format json prints parsed output as JSON on stdout.

Flags:
`

func runExec(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var o opsFlags
	var cmdsPath, format string
	fs := flag.NewFlagSet("netops exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, execUsageText); fs.PrintDefaults() }
	fs.StringVar(&cmdsPath, "commands", "", "file with one operational command per line (instead of positional arguments)")
	fs.StringVar(&format, "format", "text", "output format: text | json")
	o.registerReadOnly(fs)
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(stdout, execUsageText)
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
		fmt.Fprintf(stderr, "netops exec: "+format+"\n", a...)
		return task.ExitFatal
	}
	if format != "text" && format != "json" {
		return fatal("-format must be text or json, got %q", format)
	}

	var cmds []string
	switch positional := strings.TrimSpace(strings.Join(fs.Args(), " ")); {
	case positional != "" && cmdsPath != "":
		return fatal("give either a command or -commands, not both")
	case positional != "":
		cmds = []string{positional}
	case cmdsPath != "":
		var err error
		if cmds, err = task.ReadCommandsFile(cmdsPath); err != nil {
			return fatal("%v", err)
		}
	}
	if len(cmds) == 0 {
		return fatal("no command given (e.g. netops exec -limit R1 \"show arp\")")
	}

	env, code := newOpsEnv("exec", &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()

	jobs, err := task.BuildJobs(env.devs, task.StaticCommands(cmds))
	if err != nil {
		return env.die("%v", err)
	}
	env.prepare(jobs)
	n := 0
	for _, j := range jobs {
		if j.Skip == "" {
			n++
		}
	}
	env.log.Infof("", "%d device(s) selected, %d runnable; concurrency=%d (operational, read-only)", len(jobs), n, o.concurrency)

	opts := env.options()
	opts.OpMode, opts.Format = true, format
	r := &task.Runner{Transport: env.tr, Log: env.log, Opts: opts}
	results := r.Run(env.ctx, jobs)

	if format == "json" {
		type devJSON struct {
			Hostname string         `json:"hostname"`
			Vendor   string         `json:"vendor"`
			Status   string         `json:"status"`
			Commands map[string]any `json:"commands,omitempty"`
		}
		out := make([]devJSON, 0, len(results))
		for _, res := range results {
			out = append(out, devJSON{res.Device.Hostname, res.Device.Vendor, res.Status.String(), res.ParsedOutput})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	}
	return env.finish(results)
}

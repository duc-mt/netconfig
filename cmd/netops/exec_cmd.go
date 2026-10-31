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

	"netops/internal/catalog"
	"netops/internal/task"
)

const execUsageText = `netops exec: run operational commands on devices (no configuration changes).

Usage:
  netops exec -limit <device> [flags] "show arp"
  netops exec -limit <device> [flags] -- show arp
  netops exec -commands cmds.txt [flags]
  netops exec -profile healthcheck [flags]
  netops exec help [vendor]
  netops exec -help-vendor <vendor>

Commands run in each platform's operational shell: no configure mode, no
commit, no save. Positional words are joined into ONE command; use -commands
for several, or -profile healthcheck for vendor-aware command execution.
Output is shown per device and recorded in the audit log.
-format json prints parsed output as JSON on stdout.

Reference Vendor Help:
  netops exec help <vendor>
  netops exec -help-vendor <vendor>
  (Use 'list' as vendor to see all available vendor catalogs)

Flags:
`

func printVendorHelp(vendor string, out io.Writer) int {
	vendor = strings.TrimSpace(vendor)
	if vendor == "" || vendor == "list" || vendor == "all" {
		fmt.Fprintln(out, "Available vendor command reference catalogs:")
		for _, v := range catalog.ListVendors() {
			fmt.Fprintf(out, "  - %s\n", v)
		}
		fmt.Fprintln(out, "\nUse 'netops exec help <vendor>' or 'netops exec -help-vendor <vendor>' to view reference commands.")
		return task.ExitOK
	}
	content, err := catalog.GetRawContent(vendor)
	if err != nil {
		fmt.Fprintf(out, "Error: %v\n", err)
		return task.ExitFatal
	}
	fmt.Fprintf(out, "=== Reference Commands for %s ===\n\n%s\n", catalog.NormalizeVendor(vendor), content)
	return task.ExitOK
}

func runExec(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		if args[0] == "help" || args[0] == "commands" {
			target := ""
			if len(args) > 1 {
				target = args[1]
			}
			return printVendorHelp(target, stdout)
		}
		if isHelpArg(args[0]) {
			fmt.Fprint(stdout, execUsageText)
			fs := flag.NewFlagSet("netops exec", flag.ContinueOnError)
			fs.SetOutput(stdout)
			var o opsFlags
			var cmdsPath, format, helpVendor, profile string
			fs.StringVar(&cmdsPath, "commands", "", "file with one operational command per line")
			fs.StringVar(&format, "format", "text", "output format: text | json")
			fs.StringVar(&profile, "profile", "", "built-in multi-vendor operational profile (e.g. 'healthcheck')")
			fs.StringVar(&helpVendor, "help-vendor", "", "list reference operational commands for a vendor (or 'list')")
			o.registerReadOnly(fs)
			fs.PrintDefaults()
			return task.ExitOK
		}
	}

	var o opsFlags
	var cmdsPath, format, helpVendor, profile string
	fs := flag.NewFlagSet("netops exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, execUsageText); fs.PrintDefaults() }
	fs.StringVar(&cmdsPath, "commands", "", "file with one operational command per line (instead of positional arguments)")
	fs.StringVar(&format, "format", "text", "output format: text | json")
	fs.StringVar(&profile, "profile", "", "built-in multi-vendor operational profile to execute (e.g. 'healthcheck')")
	fs.StringVar(&helpVendor, "help-vendor", "", "list reference operational commands for a vendor (e.g. cisco_ios, aruba_aos-s, checkpoint, or list)")
	fs.StringVar(&helpVendor, "vendor-help", "", "alias for -help-vendor")
	o.registerReadOnly(fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return task.ExitOK
		}
		hintPasswordFlag(args, stderr)
		return task.ExitFatal
	}

	if helpVendor != "" {
		return printVendorHelp(helpVendor, stdout)
	}

	o.noteSetFlags(fs)
	fatal := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "netops exec: "+format+"\n", a...)
		return task.ExitFatal
	}
	if format != "text" && format != "json" {
		return fatal("-format must be text or json, got %q", format)
	}

	var src task.CommandSource
	if profile != "" {
		if profile != "healthcheck" {
			return fatal("unknown profile %q (available: healthcheck)", profile)
		}
		src = task.VendorCommands(catalog.GetCommands)
	} else {
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
			return fatal("no command given (e.g. netops exec -limit R1 \"show arp\", -commands cmds.txt, or -profile healthcheck)")
		}
		src = task.StaticCommands(cmds)
	}

	env, code := newOpsEnv("exec", &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()

	jobs, err := task.BuildJobs(env.devs, src)
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

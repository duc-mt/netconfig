// ==============================================================================
// File name:     vlan_cmd.go
// Description:   "netops config vlan add|del".
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

const vlanUsageText = `netops config vlan: create or remove a VLAN on many switches, idempotently.

Usage:
  netops config vlan add --id <1-4094> [--name <name>] [flags]
  netops config vlan del --id <2-4094> [flags]

"add" skips switches that already have the VLAN (an existing VLAN is never
renamed; a different requested name is reported). "del" skips switches that do
not have it. VLAN 1 can never be deleted. Junos deletes by name, so the name is
read from the device first.

Only platforms with a global VLAN database are handled: Cisco IOS/IOS-XE,
Arista, Ruijie, Aruba AOS-CX, Huawei and Junos. Firewalls, VyOS and Cisco SB
model a VLAN as a sub-interface of a parent port or use firmware-dependent
syntax, so they are skipped and reported.
`

func runVLAN(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, vlanUsageText)
		return task.ExitFatal
	}
	if isHelpArg(args[0]) {
		fmt.Fprint(stdout, vlanUsageText)
		return task.ExitOK
	}
	action := args[0]
	if action != "add" && action != "del" {
		fmt.Fprintf(stderr, "netops config vlan: unknown action %q (use add or del)\n\n%s", action, vlanUsageText)
		return task.ExitFatal
	}
	var o opsFlags
	var id int
	var name string
	fs := flag.NewFlagSet("netops config vlan "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintf(stderr, "%s\nFlags:\n", vlanUsageText); fs.PrintDefaults() }
	fs.IntVar(&id, "id", 0, "VLAN ID (1-4094)")
	if action == "add" {
		fs.StringVar(&name, "name", "", "VLAN name (optional; Junos defaults to VLAN<id>)")
	}
	o.register(fs)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return task.ExitOK
		}
		hintPasswordFlag(args[1:], stderr)
		return task.ExitFatal
	}
	o.noteSetFlags(fs)
	fatal := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "netops config vlan %s: "+format+"\n", append([]any{action}, a...)...)
		return task.ExitFatal
	}
	if fs.NArg() > 0 {
		return fatal("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if id == 0 {
		return fatal("--id is required")
	}
	if err := vendor.ValidateVLANID(id); err != nil {
		return fatal("--id: %v", err)
	}
	if err := vendor.ValidateVLANName(name); err != nil {
		return fatal("--name: %v", err)
	}
	if action == "del" && id == 1 {
		return fatal("VLAN 1 is the default VLAN and cannot be deleted")
	}

	env, code := newOpsEnv("vlan "+action, &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()
	jobs := task.BuildCapabilityJobs(env.devs, "vlan "+action, task.VLANCapability)
	if action == "del" {
		return env.changeRun(fmt.Sprintf("Delete VLAN %d", id), jobs, task.VLANDel(id), nil, nil)
	}
	return env.changeRun(fmt.Sprintf("Create VLAN %d", id), jobs, task.VLANAdd(task.VLANSpec{ID: id, Name: name}), nil, nil)
}

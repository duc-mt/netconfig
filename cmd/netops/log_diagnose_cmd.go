// ==============================================================================
// File name:     log_diagnose_cmd.go
// Description:   "netops log diagnose <device>": an on-demand, read-only health
//                check of one device (reachability probe, SSH, alarms, BGP/OSPF,
//                CRC errors, optical DDM, PoE). Only show/display commands are
//                ever sent.
// License:       MIT
// ==============================================================================

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"netops/internal/inventory"
	"netops/internal/log/collector"
	"netops/internal/log/diagnose"
	"netops/internal/log/triage"
	"netops/internal/task"
)

const logDiagnoseUsageText = `Usage: netops log diagnose [flags] <device-name>

A one-shot, read-only health check of one device taken from the inventory (exact
hostname or address, or a unique hostname prefix): reachability probe, SSH login,
alarms, BGP/OSPF neighbours, CRC errors, optical DDM and PoE. The device name may
come before or after the flags. Only show/display commands are sent.
`

var logDiagnoseFlagGroups = []flagGroup{
	{"Checks", []string{"interface", "no-probe", "fail"}},
	{"Output", []string{"raw", "json", "no-color"}},
	{"Connection", []string{"inventory", "connect-timeout", "command-timeout", "env-file", "host-key-policy", "known-hosts", "legacy-algorithms"}},
	{"Jump hosts", []string{"jump", "jump-host"}},
}

// logFindDevice resolves name against the inventory: exact hostname or address
// (case-insensitive) first, then a unique hostname prefix.
func logFindDevice(devices []inventory.Device, name string) (inventory.Device, error) {
	var prefix []inventory.Device
	for _, d := range devices {
		if strings.EqualFold(d.Hostname, name) || d.Address == name {
			return d, nil
		}
		if strings.HasPrefix(strings.ToLower(d.Hostname), strings.ToLower(name)) {
			prefix = append(prefix, d)
		}
	}
	switch len(prefix) {
	case 1:
		return prefix[0], nil
	case 0:
		return inventory.Device{}, fmt.Errorf("device %q not found in inventory", name)
	}
	names := make([]string, len(prefix))
	for i, d := range prefix {
		names[i] = d.Hostname
	}
	return inventory.Device{}, fmt.Errorf("device %q is ambiguous: %s", name, strings.Join(names, ", "))
}

// runLogDiagnose is "netops log diagnose".
func runLogDiagnose(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var conn logConn
	fs := newLogFlagSet("diagnose", stderr, logDiagnoseUsageText, logDiagnoseFlagGroups)
	conn.register(fs)
	var (
		iface   = fs.String("interface", "", "limit the CRC and optical checks to one interface")
		raw     = fs.Bool("raw", false, "print the verbatim device output under each check")
		failBad = fs.Bool("fail", false, "exit 1 when the device is unreachable or any check needs attention")
		noProbe = fs.Bool("no-probe", false, "skip the local reachability probe (TCP connect latency, ICMP echo, route and MTU)")
		asJSON  = fs.Bool("json", false, "print the report as JSON instead of text")
		noColor = fs.Bool("no-color", false, "disable coloured output")
	)

	// The device name may come before or after the flags.
	var names []string
	rest := args
	for {
		if code, ok := parseLogFlags(fs, rest); !ok {
			return code
		}
		if fs.NArg() == 0 {
			break
		}
		names = append(names, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(names) != 1 {
		return logFail(stderr, "diagnose", "exactly one <device-name> is required")
	}
	if *iface != "" && !diagnose.ValidInterface(*iface) {
		return logFail(stderr, "diagnose", "invalid --interface %q", *iface)
	}
	if err := conn.validateConn(); err != nil {
		return logFail(stderr, "diagnose", "%v", err)
	}

	devices, warns := inventory.LoadLenient(conn.inventory)
	if len(devices) == 0 {
		// Say why there is nothing to diagnose once: the load problems if there
		// were any (a missing file is not "an inventory with no devices"),
		// otherwise that the file is empty.
		for _, w := range warns {
			fmt.Fprintf(stderr, "netops log diagnose: inventory: %v\n", w)
		}
		if len(warns) == 0 {
			fmt.Fprintf(stderr, "netops log diagnose: inventory %q contains no devices\n", conn.inventory)
		}
		if logMissingFile(conn.inventory, nil) {
			fmt.Fprint(stderr, logInitTip)
		}
		return task.ExitFatal
	}
	dev, err := logFindDevice(devices, names[0])
	if err != nil {
		return logFail(stderr, "diagnose", "%v", err)
	}

	log := &logLogger{w: stderr}
	tp, err := conn.transport(stdin, stderr, log)
	if err != nil {
		return logFail(stderr, "diagnose", "%v", err)
	}
	tp.resolveGroups([]inventory.Device{dev}, log)
	sshOpts := tp.ssh
	if sshOpts.ConnectTimeout <= 0 || sshOpts.ConnectTimeout > triage.MaxConnectTimeout {
		sshOpts.ConnectTimeout = triage.MaxConnectTimeout
	}
	dialer := collector.NewDialer(collector.DialerConfig{
		SSH:             sshOpts,
		CredStore:       tp.resolver,
		JumpEnabled:     conn.jump,
		JumpDefaultHost: conn.jumpHost,
	})
	defer dialer.CloseJumps()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rep := diagnose.Run(ctx, dialer, dev, diagnose.Options{
		Interface:      *iface,
		CommandTimeout: conn.commandTimeout,
		SSH:            sshOpts,
		NoProbe:        *noProbe,
	})
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return logFail(stderr, "diagnose", "%v", err)
		}
	} else {
		diagnose.Render(stdout, rep, diagnose.RenderOptions{Color: logColorEnabled(stdout, *noColor), Raw: *raw})
	}
	if *failBad && !rep.Healthy() {
		return task.ExitFatal
	}
	return task.ExitOK
}

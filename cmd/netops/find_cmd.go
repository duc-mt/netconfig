// ==============================================================================
// File name:     find_cmd.go
// Description:   "netops find": locate a MAC / IP on the network.
// License:       MIT
// ==============================================================================
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"netops/internal/task"
	"netops/internal/vendor"
)

const findUsageText = `netops find: locate the switch port a host is plugged into.

Usage:
  netops find --mac <address> [flags]
  netops find --ip <address> [flags]

--mac accepts aabb.ccdd.eeff, aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff and bare hex;
it is rewritten into each platform's own notation. --ip first learns the MAC
from the ARP tables, then searches the MAC tables.

Every switch is queried concurrently. CPU / internal ports are ignored, and so
are uplinks (port-channels, and trunks on platforms that can list them): the
answer is the access port. Uplink sightings are only shown when nothing better
was found, or with --all.

Read-only. -dry-run, -yes and -backup have no effect here.

Flags:
`

func runFind(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var o opsFlags
	var mac, ip string
	var all bool
	fs := flag.NewFlagSet("netops find", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, findUsageText); fs.PrintDefaults() }
	fs.StringVar(&mac, "mac", "", "MAC address to locate")
	fs.StringVar(&ip, "ip", "", "IPv4 address to locate")
	fs.BoolVar(&all, "all", false, "also list sightings on uplinks (trunks and port-channels)")
	o.register(fs)
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(stdout, findUsageText)
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
		fmt.Fprintf(stderr, "netops find: "+format+"\n", a...)
		return task.ExitFatal
	}
	if fs.NArg() > 0 {
		return fatal("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if mac == "" && ip == "" {
		return fatal("one of --mac or --ip is required")
	}
	var wantMAC string
	if mac != "" {
		n, err := vendor.NormalizeMAC(mac)
		if err != nil {
			return fatal("--mac: %v", err)
		}
		wantMAC = vendor.FormatMAC(n, vendor.MACColon)
	}
	if ip != "" {
		p := net.ParseIP(strings.TrimSpace(ip))
		if p == nil || p.To4() == nil {
			return fatal("--ip: %q is not an IPv4 address", ip)
		}
		ip = p.To4().String()
	}

	env, code := newOpsEnv("find", &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()

	// Stage 1 (--ip only): learn the MAC from the ARP tables.
	if wantMAC == "" {
		arp := &task.FindSink{}
		arpJobs := task.BuildCapabilityJobs(env.devs, "find --ip", task.LocatorCapability(false))
		env.readOnlyRun(arpJobs, arp.ARPHandler(ip))
		seen := map[string]bool{}
		for _, m := range arp.ARP() {
			if !seen[m.Record.MAC] {
				seen[m.Record.MAC] = true
				wantMAC = m.Record.MAC
			}
		}
		switch len(seen) {
		case 0:
			fmt.Fprintf(stdout, "[NOT FOUND] %s is not in the ARP table of any device queried\n", ip)
			return task.ExitPartial
		case 1:
			env.log.Infof("", "%s resolves to %s", ip, wantMAC)
		default:
			var list []string
			for m := range seen {
				list = append(list, m)
			}
			return env.die("%s has conflicting ARP entries (%s): possible duplicate address; resolve with --mac", ip, strings.Join(list, ", "))
		}
	}

	// Stage 2: search the MAC tables.
	sink := &task.FindSink{}
	jobs := task.BuildCapabilityJobs(env.devs, "find", task.LocatorCapability(true))
	results := env.readOnlyRun(jobs, sink.MACHandler(wantMAC))
	code = env.finish(results)

	subject := wantMAC
	if ip != "" {
		subject = ip
	}
	var edge, uplink []task.Hit
	for _, h := range sink.Hits() {
		if h.Uplink {
			uplink = append(uplink, h)
		} else {
			edge = append(edge, h)
		}
	}
	vlan := func(v int) string {
		if v == 0 {
			return "VLAN unknown"
		}
		return fmt.Sprintf("VLAN %d", v)
	}
	for _, h := range edge {
		fmt.Fprintf(stdout, "[FOUND] %s (%s) -> Port %s (%s)\n", subject, h.Device.Hostname, h.Record.Interface, vlan(h.Record.VLAN))
	}
	if all || len(edge) == 0 {
		for _, h := range uplink {
			fmt.Fprintf(stdout, "[UPLINK] %s (%s) -> Port %s (%s, %s)\n", subject, h.Device.Hostname, h.Record.Interface, h.Why, vlan(h.Record.VLAN))
		}
	}
	switch {
	case len(edge) == 0 && len(uplink) == 0:
		fmt.Fprintf(stdout, "[NOT FOUND] %s is not in the MAC table of any device queried\n", subject)
		return task.ExitPartial
	case len(edge) == 0:
		fmt.Fprintf(stdout, "[NOTE] %s was only seen on uplinks: the access switch is not in this inventory or could not be queried\n", subject)
	case len(edge) > 1:
		fmt.Fprintf(stdout, "[NOTE] %d access ports reported: the host moved, or a switch's trunk could not be detected\n", len(edge))
	}
	return code
}

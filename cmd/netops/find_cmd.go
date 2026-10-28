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
	"unicode/utf8"

	"netops/internal/task"
	"netops/internal/vendor"
)

const (
	findColorReset  = "\033[0m"
	findColorGreen  = "\033[32m"
	findColorYellow = "\033[33m"
	findColorRed    = "\033[31m"
	findColorCyan   = "\033[36m"
	findColorBold   = "\033[1m"
)

func renderFindBoxTable(w io.Writer, title string, header []string, rows [][]string, statusColors []string, colorize bool) {
	width := make([]int, len(header))
	for i, h := range header {
		width[i] = utf8.RuneCountInString(h)
	}
	for _, row := range rows {
		for j, val := range row {
			if n := utf8.RuneCountInString(val); n > width[j] {
				width[j] = n
			}
		}
	}

	if title != "" {
		t := title
		if colorize {
			t = findColorBold + title + findColorReset
		}
		fmt.Fprintln(w, t)
	}

	border := func(left, mid, right string) string {
		var b strings.Builder
		b.WriteString(left)
		for i, w := range width {
			b.WriteString(strings.Repeat("─", w+2))
			if i < len(width)-1 {
				b.WriteString(mid)
			}
		}
		b.WriteString(right)
		return b.String()
	}

	fmt.Fprintln(w, border("╭", "┬", "╮"))

	// Header row
	var hb strings.Builder
	hb.WriteString("│")
	for i, h := range header {
		pad := width[i] - utf8.RuneCountInString(h)
		cell := " " + h + strings.Repeat(" ", pad) + " "
		if colorize {
			cell = findColorBold + cell + findColorReset
		}
		hb.WriteString(cell + "│")
	}
	fmt.Fprintln(w, hb.String())

	fmt.Fprintln(w, border("├", "┼", "┤"))

	// Rows
	for rowIdx, row := range rows {
		var rb strings.Builder
		rb.WriteString("│")
		for colIdx, val := range row {
			pad := width[colIdx] - utf8.RuneCountInString(val)
			cell := " " + val + strings.Repeat(" ", pad) + " "
			// Apply color to last column (Status) if provided
			if colIdx == len(row)-1 && rowIdx < len(statusColors) && statusColors[rowIdx] != "" && colorize {
				cell = statusColors[rowIdx] + cell + findColorReset
			}
			rb.WriteString(cell + "│")
		}
		fmt.Fprintln(w, rb.String())
	}

	fmt.Fprintln(w, border("╰", "┴", "╯"))
}

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

Read-only.

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
	o.registerReadOnly(fs)
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(stdout, findUsageText)
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
	var arpMatches []task.ARPMatch
	if wantMAC == "" {
		arp := &task.FindSink{}
		arpJobs := task.BuildCapabilityJobs(env.devs, "find --ip", task.LocatorCapability(false))
		env.readOnlyRun(arpJobs, arp.ARPHandler(ip))
		seen := map[string]bool{}
		for _, m := range arp.ARP() {
			arpMatches = append(arpMatches, m)
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
			arpHeader := []string{"IP ADDRESS", "MAC ADDRESS", "GATEWAY HOST", "INTERFACE", "STATUS"}
			var arpRows [][]string
			var arpColors []string
			for _, m := range arpMatches {
				iface := m.Record.Interface
				if iface == "" {
					iface = "-"
				}
				arpRows = append(arpRows, []string{ip, wantMAC, m.Device.Hostname, iface, "✔ RESOLVED"})
				arpColors = append(arpColors, findColorGreen)
			}
			renderFindBoxTable(stdout, "ARP Resolution", arpHeader, arpRows, arpColors, env.color)
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
	runnableJobs := 0
	for _, j := range jobs {
		if j.Skip == "" {
			runnableJobs++
		}
	}
	if runnableJobs == 0 {
		if ip != "" && len(arpMatches) > 0 {
			msg := fmt.Sprintf("ℹ [NOTE] %s resolves to %s on %s (%s), but no Layer-2 switches with MAC table capability in queried inventory to trace access switchport",
				ip, wantMAC, arpMatches[0].Device.Hostname, arpMatches[0].Record.Interface)
			if env.color {
				msg = findColorCyan + msg + findColorReset
			}
			fmt.Fprintln(stdout, msg)
			return task.ExitOK
		}
		// --mac with no L2 switches: attempt a reverse ARP lookup across all L3 gateways
		// to show what IP corresponds to this MAC address.
		revARP := &task.FindSink{}
		revJobs := task.BuildCapabilityJobs(env.devs, "find --mac (reverse ARP)", task.LocatorCapability(false))
		env.readOnlyRun(revJobs, revARP.MACReverseARPHandler(wantMAC))
		revMatches := revARP.ARP()
		if len(revMatches) > 0 {
			arpHeader := []string{"MAC ADDRESS", "IP ADDRESS", "GATEWAY HOST", "INTERFACE", "STATUS"}
			var arpRows [][]string
			var arpColors []string
			for _, m := range revMatches {
				iface := m.Record.Interface
				if iface == "" {
					iface = "-"
				}
				ipFound := m.Record.IP
				if ipFound == "" {
					ipFound = "-"
				}
				arpRows = append(arpRows, []string{wantMAC, ipFound, m.Device.Hostname, iface, "✔ FOUND"})
				arpColors = append(arpColors, findColorGreen)
			}
			renderFindBoxTable(stdout, "Reverse ARP Lookup", arpHeader, arpRows, arpColors, env.color)
			msg := "ℹ [NOTE] MAC resolved via gateway ARP table. No Layer-2 switches in queried inventory to trace access switchport."
			if env.color {
				msg = findColorCyan + msg + findColorReset
			}
			fmt.Fprintln(stdout, msg)
			return task.ExitOK
		}
		fmt.Fprintf(stdout, "[NOT FOUND] no devices in inventory support MAC address table queries\n")
		return task.ExitPartial
	}
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

	var switchHeader = []string{"TARGET", "MAC ADDRESS", "SWITCH HOSTNAME", "PORT", "VLAN", "TYPE", "STATUS"}
	var switchRows [][]string
	var switchColors []string

	for _, h := range edge {
		switchRows = append(switchRows, []string{subject, wantMAC, h.Device.Hostname, h.Record.Interface, vlan(h.Record.VLAN), "Access", "✔ FOUND"})
		switchColors = append(switchColors, findColorGreen)
	}
	if all || len(edge) == 0 {
		for _, h := range uplink {
			why := h.Why
			if why == "" {
				why = "Uplink"
			}
			switchRows = append(switchRows, []string{subject, wantMAC, h.Device.Hostname, h.Record.Interface, vlan(h.Record.VLAN), why, "⊘ UPLINK"})
			switchColors = append(switchColors, findColorYellow)
		}
	}

	if len(switchRows) > 0 {
		renderFindBoxTable(stdout, "Switchport Location", switchHeader, switchRows, switchColors, env.color)
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
		msg := fmt.Sprintf("[NOTE] %s was only seen on uplinks: the access switch is not in this inventory or could not be queried", subject)
		if env.color {
			msg = findColorYellow + msg + findColorReset
		}
		fmt.Fprintln(stdout, msg)
	case len(edge) > 1:
		msg := fmt.Sprintf("[NOTE] %d access ports reported: the host moved, or a switch's trunk could not be detected", len(edge))
		if env.color {
			msg = findColorYellow + msg + findColorReset
		}
		fmt.Fprintln(stdout, msg)
	}
	return code
}

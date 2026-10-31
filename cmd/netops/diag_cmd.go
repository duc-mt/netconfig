// ==============================================================================
// File name:     diag_cmd.go
// Description:   "netops diag": automated multi-vendor diagnostic & harvesting engine.
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
	"regexp"
	"strings"

	"netops/internal/catalog"
	"netops/internal/inventory"
	"netops/internal/parser"
	"netops/internal/task"
	"netops/internal/vendor"
)

const diagUsageText = `netops diag: automated multi-vendor operational diagnostics & health harvesting.

Usage:
  netops diag [flags]
  netops diag -category hardware [flags]
  netops diag -category interfaces [flags]
  netops diag -category redundancy [flags]
  netops diag -format json -output report.json [flags]

Harvests and audits live operational telemetry across three pillars:
  1. Hardware & System Status: CPU, RAM, temperature, fans, PSUs, stack state, uptime.
  2. Network & Interface Integrity: Interface status, error counters, trunks, LACP, VLANs, routes.
  3. Redundancy & High Availability: VRRP, vPC, Spanning Tree, cluster/failover status.

Commands are automatically selected per device vendor from the built-in catalog.
All commands run strictly in read-only operational mode (no state changes).

Flags:
`

// DeviceDiagnostics holds harvested operational health data for one device.
type DeviceDiagnostics struct {
	Hostname   string                    `json:"hostname"`
	Address    string                    `json:"address"`
	Vendor     string                    `json:"vendor"`
	Status     string                    `json:"status"`
	Hardware   HardwareTelemetry         `json:"hardware"`
	Network    NetworkTelemetry          `json:"network"`
	Redundancy RedundancyStatus          `json:"redundancy"`
	Resources  parser.ResourceInspection `json:"resources"`
	HealthCard parser.DeviceHealthCard   `json:"health_card,omitempty"`
	RawOutputs map[string]string         `json:"raw_outputs,omitempty"`
}

type HardwareTelemetry struct {
	Model       string `json:"model,omitempty"`
	Serial      string `json:"serial,omitempty"`
	Version     string `json:"version,omitempty"`
	Uptime      string `json:"uptime,omitempty"`
	CPUPct      string `json:"cpu_utilization,omitempty"`
	MemPct      string `json:"memory_utilization,omitempty"`
	Environment string `json:"environment_status,omitempty"`
	StackStatus string `json:"stack_status,omitempty"`
}

type NetworkTelemetry struct {
	TotalInterfaces int `json:"total_interfaces"`
	UpInterfaces    int `json:"up_interfaces"`
	DownInterfaces  int `json:"down_interfaces"`
	ErrorInterfaces int `json:"error_interfaces"`
	TotalRoutes     int `json:"total_routes"`
}

type RedundancyStatus struct {
	HAState    string `json:"ha_state,omitempty"`
	VRRPState  string `json:"vrrp_state,omitempty"`
	VPCState   string `json:"vpc_state,omitempty"`
	STPSummary string `json:"stp_summary,omitempty"`
}

// Regex helpers for extracting telemetry metrics from raw CLI outputs.
var (
	reCPUUtil  = regexp.MustCompile(`(?i)(?:CPU utilization.*?:|cpu-usage is|five minutes:\s*(\d+)%|CPU:\s*(\d+)%|CPU Util \(%\)\s*:\s*(\d+))`)
	reCPUDigit = regexp.MustCompile(`\b(\d{1,3})%`)
	reMemUtil  = regexp.MustCompile(`(?i)(?:memory.*?:|Memory   -\s*Total\s*:\s*\d+.*?Free\s*:\s*\d+|Used:\s*(\d+)%|Free:\s*(\d+)%)`)
	reMemDigit = regexp.MustCompile(`\b(\d{1,3})%`)
	reEnvBad   = regexp.MustCompile(`(?i)\b(?:fault|fail|failed|critical|alarm|error|shutdown)\b`)
	reEnvOK    = regexp.MustCompile(`(?i)\b(?:normal|ok|good|healthy)\b`)
	reVRRPMast = regexp.MustCompile(`(?i)\b(?:master|backup|init)\b`)
	reVPCStatus = regexp.MustCompile(`(?i)peer-link\s+(?:is\s+)?(up|down|ok)`)
)

func runDiag(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var o opsFlags
	var category, format, outputPath string
	var detail bool
	fs := flag.NewFlagSet("netops diag", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, diagUsageText); fs.PrintDefaults() }
	fs.StringVar(&category, "category", "all", "diagnostic category: hardware | interfaces | redundancy | resources | all")
	fs.StringVar(&format, "format", "text", "output format: text | json")
	fs.StringVar(&outputPath, "output", "", "optional file path to write diagnostic report")
	fs.BoolVar(&detail, "detail", false, "display rich human-readable Device Health Card and deep resource inspection")
	o.registerReadOnly(fs)

	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(stdout, diagUsageText)
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

	category = strings.ToLower(strings.TrimSpace(category))
	if category != "hardware" && category != "interfaces" && category != "redundancy" && category != "resources" && category != "all" {
		fmt.Fprintf(stderr, "netops diag: -category must be hardware, interfaces, redundancy, resources, or all, got %q\n", category)
		return task.ExitFatal
	}
	if format != "text" && format != "json" {
		fmt.Fprintf(stderr, "netops diag: -format must be text or json, got %q\n", format)
		return task.ExitFatal
	}

	env, code := newOpsEnv("diag", &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()

	// Build vendor-aware command resolver filtered by category
	cmdResolver := func(dev inventory.Device) ([]string, error) {
		cmds, err := catalog.GetCommands(dev.Vendor)
		if err != nil {
			return nil, err
		}
		if category == "all" {
			return cmds, nil
		}

		var filtered []string
		for _, c := range cmds {
			cLower := strings.ToLower(c)
			switch category {
			case "hardware":
				if strings.Contains(cLower, "cpu") || strings.Contains(cLower, "memory") ||
					strings.Contains(cLower, "version") || strings.Contains(cLower, "env") ||
					strings.Contains(cLower, "temp") || strings.Contains(cLower, "fan") ||
					strings.Contains(cLower, "power") || strings.Contains(cLower, "chassis") ||
					strings.Contains(cLower, "device") || strings.Contains(cLower, "switch") ||
					strings.Contains(cLower, "system") {
					filtered = append(filtered, c)
				}
			case "resources":
				if strings.Contains(cLower, "cpu") || strings.Contains(cLower, "memory") ||
					strings.Contains(cLower, "mem") || strings.Contains(cLower, "flash") ||
					strings.Contains(cLower, "file system") || strings.Contains(cLower, "env") ||
					strings.Contains(cLower, "temp") || strings.Contains(cLower, "fan") ||
					strings.Contains(cLower, "power") || strings.Contains(cLower, "inventory") ||
					strings.Contains(cLower, "version") || strings.Contains(cLower, "system") {
					filtered = append(filtered, c)
				}
			case "interfaces":
				if strings.Contains(cLower, "int") || strings.Contains(cLower, "route") ||
					strings.Contains(cLower, "trunk") || strings.Contains(cLower, "lacp") ||
					strings.Contains(cLower, "eth-trunk") || strings.Contains(cLower, "port") ||
					strings.Contains(cLower, "vlan") || strings.Contains(cLower, "vrf") {
					filtered = append(filtered, c)
				}
			case "redundancy":
				if strings.Contains(cLower, "vrrp") || strings.Contains(cLower, "standby") ||
					strings.Contains(cLower, "vpc") || strings.Contains(cLower, "stp") ||
					strings.Contains(cLower, "spanning") || strings.Contains(cLower, "cluster") ||
					strings.Contains(cLower, "ha") || strings.Contains(cLower, "failover") {
					filtered = append(filtered, c)
				}
			}
		}
		if len(filtered) == 0 {
			filtered = cmds // fallback to full list if filter yielded no subset
		}
		return filtered, nil
	}

	jobs, err := task.BuildJobs(env.devs, cmdResolver)
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
	env.log.Infof("", "%d device(s) selected, %d runnable; category=%s, concurrency=%d (operational diagnostics)", len(jobs), n, category, o.concurrency)

	opts := env.options()
	opts.OpMode, opts.Format = true, "json"
	r := &task.Runner{Transport: env.tr, Log: env.log, Opts: opts}
	results := r.Run(env.ctx, jobs)

	// Process and synthesize harvested diagnostics
	diags := make([]DeviceDiagnostics, 0, len(results))
	for _, res := range results {
		d := DeviceDiagnostics{
			Hostname: res.Device.Hostname,
			Address:  res.Device.Address,
			Vendor:   res.Device.Vendor,
			Status:   res.Status.String(),
		}

		if prof, ok := vendor.Lookup(res.Device.Vendor); ok {
			if f, ok := prof.Facts(); ok {
				// Combine all outputs into one capture block for facts driver
				var combined strings.Builder
				for cmdLine, rawOut := range res.RawOutput {
					combined.WriteString(fmt.Sprintf("=== %s ===\n%s\n", cmdLine, rawOut))
				}
				facts := f.ParseFacts(combined.String())
				d.Hardware.Model = facts.Model
				d.Hardware.Serial = facts.Serial
				d.Hardware.Version = facts.Version
				d.Hardware.Uptime = facts.Uptime
			}
		}

		// Inspect outputs for CPU, RAM, Environment, Interfaces, Redundancy
		for cmdLine, text := range res.RawOutput {
			lineLower := strings.ToLower(cmdLine)

			// CPU
			if strings.Contains(lineLower, "cpu") {
				if m := reCPUDigit.FindStringSubmatch(text); len(m) > 1 {
					d.Hardware.CPUPct = m[1] + "%"
				}
			}
			// Memory
			if strings.Contains(lineLower, "memory") || strings.Contains(lineLower, "mem") {
				if m := reMemDigit.FindStringSubmatch(text); len(m) > 1 {
					d.Hardware.MemPct = m[1] + "%"
				}
			}
			// Environment
			if strings.Contains(lineLower, "env") || strings.Contains(lineLower, "temp") || strings.Contains(lineLower, "fan") || strings.Contains(lineLower, "power") {
				cleanedText := regexp.MustCompile(`(?i)Shutdown\s*\(Celsius\)`).ReplaceAllString(text, "")
				if reEnvBad.MatchString(cleanedText) {
					d.Hardware.Environment = "ALERT"
				} else if reEnvOK.MatchString(cleanedText) && d.Hardware.Environment == "" {
					d.Hardware.Environment = "OK"
				}
			}
			// Stack
			if strings.Contains(lineLower, "switch") || strings.Contains(lineLower, "stack") || strings.Contains(lineLower, "virtual-chassis") {
				if strings.Contains(strings.ToLower(text), "ready") || strings.Contains(strings.ToLower(text), "master") {
					d.Hardware.StackStatus = "Ready"
				}
			}
			// Interfaces parsing
			if parsed, ok := parser.ParseInterfaceBrief(text); ok && len(parsed) > d.Network.TotalInterfaces {
				d.Network.TotalInterfaces = len(parsed)
				d.Network.UpInterfaces = 0
				d.Network.DownInterfaces = 0
				d.Network.ErrorInterfaces = 0
				for _, intf := range parsed {
					statusLower := strings.ToLower(intf.Status)
					if strings.Contains(statusLower, "up") {
						d.Network.UpInterfaces++
					} else {
						d.Network.DownInterfaces++
					}
					if strings.Contains(statusLower, "err") || strings.Contains(statusLower, "down (error)") {
						d.Network.ErrorInterfaces++
					}
				}
			}
			// Routes
			if routes, ok := parser.ParseRouteTable(text); ok && len(routes) > d.Network.TotalRoutes {
				d.Network.TotalRoutes = len(routes)
			}
			// Redundancy
			if strings.Contains(lineLower, "vrrp") || strings.Contains(lineLower, "standby") {
				if m := reVRRPMast.FindString(text); m != "" {
					d.Redundancy.VRRPState = strings.ToUpper(m)
				}
			}
			if strings.Contains(lineLower, "vpc") {
				if strings.Contains(strings.ToLower(text), "peer-link is up") || strings.Contains(strings.ToLower(text), "peer-link ok") {
					d.Redundancy.VPCState = "OK"
				}
			}
			if strings.Contains(lineLower, "ha") || strings.Contains(lineLower, "failover") || strings.Contains(lineLower, "cluster") {
				if strings.Contains(strings.ToLower(text), "active") || strings.Contains(strings.ToLower(text), "standby") || strings.Contains(strings.ToLower(text), "sync") {
					d.Redundancy.HAState = "Active/Sync"
				}
			}
		}

		// Parse comprehensive HealthCard & ResourceInspection
		d.HealthCard = parser.ParseDeviceHealthCard(res.Device.Vendor, res.Device.Hostname, res.Device.Address, res.RawOutput)
		d.Resources = d.HealthCard.Resources

		if d.HealthCard.Model != "-" && d.Hardware.Model == "" {
			d.Hardware.Model = d.HealthCard.Model
		}
		if d.HealthCard.OSVersion != "-" && d.Hardware.Version == "" {
			d.Hardware.Version = d.HealthCard.OSVersion
		}
		if d.HealthCard.Uptime != "-" && d.Hardware.Uptime == "" {
			d.Hardware.Uptime = d.HealthCard.Uptime
		}
		if d.Resources.CPUUtilization5s != "-" && strings.HasSuffix(d.Resources.CPUUtilization5s, "%") {
			d.Hardware.CPUPct = d.Resources.CPUUtilization5s
		} else if d.Resources.CPUUtilization5m != "-" && (d.Hardware.CPUPct == "" || d.Hardware.CPUPct == "-") {
			d.Hardware.CPUPct = d.Resources.CPUUtilization5m
		} else if d.Resources.CPUUtilization5s != "-" && (d.Hardware.CPUPct == "" || d.Hardware.CPUPct == "-") {
			d.Hardware.CPUPct = d.Resources.CPUUtilization5s
		}
		if d.Resources.MemoryUsedPct > 0 {
			d.Hardware.MemPct = fmt.Sprintf("%.1f%%", d.Resources.MemoryUsedPct)
		}

		// Structured vitals evaluation
		hasBadVital := false
		hasGoodVital := false
		for _, t := range d.Resources.Temperatures {
			if strings.EqualFold(t.Status, "ALERT") || strings.EqualFold(t.Status, "FAIL") || strings.EqualFold(t.Status, "CRITICAL") || strings.EqualFold(t.Status, "ALARM") || strings.EqualFold(t.Status, "FAULT") {
				hasBadVital = true
			} else if strings.EqualFold(t.Status, "OK") || strings.EqualFold(t.Status, "NORMAL") || strings.EqualFold(t.Status, "GOOD") {
				hasGoodVital = true
			}
		}
		for _, f := range d.Resources.Fans {
			if strings.EqualFold(f.Status, "ALERT") || strings.EqualFold(f.Status, "FAIL") || strings.EqualFold(f.Status, "FAULT") || strings.EqualFold(f.Status, "NOT OPERATIONAL") || strings.EqualFold(f.Status, "ABNORMAL") {
				hasBadVital = true
			} else if strings.EqualFold(f.Status, "OK") || strings.EqualFold(f.Status, "NORMAL") {
				hasGoodVital = true
			}
		}
		for _, p := range d.Resources.PowerSupplies {
			if strings.EqualFold(p.Status, "ALERT") || strings.EqualFold(p.Status, "FAIL") || strings.EqualFold(p.Status, "FAULT") || strings.EqualFold(p.Status, "NOT OPERATIONAL") {
				hasBadVital = true
			} else if strings.EqualFold(p.Status, "OK") || strings.EqualFold(p.Status, "NORMAL") {
				hasGoodVital = true
			}
		}
		if hasBadVital {
			d.Hardware.Environment = "ALERT"
		} else if hasGoodVital {
			d.Hardware.Environment = "OK"
		}

		if d.HealthCard.StackStatus != "-" && (d.Redundancy.HAState == "" || d.Redundancy.HAState == "-") {
			if strings.Contains(d.HealthCard.StackStatus, "Standalone") {
				d.Redundancy.HAState = "Standalone"
			} else if strings.Contains(d.HealthCard.StackStatus, "VSU") {
				d.Redundancy.HAState = "VSU"
			} else {
				d.Redundancy.HAState = d.HealthCard.StackStatus
			}
		}

		// Defaults for empty telemetry fields
		if d.Hardware.CPUPct == "" {
			d.Hardware.CPUPct = "-"
		}
		if d.Hardware.MemPct == "" {
			d.Hardware.MemPct = "-"
		}
		if d.Hardware.Environment == "" {
			d.Hardware.Environment = "OK"
		}
		if d.Redundancy.VRRPState == "" && d.Redundancy.HAState == "" && d.Redundancy.VPCState == "" {
			d.Redundancy.HAState = "-"
		}

		diags = append(diags, d)
	}

	// Render output
	if format == "json" {
		data, err := json.MarshalIndent(diags, "", "  ")
		if err != nil {
			return env.die("encoding json: %v", err)
		}
		fmt.Fprintln(stdout, string(data))
		if outputPath != "" {
			_ = os.WriteFile(outputPath, data, 0o644)
		}
	} else {
		// If detail requested or single device query, display comprehensive Health Card
		if detail || (len(diags) == 1 && category != "interfaces" && category != "redundancy") {
			for _, d := range diags {
				renderHealthCard(stdout, d.HealthCard)
			}
		}

		headers := []string{"DEVICE", "VENDOR", "STATUS", "CPU", "MEM", "ENV", "INTERFACES (UP/TOTAL)", "ROUTES", "REDUNDANCY"}
		var rows [][]string
		for _, d := range diags {
			intfStr := fmt.Sprintf("%d/%d", d.Network.UpInterfaces, d.Network.TotalInterfaces)
			if d.Network.TotalInterfaces == 0 {
				intfStr = "-"
			}
			routeStr := fmt.Sprintf("%d", d.Network.TotalRoutes)
			if d.Network.TotalRoutes == 0 {
				routeStr = "-"
			}
			redunStr := d.Redundancy.HAState
			if d.Redundancy.VRRPState != "" {
				redunStr = "VRRP:" + d.Redundancy.VRRPState
			} else if d.Redundancy.VPCState != "" {
				redunStr = "vPC:" + d.Redundancy.VPCState
			}

			rows = append(rows, []string{
				d.Hostname,
				d.Vendor,
				d.Status,
				d.Hardware.CPUPct,
				d.Hardware.MemPct,
				d.Hardware.Environment,
				intfStr,
				routeStr,
				redunStr,
			})
		}
		fmt.Fprintf(stdout, "\n=== NETOPS OPERATIONAL HEALTH & DIAGNOSTIC MATRIX ===\n\n")
		renderTable(stdout, headers, rows)
	}

	return env.finish(results)
}

func renderHealthCard(w io.Writer, card parser.DeviceHealthCard) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "========================================================================================\n")
	fmt.Fprintf(w, "%s - %s (%s):\n", card.Hostname, card.Model, card.Address)
	fmt.Fprintf(w, "========================================================================================\n")
	fmt.Fprintf(w, "Model / Vendor:    %s (%s)\n", card.Model, strings.ToUpper(card.Vendor))
	if card.OSVersion != "-" {
		fmt.Fprintf(w, "Firmware / OS:     %s\n", card.OSVersion)
	}
	fmt.Fprintf(w, "Uptime:            %s\n", card.Uptime)
	if card.RestartTime != "-" {
		fmt.Fprintf(w, "System Restarted:  %s\n", card.RestartTime)
	}
	if card.LastReload != "-" {
		fmt.Fprintf(w, "Last Reload:       %s\n", card.LastReload)
	}

	cpuLine := fmt.Sprintf("%s, utilization ~%s (5s: %s, 1p: %s, 5p: %s)",
		card.Resources.CPUHealthStatus,
		card.Resources.CPUUtilization5m,
		card.Resources.CPUUtilization5s,
		card.Resources.CPUUtilization1m,
		card.Resources.CPUUtilization5m,
	)
	fmt.Fprintf(w, "CPU:               %s\n", cpuLine)

	if card.PortSummary != "-" {
		fmt.Fprintf(w, "Network Ports:     %s\n", card.PortSummary)
	}
	if card.PowerAndFans != "-" {
		fmt.Fprintf(w, "Power & Fans:      %s\n", card.PowerAndFans)
	}
	if card.Licensing != "-" {
		fmt.Fprintf(w, "Licensing:         %s\n", card.Licensing)
	}
	if card.StackStatus != "-" {
		fmt.Fprintf(w, "Stack / HA:        %s\n", card.StackStatus)
	}
	if card.ConfigRegister != "-" {
		fmt.Fprintf(w, "Config Register:   %s\n", card.ConfigRegister)
	}

	fmt.Fprintf(w, "\n----------------------------------------------------------------------------------------\n")
	fmt.Fprintf(w, "RESOURCE INSPECTION & VITALS (Compute, Memory & Environment):\n")
	fmt.Fprintf(w, "----------------------------------------------------------------------------------------\n")
	fmt.Fprintf(w, "• CPU:             %s (5s) | %s (1m) | %s (5m) — [STATUS: %s]\n",
		card.Resources.CPUUtilization5s,
		card.Resources.CPUUtilization1m,
		card.Resources.CPUUtilization5m,
		card.Resources.CPUHealthStatus,
	)

	if card.Resources.MemoryTotalBytes > 0 {
		fmt.Fprintf(w, "• Memory (RAM):    Total: %s | Used: %s (%.1f%%) | Free: %s (%.1f%%)\n",
			parser.FormatBytes(card.Resources.MemoryTotalBytes),
			parser.FormatBytes(card.Resources.MemoryUsedBytes),
			card.Resources.MemoryUsedPct,
			parser.FormatBytes(card.Resources.MemoryFreeBytes),
			100.0-card.Resources.MemoryUsedPct,
		)
	}

	if card.Resources.StorageTotalBytes > 0 {
		fmt.Fprintf(w, "• Storage (Flash): Total: %s | Used: %s (%.1f%%) | Free: %s (%.1f%%)\n",
			parser.FormatBytes(card.Resources.StorageTotalBytes),
			parser.FormatBytes(card.Resources.StorageUsedBytes),
			card.Resources.StorageUsedPct,
			parser.FormatBytes(card.Resources.StorageFreeBytes),
			100.0-card.Resources.StorageUsedPct,
		)
	}

	if len(card.Resources.Temperatures) > 0 {
		fmt.Fprintf(w, "• Environment & Temperature:\n")
		for _, t := range card.Resources.Temperatures {
			statusTag := fmt.Sprintf("[%s]", t.Status)
			fmt.Fprintf(w, "  - %-15s: %d°C %s\n", t.Name, t.ValueC, statusTag)
		}
	}

	if len(card.Resources.Fans) > 0 {
		fmt.Fprintf(w, "• Cooling Fans:\n")
		for _, f := range card.Resources.Fans {
			dir := ""
			if f.Direction != "" {
				dir = " - " + f.Direction
			}
			if f.RPM > 0 {
				fmt.Fprintf(w, "  - %-15s: %d RPM [%s%s]\n", f.Name, f.RPM, f.Status, dir)
			} else {
				fmt.Fprintf(w, "  - %-15s: [%s%s]\n", f.Name, f.Status, dir)
			}
		}
	}

	if len(card.Resources.PowerSupplies) > 0 {
		fmt.Fprintf(w, "• Power Supplies (PSU):\n")
		for _, p := range card.Resources.PowerSupplies {
			wattsStr := ""
			if p.Watts > 0 {
				wattsStr = fmt.Sprintf(" - %dW", p.Watts)
			}
			snStr := ""
			if p.Serial != "" {
				snStr = fmt.Sprintf(" (S/N: %s)", p.Serial)
			}
			fmt.Fprintf(w, "  - %-15s: %s%s [%s%s]\n", p.Slot, p.Model, snStr, p.Status, wattsStr)
		}
	}
	fmt.Fprintf(w, "========================================================================================\n")
}

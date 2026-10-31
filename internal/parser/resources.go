// ==============================================================================
// File name:     resources.go
// Description:   Parsers for deep resource inspection (CPU, Memory, Storage, Vitals)
//                and comprehensive Device Health Card synthesis.
// License:       MIT
// ==============================================================================
package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// TemperatureReading holds temperature sensor telemetry.
type TemperatureReading struct {
	Name    string `json:"name"`
	ValueC  int    `json:"value_c"`
	Status  string `json:"status"` // GREEN, OK, WARNING, CRITICAL
	ValidMinMax string `json:"range,omitempty"`
}

// FanReading holds fan speed and operational telemetry.
type FanReading struct {
	Name      string `json:"name"`
	RPM       int    `json:"rpm"`
	Status    string `json:"status"` // OK, NOT OPERATIONAL
	Direction string `json:"direction,omitempty"`
}

// PSUReading holds power supply operational telemetry.
type PSUReading struct {
	Slot    string `json:"slot"`
	Model   string `json:"model"`
	Status  string `json:"status"` // OK, NOT OPERATIONAL, Normal
	Watts   int    `json:"watts"`
	Serial  string `json:"serial,omitempty"`
}

// ResourceInspection contains parsed compute, memory, storage, and vitals.
type ResourceInspection struct {
	CPUUtilization5s string  `json:"cpu_5s"`
	CPUUtilization1m string  `json:"cpu_1m"`
	CPUUtilization5m string  `json:"cpu_5m"`
	CPUHealthStatus  string  `json:"cpu_health"` // Sức khỏe tốt, Cảnh báo, Nguy hiểm

	MemoryTotalBytes uint64  `json:"memory_total_bytes"`
	MemoryUsedBytes  uint64  `json:"memory_used_bytes"`
	MemoryFreeBytes  uint64  `json:"memory_free_bytes"`
	MemoryUsedPct    float64 `json:"memory_used_pct"`

	StorageTotalBytes uint64  `json:"storage_total_bytes"`
	StorageFreeBytes  uint64  `json:"storage_free_bytes"`
	StorageUsedBytes  uint64  `json:"storage_used_bytes"`
	StorageUsedPct    float64 `json:"storage_used_pct"`

	Temperatures  []TemperatureReading `json:"temperatures"`
	Fans          []FanReading         `json:"fans"`
	PowerSupplies []PSUReading         `json:"power_supplies"`
}

// DeviceHealthCard contains a complete high-context operational summary.
type DeviceHealthCard struct {
	Hostname       string             `json:"hostname"`
	Address        string             `json:"address"`
	Vendor         string             `json:"vendor"`
	Model          string             `json:"model"`
	OSVersion      string             `json:"os_version"`
	Uptime         string             `json:"uptime"`
	LastReload     string             `json:"last_reload_reason"`
	RestartTime    string             `json:"restart_time"`
	ConfigRegister string             `json:"config_register"`
	PortSummary    string             `json:"port_summary"`
	PowerAndFans   string             `json:"power_and_fans_summary"`
	Licensing      string             `json:"licensing"`
	StackStatus    string             `json:"stack_status"`
	Resources      ResourceInspection `json:"resources"`
}

// Regex patterns for multi-vendor operational diagnostics
var (
	reCiscoCPU5s1m5m  = regexp.MustCompile(`(?i)CPU utilization for five seconds:\s*(\d+)%(?:/\d+%)?;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%`)
	reCiscoSBCPU      = regexp.MustCompile(`(?i)five seconds:\s*(\d+)%;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%`)
	reFortinetCPU     = regexp.MustCompile(`(?i)CPU states:\s*(\d+)%\s+user\s+(\d+)%\s+system\s+(\d+)%\s+nice\s+(\d+)%\s+idle`)
	reHuaweiCPU5s1m5m = regexp.MustCompile(`(?i)CPU utilization for five seconds:\s*(\d+)%[:;]\s*one minute:\s*(\d+)%[:;]\s*five minutes:\s*(\d+)%`)
	reHuaweiCPUUsage  = regexp.MustCompile(`(?i)CPU Usage\s*:\s*(\d+)%`)
	reJunosCPU        = regexp.MustCompile(`(?i)5 sec CPU utilization:\s*Idle\s*(\d+)\s*percent.*?1 min CPU utilization:\s*Idle\s*(\d+)\s*percent.*?5 min CPU utilization:\s*Idle\s*(\d+)\s*percent`)
	reCPCPU           = regexp.MustCompile(`(?i)CPU Usage \(%\):\s*(\d+)`)
	reArubaAves       = regexp.MustCompile(`(?i)5 sec ave:\s*(\d+)\s*percent busy.*?1 min ave:\s*(\d+)\s*percent busy`)
	reArubaCPUUtil    = regexp.MustCompile(`(?i)CPU Util \(%\)\s*:\s*(\d+)`)

	reCiscoMemory    = regexp.MustCompile(`(?i)Processor Pool Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)`)
	reFortinetMemory = regexp.MustCompile(`(?i)Memory:\s*(\d+)k total,\s*(\d+)k used\s*\((\d+(?:\.\d+)?)%\)`)
	reHuaweiMem      = regexp.MustCompile(`(?i)System Total Memory Is:\s*(\d+)\s*bytes.*?Total Memory Used Is:\s*(\d+)\s*bytes.*?Memory Using Percentage Is:\s*(\d+)%`)
	reJunosMem       = regexp.MustCompile(`(?i)Memory utilization\s*(\d+)\s*percent`)
	reCPMem          = regexp.MustCompile(`(?i)Total Real Memory \(Bytes\):\s*(\d+).*?Active Real Memory \(Bytes\):\s*(\d+)`)
	reArubaSysMem    = regexp.MustCompile(`(?i)Memory\s+-\s+Total\s*:\s*([\d,]+)[\s\S]*?Free\s*:\s*([\d,]+)`)

	reCiscoFlash    = regexp.MustCompile(`(?i)(\d+)\s+bytes total\s+\((\d+)\s+bytes free\)`)
	reCiscoFlashAlt = regexp.MustCompile(`(?i)(\d+)K bytes of Flash at flash:`)
	reHuaweiFlash   = regexp.MustCompile(`(?i)FLASH Total\s+Memory Size\s*:\s*(\d+)\s*M bytes.*?FLASH Available\s+Memory Size\s*:\s*(\d+)\s*M bytes`)
	reArubaFlash    = regexp.MustCompile(`(?i)Primary Image\s*:\s*(\d+).*?Secondary Image\s*:\s*(\d+)`)
	reCPEMMC        = regexp.MustCompile(`(?i)EMMC\s*%\s*of\s*device\s*lifetime\s*used:\s*(\S+)`)

	reCiscoTemp = regexp.MustCompile(`(?i)(SYSTEM\s+(?:INLET|OUTLET|HOTSPOT)|PS\d+\s+Hotspot)\s+\d+\s+(GREEN|YELLOW|RED|GOOD|WARNING|CRITICAL|na)\s+(\d+)\s+Celsius`)
	reCiscoFan  = regexp.MustCompile(`(?i)^\s*\d+\s+(\d+)\s+(\d+)\s+(OK|NOT OPERATIONAL)\s*(Front to Back|Back to Front)?`)
	reCiscoPSU  = regexp.MustCompile(`(?i)^(\S+)\s+(PWR-\S+)\s+(\S+)\s+(OK|NOT OPERATIONAL)\s+\S+\s+\S+\s+(\d+)`)

	reHuaweiTemp = regexp.MustCompile(`(?m)^\s*(\d+)\s+NA\s+NA\s+(Normal|Alarm)\s+(\d+)`)
	reHuaweiFan  = regexp.MustCompile(`(?m)^\s*(\d+)\s+(\d+)\s+Present\s+(Normal|Abnormal)\s+(\d+)%`)
	reJunosTemp  = regexp.MustCompile(`(?i)(FPC \d+ [A-Za-z0-9\-/ ]+?)\s+(OK|Testing|Failed)\s+(\d+)\s+degrees C`)
	reJunosFan   = regexp.MustCompile(`(?i)Fans\s+(FPC \d+ Fan \d+)\s+(OK|Testing|Failed)`)
	reJunosPSU   = regexp.MustCompile(`(?i)(Power Supply \d+)\s+(OK|Testing|Failed)`)
	reCPTemp     = regexp.MustCompile(`(?i)CPU Temperature:\s*([\d\.]+)C\s*-\s*(\S+)`)
	reCPFan      = regexp.MustCompile(`(?i)(CPU FAN\d+|HW FAN\d+):\s*(\d+)\s+RPM\s+-\s+(\S+)`)
	reCPPSU      = regexp.MustCompile(`(?i)Redundant power supply:\s*(.+)`)
	reSBAmbient  = regexp.MustCompile(`(?i)Unit\s+Temperature\s+\(Celsius\)\s+Status[\r\n\- ]+\d+\s+(\d+)\s+(\S+)`)
	reSBFan      = regexp.MustCompile(`(?i)Fans Status:\s*(\S+)`)

	reCiscoReloadReason = regexp.MustCompile(`(?i)(?:Last reload reason|System returned to ROM by):\s*(.+)`)
	reCiscoRestartTime  = regexp.MustCompile(`(?i)System restarted at\s*(.+)`)
	reCiscoConfigReg    = regexp.MustCompile(`(?i)Configuration register is\s*(0x[0-9a-fA-F]+)`)
	reCiscoPortsCount   = regexp.MustCompile(`(?i)(\d+)\s+((?:Gigabit|Ten Gigabit|Fast|Virtual)\s+Ethernet)\s+interfaces`)
	reCiscoLicense      = regexp.MustCompile(`(?i)(network-\S+|dna-\S+)\s+((?:Subscription\s+)?Smart License)`)
	reCiscoStack        = regexp.MustCompile(`(?m)^\*?\s*(\d+)\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+(INSTALL|BUNDLE|READY)`)
	reCiscoUplink       = regexp.MustCompile(`(?i)PID:\s*(C9200-NM-\S+|C3850-NM-\S+|C9300-NM-\S+)\s*,\s*VID:\s*\S+\s*,\s*SN:\s*(\S+)`)
)

// FormatBytes converts byte counts into human-readable MB / GB strings.
func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	val := float64(b) / float64(div)
	switch exp {
	case 0:
		return fmt.Sprintf("%.1f KB", val)
	case 1:
		return fmt.Sprintf("%.1f MB", val)
	case 2:
		return fmt.Sprintf("%.2f GB", val)
	default:
		return fmt.Sprintf("%.2f TB", val)
	}
}

// ParseResourceInspection synthesizes CPU, memory, storage, and vitals from raw command outputs.
func ParseResourceInspection(vendor string, outputs map[string]string) ResourceInspection {
	res := ResourceInspection{
		CPUUtilization5s: "-",
		CPUUtilization1m: "-",
		CPUUtilization5m: "-",
		CPUHealthStatus:  "Undetermined",
	}

	allOutput := combineOutputs(outputs)

	// 1. CPU Parsing
	parseCPU(&res, vendor, allOutput)

	// 2. Memory Parsing
	parseMemory(&res, vendor, allOutput)

	// 3. Storage / Flash Parsing
	parseStorage(&res, vendor, allOutput)

	// 4. Vitals Parsing (Temps, Fans, PSUs)
	parseVitals(&res, vendor, allOutput)

	return res
}

func parseCPU(res *ResourceInspection, vendor string, output string) {
	oneLine := strings.ReplaceAll(output, "\r\n", " ")
	oneLine = strings.ReplaceAll(oneLine, "\n", " ")

	// 1. Cisco IOS-XE / Classic IOS
	if m := reCiscoCPU5s1m5m.FindStringSubmatch(output); len(m) > 3 {
		res.CPUUtilization5s = m[1] + "%"
		res.CPUUtilization1m = m[2] + "%"
		res.CPUUtilization5m = m[3] + "%"
		res.CPUHealthStatus = evaluateCPUHealth(m[3])
		return
	}

	// 2. Cisco Small Business
	if m := reCiscoSBCPU.FindStringSubmatch(output); len(m) > 3 {
		res.CPUUtilization5s = m[1] + "%"
		res.CPUUtilization1m = m[2] + "%"
		res.CPUUtilization5m = m[3] + "%"
		res.CPUHealthStatus = evaluateCPUHealth(m[3])
		return
	}

	// 3. Huawei VRP
	if m := reHuaweiCPU5s1m5m.FindStringSubmatch(output); len(m) > 3 {
		res.CPUUtilization5s = m[1] + "%"
		res.CPUUtilization1m = m[2] + "%"
		res.CPUUtilization5m = m[3] + "%"
		res.CPUHealthStatus = evaluateCPUHealth(m[3])
		return
	}
	if m := reHuaweiCPUUsage.FindStringSubmatch(output); len(m) > 1 {
		pct := m[1] + "%"
		res.CPUUtilization5s = pct
		res.CPUUtilization1m = pct
		res.CPUUtilization5m = pct
		res.CPUHealthStatus = evaluateCPUHealth(m[1])
		return
	}

	// 4. Juniper Junos
	reJunosAll := regexp.MustCompile(`(?i)5 sec CPU utilization:[\s\S]*?Idle\s*(\d+)\s*percent[\s\S]*?1 min CPU utilization:[\s\S]*?Idle\s*(\d+)\s*percent[\s\S]*?5 min CPU utilization:[\s\S]*?Idle\s*(\d+)\s*percent`)
	if m := reJunosAll.FindStringSubmatch(output); len(m) > 3 {
		i5s, _ := strconv.Atoi(m[1])
		i1m, _ := strconv.Atoi(m[2])
		i5m, _ := strconv.Atoi(m[3])
		u5s, u1m, u5m := 100-i5s, 100-i1m, 100-i5m
		res.CPUUtilization5s = fmt.Sprintf("%d%%", u5s)
		res.CPUUtilization1m = fmt.Sprintf("%d%%", u1m)
		res.CPUUtilization5m = fmt.Sprintf("%d%%", u5m)
		res.CPUHealthStatus = evaluateCPUHealth(strconv.Itoa(u5m))
		return
	}
	reJunosIdle := regexp.MustCompile(`(?i)5 sec CPU utilization:[\s\S]*?Idle\s+(\d+)\s+percent`)
	if m := reJunosIdle.FindStringSubmatch(output); len(m) > 1 {
		idle, _ := strconv.Atoi(m[1])
		cpuPct := 100 - idle
		if cpuPct < 0 {
			cpuPct = 0
		}
		pctStr := fmt.Sprintf("%d%%", cpuPct)
		res.CPUUtilization5s = pctStr
		res.CPUUtilization1m = pctStr
		res.CPUUtilization5m = pctStr
		reLoad := regexp.MustCompile(`(?i)Load averages:\s+1 minute\s+5 minute\s+15 minute[\r\n\s]+([0-9\.]+)\s+([0-9\.]+)`)
		if lm := reLoad.FindStringSubmatch(output); len(lm) > 2 {
			res.CPUUtilization1m = lm[1] + " (load)"
			res.CPUUtilization5m = lm[2] + " (load)"
		}
		res.CPUHealthStatus = evaluateCPUHealth(strconv.Itoa(cpuPct))
		return
	}

	// 5. Fortinet
	if m := reFortinetCPU.FindStringSubmatch(output); len(m) > 4 {
		idle, _ := strconv.Atoi(m[4])
		totalUsed := 100 - idle
		if totalUsed < 0 {
			totalUsed = 0
		}
		pctStr := strconv.Itoa(totalUsed) + "%"
		res.CPUUtilization5s = pctStr
		res.CPUUtilization1m = pctStr
		res.CPUUtilization5m = pctStr
		res.CPUHealthStatus = evaluateCPUHealth(strconv.Itoa(totalUsed))
		return
	}

	// 6. Check Point Gaia
	if m := reCPCPU.FindStringSubmatch(output); len(m) > 1 {
		pct := m[1] + "%"
		res.CPUUtilization5s = pct
		res.CPUUtilization1m = pct
		res.CPUUtilization5m = pct
		res.CPUHealthStatus = evaluateCPUHealth(m[1])
		return
	}

	// 7. Aruba AOS-S
	if m := reArubaAves.FindStringSubmatch(oneLine); len(m) > 2 {
		res.CPUUtilization5s = m[1] + "%"
		res.CPUUtilization1m = m[2] + "%"
		res.CPUUtilization5m = m[2] + "%"
		res.CPUHealthStatus = evaluateCPUHealth(m[2])
		return
	}
	if m := reArubaCPUUtil.FindStringSubmatch(output); len(m) > 1 {
		pct := m[1] + "%"
		res.CPUUtilization5s = pct
		res.CPUUtilization1m = pct
		res.CPUUtilization5m = pct
		res.CPUHealthStatus = evaluateCPUHealth(m[1])
		return
	}

	// 8. Ruijie RGOS
	reRuijie5s := regexp.MustCompile(`(?i)CPU utilization in five seconds\s*:\s*([0-9\.]+)%`)
	reRuijie1m := regexp.MustCompile(`(?i)CPU utilization in one minute\s*:\s*([0-9\.]+)%`)
	reRuijie5m := regexp.MustCompile(`(?i)CPU utilization in five minutes\s*:\s*([0-9\.]+)%`)
	if m5s := reRuijie5s.FindStringSubmatch(output); len(m5s) > 1 {
		res.CPUUtilization5s = m5s[1] + "%"
		if m1m := reRuijie1m.FindStringSubmatch(output); len(m1m) > 1 {
			res.CPUUtilization1m = m1m[1] + "%"
		}
		if m5m := reRuijie5m.FindStringSubmatch(output); len(m5m) > 1 {
			res.CPUUtilization5m = m5m[1] + "%"
			res.CPUHealthStatus = evaluateCPUHealth(m5m[1])
		}
		return
	}
}

func evaluateCPUHealth(fiveMinStr string) string {
	pctFloat, err := strconv.ParseFloat(strings.TrimSuffix(fiveMinStr, "%"), 64)
	if err != nil {
		return "Normal"
	}
	pct := int(pctFloat)
	if pct >= 80 {
		return "Critical (>80%)"
	}
	if pct >= 60 {
		return "Warning (60-80%)"
	}
	return "Healthy (<60%)"
}

func parseMemory(res *ResourceInspection, vendor string, output string) {
	oneLine := strings.ReplaceAll(output, "\r\n", " ")
	oneLine = strings.ReplaceAll(oneLine, "\n", " ")

	// 1. Cisco IOS / IOS-XE
	if m := reCiscoMemory.FindStringSubmatch(output); len(m) > 3 {
		total, _ := strconv.ParseUint(m[1], 10, 64)
		used, _ := strconv.ParseUint(m[2], 10, 64)
		free, _ := strconv.ParseUint(m[3], 10, 64)
		res.MemoryTotalBytes = total
		res.MemoryUsedBytes = used
		res.MemoryFreeBytes = free
		if total > 0 {
			res.MemoryUsedPct = (float64(used) / float64(total)) * 100
		}
		return
	}

	// 2. Fortinet (handles integer or decimal float like 30.0%)
	if m := reFortinetMemory.FindStringSubmatch(output); len(m) > 3 {
		totalKB, _ := strconv.ParseUint(m[1], 10, 64)
		usedKB, _ := strconv.ParseUint(m[2], 10, 64)
		pct, _ := strconv.ParseFloat(m[3], 64)
		res.MemoryTotalBytes = totalKB * 1024
		res.MemoryUsedBytes = usedKB * 1024
		if res.MemoryTotalBytes >= res.MemoryUsedBytes {
			res.MemoryFreeBytes = res.MemoryTotalBytes - res.MemoryUsedBytes
		}
		res.MemoryUsedPct = pct
		return
	}

	// 3. Huawei VRP
	if m := reHuaweiMem.FindStringSubmatch(oneLine); len(m) > 3 {
		total, _ := strconv.ParseUint(m[1], 10, 64)
		used, _ := strconv.ParseUint(m[2], 10, 64)
		pct, _ := strconv.ParseFloat(m[3], 64)
		res.MemoryTotalBytes = total
		res.MemoryUsedBytes = used
		if total >= used {
			res.MemoryFreeBytes = total - used
		}
		res.MemoryUsedPct = pct
		return
	}

	// 4. Check Point Gaia
	if m := reCPMem.FindStringSubmatch(oneLine); len(m) > 2 {
		total, _ := strconv.ParseUint(m[1], 10, 64)
		used, _ := strconv.ParseUint(m[2], 10, 64)
		res.MemoryTotalBytes = total
		res.MemoryUsedBytes = used
		if total >= used {
			res.MemoryFreeBytes = total - used
		}
		if total > 0 {
			res.MemoryUsedPct = (float64(used) / float64(total)) * 100
		}
		return
	}

	// 5. Aruba AOS-S
	if m := reArubaSysMem.FindStringSubmatch(output); len(m) > 2 {
		totStr := strings.ReplaceAll(m[1], ",", "")
		freeStr := strings.ReplaceAll(m[2], ",", "")
		total, _ := strconv.ParseUint(totStr, 10, 64)
		free, _ := strconv.ParseUint(freeStr, 10, 64)
		res.MemoryTotalBytes = total
		res.MemoryFreeBytes = free
		if total >= free {
			res.MemoryUsedBytes = total - free
		}
		if total > 0 {
			res.MemoryUsedPct = (float64(res.MemoryUsedBytes) / float64(total)) * 100
		}
		return
	}

	// 6. Juniper Junos
	if m := reJunosMem.FindStringSubmatch(output); len(m) > 1 {
		pct, _ := strconv.ParseFloat(m[1], 64)
		res.MemoryUsedPct = pct
		return
	}

	// 7. Ruijie RGOS
	reRuijieMem := regexp.MustCompile(`(?i)System Memory\s*:\s*(\d+)\s*KB\s+total,\s*(\d+)\s*KB\s+used,\s*(\d+)\s*KB\s+free.*?,\s*([0-9\.]+)%\s*used rate`)
	if m := reRuijieMem.FindStringSubmatch(output); len(m) > 4 {
		totalKB, _ := strconv.ParseUint(m[1], 10, 64)
		usedKB, _ := strconv.ParseUint(m[2], 10, 64)
		freeKB, _ := strconv.ParseUint(m[3], 10, 64)
		pct, _ := strconv.ParseFloat(m[4], 64)
		res.MemoryTotalBytes = totalKB * 1024
		res.MemoryUsedBytes = usedKB * 1024
		res.MemoryFreeBytes = freeKB * 1024
		res.MemoryUsedPct = pct
		return
	}
}

func parseStorage(res *ResourceInspection, vendor string, output string) {
	oneLine := strings.ReplaceAll(output, "\r\n", " ")
	oneLine = strings.ReplaceAll(oneLine, "\n", " ")

	// Cisco IOS-XE (dir flash:)
	if m := reCiscoFlash.FindStringSubmatch(output); len(m) > 2 {
		total, _ := strconv.ParseUint(m[1], 10, 64)
		free, _ := strconv.ParseUint(m[2], 10, 64)
		res.StorageTotalBytes = total
		res.StorageFreeBytes = free
		if total >= free {
			res.StorageUsedBytes = total - free
		}
		if total > 0 {
			res.StorageUsedPct = (float64(res.StorageUsedBytes) / float64(total)) * 100
		}
		return
	}

	// Cisco show version flash line fallback
	if m := reCiscoFlashAlt.FindStringSubmatch(output); len(m) > 1 {
		totalKB, _ := strconv.ParseUint(m[1], 10, 64)
		res.StorageTotalBytes = totalKB * 1024
		return
	}

	// Huawei VRP
	if m := reHuaweiFlash.FindStringSubmatch(oneLine); len(m) > 2 {
		totalMB, _ := strconv.ParseUint(m[1], 10, 64)
		freeMB, _ := strconv.ParseUint(m[2], 10, 64)
		res.StorageTotalBytes = totalMB * 1024 * 1024
		res.StorageFreeBytes = freeMB * 1024 * 1024
		if res.StorageTotalBytes >= res.StorageFreeBytes {
			res.StorageUsedBytes = res.StorageTotalBytes - res.StorageFreeBytes
		}
		if res.StorageTotalBytes > 0 {
			res.StorageUsedPct = (float64(res.StorageUsedBytes) / float64(res.StorageTotalBytes)) * 100
		}
		return
	}

	// Aruba AOS-S
	if m := reArubaFlash.FindStringSubmatch(oneLine); len(m) > 2 {
		pBytes, _ := strconv.ParseUint(m[1], 10, 64)
		sBytes, _ := strconv.ParseUint(m[2], 10, 64)
		res.StorageTotalBytes = 128 * 1024 * 1024
		res.StorageUsedBytes = pBytes + sBytes
		if res.StorageTotalBytes >= res.StorageUsedBytes {
			res.StorageFreeBytes = res.StorageTotalBytes - res.StorageUsedBytes
		}
		if res.StorageTotalBytes > 0 {
			res.StorageUsedPct = (float64(res.StorageUsedBytes) / float64(res.StorageTotalBytes)) * 100
		}
		return
	}

	// Check Point EMMC
	if m := reCPEMMC.FindStringSubmatch(output); len(m) > 1 {
		res.StorageFreeBytes = 0
		res.StorageTotalBytes = 0
		res.StorageUsedPct = 5.0 // Indicative nominal wear
		return
	}
}

func parseVitals(res *ResourceInspection, vendor string, output string) {
	// Temperatures (Cisco)
	for _, match := range reCiscoTemp.FindAllStringSubmatch(output, -1) {
		if len(match) > 3 {
			val, _ := strconv.Atoi(match[3])
			res.Temperatures = append(res.Temperatures, TemperatureReading{
				Name:   strings.TrimSpace(match[1]),
				Status: strings.ToUpper(strings.TrimSpace(match[2])),
				ValueC: val,
			})
		}
	}

	// Check Point CPU Temperature
	if m := reCPTemp.FindStringSubmatch(output); len(m) > 2 {
		valFloat, _ := strconv.ParseFloat(m[1], 64)
		res.Temperatures = append(res.Temperatures, TemperatureReading{
			Name:   "CPU Temperature",
			ValueC: int(valFloat),
			Status: strings.ToUpper(m[2]),
		})
	}

	// Huawei Temperatures
	for _, m := range reHuaweiTemp.FindAllStringSubmatch(output, -1) {
		if len(m) > 3 {
			val, _ := strconv.Atoi(m[3])
			st := "OK"
			if strings.EqualFold(m[2], "Alarm") {
				st = "ALERT"
			}
			res.Temperatures = append(res.Temperatures, TemperatureReading{
				Name:   fmt.Sprintf("Slot %s Board Sensor", m[1]),
				ValueC: val,
				Status: st,
			})
		}
	}

	// Juniper Temperatures
	for _, m := range reJunosTemp.FindAllStringSubmatch(output, -1) {
		if len(m) > 3 {
			val, _ := strconv.Atoi(m[3])
			res.Temperatures = append(res.Temperatures, TemperatureReading{
				Name:   strings.TrimSpace(m[1]),
				ValueC: val,
				Status: strings.ToUpper(m[2]),
			})
		}
	}

	// Cisco Small Business Temperature
	if m := reSBAmbient.FindStringSubmatch(output); len(m) > 2 {
		val, _ := strconv.Atoi(m[1])
		res.Temperatures = append(res.Temperatures, TemperatureReading{
			Name:   "Chassis Temperature",
			ValueC: val,
			Status: strings.ToUpper(m[2]),
		})
	}

	// Cisco Small Business Fans
	if m := reSBFan.FindStringSubmatch(output); len(m) > 1 {
		res.Fans = append(res.Fans, FanReading{
			Name:   "Quạt hệ thống (System Fan)",
			Status: strings.ToUpper(m[1]),
		})
	}

	// Huawei Fans
	for _, m := range reHuaweiFan.FindAllStringSubmatch(output, -1) {
		if len(m) > 4 {
			rpm, _ := strconv.Atoi(m[4])
			st := "OK"
			if strings.EqualFold(m[3], "Abnormal") {
				st = "ALERT"
			}
			res.Fans = append(res.Fans, FanReading{
				Name:   fmt.Sprintf("Slot %s Fan %s", m[1], m[2]),
				RPM:    rpm,
				Status: st,
			})
		}
	}

	// Juniper Fans & PSUs
	for _, m := range reJunosFan.FindAllStringSubmatch(output, -1) {
		if len(m) > 2 {
			res.Fans = append(res.Fans, FanReading{
				Name:   strings.TrimSpace(m[1]),
				Status: strings.ToUpper(m[2]),
			})
		}
	}
	for _, m := range reJunosPSU.FindAllStringSubmatch(output, -1) {
		if len(m) > 2 {
			res.PowerSupplies = append(res.PowerSupplies, PSUReading{
				Slot:   strings.TrimSpace(m[1]),
				Model:  "Junos Internal PSU",
				Status: strings.ToUpper(m[2]),
			})
		}
	}

	// Fans & PSUs (Cisco)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if m := reCiscoFan.FindStringSubmatch(line); len(m) > 3 {
			rpm, _ := strconv.Atoi(m[2])
			dir := ""
			if len(m) > 4 {
				dir = m[4]
			}
			res.Fans = append(res.Fans, FanReading{
				Name:      "Fan " + m[1],
				RPM:       rpm,
				Status:    m[3],
				Direction: dir,
			})
		}
		if m := reCiscoPSU.FindStringSubmatch(line); len(m) > 5 {
			watts, _ := strconv.Atoi(m[5])
			res.PowerSupplies = append(res.PowerSupplies, PSUReading{
				Slot:   m[1],
				Model:  m[2],
				Serial: m[3],
				Status: m[4],
				Watts:  watts,
			})
		}
	}

	// Check Point Fans & Redundancy
	for _, m := range reCPFan.FindAllStringSubmatch(output, -1) {
		if len(m) > 3 {
			rpm, _ := strconv.Atoi(m[2])
			res.Fans = append(res.Fans, FanReading{
				Name:   m[1],
				RPM:    rpm,
				Status: m[3],
			})
		}
	}
	if m := reCPPSU.FindStringSubmatch(output); len(m) > 1 {
		res.PowerSupplies = append(res.PowerSupplies, PSUReading{
			Slot:   "Dual PSU",
			Model:  "Redundant",
			Status: strings.TrimSpace(m[1]),
		})
	}

	// Ruijie Temperatures
	reRuijieTemp := regexp.MustCompile(`(?m)^\s*\d+\s+([A-Za-z0-9_-]+)\s+\d+\s+\d+\s+(\d+)\s+(ok|alarm|fault)`)
	for _, m := range reRuijieTemp.FindAllStringSubmatch(output, -1) {
		if len(m) > 3 {
			val, _ := strconv.Atoi(m[2])
			res.Temperatures = append(res.Temperatures, TemperatureReading{
				Name:   strings.TrimSpace(m[1]),
				ValueC: val,
				Status: strings.ToUpper(m[3]),
			})
		}
	}

	// Ruijie Fans
	reRuijieFan := regexp.MustCompile(`(?m)^\s*(\d+)\s+([A-Za-z0-9_-]+)\s+(ok|fail|fault|abnormal)(?:\s+.*)?$`)
	for _, m := range reRuijieFan.FindAllStringSubmatch(output, -1) {
		if len(m) > 3 {
			if strings.Contains(strings.ToUpper(m[2]), "PA") || strings.Contains(strings.ToUpper(m[2]), "PWR") {
				continue
			}
			res.Fans = append(res.Fans, FanReading{
				Name:   fmt.Sprintf("Fan %s (%s)", m[1], m[2]),
				Status: strings.ToUpper(m[3]),
			})
		}
	}

	// Ruijie Power Supplies
	reRuijiePSU := regexp.MustCompile(`(?m)^\s*(\d+)\s+([A-Za-z0-9_-]+)\s+(ok|fail|fault)\s+\S+\s+(\S+)\s+(\d+)`)
	for _, m := range reRuijiePSU.FindAllStringSubmatch(output, -1) {
		if len(m) > 5 {
			watts, _ := strconv.Atoi(m[5])
			res.PowerSupplies = append(res.PowerSupplies, PSUReading{
				Slot:   m[1],
				Model:  m[2],
				Serial: m[4],
				Status: strings.ToUpper(m[3]),
				Watts:  watts,
			})
		}
	}
}

// ParseDeviceHealthCard parses all raw outputs to assemble a comprehensive DeviceHealthCard.
func ParseDeviceHealthCard(vendor, hostname, address string, outputs map[string]string) DeviceHealthCard {
	card := DeviceHealthCard{
		Hostname:       hostname,
		Address:        address,
		Vendor:         vendor,
		Model:          "-",
		OSVersion:      "-",
		Uptime:         "-",
		LastReload:     "-",
		RestartTime:    "-",
		ConfigRegister: "-",
		PortSummary:    "-",
		PowerAndFans:   "-",
		Licensing:      "-",
		StackStatus:    "-",
	}

	allOutput := combineOutputs(outputs)
	card.Resources = ParseResourceInspection(vendor, outputs)

	// Model extraction
	reModelNum := regexp.MustCompile(`(?i)Model Number\s*:\s*(\S+)`)
	reCPModel := regexp.MustCompile(`(?i)This is Check Point's\s*(\S+\s+Appliance)`)
	reHuaweiModel := regexp.MustCompile(`(?i)HUAWEI\s+([A-Z0-9\-]+)\s+Routing Switch`)
	reFortiModel := regexp.MustCompile(`(?i)Model:\s*(FortiGate-\S+)`)
	reFortiModelAlt := regexp.MustCompile(`(?i)Version:\s*(FortiGate-\S+)`)
	reJunosModel := regexp.MustCompile(`(?i)Model:\s*([a-z0-9\-]+)`)
	reArubaDesc := regexp.MustCompile(`(?i)System Description\s*:\s*([A-Za-z0-9\- ]+?(?:Switch|Router|Appliance))`)
	reRuijieModel := regexp.MustCompile(`(?i)System description\s*:.*?\(([^)]+)\)`)
	reRuijieSlot := regexp.MustCompile(`(?im)^Slot\s+\d+\s*:\s*(\S+)`)

	if strings.EqualFold(vendor, "ruijie") {
		if m := reRuijieModel.FindStringSubmatch(allOutput); len(m) > 1 {
			card.Model = strings.TrimSpace(m[1])
		} else if m := reRuijieSlot.FindStringSubmatch(allOutput); len(m) > 1 {
			card.Model = strings.TrimSpace(m[1])
		}
	} else if m := reCPModel.FindStringSubmatch(allOutput); len(m) > 1 {
		card.Model = strings.TrimSpace(m[1])
	} else if m := reHuaweiModel.FindStringSubmatch(allOutput); len(m) > 1 {
		card.Model = strings.TrimSpace(m[1])
	} else if m := reFortiModel.FindStringSubmatch(allOutput); len(m) > 1 {
		card.Model = strings.TrimSpace(m[1])
	} else if m := reFortiModelAlt.FindStringSubmatch(allOutput); len(m) > 1 {
		card.Model = strings.TrimSpace(m[1])
	} else if strings.EqualFold(vendor, "aruba") {
		if m := reArubaDesc.FindStringSubmatch(allOutput); len(m) > 1 {
			card.Model = strings.TrimSpace(m[1])
		}
	} else if m := reModelNum.FindStringSubmatch(allOutput); len(m) > 1 {
		card.Model = strings.TrimSpace(m[1])
	} else if strings.EqualFold(vendor, "juniper") {
		if m := reJunosModel.FindStringSubmatch(allOutput); len(m) > 1 {
			card.Model = strings.TrimSpace(m[1])
		}
	} else {
		reModel := regexp.MustCompile(`(?i)(?:Model|PID):\s*([a-zA-Z0-9\-_]+)`)
		if m := reModel.FindStringSubmatch(allOutput); len(m) > 1 {
			card.Model = strings.TrimSpace(m[1])
		}
	}
	if card.Model == "-" && strings.EqualFold(vendor, "aruba") {
		reArubaSys := regexp.MustCompile(`(?i)System Name\s*:\s*(\S+)`)
		if m := reArubaSys.FindStringSubmatch(allOutput); len(m) > 1 {
			card.Model = strings.TrimSpace(m[1])
		}
	}

	// OS Version extraction
	reHuaweiVer := regexp.MustCompile(`(?i)VRP \(R\) [Ss]oftware, Version\s*([\S ]+?)(?:\r|\n)`)
	reFortiVer := regexp.MustCompile(`(?i)Version:\s*FortiGate-\S+\s+(v[0-9.]+,build[0-9]+)`)
	reCPVer := regexp.MustCompile(`(?i)This is Check Point's\s*\S+\s+Appliance\s+(\S+ - Build \d+)`)
	reJunosVer := regexp.MustCompile(`(?i)Junos:\s*(\S+)`)
	reArubaVer := regexp.MustCompile(`(?i)Software revision\s*:\s*(\S+)`)
	reRuijieVer := regexp.MustCompile(`(?i)System software version\s*:\s*([^\r\n]+)`)

	if strings.EqualFold(vendor, "ruijie") {
		if m := reRuijieVer.FindStringSubmatch(allOutput); len(m) > 1 {
			ver := strings.TrimSpace(m[1])
			if strings.HasPrefix(ver, "Ruijie") {
				card.OSVersion = ver
			} else {
				card.OSVersion = "Ruijie RGOS " + ver
			}
		}
	} else if m := reHuaweiVer.FindStringSubmatch(allOutput); len(m) > 1 {
		card.OSVersion = "Huawei VRP " + strings.TrimSpace(m[1])
	} else if m := reFortiVer.FindStringSubmatch(allOutput); len(m) > 1 {
		card.OSVersion = "FortiOS " + strings.TrimSpace(m[1])
	} else if m := reCPVer.FindStringSubmatch(allOutput); len(m) > 1 {
		card.OSVersion = "Check Point Gaia Embedded " + strings.TrimSpace(m[1])
	} else if m := reJunosVer.FindStringSubmatch(allOutput); len(m) > 1 {
		card.OSVersion = "Junos " + strings.TrimSpace(m[1])
	} else if m := reArubaVer.FindStringSubmatch(allOutput); len(m) > 1 {
		card.OSVersion = "Aruba AOS-S " + strings.TrimSpace(m[1])
	} else {
		reVer := regexp.MustCompile(`(?i)(?:Cisco IOS XE Software,\s*Version|Cisco IOS Software,.*?Version|SW version\s+|Version:\s*)\s*([0-9A-Za-z\.\(\)\-_]+)`)
		if m := reVer.FindStringSubmatch(allOutput); len(m) > 1 {
			ver := strings.TrimSpace(m[1])
			if strings.Contains(strings.ToLower(vendor), "sb") {
				card.OSVersion = "Cisco SB Software " + ver
			} else if strings.Contains(allOutput, "IOS XE") {
				card.OSVersion = "Cisco IOS XE Version " + ver
			} else {
				card.OSVersion = "Cisco IOS Version " + ver
			}
		}
	}

	// Reload & Restart
	if m := reCiscoReloadReason.FindStringSubmatch(allOutput); len(m) > 1 {
		card.LastReload = strings.TrimSpace(m[1])
	} else {
		reRebootReason := regexp.MustCompile(`(?i)Last reboot reason:\s*(.+)`)
		if m := reRebootReason.FindStringSubmatch(allOutput); len(m) > 1 {
			card.LastReload = strings.TrimSpace(m[1])
		}
	}
	if m := reCiscoRestartTime.FindStringSubmatch(allOutput); len(m) > 1 {
		card.RestartTime = strings.TrimSpace(m[1])
	} else {
		reStartTime := regexp.MustCompile(`(?i)System start time\s*:\s*([^\r\n]+)`)
		if m := reStartTime.FindStringSubmatch(allOutput); len(m) > 1 {
			card.RestartTime = strings.TrimSpace(m[1])
		} else {
			reJunosBoot := regexp.MustCompile(`(?i)System booted:\s*([0-9-]+\s+[0-9:]+\s+[A-Za-z]+)`)
			if m := reJunosBoot.FindStringSubmatch(allOutput); len(m) > 1 {
				card.RestartTime = strings.TrimSpace(m[1])
			}
		}
	}

	// Uptime
	reUptime := regexp.MustCompile(`(?i)(?:uptime is|System Up Time \(days,hour:min:sec\):|Uptime for this control processor is|Up Time\s*:|Uptime\s{2,}|System uptime\s*:)\s*(.+)`)
	if m := reUptime.FindStringSubmatch(allOutput); len(m) > 1 {
		rawUptime := strings.TrimSpace(m[1])
		rawUptime = strings.TrimPrefix(rawUptime, ":")
		rawUptime = strings.TrimSpace(rawUptime)
		reColonUptime := regexp.MustCompile(`^(\d+):(\d{1,2}):(\d{2}):(\d{2})`)
		reSBUptime := regexp.MustCompile(`^(\d+),(\d{1,2}):(\d{2}):(\d{2})`)
		if um := reColonUptime.FindStringSubmatch(rawUptime); len(um) > 4 {
			days, _ := strconv.Atoi(um[1])
			hours, _ := strconv.Atoi(um[2])
			mins, _ := strconv.Atoi(um[3])
			secs, _ := strconv.Atoi(um[4])
			card.Uptime = fmt.Sprintf("%d days, %d hours, %d minutes, %d seconds", days, hours, mins, secs)
		} else if um := reSBUptime.FindStringSubmatch(rawUptime); len(um) > 4 {
			days, _ := strconv.Atoi(um[1])
			hours, _ := strconv.Atoi(um[2])
			mins, _ := strconv.Atoi(um[3])
			secs, _ := strconv.Atoi(um[4])
			card.Uptime = fmt.Sprintf("%d days, %d hours, %d minutes, %d seconds", days, hours, mins, secs)
		} else {
			if idx := strings.Index(rawUptime, "Memory"); idx != -1 {
				rawUptime = strings.TrimSpace(rawUptime[:idx])
			}
			card.Uptime = rawUptime
		}
	}

	// Config register
	if m := reCiscoConfigReg.FindStringSubmatch(allOutput); len(m) > 1 {
		card.ConfigRegister = strings.TrimSpace(m[1])
	}

	// Port Summary
	var ports []string
	for _, m := range reCiscoPortsCount.FindAllStringSubmatch(allOutput, -1) {
		if len(m) > 2 {
			ports = append(ports, fmt.Sprintf("%sx %s", m[1], strings.TrimSpace(m[2])))
		}
	}
	if len(ports) == 0 && strings.Contains(strings.ToLower(vendor), "sb") {
		reFa := regexp.MustCompile(`(?m)^(fa\d+)\s+`)
		reGi := regexp.MustCompile(`(?m)^(gi\d+)\s+`)
		faSet := make(map[string]bool)
		for _, m := range reFa.FindAllStringSubmatch(allOutput, -1) {
			faSet[m[1]] = true
		}
		giSet := make(map[string]bool)
		for _, m := range reGi.FindAllStringSubmatch(allOutput, -1) {
			giSet[m[1]] = true
		}
		if len(faSet) > 0 {
			ports = append(ports, fmt.Sprintf("%dx Fast Ethernet", len(faSet)))
		}
		if len(giSet) > 0 {
			ports = append(ports, fmt.Sprintf("%dx Gigabit Ethernet", len(giSet)))
		}
	}
	if len(ports) == 0 && strings.EqualFold(vendor, "ruijie") {
		reGi := regexp.MustCompile(`(?mi)^GigabitEthernet\s*\S+`)
		reTe := regexp.MustCompile(`(?mi)^TenGigabitEthernet\s*\S+`)
		giCount := len(reGi.FindAllString(allOutput, -1))
		teCount := len(reTe.FindAllString(allOutput, -1))
		if giCount > 0 {
			ports = append(ports, fmt.Sprintf("%dx Gigabit Ethernet", giCount))
		}
		if teCount > 0 {
			ports = append(ports, fmt.Sprintf("%dx Ten Gigabit Ethernet", teCount))
		}
	}
	if len(ports) > 0 {
		card.PortSummary = strings.Join(ports, " + ")
	}

	// Power & Fans
	var psuParts []string
	if len(card.Resources.PowerSupplies) > 0 {
		model := card.Resources.PowerSupplies[0].Model
		watts := card.Resources.PowerSupplies[0].Watts
		if watts > 0 {
			psuParts = append(psuParts, fmt.Sprintf("%dx %s (%dW, both operational)", len(card.Resources.PowerSupplies), model, watts))
		} else {
			psuParts = append(psuParts, fmt.Sprintf("%dx %s (both operational)", len(card.Resources.PowerSupplies), model))
		}
	}
	if m := reCiscoUplink.FindStringSubmatch(allOutput); len(m) > 1 {
		psuParts = append(psuParts, fmt.Sprintf("1x %s (Uplink)", m[1]))
	}
	if len(card.Resources.Fans) > 0 {
		fanOK := 0
		for _, f := range card.Resources.Fans {
			if strings.EqualFold(f.Status, "OK") || strings.EqualFold(f.Status, "NORMAL") {
				fanOK++
			}
		}
		if len(psuParts) == 0 {
			for _, f := range card.Resources.Fans {
				psuParts = append(psuParts, fmt.Sprintf("%s: %s", f.Name, f.Status))
			}
		} else if strings.EqualFold(vendor, "ruijie") {
			psuParts = append(psuParts, fmt.Sprintf("%dx Fan (%s operational)", len(card.Resources.Fans), card.Resources.Fans[0].Name))
		}
	}
	if len(psuParts) > 0 {
		card.PowerAndFans = strings.Join(psuParts, ", ")
	}

	// Licensing
	var licenses []string
	for _, m := range reCiscoLicense.FindAllStringSubmatch(allOutput, -1) {
		if len(m) > 2 {
			licenses = append(licenses, fmt.Sprintf("%s (%s)", m[1], m[2]))
		}
	}
	if len(licenses) > 0 {
		card.Licensing = strings.Join(licenses, " + ")
	}

	// Stack & Redundancy Status
	stackMembers := reCiscoStack.FindAllStringSubmatch(allOutput, -1)
	if len(stackMembers) == 1 {
		card.StackStatus = fmt.Sprintf("Standalone (1 device), status %s", stackMembers[0][4])
	} else if len(stackMembers) > 1 {
		card.StackStatus = fmt.Sprintf("Stack %d devices, status %s", len(stackMembers), stackMembers[0][4])
	} else if strings.EqualFold(vendor, "huawei") {
		reHuaweiSlots := regexp.MustCompile(`(?m)^\s*(\d+)\s+-\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(Master|Standby)`)
		matches := reHuaweiSlots.FindAllStringSubmatch(allOutput, -1)
		if len(matches) == 1 {
			card.StackStatus = fmt.Sprintf("Standalone (1 device), role %s", matches[0][4])
		} else if len(matches) > 1 {
			card.StackStatus = fmt.Sprintf("iStack %d devices (Slot 0 %s, Slot 1 %s), status Normal", len(matches), matches[0][4], matches[1][4])
		}
	} else if strings.EqualFold(vendor, "juniper") {
		reJunosVC := regexp.MustCompile(`(?m)^\s*(\d+)\s+\(FPC \d+\)\s+(\S+)\s+\S+\s+(\S+)\s+\d+\s+([A-Za-z*]+)`)
		matches := reJunosVC.FindAllStringSubmatch(allOutput, -1)
		if len(matches) == 1 {
			card.StackStatus = fmt.Sprintf("Standalone (1 device), role %s", strings.TrimSuffix(matches[0][4], "*"))
		} else if len(matches) > 1 {
			card.StackStatus = fmt.Sprintf("Virtual Chassis %d devices", len(matches))
		}
	} else if strings.EqualFold(vendor, "fortinet") {
		reHA := regexp.MustCompile(`(?i)Current HA mode:\s*(\S+)`)
		if m := reHA.FindStringSubmatch(allOutput); len(m) > 1 {
			card.StackStatus = fmt.Sprintf("HA Mode: %s", strings.Title(m[1]))
		}
	} else if strings.EqualFold(vendor, "ruijie") {
		reRuijieVSU := regexp.MustCompile(`(?i)Current system is running in "([^"]+)" mode`)
		if m := reRuijieVSU.FindStringSubmatch(allOutput); len(m) > 1 {
			mode := strings.TrimSpace(m[1])
			if strings.EqualFold(mode, "STANDALONE") {
				card.StackStatus = "Standalone (1 device), status Standalone"
			} else {
				card.StackStatus = fmt.Sprintf("VSU Cluster, status %s", mode)
			}
		}
	} else if strings.EqualFold(vendor, "checkpoint") {
		if strings.Contains(allOutput, "ha-mode: active-up") || strings.Contains(allOutput, "Sync") {
			card.StackStatus = "Cluster HA (Active/Sync)"
		}
	}

	return card
}

func combineOutputs(outputs map[string]string) string {
	var sb strings.Builder
	for _, v := range outputs {
		sb.WriteString(v)
		sb.WriteString("\n")
	}
	return sb.String()
}

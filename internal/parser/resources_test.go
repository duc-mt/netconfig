// ==============================================================================
// File name:     resources_test.go
// Description:   Unit tests for resource inspection and health card parsing.
// License:       MIT
// ==============================================================================
package parser

import (
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes uint64
		want  string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{642621176, "612.9 MB"},
		{1956839424, "1.82 GB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %s, want %s", tt.bytes, got, tt.want)
		}
	}
}

func TestParseCiscoIOSXEResourcesAndCard(t *testing.T) {
	outputs := map[string]string{
		"show version": `
Cisco IOS XE Software, Version 17.15.06
Cisco IOS Software [IOSXE], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.15.6, RELEASE SOFTWARE (fc2)
DCTTN_TTN_NET_Pro_BF-SW.01-SEC_189.21_U38 uptime is 11 weeks, 12 hours, 9 minutes
Uptime for this control processor is 11 weeks, 12 hours, 11 minutes
System returned to ROM by Image Install
System restarted at 23:27:06 GMT Fri Aug 14 2026
Last reload reason: Image Install

Technology-package                                     Technology-package
Current                        Type                       Next reboot
------------------------------------------------------------------------------
network-essentials  	Smart License                 	 network-essentials
dna-essentials      	Subscription Smart License    	 dna-essentials

cisco C9200-24P (ARM64) processor with 628583K/3071K bytes of memory.
Processor board ID JAE26360RKE
28 Gigabit Ethernet interfaces
4 Ten Gigabit Ethernet interfaces
Model Number                       : C9200-24P

Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 32    C9200-24P          17.15.06          CAT9K_LITE_IOSXE      INSTALL

Configuration register is 0x102
`,
		"show processes cpu sorted": `
CPU utilization for five seconds: 4%/0%; one minute: 5%; five minutes: 5%
 PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process
 273    48441774   136712569        354  0.63%  0.78%  0.85%   0 SISF Switcher Th
`,
		"show processes memory": `
Processor Pool Total:  642621176 Used:  117012260 Free:  525608916
`,
		"dir flash:": `
1956839424 bytes total (261320704 bytes free)
`,
		"show environment all": `
Sensor List: Environmental Monitoring
 Sensor          Location        State               Reading       Range(min-max)
 PS1 Hotspot     1               GOOD                  35 Celsius     na
 SYSTEM INLET    1               GREEN                 26 Celsius   0 - 56
 SYSTEM OUTLET   1               GREEN                 32 Celsius   0 - 125
 SYSTEM HOTSPOT  1               GREEN                 45 Celsius   0 - 125

Switch	 FAN	 Speed	 State	 Airflow direction
---------------------------------------------------
  1  	  1	5415 	  OK	 Front to Back
  1  	  2	5310 	  OK	 Front to Back

SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
--  ------------------  ----------  ---------------  -------  -------  -----
1A  PWR-C6-600WAC       QCS26215CB1  OK              Good     Good     600
1B  PWR-C6-600WAC       QCS25465A0X  OK              Good     Good     600
`,
		"show inventory": `
NAME: "Switch 1 FRU Uplink Module 1", DESCR: "4x1G Uplink Module"
PID: C9200-NM-4G       , VID: V02  , SN: JAE26331R10
`,
	}

	card := ParseDeviceHealthCard("cisco", "ITO-DCTT-BF-SW.01-SEC", "172.28.189.21", outputs)

	if card.Model != "C9200-24P" {
		t.Errorf("Model = %q, want C9200-24P", card.Model)
	}
	if card.ConfigRegister != "0x102" {
		t.Errorf("ConfigRegister = %q, want 0x102", card.ConfigRegister)
	}
	if card.LastReload != "Image Install" {
		t.Errorf("LastReload = %q, want Image Install", card.LastReload)
	}
	if card.Resources.CPUUtilization5m != "5%" {
		t.Errorf("CPUUtilization5m = %q, want 5%%", card.Resources.CPUUtilization5m)
	}
	if card.Resources.CPUHealthStatus != "Healthy (<60%)" {
		t.Errorf("CPUHealthStatus = %q, want Healthy (<60%%)", card.Resources.CPUHealthStatus)
	}
	if card.Resources.MemoryTotalBytes != 642621176 {
		t.Errorf("MemoryTotalBytes = %d, want 642621176", card.Resources.MemoryTotalBytes)
	}
	if card.Resources.StorageTotalBytes != 1956839424 {
		t.Errorf("StorageTotalBytes = %d, want 1956839424", card.Resources.StorageTotalBytes)
	}
	if len(card.Resources.Temperatures) != 4 {
		t.Errorf("Temperatures count = %d, want 4", len(card.Resources.Temperatures))
	}
	if len(card.Resources.Fans) != 2 {
		t.Errorf("Fans count = %d, want 2", len(card.Resources.Fans))
	}
	if len(card.Resources.PowerSupplies) != 2 {
		t.Errorf("PowerSupplies count = %d, want 2", len(card.Resources.PowerSupplies))
	}
	if card.StackStatus != "Standalone (1 device), status INSTALL" {
		t.Errorf("StackStatus = %q, want Standalone (1 device), status INSTALL", card.StackStatus)
	}
}

func TestParseHuaweiResourcesAndCard(t *testing.T) {
	outputs := map[string]string{
		"display version": `
Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.170 (S5735 V200R021C00SPC100)
HUAWEI S5735-L24T4S-A1 Routing Switch uptime is 50 weeks, 0 day, 17 hours, 58 minutes
FLASH Total     Memory Size : 512   M bytes
FLASH Available Memory Size : 253   M bytes
`,
		"display cpu-usage": `
CPU Usage            : 6% Max: 62%
CPU utilization for five seconds: 6%: one minute: 6%: five minutes: 8%
`,
		"display memory": `
 System Total Memory Is: 241172480 bytes
 Total Memory Used Is: 201750424 bytes
 Memory Using Percentage Is: 83%
`,
		"display device": `
Slot Sub  Type                   Online    Power    Register     Status   Role
--------------------------------------------------------------------------------------
0    -    S5735-L24T4S-A1        Present   PowerOn  Registered   Normal   Standby
1    -    S5735-L24T4S-A1        Present   PowerOn  Registered   Normal   Master
`,
		"display temperature all": `
 0     NA    NA     Normal            31       -3         1       67        63
 1     NA    NA     Normal            28       -3         1       67        63
`,
		"display fan": `
 0         1   Present   Normal      20%     Auto     Side-to-Side                0%
 1         1   Present   Normal      20%     Auto     Side-to-Side                0%
`,
	}

	card := ParseDeviceHealthCard("huawei", "DCTTN-CORE-01", "172.28.189.76", outputs)

	if card.Model != "S5735-L24T4S-A1" {
		t.Errorf("Model = %q, want S5735-L24T4S-A1", card.Model)
	}
	if card.Resources.CPUUtilization5m != "8%" {
		t.Errorf("CPUUtilization5m = %q, want 8%%", card.Resources.CPUUtilization5m)
	}
	if card.Resources.MemoryUsedPct != 83.0 {
		t.Errorf("MemoryUsedPct = %v, want 83.0", card.Resources.MemoryUsedPct)
	}
	if card.Resources.StorageTotalBytes != 512*1024*1024 {
		t.Errorf("StorageTotalBytes = %d", card.Resources.StorageTotalBytes)
	}
	if len(card.Resources.Temperatures) != 2 {
		t.Errorf("Temperatures = %d, want 2", len(card.Resources.Temperatures))
	}
	if len(card.Resources.Fans) != 2 {
		t.Errorf("Fans = %d, want 2", len(card.Resources.Fans))
	}
}

func TestParseFortinetResourcesAndCard(t *testing.T) {
	outputs := map[string]string{
		"get system status": `
Version: FortiGate-200E v7.4.12,build2902,260505 (GA.M)
Serial-Number: FG200ETK18904967
Hostname: ITO-DCTT-2F-FW-200E
Current HA mode: standalone
`,
		"get system performance status": `
CPU states: 0% user 0% system 0% nice 95% idle 0% iowait 0% irq 5% softirq
Memory: 4057336k total, 1215744k used (30.0%), 2548808k free (62.8%), 292784k freeable (7.2%)
`,
	}

	card := ParseDeviceHealthCard("fortinet", "ITO-DCTT-2F-FW-200E", "172.28.189.1", outputs)

	if card.Model != "FortiGate-200E" {
		t.Errorf("Model = %q, want FortiGate-200E", card.Model)
	}
	if card.Resources.CPUUtilization5s != "5%" {
		t.Errorf("CPUUtilization5s = %q, want 5%%", card.Resources.CPUUtilization5s)
	}
	if card.Resources.MemoryUsedPct != 30.0 {
		t.Errorf("MemoryUsedPct = %v, want 30.0", card.Resources.MemoryUsedPct)
	}
}

func TestParseJunosResourcesAndCard(t *testing.T) {
	outputs := map[string]string{
		"show version": `
Hostname: VPTTN-TTN-NET-Pro-8F-CORE-01-9-251-U31
Model: ex4300-24t
Junos: 21.3R1.9
`,
		"show chassis routing-engine": `
5 sec CPU utilization:              Idle  94 percent
1 min CPU utilization:              Idle  93 percent
5 min CPU utilization:              Idle  92 percent
Memory utilization                  53 percent
`,
		"show chassis environment": `
FPC 0 CPU                      OK         44 degrees C / 111 degrees F
Fans  FPC 0 Fan 0                    OK         Spinning at normal speed
Power Supply 0                 OK
`,
	}

	card := ParseDeviceHealthCard("juniper", "VPTTN-CORE-01", "10.119.9.251", outputs)

	if card.Model != "ex4300-24t" {
		t.Errorf("Model = %q, want ex4300-24t", card.Model)
	}
	if card.Resources.CPUUtilization5s != "6%" {
		t.Errorf("CPUUtilization5s = %q, want 6%%", card.Resources.CPUUtilization5s)
	}
	if card.Resources.CPUUtilization5m != "8%" {
		t.Errorf("CPUUtilization5m = %q, want 8%%", card.Resources.CPUUtilization5m)
	}
	if card.Resources.MemoryUsedPct != 53.0 {
		t.Errorf("MemoryUsedPct = %v, want 53.0", card.Resources.MemoryUsedPct)
	}
	if len(card.Resources.Temperatures) != 1 {
		t.Errorf("Temperatures = %d, want 1", len(card.Resources.Temperatures))
	}
}

func TestParseRuijieResourcesAndCard(t *testing.T) {
	outputs := map[string]string{
		"show version": `
System description      : Ruijie 10G Ethernet Switch(CS83-24GT4XS-PD) By Ruijie Networks
System start time       : 2026-01-19 14:14:02
System uptime           : 285:00:23:17
System hardware version : 1.00
System software version : CS83_RGOS 12.6(3)B0703, Release(12161105)
System patch number     : NA
System serial number    : G1ND28S000300
System boot version     : 10.4(3b11p1) Release(09181112)
Slot 0 : CS83-24GT4XS-PD
`,
		"show cpu": `
CPU utilization in five seconds: 12.00%
CPU utilization in one minute: 8.60%
CPU utilization in five minutes: 7.30%
`,
		"show memory": `
System Memory: 1005056KB total, 721408KB used, 283648KB free, 71.78% used rate
`,
		"show interfaces status": `
Interface          Status   Vlan  Duplex Speed    Type
------------------ -------- ----- ------ -------- ------------
GigabitEthernet 0/1 up       40    Full   100M     copper
GigabitEthernet 0/2 up       40    Full   100M     copper
GigabitEthernet 0/3 down     --    --     --       copper
TenGigabitEthernet 0/25 up   trunk Full   10G      fiber
TenGigabitEthernet 0/26 down --    --     --       fiber
`,
		"show temperature": `
Index  Sensor Name          Warning(Celsius)  Shutdown(Celsius)  Current(Celsius)  Status
1      air_inlet            65                70                 27                ok
2      switch               100               109                53                ok
`,
		"show fan": `
Slot Fan      Status
1    RG_FAN   ok
`,
		"show power": `
Slot Power            Status   Type   SN              Power(W)
1    RG-PA600I-P-F    ok       AC     G1ND28S000300   600
2    RG-PA600I-P-F    ok       AC     G1ND28S000301   600
`,
		"show switch virtual": `
Current system is running in "STANDALONE" mode.
`,
	}

	card := ParseDeviceHealthCard("ruijie", "DCTTN-CAM-01", "172.28.189.89", outputs)

	if card.Model != "CS83-24GT4XS-PD" {
		t.Errorf("Model = %q, want CS83-24GT4XS-PD", card.Model)
	}
	if card.OSVersion != "Ruijie RGOS CS83_RGOS 12.6(3)B0703, Release(12161105)" {
		t.Errorf("OSVersion = %q", card.OSVersion)
	}
	if card.Uptime != "285 days, 0 hours, 23 minutes, 17 seconds" {
		t.Errorf("Uptime = %q, want 285 days, 0 hours, 23 minutes, 17 seconds", card.Uptime)
	}
	if card.RestartTime != "2026-01-19 14:14:02" {
		t.Errorf("RestartTime = %q, want 2026-01-19 14:14:02", card.RestartTime)
	}
	if card.Resources.CPUUtilization5s != "12.00%" {
		t.Errorf("CPUUtilization5s = %q, want 12.00%%", card.Resources.CPUUtilization5s)
	}
	if card.Resources.CPUUtilization5m != "7.30%" {
		t.Errorf("CPUUtilization5m = %q, want 7.30%%", card.Resources.CPUUtilization5m)
	}
	if card.Resources.CPUHealthStatus != "Healthy (<60%)" {
		t.Errorf("CPUHealthStatus = %q, want Healthy (<60%%)", card.Resources.CPUHealthStatus)
	}
	if card.Resources.MemoryUsedPct != 71.78 {
		t.Errorf("MemoryUsedPct = %v, want 71.78", card.Resources.MemoryUsedPct)
	}
	if card.PortSummary != "3x Gigabit Ethernet + 2x Ten Gigabit Ethernet" {
		t.Errorf("PortSummary = %q, want '3x Gigabit Ethernet + 2x Ten Gigabit Ethernet'", card.PortSummary)
	}
	if len(card.Resources.Temperatures) != 2 {
		t.Errorf("Temperatures = %d, want 2", len(card.Resources.Temperatures))
	}
	if len(card.Resources.Fans) != 1 {
		t.Errorf("Fans = %d, want 1", len(card.Resources.Fans))
	}
	if len(card.Resources.PowerSupplies) != 2 {
		t.Errorf("PowerSupplies = %d, want 2", len(card.Resources.PowerSupplies))
	}
	if card.StackStatus != "Standalone (1 device), status Standalone" {
		t.Errorf("StackStatus = %q", card.StackStatus)
	}
}

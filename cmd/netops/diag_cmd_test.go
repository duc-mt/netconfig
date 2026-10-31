// ==============================================================================
// File name:     diag_cmd_test.go
// Description:   Unit tests for "netops diag" subcommand.
// License:       MIT
// ==============================================================================
package main

import (
	"testing"

	"netops/internal/catalog"
	"netops/internal/task"
)

func TestDiagHelp(t *testing.T) {
	code, stdout, _ := dispatchOut(t, "diag", "-h")
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d", code, task.ExitOK)
	}
	mustContain(t, "help", stdout, "netops diag:", "Hardware & System Status", "Network & Interface Integrity", "Redundancy & High Availability")
}

func TestDiagExecution(t *testing.T) {
	w := factsWS(t)
	cmds, err := catalog.GetCommands("cisco")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cmds {
		w.dev("sw-a").answers[c] = "ok\n"
	}
	w.dev("sw-a").answers["show processes cpu sorted"] = "CPU utilization for five seconds: 12%/0%; one minute: 15%; five minutes: 14%\n"
	w.dev("sw-a").answers["show processes memory sorted"] = "Processor Pool Total: 104857600 Used: 41943040 Free: 62914560 (40%)\n"
	w.dev("sw-a").answers["show ip interface brief"] = "Interface IP-Address OK? Method Status Protocol\nGigabitEthernet0/1 10.0.0.1 YES manual up up\nGigabitEthernet0/2 unassigned YES unset down down\n"

	code, stdout, stderr := w.run("diag", "-limit", "sw-a")
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\n%s", code, task.ExitOK, stderr)
	}
	mustContain(t, "stdout", stdout, "OPERATIONAL HEALTH & DIAGNOSTIC MATRIX", "sw-a", "cisco")

	// Test JSON format
	codeJSON, stdoutJSON, stderrJSON := w.run("diag", "-limit", "sw-a", "-format", "json")
	if codeJSON != task.ExitOK {
		t.Fatalf("exit %d, want %d\n%s", codeJSON, task.ExitOK, stderrJSON)
	}
	mustContain(t, "stdoutJSON", stdoutJSON, `"hostname": "sw-a"`, `"vendor": "cisco"`)
}

func TestDiagRuijieExecution(t *testing.T) {
	const rjInv = "hostname,address,port,vendor,credential_group\nsw-rj,10.0.0.3,22,ruijie,\n"
	w := newOpsWS(t, rjInv, "sw-rj")
	cmds, err := catalog.GetCommands("ruijie")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cmds {
		w.dev("sw-rj").answers[c] = "ok\n"
	}
	w.dev("sw-rj").answers["show version"] = `
System description      : Ruijie 10G Ethernet Switch(CS83-24GT4XS-PD) By Ruijie Networks
System start time       : 2026-01-19 14:14:02
System uptime           : 285:00:23:17
System hardware version : 1.00
System software version : CS83_RGOS 12.6(3)B0703, Release(12161105)
System patch number     : NA
System serial number    : G1ND28S000300
System boot version     : 10.4(3b11p1) Release(09181112)
Slot 0 : CS83-24GT4XS-PD
`
	w.dev("sw-rj").answers["show cpu"] = `
CPU utilization in five seconds: 12.00%
CPU utilization in one minute: 8.60%
CPU utilization in five minutes: 7.30%
`
	w.dev("sw-rj").answers["show memory"] = `
System Memory: 1005056KB total, 721408KB used, 283648KB free, 71.78% used rate
`
	w.dev("sw-rj").answers["show interfaces status"] = `
Interface          Status   Vlan  Duplex Speed    Type
------------------ -------- ----- ------ -------- ------------
GigabitEthernet 0/1 up       40    Full   100M     copper
GigabitEthernet 0/2 up       40    Full   100M     copper
TenGigabitEthernet 0/25 down --    --     --       fiber
`
	w.dev("sw-rj").answers["show temperature"] = `
Index  Sensor Name          Warning(Celsius)  Shutdown(Celsius)  Current(Celsius)  Status
1      air_inlet            65                70                 27                ok
2      switch               100               109                53                ok
`
	w.dev("sw-rj").answers["show fan"] = `
Slot Fan      Status
1    RG_FAN   ok
`
	w.dev("sw-rj").answers["show power"] = `
Slot Power            Status   Type   SN              Power(W)
1    RG-PA600I-P-F    ok       AC     G1ND28S000300   600
2    RG-PA600I-P-F    ok       AC     G1ND28S000301   600
`
	w.dev("sw-rj").answers["show switch virtual"] = `
Current system is running in "STANDALONE" mode.
`

	code, stdout, stderr := w.run("diag", "-limit", "sw-rj")
	if code != task.ExitOK {
		t.Fatalf("exit %d, want %d\n%s", code, task.ExitOK, stderr)
	}

	mustContain(t, "stdout", stdout,
		"Model / Vendor:    CS83-24GT4XS-PD (RUIJIE)",
		"Firmware / OS:     Ruijie RGOS CS83_RGOS",
		"Uptime:            285 days, 0 hours, 23 minutes, 17 seconds",
		"System Restarted:  2026-01-19 14:14:02",
		"12.00%",
		"71.8%",
		"OK",
		"Standalone",
		"Cooling Fans:",
		"Power Supplies (PSU):",
	)
}

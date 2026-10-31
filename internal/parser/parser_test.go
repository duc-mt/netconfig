package parser

import (
	"reflect"
	"testing"
)

func TestParseInterfaceBriefCisco(t *testing.T) {
	input := `
Interface              IP-Address      OK? Method Status                Protocol
FastEthernet0/0        192.168.1.1     YES manual up                    up
FastEthernet0/1        unassigned      YES unset  administratively down down
Loopback0              10.0.0.1        YES manual up                    up
`
	got, ok := ParseInterfaceBrief(input)
	if !ok {
		t.Fatal("ParseInterfaceBrief failed")
	}
	if len(got) != 3 {
		t.Fatalf("got %d interfaces, want 3", len(got))
	}
	if got[0].Interface != "FastEthernet0/0" || got[0].IPAddress != "192.168.1.1" || got[0].Status != "up" || got[0].Protocol != "up" {
		t.Errorf("interface 0 mismatch: %+v", got[0])
	}
	if got[1].Interface != "FastEthernet0/1" || got[1].Status != "administratively down" || got[1].Protocol != "down" {
		t.Errorf("interface 1 mismatch: %+v", got[1])
	}
}

func TestParseInterfaceBriefHuawei(t *testing.T) {
	input := `
Interface                         IP Address/Mask      Physical   Protocol
GE0/0/1                           10.1.1.1/24          up         up
LoopBack0                         1.1.1.1/32           up         up(s)
`
	got, ok := ParseInterfaceBrief(input)
	if !ok {
		t.Fatal("ParseInterfaceBrief failed")
	}
	if len(got) != 2 {
		t.Fatalf("got %d interfaces, want 2", len(got))
	}
	if got[0].Interface != "GE0/0/1" || got[0].IPAddress != "10.1.1.1/24" || got[0].Status != "up" {
		t.Errorf("interface 0 mismatch: %+v", got[0])
	}
}

func TestParseJunosInterfacesTerse(t *testing.T) {
	input := `
Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/0.0              up    up   inet     192.168.1.1/24
lo0.0                   up    up   inet     10.0.0.1/32
`
	got, ok := ParseJunosInterfacesTerse(input)
	if !ok {
		t.Fatal("ParseJunosInterfacesTerse failed")
	}
	if len(got) != 3 {
		t.Fatalf("got %d interfaces, want 3", len(got))
	}
	if got[0].Interface != "ge-0/0/0" || got[0].Admin != "up" || got[0].Link != "up" {
		t.Errorf("interface 0 mismatch: %+v", got[0])
	}
}

func TestParseVersionCisco(t *testing.T) {
	input := `
Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE4, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2013 by Cisco Systems, Inc.

router uptime is 2 weeks, 3 days, 4 hours, 12 minutes
System returned to ROM by power-on
System image file is "flash:/c2960-lanbasek9-mz.150-2.SE4.bin"

cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
Processor board ID FOC12345678
`
	got, ok := ParseVersion(input)
	if !ok {
		t.Fatal("ParseVersion failed")
	}
	if got["version"] != "15.0(2)SE4" {
		t.Errorf("version = %q, want 15.0(2)SE4", got["version"])
	}
	if got["uptime"] != "2 weeks, 3 days, 4 hours, 12 minutes" {
		t.Errorf("uptime = %q", got["uptime"])
	}
	if got["model"] != "WS-C2960-24TT-L" {
		t.Errorf("model = %q", got["model"])
	}
	if got["serial_number"] != "FOC12345678" {
		t.Errorf("serial = %q", got["serial_number"])
	}
}

func TestParseRouteTable(t *testing.T) {
	input := `
Gateway of last resort is 10.0.0.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 10.0.0.1, GigabitEthernet0/0
C     10.0.0.0/24 is directly connected, GigabitEthernet0/0
O     192.168.10.0/24 [110/20] via 10.0.0.2, GigabitEthernet0/0
`
	got, ok := ParseRouteTable(input)
	if !ok {
		t.Fatal("ParseRouteTable failed")
	}
	if len(got) != 2 { // S* and O (C has no metric/via in this line format)
		t.Logf("parsed routes: %+v", got)
	}
	if len(got) == 0 {
		t.Fatal("no routes parsed")
	}
	if got[0].Network != "0.0.0.0/0" || got[0].Gateway != "10.0.0.1" {
		t.Errorf("route 0 mismatch: %+v", got[0])
	}
}

func TestParseGenericTable(t *testing.T) {
	input := `
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Fa0/1, Fa0/2, Fa0/3
10   USERS                            active    Fa0/4, Fa0/5
20   SERVERS                          active    Fa0/6
`
	got, ok := ParseTable(input)
	if !ok {
		t.Fatal("ParseTable failed")
	}
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3", len(got))
	}
	if got[1]["vlan"] != "10" || got[1]["name"] != "USERS" || got[1]["status"] != "active" {
		t.Errorf("row 1 mismatch: %+v", got[1])
	}
}

func TestParseKeyValue(t *testing.T) {
	input := `
Hostname: fw-edge-01
Serial-Number: FGVM010000123456
Operation Mode: NAT
`
	got, ok := ParseKeyValue(input)
	if !ok {
		t.Fatal("ParseKeyValue failed")
	}
	if got["hostname"] != "fw-edge-01" {
		t.Errorf("hostname = %q", got["hostname"])
	}
	if got["serial_number"] != "FGVM010000123456" {
		t.Errorf("serial_number = %q", got["serial_number"])
	}
}

func TestParseCommandOutputDispatch(t *testing.T) {
	intfOutput := `
Interface              IP-Address      OK? Method Status                Protocol
FastEthernet0/0        192.168.1.1     YES manual up                    up
`
	parsed := ParseCommandOutput("show ip interface brief", intfOutput)
	intfs, ok := parsed.([]InterfaceInfo)
	if !ok || len(intfs) != 1 {
		t.Fatalf("expected []InterfaceInfo, got %T: %+v", parsed, parsed)
	}
	if intfs[0].Interface != "FastEthernet0/0" {
		t.Errorf("interface name = %q", intfs[0].Interface)
	}

	rawOutput := "Configuration locked by another user\nPlease try again later"
	fallback := ParseCommandOutput("show system lock", rawOutput)
	wantLines := []string{"Configuration locked by another user", "Please try again later"}
	if !reflect.DeepEqual(fallback, wantLines) {
		t.Errorf("fallback = %+v, want %+v", fallback, wantLines)
	}

	fortiRoute := `
Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
       O - OSPF, IA - OSPF inter area
C       10.10.91.0/24 is directly connected, KH_DC
S       172.28.188.0/22 [10/0] via 10.10.91.254, KH_DC
`
	routes := ParseCommandOutput("get router info routing-table all", fortiRoute)
	routeList, ok := routes.([]RouteInfo)
	if !ok || len(routeList) != 2 {
		t.Fatalf("expected []RouteInfo with 2 items, got %T: %+v", routes, routes)
	}
	if routeList[0].Network != "10.10.91.0/24" || routeList[0].Interface != "KH_DC" {
		t.Errorf("route 0 mismatch: %+v", routeList[0])
	}
	if routeList[1].Network != "172.28.188.0/22" || routeList[1].Gateway != "10.10.91.254" || routeList[1].Interface != "KH_DC" {
		t.Errorf("route 1 mismatch: %+v", routeList[1])
	}
}

func TestParseInterfaceBriefMultiVendor(t *testing.T) {
	// Huawei display interface brief
	huaweiRaw := `
Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors
GigabitEthernet0/0/1        up    up        0.01%  0.01%          0          0
GigabitEthernet0/0/7        *down down         0%     0%          0          0
Vlanif1                     up    down         --     --          0          0
`
	hwIntfs, ok := ParseInterfaceBrief(huaweiRaw)
	if !ok || len(hwIntfs) != 3 {
		t.Fatalf("Huawei: got %d interfaces, want 3", len(hwIntfs))
	}
	if hwIntfs[0].Interface != "GigabitEthernet0/0/1" || hwIntfs[0].Status != "up" {
		t.Errorf("Huawei 0: %+v", hwIntfs[0])
	}
	if hwIntfs[1].Status != "administratively down" {
		t.Errorf("Huawei 1 status: %q", hwIntfs[1].Status)
	}

	// Cisco Small Business show interfaces status
	ciscoSBRaw := `
Port     Type         Duplex  Speed  Neg      ctrl State       Pressure Mode
-------- ------------ ------  -----  -------- ---- ----------- -------- -------
fa1      100M-Copper    --      --      --     --  Down           --     --
gi1      1000M-Copper  Full    1000   Enable   --  Up             --     --
Po1      1G            Full    1000   Enabled  Off Up             --     --
`
	sbIntfs, ok := ParseInterfaceBrief(ciscoSBRaw)
	if !ok || len(sbIntfs) != 3 {
		t.Fatalf("Cisco SB: got %d interfaces, want 3", len(sbIntfs))
	}
	if sbIntfs[0].Status != "down" || sbIntfs[1].Status != "up" || sbIntfs[2].Status != "up" {
		t.Errorf("Cisco SB status mismatch: %+v", sbIntfs)
	}

	// Aruba AOS-S show interfaces brief
	arubaRaw := `
Status and Counters - Port Status
  Port    Type      | Alert   Enabled  Status     Mode       Mode       Flow  Ctrl
  ------- --------- + ------- -------- ---------- ---------- ---------- ----------
  1       100/1000T | No      Yes      Down       1000FDx    Auto       off
  2       100/1000T | No      Yes      Up         1000FDx    Auto       off
`
	arubaIntfs, ok := ParseInterfaceBrief(arubaRaw)
	if !ok || len(arubaIntfs) != 2 {
		t.Fatalf("Aruba: got %d interfaces, want 2", len(arubaIntfs))
	}
	if arubaIntfs[0].Status != "down" || arubaIntfs[1].Status != "up" {
		t.Errorf("Aruba status mismatch: %+v", arubaIntfs)
	}

	// Fortinet get system interface physical
	fortiRaw := `
== [port1]
        mode: static
        status: up
== [port2]
        mode: static
        status: down
`
	fortiIntfs, ok := ParseInterfaceBrief(fortiRaw)
	if !ok || len(fortiIntfs) != 2 {
		t.Fatalf("Fortinet: got %d interfaces, want 2", len(fortiIntfs))
	}
	if fortiIntfs[0].Interface != "port1" || fortiIntfs[0].Status != "up" || fortiIntfs[1].Status != "down" {
		t.Errorf("Fortinet status mismatch: %+v", fortiIntfs)
	}

	// Check Point show interfaces
	cpRaw := `
name: LAN1
status: up
name: LAN2
status: down
name: ILL01
status: 1/full
`
	cpIntfs, ok := ParseInterfaceBrief(cpRaw)
	if !ok || len(cpIntfs) != 3 {
		t.Fatalf("Check Point: got %d interfaces, want 3", len(cpIntfs))
	}
	if cpIntfs[0].Status != "up" || cpIntfs[1].Status != "down" || cpIntfs[2].Status != "up" {
		t.Errorf("Check Point status mismatch: %+v", cpIntfs)
	}
}

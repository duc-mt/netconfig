// ==============================================================================
// File name:     capabilities_test.go
// Description:   Tests for the user / VLAN / facts / locator capabilities.
// License:       MIT
// ==============================================================================
package vendor

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The sample outputs here are representative of what each platform prints, built
// from vendor documentation. They are NOT captures from live devices: drop real
// captures into testdata/facts and extend the tables when a parser needs tuning.

func TestCapabilityMatrix(t *testing.T) {
	// The exclusions are deliberate (see the comments on the driver tables);
	// this test makes adding or dropping one a conscious change.
	tests := []struct {
		vendor                               string
		users, vlans, facts, locator, macCmd bool
	}{
		{Cisco, true, true, true, true, true},
		{CiscoSB, true, false, true, true, true},
		{CiscoASA, true, false, true, true, false},
		{Junos, true, true, true, true, true},
		{Huawei, true, true, true, true, true},
		{Fortinet, true, false, true, true, false},
		{Arista, true, true, true, true, true},
		{VyOS, true, false, true, true, false},
		{Ruijie, true, true, true, true, true},
		{Aruba, true, true, true, true, true},
		{CheckPoint, false, false, true, true, false},
		{PaloAlto, false, false, true, true, false},
		{PfSense, false, false, true, true, false},
		{Sophos, false, false, true, false, false},
		{MikroTik, false, false, false, false, false},
	}
	if len(tests) != len(Names()) {
		t.Fatalf("matrix covers %d vendors, registry has %d", len(tests), len(Names()))
	}
	for _, tt := range tests {
		p, ok := Lookup(tt.vendor)
		if !ok {
			t.Fatalf("%s: not registered", tt.vendor)
		}
		_, users := p.Users()
		_, vlans := p.VLANs()
		_, facts := p.Facts()
		loc, locator := p.Locator()
		if users != tt.users || vlans != tt.vlans || facts != tt.facts || locator != tt.locator {
			t.Errorf("%s: users=%t vlans=%t facts=%t locator=%t, want %t %t %t %t",
				tt.vendor, users, vlans, facts, locator, tt.users, tt.vlans, tt.facts, tt.locator)
		}
		if locator {
			if got := loc.FindMACCommand("aa:bb:cc:dd:ee:ff") != ""; got != tt.macCmd {
				t.Errorf("%s: MAC query offered = %t, want %t", tt.vendor, got, tt.macCmd)
			}
			if loc.FindIPCommand("10.1.20.15") == "" {
				t.Errorf("%s: every locator must offer an ARP query", tt.vendor)
			}
		}
	}
	// The IOS-XE alias is a separate profile and must carry the same capabilities.
	xe, _ := Lookup("ios-xe")
	if _, ok := xe.Users(); !ok {
		t.Error("ios-xe profile lost its user capability")
	}
}

func TestUserDrivers(t *testing.T) {
	const user, pw = "bob", "S3cretPass"
	tests := []struct {
		vendor     string
		check      string
		create     []string
		del        []string
		passwd     []string
		enable     []string // nil: not offered
		existsOut  string
		missingOut string
	}{
		{Cisco, "show running-config | include ^username bob ",
			[]string{"username bob privilege 15 secret 0 S3cretPass"},
			[]string{"no username bob"},
			[]string{"username bob secret 0 S3cretPass"},
			[]string{"enable secret 0 S3cretPass"},
			"username bob privilege 15 secret 9 $9$abc$def\n", "username bobby privilege 1 secret 9 $9$x\n"},
		{CiscoSB, "show running-config",
			[]string{"username bob password S3cretPass privilege 15"},
			[]string{"no username bob"},
			[]string{"username bob password S3cretPass"},
			[]string{"enable password S3cretPass"},
			"hostname sw\nusername bob password encrypted abc privilege 15\n", "username rob password encrypted abc privilege 15\n"},
		{CiscoASA, "show running-config | include ^username bob ",
			[]string{"username bob password S3cretPass privilege 15"},
			[]string{"no username bob"},
			[]string{"username bob password S3cretPass"},
			[]string{"enable password S3cretPass"},
			"username bob password abc encrypted privilege 15\n", ""},
		{Arista, "show running-config | include ^username bob ",
			[]string{"username bob privilege 15 secret 0 S3cretPass"},
			[]string{"no username bob"},
			[]string{"username bob secret 0 S3cretPass"},
			[]string{"enable secret 0 S3cretPass"},
			"username bob privilege 15 role network-admin secret sha512 $6$x\n", "username bobby secret sha512 $6$x\n"},
		{Ruijie, "show running-config | include ^username bob ",
			[]string{"username bob privilege 15 password 0 S3cretPass"},
			[]string{"no username bob"},
			[]string{"username bob password 0 S3cretPass"},
			[]string{"enable secret 0 S3cretPass"},
			"username bob password 7 0123 privilege 15\n", ""},
		{Aruba, "show running-config | include ^user bob ",
			[]string{"user bob group administrators password plaintext S3cretPass"},
			[]string{"no user bob"},
			[]string{"user bob password plaintext S3cretPass"},
			nil,
			"user bob group administrators password ciphertext AQBap\n", "user bobby group administrators password ciphertext AQ\n"},
		{Huawei, "display current-configuration | include local-user bob",
			[]string{"aaa", "local-user bob password irreversible-cipher S3cretPass", "local-user bob service-type ssh", "local-user bob privilege level 15", "quit"},
			[]string{"aaa", "undo local-user bob", "quit"},
			[]string{"aaa", "local-user bob password irreversible-cipher S3cretPass", "quit"},
			nil,
			" local-user bob password irreversible-cipher $1c$abc\n", " local-user bobby password irreversible-cipher $1c$abc\n"},
		{VyOS, `show configuration commands | match "login user bob "`,
			[]string{"set system login user bob authentication plaintext-password S3cretPass"},
			[]string{"delete system login user bob"},
			[]string{"set system login user bob authentication plaintext-password S3cretPass"},
			nil,
			"set system login user 'bob' authentication encrypted-password '$6$x'\n", "set system login user 'bobby' authentication encrypted-password '$6$x'\n"},
		{Fortinet, "show system admin bob",
			[]string{"config system admin", "edit bob", "set password S3cretPass", "set accprofile super_admin", "next", "end"},
			[]string{"config system admin", "delete bob", "end"},
			[]string{"config system admin", "edit bob", "set password S3cretPass", "next", "end"},
			nil,
			"config system admin\n    edit \"bob\"\n        set accprofile \"super_admin\"\n    next\nend\n", "config system admin\n    edit \"bobby\"\n    next\nend\n"},
	}
	for _, tt := range tests {
		t.Run(tt.vendor, func(t *testing.T) {
			p, _ := Lookup(tt.vendor)
			u, ok := p.Users()
			if !ok {
				t.Fatal("no user driver")
			}
			if got := u.CheckUserCommand(user); got != tt.check {
				t.Errorf("CheckUserCommand = %q, want %q", got, tt.check)
			}
			if !u.UserExists(tt.existsOut, user) {
				t.Errorf("UserExists(%q) = false, want true", tt.existsOut)
			}
			if u.UserExists(tt.missingOut, user) {
				t.Errorf("UserExists(%q) = true, want false (prefix collision or absent)", tt.missingOut)
			}
			if u.UserExists("", user) {
				t.Error("UserExists on empty output must be false")
			}
			eq := func(what string, steps []Step, want []string) {
				t.Helper()
				for _, s := range steps {
					if s.Kind != StepBody {
						t.Errorf("%s: step %q has kind %v, want StepBody", what, s.Line, s.Kind)
					}
				}
				if got := Lines(steps); !reflect.DeepEqual(got, want) {
					t.Errorf("%s:\n got  %q\n want %q", what, got, want)
				}
			}
			eq("create", u.CreateUserSteps(user, pw, 15), tt.create)
			eq("delete", u.DeleteUserSteps(user), tt.del)
			eq("passwd", u.ChangePasswordSteps(user, pw, false), tt.passwd)
			got := Lines(u.ChangePasswordSteps(user, pw, true))
			if !reflect.DeepEqual(got, tt.enable) && (len(got) != 0 || len(tt.enable) != 0) {
				t.Errorf("enable secret: got %q, want %q", got, tt.enable)
			}
		})
	}
}

func TestJunosUserHashing(t *testing.T) {
	p, _ := Lookup(Junos)
	u, _ := p.Users()
	steps := Lines(u.CreateUserSteps("bob", "S3cretPass", 15))
	if len(steps) != 2 || steps[0] != "set system login user bob class super-user" {
		t.Fatalf("create steps = %q", steps)
	}
	// the hash on the wire must be a genuine SHA-512 crypt of the password
	line := steps[1]
	if strings.Contains(line, "S3cretPass") {
		t.Fatalf("plaintext password leaked into the command: %q", line)
	}
	const prefix = `set system login user bob authentication encrypted-password "`
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, `"`) {
		t.Fatalf("unexpected line %q", line)
	}
	hash := strings.TrimSuffix(strings.TrimPrefix(line, prefix), `"`)
	parts := strings.Split(hash, "$") // "", "6", salt, digest
	if len(parts) != 4 || parts[1] != "6" || len(parts[2]) != 16 || len(parts[3]) != 86 {
		t.Fatalf("malformed hash %q", hash)
	}
	if again := sha512Crypt("S3cretPass", parts[2]); again != hash {
		t.Errorf("hash does not verify: %s != %s", again, hash)
	}
	// two hashes of the same password use different salts
	a, _ := HashPassword("S3cretPass")
	b, _ := HashPassword("S3cretPass")
	if a == b {
		t.Error("salts are not random")
	}
	// privilege classes
	for priv, want := range map[int]string{15: "super-user", 10: "operator", 8: "operator", 7: "read-only", 1: "read-only"} {
		if got := Lines(u.CreateUserSteps("bob", "S3cretPass", priv))[0]; !strings.HasSuffix(got, "class "+want) {
			t.Errorf("privilege %d: %q, want class %s", priv, got, want)
		}
	}
}

func TestSHA512CryptKnownVectors(t *testing.T) {
	// Vector from Ulrich Drepper's SHA-crypt specification.
	if got, want := sha512Crypt("Hello world!", "saltstring"),
		"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"; got != want {
		t.Errorf("Drepper vector: got %s want %s", got, want)
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed; skipping the cross-check")
	}
	for _, tc := range [][2]string{{"hunter2", "saltsalt"}, {"P@ssw0rd!x", "abcdefghijklmnop"}, {"a", "Z"},
		{"averyveryverylongpasswordthatexceedsonehashblock_0123456789_0123456789", "xyz"}} {
		want, err := exec.Command("openssl", "passwd", "-6", "-salt", tc[1], tc[0]).Output() // #nosec G204 -- fixed test vectors
		if err != nil {
			t.Skipf("openssl cannot do SHA-512 crypt: %v", err)
		}
		if got := sha512Crypt(tc[0], tc[1]); got != strings.TrimSpace(string(want)) {
			t.Errorf("sha512Crypt(%q,%q) = %s, openssl says %s", tc[0], tc[1], got, want)
		}
	}
}

func TestUnsupportedUserPrivileges(t *testing.T) {
	for _, v := range []string{Aruba, Fortinet} {
		p, _ := Lookup(v)
		u, _ := p.Users()
		if got := u.CreateUserSteps("bob", "S3cretPass", 5); len(got) != 0 {
			t.Errorf("%s: privilege 5 must yield no steps (no equivalent), got %q", v, Lines(got))
		}
	}
}

func TestRestoreUserSteps(t *testing.T) {
	tests := []struct {
		vendor, snapshot string
		want             []string
	}{
		{Cisco, "username other privilege 1 secret 9 $9$z\nusername bob privilege 15 secret 9 $9$abc\n", []string{"username bob privilege 15 secret 9 $9$abc"}},
		{Aruba, "user bob group administrators password ciphertext AQBap\n", []string{"user bob group administrators password ciphertext AQBap"}},
		{Huawei, " local-user bob password irreversible-cipher $1c$abc\n local-user bob privilege level 15\n",
			[]string{"aaa", "local-user bob password irreversible-cipher $1c$abc", "local-user bob privilege level 15", "quit"}},
		{Fortinet, "config system admin\n    edit \"bob\"\n        set password ENC SH2xyz\n    next\nend\n",
			[]string{"config system admin", "edit \"bob\"", "set password ENC SH2xyz", "next", "end"}},
	}
	for _, tt := range tests {
		p, _ := Lookup(tt.vendor)
		u, _ := p.Users()
		if got := Lines(u.RestoreUserSteps("bob", tt.snapshot)); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s restore:\n got  %q\n want %q", tt.vendor, got, tt.want)
		}
		if got := u.RestoreUserSteps("bob", ""); len(got) != 0 {
			t.Errorf("%s: an empty snapshot must restore nothing, got %q", tt.vendor, Lines(got))
		}
	}
	// candidate-config platforms restore through commit-confirm, not a snapshot
	for _, v := range []string{Junos, VyOS, Arista} {
		p, _ := Lookup(v)
		u, _ := p.Users()
		if got := u.RestoreUserSteps("bob", "username bob secret 0 x"); len(got) != 0 {
			t.Errorf("%s: unexpected restore steps %q", v, Lines(got))
		}
	}
}

func TestVLANDrivers(t *testing.T) {
	tests := []struct {
		vendor  string
		check   string
		present string
		absent  string
		name    string
		create  []string
		createN []string
		del     []string
	}{
		{Cisco, "show vlan id 30",
			"VLAN Name                             Status    Ports\n---- -------------------------------- --------- ---------\n30   Servers                          active    Gi1/0/1, Gi1/0/2\n                                                Gi1/0/3\n\nVLAN Type  SAID       MTU\n---- ----- ---------- -----\n30   enet  100030     1500\n",
			"VLAN id 30 not found in current VLAN database\n", "Servers",
			[]string{"vlan 30"}, []string{"vlan 30", "name Srv"}, []string{"no vlan 30"}},
		{Ruijie, "show vlan id 30",
			"VLAN Name      Status  Ports\n---- --------- ------- ------\n  30 Servers   STATIC  Gi0/1\n", "", "Servers",
			[]string{"vlan 30"}, []string{"vlan 30", "name Srv"}, []string{"no vlan 30"}},
		{Arista, "show vlan 30",
			"VLAN  Name                             Status    Ports\n----- -------------------------------- --------- -----\n30    Servers                          active    Et1, Et2\n",
			"% VLAN 30 not found in current VLAN database\n", "Servers",
			[]string{"vlan 30"}, []string{"vlan 30", "name Srv"}, []string{"no vlan 30"}},
		{Aruba, "show vlan 30",
			"VLAN  Name     Status Reason Type    Interfaces\n-----------------------------------------\n30    Servers  up     ok     static  1/1/1\n",
			"VLAN 30 was not found\n", "Servers",
			[]string{"vlan 30"}, []string{"vlan 30", "name Srv"}, []string{"no vlan 30"}},
		{Huawei, "display vlan 30",
			"VID  Type    Ports\n------------------------------\n30   common  UT:GE0/0/1(U)\n\nVID  Status  Property      MAC-LRN Statistics Description\n------------------------------\n30   enable  default       enable  disable    Servers\n",
			"Error: The VLAN does not exist.\n", "Servers",
			[]string{"vlan 30", "quit"}, []string{"vlan 30", "description Srv", "quit"}, []string{"undo vlan 30"}},
		{Junos, `show configuration vlans | display set | match "vlan-id 30$"`,
			"set vlans Servers vlan-id 30\n", "", "Servers",
			[]string{"set vlans VLAN30 vlan-id 30"}, []string{"set vlans Srv vlan-id 30"}, []string{"delete vlans Servers"}},
	}
	for _, tt := range tests {
		t.Run(tt.vendor, func(t *testing.T) {
			p, _ := Lookup(tt.vendor)
			v, ok := p.VLANs()
			if !ok {
				t.Fatal("no VLAN driver")
			}
			if got := v.CheckVLANCommand(30); got != tt.check {
				t.Errorf("CheckVLANCommand = %q, want %q", got, tt.check)
			}
			if !v.VLANExists(tt.present, 30) {
				t.Error("VLANExists(present) = false")
			}
			if v.VLANExists(tt.absent, 30) {
				t.Errorf("VLANExists(%q) = true", tt.absent)
			}
			if v.VLANExists(tt.present, 31) {
				t.Error("VLAN 31 must not match the row of VLAN 30")
			}
			if got := v.VLANName(tt.present, 30); got != tt.name {
				t.Errorf("VLANName = %q, want %q", got, tt.name)
			}
			if got := Lines(v.CreateVLANSteps(30, "")); !reflect.DeepEqual(got, tt.create) {
				t.Errorf("create: got %q want %q", got, tt.create)
			}
			if got := Lines(v.CreateVLANSteps(30, "Srv")); !reflect.DeepEqual(got, tt.createN) {
				t.Errorf("create named: got %q want %q", got, tt.createN)
			}
			if got := Lines(v.DeleteVLANSteps(30, "Servers")); !reflect.DeepEqual(got, tt.del) {
				t.Errorf("delete: got %q want %q", got, tt.del)
			}
		})
	}
	// Junos deletes by name: with no name known, refuse rather than guess.
	p, _ := Lookup(Junos)
	v, _ := p.VLANs()
	if got := v.DeleteVLANSteps(30, ""); len(got) != 0 {
		t.Errorf("Junos delete without a name must yield no steps, got %q", Lines(got))
	}
}

func TestFactsParsers(t *testing.T) {
	tests := []struct {
		vendor string
		want   DeviceFacts
	}{
		{Cisco, DeviceFacts{"sw-core01", "C9300-48P", "FCW2301A0AB", "16.12.04", "2 weeks, 3 days, 4 hours, 5 minutes"}},
		{CiscoSB, DeviceFacts{"sw-sb1", "SG350-28-K9", "DNI2147ABCD", "2.5.5.47", "05,02:03:04"}},
		{CiscoASA, DeviceFacts{"fw-edge", "ASA5525", "JMX1234L0AB", "9.12(4)", "12 days 3 hours"}},
		{Junos, DeviceFacts{"ex4300-sw1", "ex4300-48t", "VK3718123456", "21.4R3-S2.3", "6w2d 02:11"}},
		{Huawei, DeviceFacts{"", "S5720-28X-LI-AC", "2102350XXXXXXXXXXXXX", "5.170 (S5720 V200R011C10SPC600)", "12 weeks, 4 days, 3 hours, 5 minutes"}},
		{Fortinet, DeviceFacts{"FGT-HQ", "FortiGate-60F", "FGT60FTK20012345", "v7.0.12", "12 days,  3 hours,  24 minutes"}},
		{Arista, DeviceFacts{"arista-leaf1", "DCS-7050TX-64-F", "JPE12345678", "4.28.3M", "12 weeks, 3 days, 2 hours and 10 minutes"}},
		{VyOS, DeviceFacts{"vyos-edge1", "A2SDi-8C-HLN4F", "1234567890", "1.3.3", "21 days,  3:04"}},
		{Ruijie, DeviceFacts{"", "S5750C-28GT4XS-H", "G1MQ12345678", "S5750C_RGOS 11.4(1)B79P3", "53:12:30:41"}},
		{Aruba, DeviceFacts{"sw-cx1", "JL675A 6100 48G CL4 4SFP+ Swch", "SG12345678", "FL.10.10.1010", "23 days, 4 hours, 12 minutes"}},
		{CheckPoint, DeviceFacts{"cp-gw1", "Check Point 5200", "1234567890", "Check Point Gaia R81.10", "8 days, 4:04"}},
		{PaloAlto, DeviceFacts{"PA-220-HQ", "PA-220", "012345678901", "10.1.6-h6", "5 days, 12:03:10"}},
		{PfSense, DeviceFacts{"pfsense.example.net", "Netgate 4100", "1234567890ABC", "2.7.2-RELEASE", "42 days,  1:23"}},
		{Sophos, DeviceFacts{"", "XG115", "C12345ABCDEF123", "SFOS 18.5.3 MR-3-Build408", ""}},
	}
	if len(tests) != len(factsDrivers) {
		t.Fatalf("facts table covers %d vendors, factsDrivers has %d", len(tests), len(factsDrivers))
	}
	for _, tt := range tests {
		t.Run(tt.vendor, func(t *testing.T) {
			p, _ := Lookup(tt.vendor)
			f, ok := p.Facts()
			if !ok {
				t.Fatal("no facts driver")
			}
			sample, err := os.ReadFile(filepath.Join("testdata", "facts", tt.vendor+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			// the sample's section headers must be exactly the commands the driver sends
			var headers []string
			for _, l := range strings.Split(string(sample), "\n") {
				if strings.HasPrefix(l, "=== ") && strings.HasSuffix(l, " ===") {
					headers = append(headers, strings.TrimSuffix(strings.TrimPrefix(l, "=== "), " ==="))
				}
			}
			if cmds := SplitCommands(f.FactsCommand()); !reflect.DeepEqual(cmds, headers) {
				t.Errorf("sample sections %q do not match FactsCommand %q", headers, cmds)
			}
			if got := f.ParseFacts(string(sample)); got != tt.want {
				t.Errorf("ParseFacts:\n got  %+v\n want %+v", got, tt.want)
			}
			// CRLF output (SSH PTYs) must parse the same
			if got := f.ParseFacts(strings.ReplaceAll(string(sample), "\n", "\r\n")); got != tt.want {
				t.Errorf("ParseFacts with CRLF:\n got  %+v\n want %+v", got, tt.want)
			}
			if got := f.ParseFacts(""); got != (DeviceFacts{}) {
				t.Errorf("empty output must give empty facts, got %+v", got)
			}
		})
	}
}

func TestCombineOutputsRoundTrip(t *testing.T) {
	cmds := SplitCommands(" show version \n\nshow system\n")
	if !reflect.DeepEqual(cmds, []string{"show version", "show system"}) {
		t.Fatalf("SplitCommands = %q", cmds)
	}
	got := CombineOutputs(cmds, []string{"a\r\n", "b"})
	if want := "=== show version ===\na\n=== show system ===\nb\n"; got != want {
		t.Errorf("CombineOutputs = %q, want %q", got, want)
	}
}

func rec(mac, ip, iface string, vlan int) LocatorRecord {
	return LocatorRecord{MAC: mac, IP: ip, Interface: iface, VLAN: vlan}
}

func TestLocatorParsers(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"
	tests := []struct {
		vendor  string
		macOut  string
		wantMAC []LocatorRecord
		ipOut   string
		wantIP  []LocatorRecord
	}{
		{Cisco,
			"          Mac Address Table\n-------------------------------------------\n\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n  30    aabb.ccdd.eeff    DYNAMIC     Gi1/0/14\nAll    ffff.ffff.ffff    STATIC      CPU\nTotal Mac Addresses for this criterion: 2\n",
			[]LocatorRecord{rec(mac, "", "Gi1/0/14", 30), rec("ff:ff:ff:ff:ff:ff", "", "CPU", 0)},
			"Protocol  Address          Age (min)  Hardware Addr   Type   Interface\nInternet  10.1.20.15              5   aabb.ccdd.eeff  ARPA   Vlan30\nInternet  10.1.20.99              0   Incomplete      ARPA\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "Vlan30", 30)}},
		{CiscoSB,
			"Aging time is 300 sec\n\nVlan       Mac Address         Port       Type\n-------- --------------------- ---------- ----------\n  30      aa:bb:cc:dd:ee:ff     gi14       dynamic\n",
			[]LocatorRecord{rec(mac, "", "gi14", 30)},
			"Interface   IP address         HW address           status\n----------- ----------------- -------------------- --------\nvlan 30     10.1.20.15         aa:bb:cc:dd:ee:ff    dynamic\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "vlan 30", 30)}},
		{CiscoASA, "", nil,
			"        inside 10.1.20.15 aabb.ccdd.eeff 12\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "inside", 0)}},
		{Junos,
			"Ethernet-switching table: 1 entries, 1 learned, 0 persistent entries\n  VLAN              MAC address       Type         Age Interfaces\n  VLAN30            aa:bb:cc:dd:ee:ff Learn          0 ge-0/0/14.0\n",
			[]LocatorRecord{rec(mac, "", "ge-0/0/14.0", 30)},
			"aa:bb:cc:dd:ee:ff 10.1.20.15 10.1.20.15 irb.30 none\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "irb.30", 30)}},
		{Huawei,
			"MAC address table of slot 0:\n-------------------------------------------------------------------------------\nMAC Address    VLAN/VSI/BD                       Learned-From        Type\n-------------------------------------------------------------------------------\naabb-ccdd-eeff 30/-/-                            GE0/0/14            dynamic\n",
			[]LocatorRecord{rec(mac, "", "GE0/0/14", 30)},
			"IP ADDRESS      MAC ADDRESS     EXPIRE(M)  TYPE  INTERFACE      VPN-INSTANCE\n                                           VLAN/CEVLAN\n------------------------------------------------------------------------------\n10.1.20.15      aabb-ccdd-eeff  20         D-0   Vlanif30\n                                           30/-\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "Vlanif30", 30)}},
		{Fortinet, "", nil,
			"Address           Age(min)   Hardware Addr      Interface\n10.1.20.15        0          aa:bb:cc:dd:ee:ff  port1\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "port1", 0)}},
		{Arista,
			"          Mac Address Table\n------------------------------------------------------------------\nVlan    Mac Address       Type        Ports      Moves   Last Move\n----    -----------       ----        -----      -----   ---------\n  30    aabb.ccdd.eeff    DYNAMIC     Et14       1       0:03:01 ago\n",
			[]LocatorRecord{rec(mac, "", "Et14", 30)},
			"Address         Age (sec)  Hardware Addr   Interface\n10.1.20.15      0:00:41    aabb.ccdd.eeff  Vlan30, Ethernet14\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "Ethernet14", 30)}},
		{VyOS, "", nil,
			"Address                  HWtype  HWaddress           Flags Mask            Iface\n10.1.20.15              ether   aa:bb:cc:dd:ee:ff   C                     eth1\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "eth1", 0)}},
		{Ruijie,
			"Vlan      MAC Address        Type      Interface\n----  ----------------  --------  ----------------\n  30    aabb.ccdd.eeff   DYNAMIC   GigabitEthernet 0/14\n",
			[]LocatorRecord{rec(mac, "", "GigabitEthernet 0/14", 30)},
			"Protocol  IP Address      Age(min)  Hardware Address  Type   Interface\nInternet  10.1.20.15            5   aabb.ccdd.eeff    arpa   GigabitEthernet 0/24\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "GigabitEthernet 0/24", 0)}},
		{Aruba,
			"MAC age-time            : 300 seconds\nNumber of MAC addresses : 1\n\nMAC Address          VLAN     Type                      Port\n--------------------------------------------------------------\naa:bb:cc:dd:ee:ff    30       dynamic                   1/1/14\n",
			[]LocatorRecord{rec(mac, "", "1/1/14", 30)},
			"IPv4 Address     MAC                Port         Physical Port        State\n10.1.20.15       aa:bb:cc:dd:ee:ff  vlan30       1/1/14               reachable\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "1/1/14", 30)}},
		{CheckPoint, "", nil,
			"10.1.20.15      ether   aa:bb:cc:dd:ee:ff   C   eth1\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "eth1", 0)}},
		{PaloAlto, "", nil,
			"interface         ip address      hw address        port  status  ttl\nethernet1/1       10.1.20.15      aa:bb:cc:dd:ee:ff ethernet1/1  c  1795\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "ethernet1/1", 0)}},
		{PfSense, "", nil,
			"? (10.1.20.15) at aa:bb:cc:dd:ee:ff on em1 expires in 1195 seconds [ethernet]\n",
			[]LocatorRecord{rec(mac, "10.1.20.15", "em1", 0)}},
	}
	for _, tt := range tests {
		t.Run(tt.vendor, func(t *testing.T) {
			p, _ := Lookup(tt.vendor)
			l, ok := p.Locator()
			if !ok {
				t.Fatal("no locator")
			}
			if got := l.ParseMAC(tt.macOut); !reflect.DeepEqual(got, tt.wantMAC) {
				t.Errorf("ParseMAC:\n got  %+v\n want %+v", got, tt.wantMAC)
			}
			if got := l.ParseIP(tt.ipOut); !reflect.DeepEqual(got, tt.wantIP) {
				t.Errorf("ParseIP:\n got  %+v\n want %+v", got, tt.wantIP)
			}
			if got := l.ParseMAC(""); len(got) != 0 {
				t.Errorf("ParseMAC(\"\") = %+v", got)
			}
		})
	}
}

func TestLocatorCommands(t *testing.T) {
	tests := []struct {
		vendor, in, wantMAC string
	}{
		{Cisco, "AA-BB-CC-DD-EE-FF", "show mac address-table address aabb.ccdd.eeff"},
		{CiscoSB, "aabb.ccdd.eeff", "show mac address-table address aa:bb:cc:dd:ee:ff"},
		{Junos, "aabb.ccdd.eeff", "show ethernet-switching table | match aa:bb:cc:dd:ee:ff"},
		{Huawei, "aa:bb:cc:dd:ee:ff", "display mac-address aabb-ccdd-eeff"},
		{Arista, "aabbccddeeff", "show mac address-table address aabb.ccdd.eeff"},
		{Ruijie, "aa:bb:cc:dd:ee:ff", "show mac-address-table address aabb.ccdd.eeff"},
		{Aruba, "aabb.ccdd.eeff", "show mac-address-table | include aa:bb:cc:dd:ee:ff"},
	}
	for _, tt := range tests {
		p, _ := Lookup(tt.vendor)
		l, _ := p.Locator()
		if got := l.FindMACCommand(tt.in); got != tt.wantMAC {
			t.Errorf("%s FindMACCommand(%q) = %q, want %q", tt.vendor, tt.in, got, tt.wantMAC)
		}
		if got := l.FindMACCommand("not-a-mac"); got != "" {
			t.Errorf("%s: invalid MAC produced command %q", tt.vendor, got)
		}
	}
	p, _ := Lookup(Cisco)
	l, _ := p.Locator()
	if got := l.FindIPCommand("10.1.20.15"); got != "show ip arp 10.1.20.15" {
		t.Errorf("FindIPCommand = %q", got)
	}
	if got := l.FindIPCommand("10.1.20.15; reload"); got != "" {
		t.Errorf("a non-IP argument must never reach the device, got %q", got)
	}
}

func TestTrunkDetection(t *testing.T) {
	p, _ := Lookup(Cisco)
	td, ok := p.Trunks()
	if !ok {
		t.Fatal("cisco has no trunk detector")
	}
	out := "Port        Mode             Encapsulation  Status        Native vlan\nGi1/0/48    on               802.1q         trunking      1\nPo1         on               802.1q         trunking      1\nGi1/0/3     auto             802.1q         not-trunking  1\n\nPort        Vlans allowed on trunk\nGi1/0/48    1-4094\n"
	if got, want := td.ParseTrunkPorts(out), []string{"Gi1/0/48", "Po1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("cisco trunks = %q, want %q", got, want)
	}
	p, _ = Lookup(Arista)
	td, _ = p.Trunks()
	if got, want := td.ParseTrunkPorts("Port       Mode         Status       Native vlan\nEt47       trunk        trunking     1\nEt3        access       -            1\n"), []string{"Et47"}; !reflect.DeepEqual(got, want) {
		t.Errorf("arista trunks = %q, want %q", got, want)
	}
	p, _ = Lookup(Junos)
	if _, ok := p.Trunks(); ok {
		if td, _ := p.Trunks(); td.TrunkPortsCommand() != "" {
			t.Error("junos must not claim a trunk command it does not implement")
		}
	}
}

func TestInternalAndAggregatePorts(t *testing.T) {
	for _, n := range []string{"CPU", "cpu", "Router", "Vlan30", "Vlanif30", "irb", "irb.30", "sup-eth1", "vme", ""} {
		if !IsInternalPort(n) {
			t.Errorf("%q should be internal", n)
		}
	}
	for _, n := range []string{"Gi1/0/14", "ge-0/0/14.0", "Et14", "GE0/0/14", "1/1/14", "port1"} {
		if IsInternalPort(n) {
			t.Errorf("%q must not be internal", n)
		}
	}
	for _, n := range []string{"Po1", "Port-channel1", "ae0", "ae0.0", "Eth-Trunk1", "Bridge-Aggregation1"} {
		if !IsAggregatePort(n) {
			t.Errorf("%q should be an aggregate", n)
		}
	}
	if IsAggregatePort("Gi1/0/1") {
		t.Error("Gi1/0/1 is not an aggregate")
	}
}

func TestValidation(t *testing.T) {
	for _, u := range []string{"bob", "svc.backup-01", "A", strings.Repeat("a", 32)} {
		if err := ValidateUsername(u); err != nil {
			t.Errorf("ValidateUsername(%q): %v", u, err)
		}
	}
	for _, u := range []string{"", "-bob", "bob smith", "bob;reload", "bob\"", strings.Repeat("a", 33), "bob\nenable"} {
		if ValidateUsername(u) == nil {
			t.Errorf("ValidateUsername(%q) accepted", u)
		}
	}
	for _, pw := range []string{"S3cretPass", "P@ss!w0rd#$%^&*()", "a"} {
		if err := ValidatePassword(pw); err != nil {
			t.Errorf("ValidatePassword(%q): %v", pw, err)
		}
	}
	for _, pw := range []string{"", "has space", "ques?tion", `quo"te`, "quo'te", `back\slash`, "tab\there", "new\nline", "ünïcode", strings.Repeat("x", 65)} {
		if ValidatePassword(pw) == nil {
			t.Errorf("ValidatePassword(%q) accepted", pw)
		}
	}
	for _, id := range []int{1, 30, 4094} {
		if err := ValidateVLANID(id); err != nil {
			t.Errorf("ValidateVLANID(%d): %v", id, err)
		}
	}
	for _, id := range []int{-1, 0, 4095, 70000} {
		if ValidateVLANID(id) == nil {
			t.Errorf("ValidateVLANID(%d) accepted", id)
		}
	}
	if ValidateVLANName("") != nil || ValidateVLANName("Servers_1") != nil {
		t.Error("valid VLAN names rejected")
	}
	if ValidateVLANName("two words") == nil || ValidateVLANName("x;y") == nil {
		t.Error("invalid VLAN names accepted")
	}
	if ValidatePrivilege(0) == nil || ValidatePrivilege(16) == nil || ValidatePrivilege(15) != nil {
		t.Error("privilege range check wrong")
	}
}

func TestMACNormalizeAndFormat(t *testing.T) {
	for _, in := range []string{"aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb-ccdd-eeff", "aabbccddeeff", " AaBb.CcDd.EeFf "} {
		n, err := NormalizeMAC(in)
		if err != nil || n != "aabbccddeeff" {
			t.Errorf("NormalizeMAC(%q) = %q, %v", in, n, err)
		}
	}
	for _, in := range []string{"", "aabb.ccdd", "gg:bb:cc:dd:ee:ff", "aabb.ccdd.eeff.0011"} {
		if _, err := NormalizeMAC(in); err == nil {
			t.Errorf("NormalizeMAC(%q) accepted", in)
		}
	}
	for style, want := range map[MACStyle]string{
		MACDotted: "aabb.ccdd.eeff", MACColon: "aa:bb:cc:dd:ee:ff", MACHyphen: "aa-bb-cc-dd-ee-ff", MACHuawei: "aabb-ccdd-eeff",
	} {
		if got := FormatMAC("aabbccddeeff", style); got != want {
			t.Errorf("FormatMAC style %d = %q, want %q", style, got, want)
		}
	}
}

func stepKinds(steps []Step) []StepKind {
	out := make([]StepKind, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Kind)
	}
	return out
}

func TestPreVerifyPlacement(t *testing.T) {
	cmds := []string{"x"}
	// plain platforms: the check sits between leaving config mode and saving
	p, _ := Lookup(Cisco)
	got := stepKinds(p.BuildPlan(cmds, PlanOptions{PreVerify: true}).Steps)
	want := []StepKind{StepEnter, StepBody, StepExit, StepVerify, StepPersist}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cisco PreVerify plan = %v, want %v", got, want)
	}
	// FortiOS never persists: the check goes last
	p, _ = Lookup(Fortinet)
	got = stepKinds(p.BuildPlan(cmds, PlanOptions{PreVerify: true}).Steps)
	if want = []StepKind{StepBody, StepVerify}; !reflect.DeepEqual(got, want) {
		t.Errorf("fortinet PreVerify plan = %v, want %v", got, want)
	}
	// commit-confirm plans already verify before confirming: exactly one check
	p, _ = Lookup(Junos)
	plan := p.BuildPlan(cmds, PlanOptions{PreVerify: true, CommitConfirm: 5})
	n := 0
	for _, s := range plan.Steps {
		if s.Kind == StepVerify {
			n++
		}
	}
	if n != 1 || plan.Confirm != ConfirmNative {
		t.Errorf("junos commit-confirm plan has %d verify steps, confirm=%v", n, plan.Confirm)
	}
	// without PreVerify the classic behaviour is unchanged
	p, _ = Lookup(Cisco)
	if got = stepKinds(p.BuildPlan(cmds, PlanOptions{Verify: true}).Steps); got[len(got)-1] != StepVerify {
		t.Errorf("classic Verify placement changed: %v", got)
	}
}

package vendor

import (
	"slices"
	"strings"
	"testing"
)

func lines(steps []Step) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Line)
	}
	return out
}

func mustLookup(t *testing.T, name string) *Profile {
	t.Helper()
	p, ok := Lookup(name)
	if !ok {
		t.Fatalf("Lookup(%q) failed", name)
	}
	return p
}

var testCmds = []string{"hostname lab1", "ntp server 10.0.0.9"}

func TestLookupAliases(t *testing.T) {
	cases := map[string]string{
		"cisco": Cisco, "Cisco": Cisco, "IOS-XE": Cisco, "ios_xe": Cisco, " iosxe ": Cisco,
		"junos": Junos, "Juniper": Junos,
		"huawei": Huawei, "VRP": Huawei,
		"fortinet": Fortinet, "FortiGate": Fortinet, "fortios": Fortinet,
		"arista": Arista, "EOS": Arista,
		"vyos": VyOS, "VyOS": VyOS, "vyatta": VyOS,
		"ruijie": Ruijie, "RGOS": Ruijie,
		"aruba": Aruba, "AOS-CX": Aruba,
		"checkpoint": CheckPoint, "checkpoint-gaia": CheckPoint, "clish": CheckPoint,
		"paloalto": PaloAlto, "panos": PaloAlto,
		"pfsense": PfSense,
		"sophos":  Sophos, "sfos": Sophos,
		"cisco_sb": CiscoSB, "Cisco-SB": CiscoSB, "SG350": CiscoSB, "CBS350": CiscoSB,
		"cisco_asa": CiscoASA, "ASA": CiscoASA, "FTD": CiscoASA,
		"h3c": Huawei, "Comware": Huawei, "HP_Comware": Huawei,
	}
	for in, want := range cases {
		p, ok := Lookup(in)
		if !ok || p.Name != want {
			t.Errorf("Lookup(%q) = %v, %v; want %s", in, p, ok, want)
		}
	}
	if _, ok := Lookup("nokia"); ok {
		t.Error("Lookup(nokia) should fail")
	}
	if got := Names(); !slices.Equal(got, []string{"arista", "aruba", "checkpoint", "cisco", "cisco_asa", "cisco_sb", "fortinet", "huawei", "junos", "paloalto", "pfsense", "ruijie", "sophos", "vyos"}) {
		t.Errorf("Names() = %v", got)
	}
}

func TestLookupCiscoSBAndASAAliases(t *testing.T) {
	groups := map[string][]string{
		CiscoSB: {
			"cisco_sb", "cisco_sf", "cisco_sg", "ciscosb", "ciscosf", "ciscosg",
			"cbs", "cbs350", "sg300", "sg350", "sg500", "sf300", "sf500",
		},
		CiscoASA: {"cisco_asa", "asa", "cisco_ftd", "ftd"},
		Huawei:   {"h3c", "comware", "hp_comware"},
	}
	for want, names := range groups {
		for _, name := range names {
			// Lookup folds case and treats "_", "-" and " " alike.
			variants := []string{
				name,
				strings.ToUpper(name),
				strings.ReplaceAll(name, "_", "-"),
				strings.ReplaceAll(name, "_", " "),
				"  " + name + "\t",
			}
			for _, in := range variants {
				if p, ok := Lookup(in); !ok || p.Name != want {
					t.Errorf("Lookup(%q) = %v, %v; want %s", in, p, ok, want)
				}
			}
		}
	}
}

// Lookup normalises its input before consulting the alias table, so a key
// that is not already in normalised form can never match and silently does
// nothing. Canonical names such as "cisco_sb" must also resolve themselves.
func TestAliasTableIsReachable(t *testing.T) {
	for key, canonical := range aliases {
		norm := strings.NewReplacer("_", "-", " ", "-").Replace(strings.ToLower(strings.TrimSpace(key)))
		if key != norm {
			t.Errorf("alias key %q is unreachable: Lookup normalises it to %q", key, norm)
		}
		if _, ok := registry[canonical]; !ok {
			t.Errorf("alias %q points at unregistered vendor %q", key, canonical)
		}
	}
	for _, name := range Names() {
		if p, ok := Lookup(name); !ok || p.Name != name {
			t.Errorf("canonical name %q does not resolve to itself: %v, %v", name, p, ok)
		}
	}
}

func TestApplyPlans(t *testing.T) {
	cisco := []string{"configure terminal", "hostname lab1", "ntp server 10.0.0.9", "end", "write memory"}
	cases := []struct {
		vendor string
		want   []string
	}{
		{"cisco", cisco},
		{"ios-xe", cisco},
		{"arista", cisco},
		{"ruijie", cisco},
		{"aruba", cisco},
		{"cisco_sb", cisco},
		{"sg350", cisco},
		{"cisco_asa", cisco},
		{"asa", cisco},
		{"junos", []string{"configure", "hostname lab1", "ntp server 10.0.0.9", "commit", "exit"}},
		{"huawei", []string{"system-view", "hostname lab1", "ntp server 10.0.0.9", "return", "save"}},
		{"fortinet", []string{"hostname lab1", "ntp server 10.0.0.9"}},
		{"vyos", []string{"configure", "hostname lab1", "ntp server 10.0.0.9", "commit", "save", "exit"}},
		{"paloalto", []string{"configure", "hostname lab1", "ntp server 10.0.0.9", "commit", "exit"}},
		{"pfsense", []string{"hostname lab1", "ntp server 10.0.0.9"}},
		{"sophos", []string{"hostname lab1", "ntp server 10.0.0.9"}},
		{"checkpoint", []string{"hostname lab1", "ntp server 10.0.0.9", "save config"}},
	}
	for _, c := range cases {
		plan := mustLookup(t, c.vendor).BuildPlan(testCmds, PlanOptions{})
		if got := lines(plan.Steps); !slices.Equal(got, c.want) {
			t.Errorf("%s apply plan:\n got  %q\n want %q", c.vendor, got, c.want)
		}
		if plan.DryRun || plan.Validates || len(plan.Simulated) != 0 {
			t.Errorf("%s apply plan flagged as dry-run: %+v", c.vendor, plan)
		}
	}
}

func TestPersistStepsAreSlow(t *testing.T) {
	for _, name := range Names() {
		for _, s := range mustLookup(t, name).BuildPlan(testCmds, PlanOptions{}).Steps {
			if s.Kind == StepPersist && !s.Slow {
				t.Errorf("%s: persist step %q should be marked slow", name, s.Line)
			}
		}
	}
}

func TestDryRunNeverPersists(t *testing.T) {
	forbidden := []string{"write memory", "commit", "save"}
	for _, name := range Names() {
		plan := mustLookup(t, name).BuildPlan(testCmds, PlanOptions{DryRun: true, Token: "t1"})
		if !plan.DryRun {
			t.Errorf("%s: DryRun flag not set", name)
		}
		for _, s := range plan.Steps {
			if s.Kind == StepPersist {
				t.Errorf("%s: dry-run contains a persist step %q", name, s.Line)
			}
			if slices.Contains(forbidden, s.Line) {
				t.Errorf("%s: dry-run would send %q", name, s.Line)
			}
		}
		for _, s := range plan.Cleanup {
			if s.Kind == StepPersist || slices.Contains(forbidden, s.Line) {
				t.Errorf("%s: dry-run cleanup persists via %q", name, s.Line)
			}
		}
	}
}

func TestDryRunProbeOnlyVendors(t *testing.T) {
	for _, name := range []string{"cisco", "cisco_sb", "cisco_asa", "huawei", "fortinet", "ruijie", "aruba", "checkpoint"} {
		plan := mustLookup(t, name).BuildPlan(testCmds, PlanOptions{DryRun: true})
		if plan.Validates {
			t.Errorf("%s: must not claim device-side validation", name)
		}
		if len(plan.Steps) != 1 || plan.Steps[0].Kind != StepProbe {
			t.Errorf("%s: want a single probe step, got %+v", name, plan.Steps)
		}
		for _, s := range plan.Steps {
			if s.Kind == StepBody {
				t.Errorf("%s: configuration command %q would be sent in dry-run", name, s.Line)
			}
		}
		var simulatedBody []string
		for _, s := range plan.Simulated {
			if s.Kind == StepBody {
				simulatedBody = append(simulatedBody, s.Line)
			}
		}
		if !slices.Equal(simulatedBody, testCmds) {
			t.Errorf("%s: simulated body = %q, want %q", name, simulatedBody, testCmds)
		}
	}
}

func TestDryRunValidatingVendors(t *testing.T) {
	junos := mustLookup(t, "junos").BuildPlan(testCmds, PlanOptions{DryRun: true})
	wantJunos := []string{"configure", "hostname lab1", "ntp server 10.0.0.9", "show | compare", "commit check", "rollback 0", "exit"}
	if !junos.Validates || !slices.Equal(lines(junos.Steps), wantJunos) {
		t.Errorf("junos dry-run = %q (validates=%v), want %q", lines(junos.Steps), junos.Validates, wantJunos)
	}

	eos := mustLookup(t, "arista").BuildPlan(testCmds, PlanOptions{DryRun: true, Token: "ab-12!"})
	wantEOS := []string{"configure session netconfig-ab12", "hostname lab1", "ntp server 10.0.0.9", "show session-config diffs", "abort"}
	if !eos.Validates || !slices.Equal(lines(eos.Steps), wantEOS) {
		t.Errorf("arista dry-run = %q (validates=%v), want %q", lines(eos.Steps), eos.Validates, wantEOS)
	}
	if got := lines(eos.Cleanup); !slices.Equal(got, []string{"abort"}) {
		t.Errorf("arista dry-run cleanup = %q", got)
	}

	vyos := mustLookup(t, "vyos").BuildPlan(testCmds, PlanOptions{DryRun: true})
	wantVyOS := []string{"configure", "hostname lab1", "ntp server 10.0.0.9", "compare", "exit discard"}
	if !vyos.Validates || !slices.Equal(lines(vyos.Steps), wantVyOS) {
		t.Errorf("vyos dry-run = %q (validates=%v), want %q", lines(vyos.Steps), vyos.Validates, wantVyOS)
	}
	if got := lines(vyos.Cleanup); !slices.Equal(got, []string{"exit discard"}) {
		t.Errorf("vyos dry-run cleanup = %q", got)
	}
}

func TestCleanupNeverPersists(t *testing.T) {
	for _, name := range Names() {
		plan := mustLookup(t, name).BuildPlan(testCmds, PlanOptions{})
		for _, s := range plan.Cleanup {
			if s.Kind == StepPersist || !s.IgnoreError {
				t.Errorf("%s: cleanup step %+v must be best-effort and non-persisting", name, s)
			}
		}
	}
	// Spot-check the two that matter most: failed Cisco changes are not saved,
	// failed Junos changes are rolled back instead of committed.
	if got := lines(mustLookup(t, "cisco").BuildPlan(testCmds, PlanOptions{}).Cleanup); !slices.Equal(got, []string{"end"}) {
		t.Errorf("cisco cleanup = %q", got)
	}
	if got := lines(mustLookup(t, "junos").BuildPlan(testCmds, PlanOptions{}).Cleanup); !slices.Equal(got, []string{"rollback 0", "exit"}) {
		t.Errorf("junos cleanup = %q", got)
	}
}

func TestPrompts(t *testing.T) {
	cases := []struct {
		vendor string
		line   string
		want   bool
	}{
		{"cisco", "Router#", true},
		{"cisco", "Router>", true},
		{"cisco", "Router(config)#", true},
		{"cisco", "SW-1(config-if)# ", true},
		{"cisco", "Password:", false},
		{"cisco", "% Invalid input detected at '^' marker.", false},
		{"junos", "admin@mx480>", true},
		{"junos", "admin@mx480#", true},
		{"junos", "root@srx:RE:0%", true},
		{"junos", "[edit]", false},
		{"huawei", "<Huawei>", true},
		{"huawei", "[Huawei]", true},
		{"huawei", "[Huawei-GigabitEthernet0/0/1]", true},
		{"huawei", "[~HUAWEI]", true},
		{"huawei", "Info: Succeeded", false},
		{"fortinet", "FGT60E #", true},
		{"fortinet", "FGT60E (root) # ", true},
		{"fortinet", "FGT60E (interface) #", true},
		{"fortinet", "Command fail. Return code -3", false},
		{"arista", "switch(config-s-netconfig-ab12)#", true},
		{"arista", "switch>", true},
		{"vyos", "vyos@vpc-transit-node01:~$ ", true},
		{"vyos", "vyos@vpc-transit-node01# ", true},
		{"vyos", "[edit]", false},
		{"checkpoint", "my-gw> ", true},
		{"cisco_sb", "switch1a2b3c#", true},
		{"cisco_sb", "switch1a2b3c>", true},
		{"cisco_sb", "switch1a2b3c(config)#", true},
		{"cisco_sb", "switch1a2b3c(config-if)# ", true},
		{"cisco_sb", "% Unrecognized command", false},
		{"cisco_asa", "asa1#", true},
		{"cisco_asa", "asa1>", true},
		{"cisco_asa", "asa1/pri/act#", true},
		{"cisco_asa", "asa1/pri/act(config)# ", true},
		{"cisco_asa", "asa1(config-if)#", true},
		{"cisco_asa", "ERROR: % Invalid input detected at '^' marker.", false},
	}
	for _, c := range cases {
		if got := mustLookup(t, c.vendor).Prompt.MatchString(c.line); got != c.want {
			t.Errorf("%s prompt match(%q) = %v, want %v", c.vendor, c.line, got, c.want)
		}
	}

	if !mustLookup(t, "cisco").UserPrompt.MatchString("Router>") {
		t.Error("cisco user prompt should match Router>")
	}
	if mustLookup(t, "cisco").UserPrompt.MatchString("Router#") {
		t.Error("cisco user prompt must not match privileged prompt")
	}
}

func TestFindError(t *testing.T) {
	cases := []struct {
		vendor string
		output string
		want   bool
	}{
		{"cisco", "% Invalid input detected at '^' marker.\n", true},
		{"cisco", "% Incomplete command.", true},
		{"cisco", "% Warning: something harmless", false},
		{"cisco", "Building configuration...\n[OK]", false},
		{"arista", "% Unavailable command (not supported on this hardware platform)", true},
		{"junos", "syntax error, expecting <command>.", true},
		{"junos", "error: configuration check-out failed", true},
		{"junos", "warning: statement not found", false},
		{"junos", "commit complete", false},
		{"huawei", "Error: Unrecognized command found at '^' position.", true},
		{"huawei", "Info: Succeeded.", false},
		{"fortinet", "Command fail. Return code -3", true},
		{"fortinet", "node_check_object fail! for member", true},
		{"fortinet", "FGT # ", false},
		{"vyos", "Invalid command: [set interfaces]", true},
		{"vyos", "Configuration error: commit failed", true},
		{"vyos", "vyos@router# ", false},
		{"checkpoint", "CLISH error: command not found", true},
		{"cisco_sb", "% Unrecognized command\r\n", true},
		{"cisco_sb", "% Invalid input detected at '^' marker.", true},
		{"cisco_sb", "Copy succeeded", false},
		{"cisco_asa", "% Invalid input detected at '^' marker.", true},
		{"cisco_asa", "Cryptochecksum: 0123abcd 4567ef01\n[OK]", false},
		// ASA prefixes its rejections with "ERROR: ", which the IOS pattern
		// (anchored on a leading "%") does not see.
		{"cisco_asa", "ERROR: % Invalid input detected at '^' marker.\r\n", true},
		{"cisco_asa", "ERROR: % Incomplete command.", true},
		{"cisco_asa", "ERROR: Interface name Gi0/9 doesn't exist", true},
		{"cisco_asa", "INFO: Converting 10.0.0.0 to 10.0.0.0", false},
		{"cisco_asa", "WARNING: IP address 10.0.0.1 is in use", false},
		{"cisco_asa", "banner motd ERROR: restricted system", false},
		{"cisco_asa", ": end", false},
		// ...and the ASA rule must not leak into the other Cisco-style vendors.
		{"cisco", "ERROR: not an IOS error format", false},
		{"cisco_sb", "ERROR: not an SB error format", false},
	}
	for _, c := range cases {
		_, got := mustLookup(t, c.vendor).FindError(c.output)
		if got != c.want {
			t.Errorf("%s FindError(%q) = %v, want %v", c.vendor, c.output, got, c.want)
		}
	}

	line, ok := mustLookup(t, "cisco").FindError("some output\r\n% Invalid input detected at '^' marker.\r\nmore")
	if !ok || line != "% Invalid input detected at '^' marker." {
		t.Errorf("FindError returned %q, %v", line, ok)
	}
}

func TestConfirmReply(t *testing.T) {
	cisco := mustLookup(t, "cisco")
	cases := []struct {
		prompt string
		reply  string
		ok     bool
	}{
		{"Do you want to continue? [y/n]: ", "y", true},
		{"Are you sure to continue?[Y/N]:", "y", true},
		{"Reboot the system ? [yes,no] (no) ", "yes", true},
		{"Do you really want to replace them? [yes/no]: ", "yes", true},
		{"Do you want to continue? (y/n) ", "y", true},
		{"Proceed with reload? [confirm]", "", true},
		{"Destination filename [startup-config]? ", "", true},
		{"Please input the file name ( *.cfg, *.zip ) [vrpcfg.zip]:", "", true},
		{"Building configuration...", "", false},
		{"Router#", "", false},
	}
	for _, c := range cases {
		reply, ok := cisco.ConfirmReply(c.prompt)
		if ok != c.ok || reply != c.reply {
			t.Errorf("ConfirmReply(%q) = %q, %v; want %q, %v", c.prompt, reply, ok, c.reply, c.ok)
		}
	}
}

func TestValidateBackup(t *testing.T) {
	cisco := mustLookup(t, "cisco")
	huawei := mustLookup(t, "huawei")
	pfsense := mustLookup(t, "pfsense")
	vyos := mustLookup(t, "vyos")

	// Empty output
	if err := cisco.ValidateBackup("   \n"); err == nil {
		t.Error("expected error for empty backup output")
	}

	// Missing config markers
	if err := cisco.ValidateBackup("random text without any config marker\nend\n"); err == nil {
		t.Error("expected error for missing config markers")
	}

	// Valid Cisco untruncated
	if err := cisco.ValidateBackup("!\ninterface GigabitEthernet0/1\nend\n"); err != nil {
		t.Errorf("expected valid cisco backup, got %v", err)
	}

	// Cisco truncated (no end marker)
	if err := cisco.ValidateBackup("!\ninterface GigabitEthernet0/1\nshutdown\n"); err == nil {
		t.Error("expected truncation error for missing cisco end marker")
	}

	// Valid Huawei untruncated
	if err := huawei.ValidateBackup("#\ninterface GE0/0/1\nreturn\n"); err != nil {
		t.Errorf("expected valid huawei backup, got %v", err)
	}

	// Huawei truncated
	if err := huawei.ValidateBackup("#\ninterface GE0/0/1\nshutdown\n"); err == nil {
		t.Error("expected truncation error for missing huawei return marker")
	}

	// Valid pfSense untruncated
	if err := pfsense.ValidateBackup("<pfsense>\n<system>\nsystem hostname\n<version>1</version>\n</pfsense>"); err != nil {
		t.Errorf("expected valid pfsense backup, got %v", err)
	}

	// pfSense truncated
	if err := pfsense.ValidateBackup("<pfsense>\n<system>\nsystem hostname\n<version>1</version>"); err == nil {
		t.Error("expected truncation error for missing pfsense </pfsense> marker")
	}

	// VyOS without EndMarkers defined (passes with config marker)
	if err := vyos.ValidateBackup("set interfaces ethernet eth0\n"); err != nil {
		t.Errorf("expected valid vyos backup, got %v", err)
	}
}

func TestPreDiffPlans(t *testing.T) {
	cmds := []string{"set system host-name lab1"}
	opts := PlanOptions{PreDiff: true, Token: "test"}

	junos := mustLookup(t, "junos").BuildPlan(cmds, opts)
	wantJunos := []string{"configure", "set system host-name lab1", "show | compare", "commit", "exit"}
	if got := lines(junos.Steps); !slices.Equal(got, wantJunos) {
		t.Errorf("Junos PreDiff steps = %v, want %v", got, wantJunos)
	}

	vyos := mustLookup(t, "vyos").BuildPlan(cmds, opts)
	wantVyOS := []string{"configure", "set system host-name lab1", "compare", "commit", "save", "exit"}
	if got := lines(vyos.Steps); !slices.Equal(got, wantVyOS) {
		t.Errorf("VyOS PreDiff steps = %v, want %v", got, wantVyOS)
	}

	arista := mustLookup(t, "arista").BuildPlan([]string{"hostname lab1"}, opts)
	wantArista := []string{
		"configure session netconfig-test",
		"hostname lab1",
		"show session-config diffs",
		"commit",
		"write memory",
	}
	if got := lines(arista.Steps); !slices.Equal(got, wantArista) {
		t.Errorf("Arista PreDiff steps = %v, want %v", got, wantArista)
	}

	cisco := mustLookup(t, "cisco").BuildPlan([]string{"hostname lab1"}, opts)
	wantCisco := []string{"configure terminal", "hostname lab1", "end", "write memory"}
	if got := lines(cisco.Steps); !slices.Equal(got, wantCisco) {
		t.Errorf("Cisco PreDiff steps = %v, want %v", got, wantCisco)
	}
}

func TestCiscoSBConfirmReply(t *testing.T) {
	sb := mustLookup(t, "cisco_sb")
	cases := []struct {
		prompt string
		reply  string
		ok     bool
	}{
		{"Proceed with reload? [confirm]", "", true},
		{"Do you want to continue? [y/n]: ", "y", true},
		{"Do you really want to replace them? [yes/no]: ", "yes", true},
		{"Destination filename [startup-config]? ", "", true},
		// "write memory" / "copy running-config startup-config" on SF/SG/CBS
		// default to N, so the question must be answered explicitly.
		{"Overwrite file [startup-config].... (Y/N)[N] ?", "Y", true},
		{"Overwrite file [startup-config].... (Y/N)[N] ? ", "Y", true},
		{"overwrite file [startup-config]...(y/n)[n]?", "Y", true},
		{"Overwrite file [startup-config]", "", false},
		{"Building configuration...", "", false},
		{"switch1a2b3c#", "", false},
	}
	for _, c := range cases {
		reply, ok := sb.ConfirmReply(c.prompt)
		if ok != c.ok || reply != c.reply {
			t.Errorf("ConfirmReply(%q) = %q, %v; want %q, %v", c.prompt, reply, ok, c.reply, c.ok)
		}
	}
}

func TestValidateBackupCiscoSBAndASA(t *testing.T) {
	sb := mustLookup(t, "cisco_sb")
	asa := mustLookup(t, "cisco_asa")

	const sbHeader = "config-file-header\nswitch1a2b3c\nCLI v1.0\n@\n!\n"
	const asaHeader = ": Saved\n:\nASA Version 9.16(4)\n!\nhostname asa1\n"

	cases := []struct {
		name   string
		p      *Profile
		output string
		wantOK bool
	}{
		{"sb ends with exit", sb, sbHeader + "interface gigabitethernet1\n description uplink\nexit\n", true},
		{"sb ends with exit, CRLF", sb, "config-file-header\r\nswitch1a2b3c\r\n!\r\ninterface gigabitethernet1\r\nexit\r\n", true},
		{"sb ends with end", sb, sbHeader + "interface gigabitethernet1\n description uplink\nend\n", true},
		{"sb ends with end, CRLF", sb, "config-file-header\r\n!\r\ninterface gigabitethernet1\r\nend\r\n", true},
		// SF/SG/CBS close every vlan/interface/line block with "exit", so "exit" is
		// only a terminator when it is the last line.
		{"sb cut mid-block after earlier exits", sb, sbHeader + "vlan database\nvlan 10\nexit\ninterface gigabitethernet1\n description uplink\nexit\ninterface gigabitethernet2\n description tru", false},
		{"sb cut right after a block header", sb, sbHeader + "interface gigabitethernet1\nexit\ninterface gigabitethernet2", false},
		{"sb cut mid-block, CRLF", sb, "config-file-header\r\n!\r\ninterface gigabitethernet1\r\nexit\r\ninterface gigabitethernet2\r\n description x", false},
		{"sb end in the middle, cut later", sb, sbHeader + "interface gigabitethernet1\nend\ninterface gigabitethernet2\n shutd", false},
		{"sb ends with exit, trailing whitespace", sb, sbHeader + "interface gigabitethernet1\nexit \r\n\r\n  \n", true},
		{"sb ends with end, trailing blank lines", sb, sbHeader + "interface gigabitethernet1\nend\n\n", true},
		{"sb without any end marker", sb, sbHeader + "interface gigabitethernet1\n description uplink\n", false},
		{"sb empty", sb, "  \n", false},
		{"sb no config markers", sb, "random text\nexit\n", false},
		{"asa ends with : end", asa, asaHeader + "interface GigabitEthernet0/0\n nameif outside\n: end\n", true},
		{"asa ends with : end, CRLF", asa, ": Saved\r\n!\r\ninterface GigabitEthernet0/0\r\n: end\r\n", true},
		// Send strips the newline before the prompt, so ": end" is the last thing
		// in a real backup.
		{"asa ends with : end, no trailing newline", asa, asaHeader + "interface GigabitEthernet0/0\n nameif outside\n: end", true},
		{"asa ends with : end, CRLF, no trailing newline", asa, ": Saved\r\n!\r\ninterface GigabitEthernet0/0\r\n: end", true},
		{"asa plain end fallback", asa, asaHeader + "interface GigabitEthernet0/0\nend\n", true},
		{"asa truncated", asa, asaHeader + "interface GigabitEthernet0/0\n nameif outside\n security-lev", false},
		{"asa empty", asa, "", false},
		{"asa no config markers", asa, "random text\n: end\n", false},
	}
	for _, c := range cases {
		err := c.p.ValidateBackup(c.output)
		if (err == nil) != c.wantOK {
			t.Errorf("%s: ValidateBackup error = %v, want ok=%v", c.name, err, c.wantOK)
		}
	}
}

// The SB save prompt must not leak into the shared confirmation list.
func TestCiscoSBOverwritePromptIsSBOnly(t *testing.T) {
	const prompt = "Overwrite file [startup-config].... (Y/N)[N] ?"
	for _, name := range Names() {
		if name == CiscoSB {
			continue
		}
		if reply, ok := mustLookup(t, name).ConfirmReply(prompt); ok {
			t.Errorf("%s answers the SF/SG/CBS overwrite prompt with %q", name, reply)
		}
	}
}

func TestCiscoSBPagerAndASASavePrompt(t *testing.T) {
	// SF/SG/CBS page with their own marker, not IOS's "--More--".
	sb := mustLookup(t, "cisco_sb")
	paged := func(line string) bool {
		for _, re := range sb.Pagers {
			if re.MatchString(line) {
				return true
			}
		}
		return false
	}
	for line, want := range map[string]bool{
		"More: <space>,  Quit: q or CTRL+Z, One line: <return> ": true,
		" --More-- ":                 true,
		"switch1a2b3c#":              false,
		"interface gigabitethernet1": false,
	} {
		if got := paged(line); got != want {
			t.Errorf("cisco_sb pager match %q = %v, want %v", line, got, want)
		}
	}

	// ASA asks whether to save before "reload in"; answering yes keeps the
	// pre-change state, as on IOS. No other vendor answers this dialog.
	const save = "System config has been modified. Save? [Y]es/[N]o:"
	if reply, ok := mustLookup(t, "cisco_asa").ConfirmReply(save); !ok || reply != "y" {
		t.Errorf("cisco_asa ConfirmReply(%q) = %q, %v; want %q, true", save, reply, ok, "y")
	}
	for _, name := range Names() {
		if name == CiscoASA {
			continue
		}
		if reply, ok := mustLookup(t, name).ConfirmReply(save); ok {
			t.Errorf("%s answers the ASA save prompt with %q", name, reply)
		}
	}
}

func TestCanonicalResolvesAnyAliasToTheProfileName(t *testing.T) {
	for in, want := range map[string]string{
		"cisco_ios": Cisco, "IOS": Cisco, "sg350": CiscoSB, "Cisco-ASA": CiscoASA, "h3c": Huawei,
		"juniper": Junos, "fortigate": Fortinet, "vyos": VyOS,
	} {
		if got, ok := Canonical(in); !ok || got != want {
			t.Errorf("Canonical(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "mikrotik", "no such vendor"} {
		if got, ok := Canonical(in); ok || got != "" {
			t.Errorf("Canonical(%q) = %q, %v; want nothing", in, got, ok)
		}
	}
	// it agrees with Lookup for every registered name
	for _, name := range Names() {
		p, _ := Lookup(name)
		if got, ok := Canonical(name); !ok || got != p.Name {
			t.Errorf("Canonical(%q) = %q, %v", name, got, ok)
		}
	}
}

package vendor

import (
	"slices"
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
	if got := Names(); !slices.Equal(got, []string{"arista", "aruba", "checkpoint", "cisco", "fortinet", "huawei", "junos", "paloalto", "pfsense", "ruijie", "sophos", "vyos"}) {
		t.Errorf("Names() = %v", got)
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
	for _, name := range []string{"cisco", "huawei", "fortinet", "ruijie", "aruba", "checkpoint"} {
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

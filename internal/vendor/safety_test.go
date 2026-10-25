package vendor

import (
	"slices"
	"strings"
	"testing"
)

func kinds(steps []Step) []StepKind {
	out := make([]StepKind, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Kind)
	}
	return out
}

func TestRollbackSafetyClassification(t *testing.T) {
	cases := map[string]RollbackSafety{
		// hitless, non-reboot auto-rollback
		"junos": RollbackSafe, "vyos": RollbackSafe, "arista": RollbackSafe, "eos": RollbackSafe,
		"ios-xe": RollbackSafe, "iosxe": RollbackSafe, "cisco-ios-xe": RollbackSafe, "IOS_XE": RollbackSafe,
		// classic IOS: only a timed reload
		"cisco": RollbackRebootOnly, "ios": RollbackRebootOnly, "cisco-ios": RollbackRebootOnly,
		// ASA: "reload in <min>" / "reload cancel", same as classic IOS
		"cisco_asa": RollbackRebootOnly, "asa": RollbackRebootOnly, "ftd": RollbackRebootOnly,
		// no independent on-box watchdog
		"huawei": RollbackClientOnly, "fortinet": RollbackClientOnly, "ruijie": RollbackClientOnly,
		"aruba": RollbackClientOnly, "checkpoint": RollbackClientOnly, "paloalto": RollbackClientOnly,
		"pfsense": RollbackClientOnly, "sophos": RollbackClientOnly,
		// Small Business SF/SG/CBS: "reload in" is not supported
		"cisco_sb": RollbackClientOnly, "sg350": RollbackClientOnly, "cbs350": RollbackClientOnly,
	}
	for name, want := range cases {
		if got := mustLookup(t, name).Safety(); got != want {
			t.Errorf("%s: Safety = %v, want %v", name, got, want)
		}
	}
	// Every registered vendor has an explicit, defensible class.
	for _, n := range Names() {
		_ = mustLookup(t, n).Safety()
	}
	var unclassified Profile
	if unclassified.Safety() != RollbackClientOnly {
		t.Fatal("an unclassified profile must never be presented as safer than it is")
	}
}

func TestIOSXEVariantKeepsCanonicalName(t *testing.T) {
	xe, classic := mustLookup(t, "ios-xe"), mustLookup(t, "ios")
	if xe == classic {
		t.Fatal("IOS-XE and classic IOS must be distinct profiles")
	}
	if xe.Name != Cisco || classic.Name != Cisco {
		t.Fatalf("both stay the canonical %q vendor (templates compare on it): %q / %q", Cisco, xe.Name, classic.Name)
	}
	if slices.Contains(Names(), "ios-xe") || len(Names()) != 15 {
		t.Fatalf("the variant must not become a separate canonical vendor: %v", Names())
	}
	// Everything but the safety mechanism is shared.
	if xe.Display != classic.Display || xe.BackupCommand != classic.BackupCommand {
		t.Fatal("variant diverged from the cisco profile beyond commit-confirm")
	}
	// The plain plan is identical, so existing behaviour does not change.
	if !slices.Equal(lines(xe.BuildPlan(testCmds, PlanOptions{}).Steps), lines(classic.BuildPlan(testCmds, PlanOptions{}).Steps)) {
		t.Fatal("plain plans differ between IOS and IOS-XE")
	}
}

func TestRollbackSafetyLabels(t *testing.T) {
	cases := []struct {
		s           RollbackSafety
		long, short string
	}{
		{RollbackSafe, "SAFE", "SAFE"},
		{RollbackRebootOnly, "REBOOT REQUIRED", "REBOOT ONLY"},
		{RollbackClientOnly, "UNSAFE / OOB REQUIRED", "UNSAFE"},
	}
	for _, tc := range cases {
		if tc.s.String() != tc.long || tc.s.Label() != tc.short || tc.s.Hazard() == "" {
			t.Errorf("%d: %q / %q / %q", tc.s, tc.s.String(), tc.s.Label(), tc.s.Hazard())
		}
	}
	const wantHazard = "Safe commit-confirm cannot be achieved: platform lacks non-reboot auto-rollback. " +
		"If network isolation occurs, automated rollback will FAIL and OOB/console access will be required."
	if HazardClientOnly != wantHazard {
		t.Fatalf("hazard text changed:\n%s", HazardClientOnly)
	}
}

func TestCommitConfirmPlans(t *testing.T) {
	opts := PlanOptions{CommitConfirm: 5, Token: "abc"}
	cmds := []string{"hostname lab1"}
	cases := []struct {
		name    string
		vendor  string
		opts    PlanOptions
		confirm ConfirmMode
		want    []string
		abort   []string
	}{
		{"junos", "junos", opts, ConfirmNative,
			[]string{"configure", "hostname lab1", "commit confirmed 5", "run ", "commit", "exit"},
			[]string{"rollback 1", "commit", "exit"}},
		{"vyos", "vyos", opts, ConfirmNative,
			[]string{"configure", "hostname lab1", "commit-confirm 5", "run ", "confirm", "save", "exit"}, nil},
		{"arista", "arista", opts, ConfirmNative,
			[]string{"configure session netops-abc", "hostname lab1", "commit timer 00:05:00", "",
				"configure session netops-abc", "commit", "write memory"}, nil},
		{"ios-xe", "ios-xe", opts, ConfirmNative,
			[]string{"configure terminal revert timer 5", "hostname lab1", "end", "", "configure confirm", "write memory"}, nil},
		{"classic ios with reload allowed", "ios", PlanOptions{CommitConfirm: 5, AllowReboot: true}, ConfirmReload,
			[]string{"reload in 5", "configure terminal", "hostname lab1", "end", "", "reload cancel", "write memory"}, nil},
		{"cisco asa with reload allowed", "cisco_asa", PlanOptions{CommitConfirm: 5, AllowReboot: true}, ConfirmReload,
			[]string{"reload in 5", "configure terminal", "hostname lab1", "end", "", "reload cancel", "write memory"}, nil},
	}
	for _, tc := range cases {
		plan := mustLookup(t, tc.vendor).BuildPlan(cmds, tc.opts)
		if plan.Confirm != tc.confirm || plan.Window != 5 {
			t.Errorf("%s: Confirm=%v Window=%d", tc.name, plan.Confirm, plan.Window)
		}
		if got := lines(plan.Steps); !slices.Equal(got, tc.want) {
			t.Errorf("%s: steps\n got %q\nwant %q", tc.name, got, tc.want)
		}
		if got := lines(plan.Abort); !slices.Equal(got, tc.abort) {
			t.Errorf("%s: abort = %q, want %q", tc.name, got, tc.abort)
		}
		for _, s := range plan.Steps {
			if strings.ContainsAny(s.Line, "{}") {
				t.Errorf("%s: unexpanded placeholder in %q", tc.name, s.Line)
			}
		}
		if len(plan.Cleanup) == 0 {
			t.Errorf("%s: a confirm plan needs cleanup steps", tc.name)
		}
	}
}

func TestCommitConfirmPlanStructure(t *testing.T) {
	for _, name := range Names() {
		p := mustLookup(t, name)
		for _, p := range []*Profile{p, mustLookup(t, "ios-xe")} {
			if len(p.confirmApply) == 0 {
				if p.safety == RollbackSafe {
					t.Errorf("%s is classified SAFE but has no commit-confirm plan", name)
				}
				continue
			}
			var timed, verify, confirm = -1, -1, -1
			for i, s := range p.confirmApply {
				switch {
				case s.Timed && timed < 0:
					timed = i
				case s.Kind == StepVerify && verify < 0:
					verify = i
				case s.Kind == StepConfirm && confirm < 0:
					confirm = i
				}
			}
			if timed < 0 || verify < 0 || confirm < 0 || !(timed < verify && verify < confirm) {
				t.Errorf("%s: need timer start < verify < confirm, got %d/%d/%d", name, timed, verify, confirm)
			}
			if p.safety == RollbackClientOnly {
				t.Errorf("%s has a confirm plan but is classified client-only", name)
			}
		}
	}
}

func TestCommitConfirmNotArmedWhereImpossible(t *testing.T) {
	cmds := []string{"hostname lab1"}
	for _, name := range []string{"huawei", "fortinet", "ruijie", "aruba", "cisco_sb", "checkpoint", "paloalto", "pfsense", "sophos"} {
		p := mustLookup(t, name)
		plan := p.BuildPlan(cmds, PlanOptions{CommitConfirm: 5, AllowReboot: true})
		plain := p.BuildPlan(cmds, PlanOptions{})
		if plan.Confirm != ConfirmNone || plan.Window != 0 || !slices.Equal(lines(plan.Steps), lines(plain.Steps)) {
			t.Errorf("%s: no on-box timer exists, the plan must stay plain: %+v", name, plan)
		}
	}
	// Classic IOS needs an explicit opt-in before it may reload.
	ios := mustLookup(t, "ios")
	plan := ios.BuildPlan(cmds, PlanOptions{CommitConfirm: 5})
	if plan.Confirm != ConfirmNone || !slices.Equal(lines(plan.Steps), lines(ios.BuildPlan(cmds, PlanOptions{}).Steps)) {
		t.Fatalf("classic IOS must not reload without -allow-reboot-rollback: %+v", plan)
	}
	// AllowReboot alone does not enable commit-confirm.
	if plan := ios.BuildPlan(cmds, PlanOptions{AllowReboot: true}); plan.Confirm != ConfirmNone {
		t.Fatal("-allow-reboot-rollback without -commit-confirm must do nothing")
	}
}

func TestCommitConfirmIgnoredOnDryRun(t *testing.T) {
	for _, name := range []string{"junos", "vyos", "arista", "ios-xe", "ios", "cisco_asa", "cisco_sb"} {
		plan := mustLookup(t, name).BuildPlan(testCmds, PlanOptions{DryRun: true, CommitConfirm: 5, AllowReboot: true, Verify: true})
		if plan.Confirm != ConfirmNone || !plan.DryRun || slices.Contains(kinds(plan.Steps), StepVerify) {
			t.Errorf("%s: dry-run must stay a dry run: %+v", name, plan)
		}
	}
}

func TestVerifyPlaceholder(t *testing.T) {
	// Plain plans get a trailing StepVerify only when checks exist.
	junos := mustLookup(t, "junos")
	if slices.Contains(kinds(junos.BuildPlan(testCmds, PlanOptions{}).Steps), StepVerify) {
		t.Fatal("no verify rules: the plain plan must be unchanged")
	}
	plan := junos.BuildPlan(testCmds, PlanOptions{Verify: true})
	if last := plan.Steps[len(plan.Steps)-1]; last.Kind != StepVerify || last.Line != "" {
		t.Fatalf("checks run after the change is complete, in operational mode: %+v", last)
	}
	// Confirm plans always verify: the runner proves management reachability
	// even when the operator defined no checks.
	cc := junos.BuildPlan(testCmds, PlanOptions{CommitConfirm: 5})
	if n := strings.Count(strings.Join(sliceKinds(cc.Steps), ","), "verify"); n != 1 {
		t.Fatalf("a confirm plan carries exactly one verify step, got %d", n)
	}
}

func sliceKinds(steps []Step) []string {
	var out []string
	for _, s := range steps {
		out = append(out, s.Kind.String())
	}
	return out
}

func TestCommitConfirmMinutesFormatting(t *testing.T) {
	plan := mustLookup(t, "arista").BuildPlan(testCmds, PlanOptions{CommitConfirm: 90, Token: "x"})
	if !slices.Contains(lines(plan.Steps), "commit timer 01:30:00") {
		t.Fatalf("90 minutes must render as hh:mm:ss: %q", lines(plan.Steps))
	}
	if !slices.Contains(lines(mustLookup(t, "junos").BuildPlan(testCmds, PlanOptions{CommitConfirm: 90}).Steps), "commit confirmed 90") {
		t.Fatal("native minute count")
	}
}

func TestDefaultPlansUnchanged(t *testing.T) {
	// The exact plain plans existing deployments rely on.
	want := map[string][]string{
		"cisco": {"configure terminal", "hostname lab1", "ntp server 10.0.0.9", "end", "write memory"},
		"junos": {"configure", "hostname lab1", "ntp server 10.0.0.9", "commit", "exit"},
		"vyos":  {"configure", "hostname lab1", "ntp server 10.0.0.9", "commit", "save", "exit"},
	}
	for name, w := range want {
		plan := mustLookup(t, name).BuildPlan(testCmds, PlanOptions{})
		if !slices.Equal(lines(plan.Steps), w) || plan.Confirm != ConfirmNone || len(plan.Abort) != 0 {
			t.Errorf("%s: %q", name, lines(plan.Steps))
		}
	}
}

func TestLooksLikeFailure(t *testing.T) {
	bad := []string{
		"% Archive not configured", "%Config rollback not enabled", "Error: no such command", "syntax error, expecting <command>",
		"Invalid input detected at '^' marker", "unknown command: commit-confirm", "Failed to arm", "Unable to start timer",
		"commit-confirm is not supported", "Cannot schedule a reload", "  % indented error\r",
	}
	for _, out := range bad {
		if _, ok := LooksLikeFailure("some banner\n" + out + "\nsw1#"); !ok {
			t.Errorf("not detected: %q", out)
		}
	}
	good := []string{
		"commit confirmed will be automatically rolled back in 5 minutes unless confirmed\ncommit complete",
		"Reload scheduled in 5 minutes by svc on vty0 (10.0.0.9)", "", "Enter configuration commands, one per line.  End with CNTL/Z.",
		"Timer 00:05:00 started", "[edit]\nsw1#",
	}
	for _, out := range good {
		if line, ok := LooksLikeFailure(out); ok {
			t.Errorf("false positive on %q (matched %q)", out, line)
		}
	}
	line, _ := LooksLikeFailure("x\n%Archive not configured\r\ny")
	if line != "%Archive not configured" {
		t.Fatalf("matched line = %q", line)
	}
}

func TestStepKindStrings(t *testing.T) {
	want := map[StepKind]string{
		StepUnknown: "unknown", StepProbe: "probe", StepEnter: "enter config", StepBody: "config", StepInspect: "inspect",
		StepValidate: "validate", StepExit: "exit config", StepPersist: "persist",
		StepArm: "arm rollback", StepVerify: "verify", StepConfirm: "confirm",
	}
	for k, w := range want {
		if k.String() != w {
			t.Errorf("%d = %q, want %q", k, k.String(), w)
		}
	}
	if StepKind(99).String() != "unknown" {
		t.Error("out-of-range kinds read as unknown")
	}
}

func TestCiscoSBPlan(t *testing.T) {
	sb := mustLookup(t, "cisco_sb")
	if sb.Name != CiscoSB || sb.Display != "Cisco Small Business (SF/SG/CBS)" {
		t.Fatalf("identity = %q / %q", sb.Name, sb.Display)
	}
	if !slices.Equal(sb.DisablePaging, []string{"terminal datadump", "terminal length 0"}) {
		t.Errorf("paging suppression = %q", sb.DisablePaging)
	}
	if sb.BackupCommand != "show running-config" {
		t.Errorf("backup command = %q", sb.BackupCommand)
	}
	if sb.Safety() != RollbackClientOnly {
		t.Fatalf("Safety = %v, want client-only: SF/SG/CBS has no \"reload in\"", sb.Safety())
	}

	plan := sb.BuildPlan(testCmds, PlanOptions{})
	want := []string{"configure terminal", "hostname lab1", "ntp server 10.0.0.9", "end", "write memory"}
	if got := lines(plan.Steps); !slices.Equal(got, want) {
		t.Fatalf("plan:\n got  %q\n want %q", got, want)
	}
	wantKinds := []StepKind{StepEnter, StepBody, StepBody, StepExit, StepPersist}
	if got := kinds(plan.Steps); !slices.Equal(got, wantKinds) {
		t.Errorf("kinds = %v, want %v", got, wantKinds)
	}
	if last := plan.Steps[len(plan.Steps)-1]; !last.Slow {
		t.Error("write memory must be marked slow")
	}

	// No timer exists: a commit-confirm request must not arm "reload in".
	for _, opts := range []PlanOptions{{CommitConfirm: 5}, {CommitConfirm: 5, AllowReboot: true}} {
		p := sb.BuildPlan(testCmds, opts)
		if p.Confirm != ConfirmNone || p.Window != 0 || len(p.Abort) != 0 {
			t.Errorf("opts %+v armed a deadman: %+v", opts, p)
		}
		if got := lines(p.Steps); !slices.Equal(got, want) {
			t.Errorf("opts %+v changed the plan: %q", opts, got)
		}
		if slices.Contains(lines(p.Steps), "reload in 5") || slices.Contains(lines(p.Steps), "reload cancel") {
			t.Errorf("opts %+v: SF/SG/CBS does not support reload timers: %q", opts, lines(p.Steps))
		}
	}
	if got := lines(sb.BuildPlan(testCmds, PlanOptions{}).Cleanup); !slices.Equal(got, []string{"end"}) {
		t.Errorf("cleanup = %q, want just \"end\" (a failed change is never saved)", got)
	}
}

func TestCiscoASAPlan(t *testing.T) {
	asa := mustLookup(t, "cisco_asa")
	if asa.Name != CiscoASA || asa.Display != "Cisco ASA" {
		t.Fatalf("identity = %q / %q", asa.Name, asa.Display)
	}
	if !slices.Equal(asa.DisablePaging, []string{"terminal pager 0"}) {
		t.Errorf("paging suppression = %q, want only \"terminal pager 0\"", asa.DisablePaging)
	}
	if asa.BackupCommand != "show running-config" {
		t.Errorf("backup command = %q", asa.BackupCommand)
	}
	if asa.Safety() != RollbackRebootOnly {
		t.Fatalf("Safety = %v, want reboot-only", asa.Safety())
	}

	plain := asa.BuildPlan(testCmds, PlanOptions{})
	wantPlain := []string{"configure terminal", "hostname lab1", "ntp server 10.0.0.9", "end", "write memory"}
	if got := lines(plain.Steps); !slices.Equal(got, wantPlain) {
		t.Fatalf("plain plan:\n got  %q\n want %q", got, wantPlain)
	}

	// Armed with the operator's consent: reload in N before the change, cancel
	// after verification, save last.
	armed := asa.BuildPlan(testCmds, PlanOptions{CommitConfirm: 7, AllowReboot: true})
	wantArmed := []string{"reload in 7", "configure terminal", "hostname lab1", "ntp server 10.0.0.9", "end", "", "reload cancel", "write memory"}
	if armed.Confirm != ConfirmReload || armed.Window != 7 {
		t.Fatalf("Confirm=%v Window=%d, want reload/7", armed.Confirm, armed.Window)
	}
	if got := lines(armed.Steps); !slices.Equal(got, wantArmed) {
		t.Fatalf("armed plan:\n got  %q\n want %q", got, wantArmed)
	}
	first := armed.Steps[0]
	if first.Kind != StepArm || !first.Timed {
		t.Errorf("first step must arm the timer and start the deadman: %+v", first)
	}
	if idx := slices.Index(lines(armed.Steps), "reload cancel"); armed.Steps[idx].Kind != StepConfirm || idx < slices.Index(kinds(armed.Steps), StepVerify) {
		t.Errorf("reload cancel must be a confirm step after verification: %+v", armed.Steps)
	}
	if len(armed.Cleanup) == 0 {
		t.Error("an armed plan needs cleanup steps")
	}

	// A disruptive reload needs an explicit opt-in.
	if p := asa.BuildPlan(testCmds, PlanOptions{CommitConfirm: 7}); p.Confirm != ConfirmNone || !slices.Equal(lines(p.Steps), wantPlain) {
		t.Errorf("ASA must not reload without -allow-reboot-rollback: %+v", p)
	}
	if p := asa.BuildPlan(testCmds, PlanOptions{AllowReboot: true}); p.Confirm != ConfirmNone {
		t.Error("-allow-reboot-rollback without -commit-confirm must do nothing")
	}
}

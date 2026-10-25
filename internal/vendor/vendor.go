// Package vendor describes how each supported network OS is driven over an
// interactive SSH shell: what its prompt looks like, how paging and
// confirmation dialogs behave, what an error looks like, and which commands
// enter/leave configuration mode and persist the result.
//
// The package is pure data and string logic (no I/O) so every behaviour here
// can be unit-tested without a device.
package vendor

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Canonical vendor names.
const (
	Cisco      = "cisco"
	CiscoSB    = "cisco_sb"
	CiscoASA   = "cisco_asa"
	Junos      = "junos"
	Huawei     = "huawei"
	Fortinet   = "fortinet"
	Arista     = "arista"
	VyOS       = "vyos"
	Ruijie     = "ruijie"
	Aruba      = "aruba"
	CheckPoint = "checkpoint"
	PaloAlto   = "paloalto"
	PfSense    = "pfsense"
	Sophos     = "sophos"
	MikroTik   = "mikrotik"
)

// StepKind classifies one command of an execution plan; the runner uses it to
// pick a failure category and a timeout.
type StepKind int

const (
	StepUnknown StepKind = iota
	StepProbe
	StepEnter    // enter configuration mode
	StepBody     // one user-supplied configuration command
	StepInspect  // read-only look inside config mode (diff)
	StepValidate // device-side validation without persisting (commit check)
	StepExit     // leave configuration mode / discard candidate
	StepPersist  // commit / write memory / save
	StepArm      // arm an on-box rollback safety net (commit-confirm); must succeed before the change is applied
	StepVerify   // placeholder: the runner runs post-change health checks here (Line is a command prefix such as "run ")
	StepConfirm  // confirm a timed commit once verification passed (cancels the deadman timer)
)

func (k StepKind) String() string {
	switch k {
	case StepUnknown:
		return "unknown"
	case StepProbe:
		return "probe"
	case StepEnter:
		return "enter config"
	case StepBody:
		return "config"
	case StepInspect:
		return "inspect"
	case StepValidate:
		return "validate"
	case StepExit:
		return "exit config"
	case StepPersist:
		return "persist"
	case StepArm:
		return "arm rollback"
	case StepVerify:
		return "verify"
	case StepConfirm:
		return "confirm"
	}
	return "unknown"
}

// Step is one line to send to the device.
type Step struct {
	Kind        StepKind
	Line        string
	Slow        bool // commit/save: may take much longer than a normal command
	IgnoreError bool // best-effort (cleanup) - a device error here is not a failure
	Timed       bool // a successful step starts the on-box deadman timer (commit confirmed, reload in, ...)
}

// ConfirmMode says which on-box deadman mechanism a plan uses.
type ConfirmMode int

// Deadman mechanisms a plan can use.
const (
	ConfirmNone   ConfirmMode = iota // no on-box safety net (client-side rollback only)
	ConfirmNative                    // hitless platform timer (commit confirmed, session timers, revert timer)
	ConfirmReload                    // timed reload (disruptive)
)

// RollbackSafety classifies what a platform can do when a change cuts the
// management session. The zero value is the most hazardous class, so a
// profile that was never classified is never presented as safer than it is.
type RollbackSafety int

// Rollback safety classes.
const (
	// RollbackClientOnly: no independent on-box watchdog. If connectivity or
	// SSH is lost the change cannot be rolled back without out-of-band or
	// serial console access.
	RollbackClientOnly RollbackSafety = iota
	// RollbackSafe: native, hitless, non-reboot auto-rollback on lost
	// connectivity (Junos commit confirmed, VyOS commit-confirm, EOS session
	// timers, IOS-XE revert timer).
	RollbackSafe
	// RollbackRebootOnly: the platform can revert on its own, but only through
	// a disruptive reload (classic IOS "reload in <min>" / "reload cancel").
	RollbackRebootOnly
)

// String is the long rating used in warnings and the run summary.
func (s RollbackSafety) String() string {
	switch s {
	case RollbackSafe:
		return "SAFE"
	case RollbackRebootOnly:
		return "REBOOT REQUIRED"
	}
	return "UNSAFE / OOB REQUIRED"
}

// Label is the short rating used in the --plan matrix.
func (s RollbackSafety) Label() string {
	switch s {
	case RollbackSafe:
		return "SAFE"
	case RollbackRebootOnly:
		return "REBOOT ONLY"
	}
	return "UNSAFE"
}

// Hazard explains the rating in one sentence.
func (s RollbackSafety) Hazard() string {
	switch s {
	case RollbackSafe:
		return "native hitless auto-rollback is available"
	case RollbackRebootOnly:
		return "auto-rollback needs a disruptive reload (requires -allow-reboot-rollback)"
	}
	return "no on-box watchdog: if connectivity is lost, rollback is impossible without OOB/console access"
}

// HazardClientOnly is the warning logged for RollbackClientOnly platforms when
// -commit-confirm was requested.
const HazardClientOnly = "Safe commit-confirm cannot be achieved: platform lacks non-reboot auto-rollback. " +
	"If network isolation occurs, automated rollback will FAIL and OOB/console access will be required."

// Plan is the ordered command sequence for one device.
type Plan struct {
	Steps     []Step // executed in order
	Cleanup   []Step // best-effort steps run after a failure (never persists)
	Simulated []Step // dry-run on vendors without a candidate config: what would have run (not sent)
	Validates bool   // dry-run: the device itself validated the change, then discarded it
	DryRun    bool

	Confirm ConfirmMode // on-box deadman mechanism the Steps arm (ConfirmNone: none)
	Window  int         // deadman timer in minutes (Confirm != ConfirmNone)
	Abort   []Step      // optional: revert an armed change immediately instead of waiting for the timer
}

// PlanOptions controls BuildPlan.
type PlanOptions struct {
	DryRun bool
	Token  string // makes device-side session names unique (Arista config sessions)

	CommitConfirm int  // minutes; > 0 requests an on-box deadman timer where the platform has one
	AllowReboot   bool // permit a timed reload as the deadman (RollbackRebootOnly platforms)
	Verify        bool // keep a StepVerify placeholder so the runner can run post-change checks
	PreDiff       bool // inspect candidate configuration diff before committing on supported platforms
}

// Confirm describes an interactive confirmation dialog and its answer.
type Confirm struct {
	Re    *regexp.Regexp // matched against the last (unterminated) output line
	Reply string         // sent followed by a newline; "" just presses Enter
}

// Profile holds everything vendor specific.
type Profile struct {
	Name    string
	Display string

	Prompt        *regexp.Regexp   // matches the last output line when the device is ready for input
	UserPrompt    *regexp.Regexp   // unprivileged prompt; if matched, EnableCommand is needed first
	PromptPrefix  *regexp.Regexp   // optional multi-line prompt prefix (e.g. Junos "{master:0}") stripped with the prompt
	EnableCommand string           // "" when the vendor has no privilege escalation step
	DisablePaging []string         // session-local commands that turn the pager off
	Pagers        []*regexp.Regexp // "--More--" style markers; answered with a space
	Confirms      []Confirm
	ErrorPatterns []*regexp.Regexp         // matched per output line
	BackupCommand string                   // prints the full running configuration
	EndMarkers    []string                 // substrings expected at or near end of untruncated backup (e.g. "\nend", "\nreturn")
	EndAnchored   bool                     // EndMarkers must end the output, not merely occur in it (for terminators that also appear mid-config)
	ValidateTail  func(output string) bool // optional fallback validation when EndAnchored is true but trailing global config is present
	CandidateDiff string                   // read-only command inside config mode to inspect candidate diff (e.g. "show | compare")

	probe         string
	apply         []Step // StepBody is a placeholder for the user's commands
	applyCleanup  []Step
	applySession  []Step // optional session-based apply plan with candidate diff (e.g. Arista EOS)
	opApply       []Step // operational (read-only/show) command plan — no config mode
	dryRun        []Step // nil: vendor has no way to validate without applying
	dryRunCleanup []Step

	safety         RollbackSafety
	confirmApply   []Step // apply template with an on-box deadman ({mins}/{hms} are substituted); nil: none
	confirmCleanup []Step
	confirmAbort   []Step // optional immediate revert of an armed change
}

// ValidateBackup checks that backup output contains valid configuration markers
// and required platform-specific termination end-markers.
func (p *Profile) ValidateBackup(output string) error {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return fmt.Errorf("%q returned no output", p.BackupCommand)
	}
	if !hasConfigMarkers(trimmed) {
		return fmt.Errorf("%q output does not contain valid configuration markers", p.BackupCommand)
	}
	if len(p.EndMarkers) == 0 {
		return nil
	}
	tail := "\n" + strings.TrimRight(output, " \t\r\n")
	for _, marker := range p.EndMarkers {
		if p.EndAnchored && strings.HasSuffix(tail, marker) || !p.EndAnchored && strings.Contains(output, marker) {
			return nil
		}
	}
	if p.ValidateTail != nil && p.ValidateTail(output) {
		return nil
	}
	return fmt.Errorf("%q output appears truncated: expected end marker %v not found", p.BackupCommand, p.EndMarkers)
}

func hasConfigMarkers(out string) bool {
	markers := []string{"version ", "!", "#", "system", "interface", "config ", "set ", "<pfsense", "<?xml", "<config"}
	for _, m := range markers {
		if strings.Contains(out, "\n"+m) || strings.HasPrefix(out, m) {
			return true
		}
	}
	return false
}

// Safety reports the platform's rollback safety class.
func (p *Profile) Safety() RollbackSafety { return p.safety }

// ProbeCommand is the cheap read-only command used to prove a session works.
func (p *Profile) ProbeCommand() string { return p.probe }

var (
	reIOSPrompt         = regexp.MustCompile(`^[\w.\-/:~()]+[#>]\s*$`)
	reIOSUserPrompt     = regexp.MustCompile(`^[\w.\-/:~()]+>\s*$`)
	reJunosPrompt       = regexp.MustCompile(`^[\w.\-]+@[\w.\-:]+[>#%]\s*$`)
	reJunosPromptPrefix = regexp.MustCompile(`(?i)^\s*(\{(?:master|backup|primary|secondary|linecard|node\d+)(?::[^\}]+)?\}|\[edit(?:\s+[^\]]*)?\])\s*$`)
	reHuaweiPrompt      = regexp.MustCompile(`^[<\[][~*\w.\-/:]+[>\]]\s*$`)
	reFortiPrompt       = regexp.MustCompile(`^\S+(?: \([^()]+\))* ?[#$]\s*$`)
	reVyOSPrompt        = regexp.MustCompile(`^[\w.\-]+@[\w.\-]+(?:(?::\S*)?[$#]|#)\s*$`)
	reCheckPointPrompt  = regexp.MustCompile(`^[\w.\-]+>\s*$`)

	rePaloAltoPrompt = regexp.MustCompile(`^[\w.\-]+@[\w.\-]+(?:>|#)\s*$`)
	rePfSensePrompt  = regexp.MustCompile(`^(?:(?:\[[^\]]+\])*\[[\w.\-]+@[\w.\-]+\][^:#$%]*[:#$%]\s*$|Enter an option:\s*$)`)
	reSophosPrompt   = regexp.MustCompile(`^(?:[a-zA-Z0-9.\-]+_)?console>\s*$`)
	reSophosMenu     = regexp.MustCompile(`(?i)^Select Menu Number \[[0-9\-]+\]:\s*$`)
	reRouterOSPrompt = regexp.MustCompile(`^\[[^@\s]+@[^\]\s]+\](?:\s+[^>#]+)*\s*[>#]\s*$`)

	rePagerMore   = regexp.MustCompile(`(?i)--\s*More\s*--`)
	rePagerHuawei = regexp.MustCompile(`(?i)----\s*More\s*----`)
	rePagerJunos  = regexp.MustCompile(`(?i)---\(more(?:\s+\d+%)?\)---`)

	reCiscoErr      = regexp.MustCompile(`(?i)^\s*%\s*(?:invalid|incomplete|ambiguous|unrecognized|unknown|bad\s|authorization failed|access denied)`)
	reAristaErr     = regexp.MustCompile(`(?i)^\s*%\s*(?:invalid|incomplete|ambiguous|unrecognized|unknown|unavailable|error|bad\s|authorization failed|access denied)`)
	reJunosErr      = regexp.MustCompile(`(?i)^\s*(?:syntax error|unknown command|error:|missing argument)`)
	reHuaweiErr     = regexp.MustCompile(`(?i)^\s*error:`)
	reFortiErr      = regexp.MustCompile(`(?i)^\s*(?:command fail|command parse error|value parse error|unknown action|object check operator error|node_check_object fail|entry not found)`)
	reVyOSErr       = regexp.MustCompile(`(?i)^\s*(?:syntax error|invalid command|configuration error|commit failed|failed to parse|error:|\.\.\. failed)`)
	reCheckPointErr = regexp.MustCompile(`(?i)^\s*(?:CLISH|syntax error|unknown command|error:)`)
	rePaloAltoErr   = regexp.MustCompile(`(?i)^\s*(?:Invalid syntax\.|Unknown command:|Server error)`)
	rePfSenseMenu   = regexp.MustCompile(`^Enter an option:\s*$`)
	rePfSenseErr    = regexp.MustCompile(`(?i)^\s*(?:(?:[/\w.\-]+:\s*)*(?:not found|command not found|Permission denied|syntax error)|usage:)`)
	reSophosErr     = regexp.MustCompile(`(?i)^\s*(?:% Error:|Unknown parameter|Syntax Error)`)
	reRouterOSErr   = regexp.MustCompile(`(?i)^\s*(?:bad command name|syntax error|failure:|script error:|no such item|interrupted)`)
)

// reASAErr complements reCiscoErr for the ASA, which prints rejections as
// "ERROR: % Invalid input ..." / "ERROR: Interface ...": the leading "%" that
// reCiscoErr anchors on is then not at the start of the line.
var reASAErr = regexp.MustCompile(`(?i)^\s*error:`)

// rePagerSB is the SF/SG/CBS pager ("More: <space>, Quit: q or CTRL+Z, One
// line: <return>"); the IOS "--More--" form does not match it.
var rePagerSB = regexp.MustCompile(`(?i)more:\s*<space>`)

// reCiscoSBBlock matches lines that open a sub-configuration block (e.g. interfaces,
// VLAN database, lines) which must be closed with an "exit" command.
var reCiscoSBBlock = regexp.MustCompile(`(?i)^\s*(interface|vlan\s+database|line|router|policy-map|class-map)\b`)

// reCiscoSBTerminator matches an "exit" or "end" command line.
var reCiscoSBTerminator = regexp.MustCompile(`(?i)^\s*(exit|end)\s*$`)

// validateCiscoSBTail verifies that for Cisco Small Business switches, if global configuration
// commands (such as "banner login", "ip default-gateway", "snmp-server") follow the final
// interface block's "exit", no subsequent sub-configuration block was left unclosed.
func validateCiscoSBTail(output string) bool {
	lines := strings.Split(output, "\n")
	lastTerm := -1
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimRight(lines[i], "\r \t")
		if reCiscoSBTerminator.MatchString(line) {
			lastTerm = i
			break
		}
	}
	if lastTerm < 0 {
		return false
	}
	for i := lastTerm + 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || line == "!" {
			continue
		}
		if reCiscoSBBlock.MatchString(line) {
			return false
		}
	}
	return true
}

// reASASave is the ASA's "System config has been modified. Save? [Y]es/[N]o:",
// which the generic "[y/n]" / "[yes/no]" patterns do not match.
var reASASave = regexp.MustCompile(`(?i)\[y\]es/\[n\]o\s*:?\s*$`)

// genericConfirms are shared by all vendors. Each regexp is anchored to the end
// of the (unterminated) last line, so a confirmation word in ordinary output
// is never mistaken for a question.
var genericConfirms = []Confirm{
	{regexp.MustCompile(`(?i)\[yes,\s*no\]\s*(?:\([^)]*\))?\s*:?\s*$`), "yes"}, // Junos
	{regexp.MustCompile(`(?i)\[yes/no\]\s*:?\s*$`), "yes"},                     // Cisco key/cert prompts
	{regexp.MustCompile(`(?i)\[y/n\]\s*(?:\([^)]*\))?\s*:?\s*$`), "y"},         // Cisco/Arista [y/n], Huawei [Y/N]
	{regexp.MustCompile(`(?i)\(y/n\)\s*:?\s*$`), "y"},                          // FortiOS
	{regexp.MustCompile(`(?i)\[confirm\]\s*$`), ""},                            // Cisco: press Enter
	{regexp.MustCompile(`(?i)please input the file name.*\]\s*:?\s*$`), ""},    // Huawei save: accept default name
	{regexp.MustCompile(`(?i)destination filename \[[^\]]*\]\??\s*$`), ""},     // Cisco copy
}

// BuildPlan expands the vendor template for the given configuration commands.
func (p *Profile) BuildPlan(commands []string, opts PlanOptions) Plan {
	token := sanitizeToken(opts.Token)
	repl := strings.NewReplacer(
		"{token}", token,
		"{mins}", fmt.Sprint(opts.CommitConfirm),
		"{hms}", fmt.Sprintf("%02d:%02d:00", opts.CommitConfirm/60, opts.CommitConfirm%60),
	)
	expand := func(tmpl []Step) []Step {
		var out []Step
		for _, s := range tmpl {
			if s.Kind == StepBody {
				for _, c := range commands {
					out = append(out, Step{Kind: StepBody, Line: c})
				}
				continue
			}
			s.Line = repl.Replace(s.Line)
			out = append(out, s)
		}
		return out
	}

	if !opts.DryRun {
		return p.buildApply(expand, opts)
	}
	if p.dryRun == nil {
		// No candidate datastore: the only safe simulation is a read-only
		// probe. The real plan is returned for display, never executed.
		return Plan{
			DryRun:    true,
			Steps:     []Step{{Kind: StepProbe, Line: p.probe}},
			Simulated: expand(p.apply),
		}
	}
	return Plan{
		DryRun:    true,
		Validates: true,
		Steps:     expand(p.dryRun),
		Cleanup:   expand(p.dryRunCleanup),
	}
}

// insertStepInspect inserts a StepInspect step right before the first StepPersist
// or StepConfirm step in steps, unless a StepInspect is already present.
func insertStepInspect(steps []Step, diffCmd string) []Step {
	if diffCmd == "" {
		return steps
	}
	for _, s := range steps {
		if s.Kind == StepInspect {
			return steps
		}
	}
	for i, s := range steps {
		if s.Kind == StepPersist || s.Kind == StepConfirm {
			out := make([]Step, 0, len(steps)+1)
			out = append(out, steps[:i]...)
			out = append(out, Step{Kind: StepInspect, Line: diffCmd})
			out = append(out, steps[i:]...)
			return out
		}
	}
	return append(steps, Step{Kind: StepInspect, Line: diffCmd})
}

// buildApply builds the real (non dry-run) plan. A requested commit-confirm is
// honoured only when the platform can do it: natively, or via a timed reload
// when the operator allowed one. Otherwise the plain plan is returned and the
// caller falls back to client-side rollback (see Safety).
func (p *Profile) buildApply(expand func([]Step) []Step, opts PlanOptions) Plan {
	var plan Plan
	if opts.CommitConfirm > 0 && len(p.confirmApply) > 0 {
		switch {
		case p.safety == RollbackSafe:
			plan.Confirm = ConfirmNative
		case p.safety == RollbackRebootOnly && opts.AllowReboot:
			plan.Confirm = ConfirmReload
		}
	}
	if plan.Confirm == ConfirmNone {
		if opts.PreDiff && len(p.applySession) > 0 {
			plan.Steps, plan.Cleanup = expand(p.applySession), expand(p.dryRunCleanup)
		} else {
			plan.Steps, plan.Cleanup = expand(p.apply), expand(p.applyCleanup)
		}
		if opts.Verify {
			plan.Steps = append(plan.Steps, Step{Kind: StepVerify})
		}
		if opts.PreDiff && p.CandidateDiff != "" {
			plan.Steps = insertStepInspect(plan.Steps, p.CandidateDiff)
		}
		return plan
	}
	// The confirm templates always carry a StepVerify: even without
	// user-defined checks the runner proves management reachability with a
	// fresh session before it confirms.
	plan.Window = opts.CommitConfirm
	plan.Steps, plan.Cleanup = expand(p.confirmApply), expand(p.confirmCleanup)
	plan.Abort = expand(p.confirmAbort)
	if opts.PreDiff && p.CandidateDiff != "" {
		plan.Steps = insertStepInspect(plan.Steps, p.CandidateDiff)
	}
	return plan
}

// LooksLikeFailure reports whether command output reads like an error even
// though no vendor error pattern matched. It is applied to steps that arm a
// safety net, which must fail closed: a timer that silently did not start is
// worse than no attempt at all.
func LooksLikeFailure(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if reArmFailure.MatchString(line) {
			return line, true
		}
	}
	return "", false
}

var reArmFailure = regexp.MustCompile(`(?i)^(?:%|error\b|syntax error|invalid\b|unknown command|command not found|failed\b|\.\.\. failed|cannot\b|can't\b|unable to\b)|\bnot (?:supported|enabled|configured|available)\b`)

// BuildOpPlan returns an operational-mode execution plan: commands run in the
// device's operational shell without entering configuration mode, so no
// commit or save is ever issued. Suitable for show/display/get commands.
// If the vendor has no dedicated operational plan the commands run directly
// (which is already correct for FortiOS and Check Point that have no config
// mode wrapper). For vendors that normally enter configure automatically
// (Cisco, Junos, VyOS, …) this avoids that entirely.
func (p *Profile) BuildOpPlan(commands []string) Plan {
	steps := p.opApply
	if len(steps) == 0 {
		// Fallback: run commands bare in the operational shell.
		steps = []Step{{Kind: StepBody}}
	}
	expand := func(tmpl []Step) []Step {
		var out []Step
		for _, s := range tmpl {
			if s.Kind == StepBody {
				for _, c := range commands {
					out = append(out, Step{Kind: StepBody, Line: c})
				}
				continue
			}
			out = append(out, s)
		}
		return out
	}
	return Plan{Steps: expand(steps)}
}

// FindError returns the first output line that matches a vendor error signature.
func (p *Profile) FindError(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, re := range p.ErrorPatterns {
			if re.MatchString(line) {
				return strings.TrimSpace(line), true
			}
		}
	}
	return "", false
}

// ConfirmReply returns the answer for a confirmation prompt, if prompt is one.
func (p *Profile) ConfirmReply(prompt string) (string, bool) {
	for _, c := range p.Confirms {
		if c.Re.MatchString(prompt) {
			return c.Reply, true
		}
	}
	return "", false
}

func sanitizeToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "dryrun"
	}
	return b.String()
}

// ciscoLike builds the IOS/IOS-XE style profile that Arista EOS shares.
func ciscoLike(name, display string, errRe *regexp.Regexp) *Profile {
	return &Profile{
		Name:          name,
		Display:       display,
		Prompt:        reIOSPrompt,
		UserPrompt:    reIOSUserPrompt,
		EnableCommand: "enable",
		DisablePaging: []string{"terminal length 0"},
		Pagers:        []*regexp.Regexp{rePagerMore},
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{errRe},
		BackupCommand: "show running-config",
		EndMarkers:    []string{"\nend", "\r\nend"},
		probe:         "show clock",
		apply: []Step{
			{Kind: StepEnter, Line: "configure terminal"},
			{Kind: StepBody},
			{Kind: StepExit, Line: "end"},
			{Kind: StepPersist, Line: "write memory", Slow: true},
		},
		applyCleanup: []Step{{Kind: StepExit, Line: "end", IgnoreError: true}},
	}
}

// newCisco is classic IOS: the only on-box deadman is a timed reload.
// It also accommodates Cisco Small Business (SF/SG/CBS) and ASA when generic
// "cisco" is specified in the inventory.
func newCisco() *Profile {
	p := ciscoLike(Cisco, "Cisco IOS/IOS-XE", reCiscoErr)
	p.DisablePaging = []string{"terminal length 0", "terminal datadump", "terminal pager 0"}
	p.Pagers = append(p.Pagers, rePagerSB)
	p.EndMarkers = []string{"\nend", "\r\nend", "\nexit", "\r\nexit", "\n: end", ": end\n"}
	p.ValidateTail = validateCiscoSBTail
	p.safety = RollbackRebootOnly
	// "reload in" first offers to save the running configuration (answered
	// "yes" by the generic confirms), which stores the pre-change state that
	// the reload returns to. The reload is cancelled only after verification.
	p.confirmApply = []Step{
		{Kind: StepArm, Line: "reload in {mins}", Timed: true},
		{Kind: StepEnter, Line: "configure terminal"},
		{Kind: StepBody},
		{Kind: StepExit, Line: "end"},
		{Kind: StepVerify},
		{Kind: StepConfirm, Line: "reload cancel"},
		{Kind: StepPersist, Line: "write memory", Slow: true},
	}
	p.confirmCleanup = p.applyCleanup
	return p
}

// newCiscoXE is IOS-XE, selected by the "ios-xe" family of vendor names. It
// has a hitless confirmed-change mechanism: a revert timer that restores the
// pre-change configuration unless "configure confirm" is issued. The arm step
// fails (before anything is changed) on releases without it.
func newCiscoXE() *Profile {
	p := ciscoLike(Cisco, "Cisco IOS/IOS-XE", reCiscoErr)
	p.safety = RollbackSafe
	p.confirmApply = []Step{
		{Kind: StepArm, Line: "configure terminal revert timer {mins}", Timed: true},
		{Kind: StepBody},
		{Kind: StepExit, Line: "end"},
		{Kind: StepVerify},
		{Kind: StepConfirm, Line: "configure confirm"},
		{Kind: StepPersist, Line: "write memory", Slow: true},
	}
	p.confirmCleanup = p.applyCleanup
	return p
}

// newCiscoSB is the Cisco Small Business line (SF/SG/CBS). It shares the IOS
// prompt, error format and "configure terminal" / "end" / "write memory"
// flow, but differs where automation notices:
//   - paging is turned off with "terminal datadump" (older firmware) or
//     "terminal length 0"; a device rejects whichever it does not know and
//     the session logs a warning instead of failing;
//   - a backup does not always end in "end": it may end in "exit";
//   - there is no "reload in <min>", so there is no on-box deadman at all and
//     a change that cuts the management session can only be undone from the
//     console (RollbackClientOnly, and confirmApply is deliberately nil).
func newCiscoSB() *Profile {
	p := ciscoLike(CiscoSB, "Cisco Small Business (SF/SG/CBS)", reCiscoErr)
	p.DisablePaging = []string{"terminal datadump", "terminal length 0"}
	// If both commands are refused the pager stays on, and an unanswered pager
	// would stall the backup until the command timeout.
	p.Pagers = append(p.Pagers, rePagerSB)
	p.EndMarkers = []string{"\nend", "\r\nend", "\nexit", "\r\nexit"}
	// Every vlan/interface/line block closes with "exit", so "exit" anywhere
	// proves nothing: it only terminates the backup when it is the last line.
	// The backup is also the only rollback source here (no on-box deadman).
	p.EndAnchored = true
	p.ValidateTail = validateCiscoSBTail
	// Saving asks "Overwrite file [startup-config].... (Y/N)[N] ?" instead of
	// IOS's "Destination filename [startup-config]?", and the default is N, so
	// an unanswered prompt would leave the change unsaved. A new slice is built
	// because genericConfirms is shared by every vendor.
	p.Confirms = append([]Confirm{
		{regexp.MustCompile(`(?i)overwrite file \[[^\]]*\]\.*\s*\(y/n\)\s*\[[yn]\]\s*\?\s*$`), "Y"},
	}, genericConfirms...)
	p.safety = RollbackClientOnly
	return p
}

// newCiscoASA is the Cisco ASA. It is IOS like but pages with
// "terminal pager 0", ends its running configuration with ": end" and, like
// classic IOS, can only revert through a timed reload.
func newCiscoASA() *Profile {
	p := ciscoLike(CiscoASA, "Cisco ASA", reCiscoErr)
	p.ErrorPatterns = append(p.ErrorPatterns, reASAErr)
	p.DisablePaging = []string{"terminal pager 0"}
	// Send drops the newline in front of the final prompt, so a real backup ends
	// in a bare ": end"; the newline-terminated forms only occur in files.
	p.EndMarkers = []string{"\n: end", ": end\n", ": end\r\n", "\nend", "\r\nend"}
	p.safety = RollbackRebootOnly
	// "reload in" may first offer to save a modified configuration. As on IOS,
	// yes keeps the pre-change state; a new slice because genericConfirms is
	// shared by every vendor.
	p.Confirms = append([]Confirm{{reASASave, "y"}}, genericConfirms...)
	p.confirmApply = []Step{
		{Kind: StepArm, Line: "reload in {mins}", Timed: true},
		{Kind: StepEnter, Line: "configure terminal"},
		{Kind: StepBody},
		{Kind: StepExit, Line: "end"},
		{Kind: StepVerify},
		{Kind: StepConfirm, Line: "reload cancel"},
		{Kind: StepPersist, Line: "write memory", Slow: true},
	}
	p.confirmCleanup = p.applyCleanup
	return p
}

func newArista() *Profile {
	p := ciscoLike(Arista, "Arista EOS", reAristaErr)
	p.CandidateDiff = "show session-config diffs"
	p.applySession = []Step{
		{Kind: StepEnter, Line: "configure session netconfig-{token}"},
		{Kind: StepBody},
		{Kind: StepInspect, Line: "show session-config diffs"},
		{Kind: StepPersist, Line: "commit", Slow: true},
		{Kind: StepPersist, Line: "write memory", Slow: true},
	}
	// EOS config sessions validate every command as it is entered and can be
	// aborted, which makes a genuine dry run possible.
	p.dryRun = []Step{
		{Kind: StepEnter, Line: "configure session netconfig-{token}"},
		{Kind: StepBody},
		{Kind: StepInspect, Line: "show session-config diffs"},
		{Kind: StepExit, Line: "abort"},
	}
	p.dryRunCleanup = []Step{{Kind: StepExit, Line: "abort", IgnoreError: true}}
	// Session timers: "commit timer" applies the session and reverts it on
	// its own unless the session is re-entered and committed.
	p.safety = RollbackSafe
	p.confirmApply = []Step{
		{Kind: StepEnter, Line: "configure session netconfig-{token}"},
		{Kind: StepBody},
		{Kind: StepPersist, Line: "commit timer {hms}", Slow: true, Timed: true},
		{Kind: StepVerify},
		{Kind: StepConfirm, Line: "configure session netconfig-{token}"},
		{Kind: StepConfirm, Line: "commit", Slow: true},
		{Kind: StepPersist, Line: "write memory", Slow: true},
	}
	p.confirmCleanup = p.dryRunCleanup
	return p
}

func newJunos() *Profile {
	discard := []Step{
		{Kind: StepExit, Line: "rollback 0", IgnoreError: true},
		{Kind: StepExit, Line: "exit", IgnoreError: true},
	}
	return &Profile{
		Name:          Junos,
		Display:       "Juniper Junos",
		Prompt:        reJunosPrompt,
		PromptPrefix:  reJunosPromptPrefix,
		DisablePaging: []string{"set cli screen-length 0"},
		Pagers:        []*regexp.Regexp{rePagerJunos},
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reJunosErr},
		BackupCommand: "show configuration | no-more",
		CandidateDiff: "show | compare",
		probe:         "show system uptime",
		apply: []Step{
			{Kind: StepEnter, Line: "configure"},
			{Kind: StepBody},
			{Kind: StepPersist, Line: "commit", Slow: true},
			{Kind: StepExit, Line: "exit"},
		},
		applyCleanup: discard,
		dryRun: []Step{
			{Kind: StepEnter, Line: "configure"},
			{Kind: StepBody},
			{Kind: StepInspect, Line: "show | compare"},
			{Kind: StepValidate, Line: "commit check", Slow: true},
			{Kind: StepExit, Line: "rollback 0"},
			{Kind: StepExit, Line: "exit"},
		},
		dryRunCleanup: discard,

		safety: RollbackSafe,
		confirmApply: []Step{
			{Kind: StepEnter, Line: "configure"},
			{Kind: StepBody},
			{Kind: StepPersist, Line: "commit confirmed {mins}", Slow: true, Timed: true},
			{Kind: StepVerify, Line: "run "},
			{Kind: StepConfirm, Line: "commit", Slow: true},
			{Kind: StepExit, Line: "exit"},
		},
		confirmCleanup: discard,
		// Revert immediately instead of waiting for the timer.
		confirmAbort: []Step{
			{Kind: StepExit, Line: "rollback 1"},
			{Kind: StepPersist, Line: "commit", Slow: true},
			{Kind: StepExit, Line: "exit"},
		},
	}
}

func newHuawei() *Profile {
	return &Profile{
		Name:          Huawei,
		Display:       "Huawei VRP",
		Prompt:        reHuaweiPrompt,
		DisablePaging: []string{"screen-length 0 temporary"},
		Pagers:        []*regexp.Regexp{rePagerHuawei},
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reHuaweiErr},
		BackupCommand: "display current-configuration",
		EndMarkers:    []string{"\nreturn", "\r\nreturn"},
		probe:         "display clock",
		apply: []Step{
			{Kind: StepEnter, Line: "system-view"},
			{Kind: StepBody},
			{Kind: StepExit, Line: "return"},
			{Kind: StepPersist, Line: "save", Slow: true},
		},
		applyCleanup: []Step{{Kind: StepExit, Line: "return", IgnoreError: true}},
	}
}

func newFortinet() *Profile {
	// FortiOS has no global configuration mode: the user's commands are
	// themselves "config ... / edit ... / set ... / next / end" blocks, and
	// every block is saved when its "end" is processed.
	return &Profile{
		Name:          Fortinet,
		Display:       "Fortinet FortiOS",
		Prompt:        reFortiPrompt,
		DisablePaging: []string{"config system console", "set output standard", "end"},
		Pagers:        []*regexp.Regexp{rePagerMore},
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reFortiErr},
		BackupCommand: "show",
		probe:         "get system status",
		apply:         []Step{{Kind: StepBody}},
		applyCleanup:  []Step{{Kind: StepExit, Line: "abort", IgnoreError: true}},
	}
}

func newVyOS() *Profile {
	discard := []Step{
		{Kind: StepExit, Line: "exit discard", IgnoreError: true},
	}
	return &Profile{
		Name:          VyOS,
		Display:       "VyOS",
		Prompt:        reVyOSPrompt,
		DisablePaging: []string{"set terminal length 0"},
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reVyOSErr},
		BackupCommand: "show configuration commands",
		CandidateDiff: "compare",
		probe:         "show version",
		apply: []Step{
			{Kind: StepEnter, Line: "configure"},
			{Kind: StepBody},
			{Kind: StepPersist, Line: "commit", Slow: true},
			{Kind: StepPersist, Line: "save", Slow: true},
			{Kind: StepExit, Line: "exit"},
		},
		applyCleanup: discard,
		dryRun: []Step{
			{Kind: StepEnter, Line: "configure"},
			{Kind: StepBody},
			{Kind: StepInspect, Line: "compare"},
			{Kind: StepExit, Line: "exit discard"},
		},
		dryRunCleanup: discard,

		// Classified RollbackSafe per the project's policy. Some VyOS
		// releases implement commit-confirm with a reboot; if yours does,
		// change this to RollbackRebootOnly.
		safety: RollbackSafe,
		confirmApply: []Step{
			{Kind: StepEnter, Line: "configure"},
			{Kind: StepBody},
			{Kind: StepPersist, Line: "commit-confirm {mins}", Slow: true, Timed: true},
			{Kind: StepVerify, Line: "run "},
			{Kind: StepConfirm, Line: "confirm", Slow: true},
			{Kind: StepPersist, Line: "save", Slow: true},
			{Kind: StepExit, Line: "exit"},
		},
		confirmCleanup: discard,
	}
}

func newRuijie() *Profile {
	return ciscoLike(Ruijie, "Ruijie RGOS", reCiscoErr)
}

func newAruba() *Profile {
	p := ciscoLike(Aruba, "Aruba AOS-CX/AOS-S", reCiscoErr)
	p.DisablePaging = []string{"no page", "terminal length 0"}
	p.EndMarkers = nil
	return p
}

func newCheckPoint() *Profile {
	return &Profile{
		Name:          CheckPoint,
		Display:       "Check Point Gaia (clish)",
		Prompt:        reCheckPointPrompt,
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reCheckPointErr},
		BackupCommand: "show configuration",
		probe:         "show version",
		apply: []Step{
			{Kind: StepBody},
			{Kind: StepPersist, Line: "save config", Slow: true},
		},
	}
}

func newPaloAlto() *Profile {
	return &Profile{
		Name:          PaloAlto,
		Display:       "Palo Alto PAN-OS",
		Prompt:        rePaloAltoPrompt,
		DisablePaging: []string{"set cli pager off"},
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{rePaloAltoErr},
		BackupCommand: "show config running",
		CandidateDiff: "show config diff",
		probe:         "show system info",
		apply: []Step{
			{Kind: StepEnter, Line: "configure"},
			{Kind: StepBody},
			{Kind: StepPersist, Line: "commit", Slow: true},
			{Kind: StepExit, Line: "exit"},
		},
		applyCleanup: []Step{
			{Kind: StepExit, Line: "exit", IgnoreError: true},
		},
	}
}

func newPfSense() *Profile {
	return &Profile{
		Name:          PfSense,
		Display:       "pfSense",
		Prompt:        rePfSensePrompt,
		UserPrompt:    rePfSenseMenu,
		EnableCommand: "8",
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{rePfSenseErr},
		BackupCommand: "cat /conf/config.xml",
		EndMarkers:    []string{"</pfsense>"},
		probe:         "uname -a",
		apply: []Step{
			{Kind: StepBody},
		},
	}
}

func newSophos() *Profile {
	return &Profile{
		Name:          Sophos,
		Display:       "Sophos",
		Prompt:        reSophosPrompt,
		UserPrompt:    reSophosMenu,
		EnableCommand: "4",
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reSophosErr},
		BackupCommand: "show network interfaces",
		probe:         "show version",
		apply: []Step{
			{Kind: StepBody},
		},
	}
}

func newMikroTik() *Profile {
	return &Profile{
		Name:          MikroTik,
		Display:       "MikroTik RouterOS",
		Prompt:        reRouterOSPrompt,
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reRouterOSErr},
		BackupCommand: "/export verbose",
		probe:         "/system resource print",
		apply: []Step{
			{Kind: StepBody},
		},
		opApply: []Step{
			{Kind: StepBody},
		},
	}
}

var registry = map[string]*Profile{}

// ciscoXE is the IOS-XE variant of the cisco profile. It is reachable only
// through the IOS-XE aliases below and is not a separate canonical vendor.
var ciscoXE = newCiscoXE()

var ciscoXEAliases = map[string]bool{"ios-xe": true, "iosxe": true, "cisco-ios-xe": true}

// Keys must already be in the form Lookup normalises its input to: lower case,
// with "-" standing in for "_" and spaces. "cisco-sb" therefore also answers
// to "cisco_sb" and "Cisco SB"; a key containing "_" could never match.
var aliases = map[string]string{
	"cisco": Cisco, "cisco-ios": Cisco, "cisco-ios-xe": Cisco, "ios": Cisco, "ios-xe": Cisco, "iosxe": Cisco,
	"cisco-sb": CiscoSB, "cisco-sf": CiscoSB, "cisco-sg": CiscoSB, "ciscosb": CiscoSB, "ciscosf": CiscoSB, "ciscosg": CiscoSB,
	"cbs": CiscoSB, "cbs350": CiscoSB, "sg300": CiscoSB, "sg350": CiscoSB, "sg500": CiscoSB, "sf300": CiscoSB, "sf500": CiscoSB,
	"cisco-asa": CiscoASA, "asa": CiscoASA, "cisco-ftd": CiscoASA, "ftd": CiscoASA,
	"junos": Junos, "juniper": Junos, "juniper-junos": Junos,
	"huawei": Huawei, "vrp": Huawei, "huawei-vrp": Huawei,
	"h3c": Huawei, "comware": Huawei, "hp-comware": Huawei,
	"fortinet": Fortinet, "fortios": Fortinet, "fortigate": Fortinet,
	"arista": Arista, "eos": Arista, "arista-eos": Arista,
	"vyos": VyOS, "vyatta": VyOS,
	"ruijie": Ruijie, "rgos": Ruijie,
	"aruba": Aruba, "aruba-cx": Aruba, "aruba-s": Aruba, "aos-cx": Aruba, "aos-s": Aruba,
	"checkpoint": CheckPoint, "checkpoint-gaia": CheckPoint, "gaia": CheckPoint, "clish": CheckPoint,
	"paloalto": PaloAlto, "panos": PaloAlto, "pan-os": PaloAlto,
	"pfsense": PfSense,
	"sophos":  Sophos, "sophos-xg": Sophos, "sfos": Sophos,
	"mikrotik": MikroTik, "routeros": MikroTik, "ros": MikroTik,
}

func init() {
	for _, p := range []*Profile{
		newCisco(), newCiscoSB(), newCiscoASA(), newJunos(), newHuawei(), newFortinet(), newArista(),
		newVyOS(), newRuijie(), newAruba(), newCheckPoint(), newPaloAlto(), newPfSense(), newSophos(),
		newMikroTik(),
	} {
		registry[p.Name] = p
	}
}

// Lookup resolves a vendor name or alias ("IOS-XE", "eos", "FortiGate").
// The returned profile is shared and must be treated as read-only.
func Lookup(name string) (*Profile, bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.NewReplacer("_", "-", " ", "-").Replace(key)
	canonical, ok := aliases[key]
	if !ok {
		return nil, false
	}
	if canonical == Cisco && ciscoXEAliases[key] {
		return ciscoXE, true
	}
	p, ok := registry[canonical]
	return p, ok
}

// Canonical resolves a vendor name or alias ("cisco_ios", "ios", "sg350") to
// the canonical name of its profile ("cisco", "cisco_sb"). Callers that key
// their own tables by vendor use it instead of repeating Lookup.
func Canonical(name string) (string, bool) {
	p, ok := Lookup(name)
	if !ok {
		return "", false
	}
	return p.Name, true
}

// Names lists the canonical vendor names, sorted.
func Names() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

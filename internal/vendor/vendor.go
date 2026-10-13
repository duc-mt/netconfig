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
	EnableCommand string           // "" when the vendor has no privilege escalation step
	DisablePaging []string         // session-local commands that turn the pager off
	Pagers        []*regexp.Regexp // "--More--" style markers; answered with a space
	Confirms      []Confirm
	ErrorPatterns []*regexp.Regexp // matched per output line
	BackupCommand string           // prints the full running configuration

	probe         string
	apply         []Step // StepBody is a placeholder for the user's commands
	applyCleanup  []Step
	opApply       []Step // operational (read-only/show) command plan — no config mode
	dryRun        []Step // nil: vendor has no way to validate without applying
	dryRunCleanup []Step

	safety         RollbackSafety
	confirmApply   []Step // apply template with an on-box deadman ({mins}/{hms} are substituted); nil: none
	confirmCleanup []Step
	confirmAbort   []Step // optional immediate revert of an armed change
}

// Safety reports the platform's rollback safety class.
func (p *Profile) Safety() RollbackSafety { return p.safety }

// ProbeCommand is the cheap read-only command used to prove a session works.
func (p *Profile) ProbeCommand() string { return p.probe }

var (
	reIOSPrompt        = regexp.MustCompile(`^[\w.\-/:~()]+[#>]\s*$`)
	reIOSUserPrompt    = regexp.MustCompile(`^[\w.\-/:~()]+>\s*$`)
	reJunosPrompt      = regexp.MustCompile(`^[\w.\-]+@[\w.\-:]+[>#%]\s*$`)
	reHuaweiPrompt     = regexp.MustCompile(`^[<\[][~*\w.\-/:]+[>\]]\s*$`)
	reFortiPrompt      = regexp.MustCompile(`^\S+(?: \([^()]+\))? ?[#$]\s*$`)
	reVyOSPrompt       = regexp.MustCompile(`^[\w.\-]+@[\w.\-]+(?:(?::\S*)?[$#]|#)\s*$`)
	reCheckPointPrompt = regexp.MustCompile(`^[\w.\-]+>\s*$`)

	rePaloAltoPrompt = regexp.MustCompile(`^[\w.\-]+@[\w.\-]+(?:>|#)\s*$`)
	rePfSensePrompt  = regexp.MustCompile(`^(?:\[[\w.\-]+@[\w.\-]+\][^#$]*[#$]\s*$|Enter an option:\s*$)`)
	reSophosPrompt   = regexp.MustCompile(`^(?:[a-zA-Z0-9.\-]+_)?console>\s*$`)
	reSophosMenu     = regexp.MustCompile(`(?i)^Select Menu Number \[[0-9\-]+\]:\s*$`)

	rePagerMore   = regexp.MustCompile(`--\s*More\s*--`)
	rePagerHuawei = regexp.MustCompile(`----\s*More\s*----`)
	rePagerJunos  = regexp.MustCompile(`---\(more(?:\s+\d+%)?\)---`)

	reCiscoErr      = regexp.MustCompile(`(?i)^\s*%\s*(?:invalid|incomplete|ambiguous|unrecognized|unknown|bad\s|authorization failed|access denied)`)
	reAristaErr     = regexp.MustCompile(`(?i)^\s*%\s*(?:invalid|incomplete|ambiguous|unrecognized|unknown|unavailable|error|bad\s|authorization failed|access denied)`)
	reJunosErr      = regexp.MustCompile(`(?i)^\s*(?:syntax error|unknown command|error:|missing argument)`)
	reHuaweiErr     = regexp.MustCompile(`(?i)^\s*error:`)
	reFortiErr      = regexp.MustCompile(`(?i)^\s*(?:command fail|command parse error|value parse error|unknown action|object check operator error|node_check_object fail|entry not found)`)
	reVyOSErr       = regexp.MustCompile(`(?i)^\s*(?:syntax error|invalid command|configuration error|commit failed|failed to parse|error:|\.\.\. failed)`)
	reCheckPointErr = regexp.MustCompile(`(?i)^\s*(?:CLISH|syntax error|unknown command|error:)`)
	rePaloAltoErr   = regexp.MustCompile(`(?i)^\s*(?:Invalid syntax\.|Unknown command:|Server error)`)
	rePfSenseMenu   = regexp.MustCompile(`^Enter an option:\s*$`)
	rePfSenseErr    = regexp.MustCompile(`(?i)^\s*(?:[/\w.\-]+:\s*(?:not found|command not found|Permission denied|syntax error)|usage:)`)
	reSophosErr     = regexp.MustCompile(`(?i)^\s*(?:% Error:|Unknown parameter|Syntax Error)`)
)

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
		plan.Steps, plan.Cleanup = expand(p.apply), expand(p.applyCleanup)
		if opts.Verify {
			plan.Steps = append(plan.Steps, Step{Kind: StepVerify})
		}
		return plan
	}
	// The confirm templates always carry a StepVerify: even without
	// user-defined checks the runner proves management reachability with a
	// fresh session before it confirms.
	plan.Window = opts.CommitConfirm
	plan.Steps, plan.Cleanup = expand(p.confirmApply), expand(p.confirmCleanup)
	plan.Abort = expand(p.confirmAbort)
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
func newCisco() *Profile {
	p := ciscoLike(Cisco, "Cisco IOS/IOS-XE", reCiscoErr)
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

func newArista() *Profile {
	p := ciscoLike(Arista, "Arista EOS", reAristaErr)
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
		DisablePaging: []string{"set cli screen-length 0"},
		Pagers:        []*regexp.Regexp{rePagerJunos},
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reJunosErr},
		BackupCommand: "show configuration | no-more",
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
		Pagers:        []*regexp.Regexp{rePagerMore},
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reFortiErr},
		BackupCommand: "show full-configuration",
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
		DisablePaging: []string{"terminal length 0"},
		Confirms:      genericConfirms,
		ErrorPatterns: []*regexp.Regexp{reVyOSErr},
		BackupCommand: "show configuration commands",
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
	return ciscoLike(Aruba, "Aruba AOS-CX/AOS-S", reCiscoErr)
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

var registry = map[string]*Profile{}

// ciscoXE is the IOS-XE variant of the cisco profile. It is reachable only
// through the IOS-XE aliases below and is not a separate canonical vendor.
var ciscoXE = newCiscoXE()

var ciscoXEAliases = map[string]bool{"ios-xe": true, "iosxe": true, "cisco-ios-xe": true}

var aliases = map[string]string{
	"cisco": Cisco, "cisco-ios": Cisco, "cisco-ios-xe": Cisco, "ios": Cisco, "ios-xe": Cisco, "iosxe": Cisco,
	"junos": Junos, "juniper": Junos, "juniper-junos": Junos,
	"huawei": Huawei, "vrp": Huawei, "huawei-vrp": Huawei,
	"fortinet": Fortinet, "fortios": Fortinet, "fortigate": Fortinet,
	"arista": Arista, "eos": Arista, "arista-eos": Arista,
	"vyos": VyOS, "vyatta": VyOS,
	"ruijie": Ruijie, "rgos": Ruijie,
	"aruba": Aruba, "aruba-cx": Aruba, "aruba-s": Aruba, "aos-cx": Aruba, "aos-s": Aruba,
	"checkpoint": CheckPoint, "checkpoint-gaia": CheckPoint, "gaia": CheckPoint, "clish": CheckPoint,
	"paloalto": PaloAlto, "panos": PaloAlto, "pan-os": PaloAlto,
	"pfsense": PfSense,
	"sophos":  Sophos, "sophos-xg": Sophos, "sfos": Sophos,
}

func init() {
	for _, p := range []*Profile{
		newCisco(), newJunos(), newHuawei(), newFortinet(), newArista(),
		newVyOS(), newRuijie(), newAruba(), newCheckPoint(), newPaloAlto(), newPfSense(), newSophos(),
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

// Names lists the canonical vendor names, sorted.
func Names() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

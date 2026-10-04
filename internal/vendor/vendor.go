// Package vendor describes how each supported network OS is driven over an
// interactive SSH shell: what its prompt looks like, how paging and
// confirmation dialogs behave, what an error looks like, and which commands
// enter/leave configuration mode and persist the result.
//
// The package is pure data and string logic (no I/O) so every behaviour here
// can be unit-tested without a device.
package vendor

import (
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
)

// StepKind classifies one command of an execution plan; the runner uses it to
// pick a failure category and a timeout.
type StepKind int

const (
	StepProbe    StepKind = iota // read-only command proving the CLI answers
	StepEnter                    // enter configuration mode
	StepBody                     // one user-supplied configuration command
	StepInspect                  // read-only look inside config mode (diff)
	StepValidate                 // device-side validation without persisting (commit check)
	StepExit                     // leave configuration mode / discard candidate
	StepPersist                  // commit / write memory / save
)

func (k StepKind) String() string {
	switch k {
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
	}
	return "unknown"
}

// Step is one line to send to the device.
type Step struct {
	Kind        StepKind
	Line        string
	Slow        bool // commit/save: may take much longer than a normal command
	IgnoreError bool // best-effort (cleanup) - a device error here is not a failure
}

// Plan is the ordered command sequence for one device.
type Plan struct {
	Steps     []Step // executed in order
	Cleanup   []Step // best-effort steps run after a failure (never persists)
	Simulated []Step // dry-run on vendors without a candidate config: what would have run (not sent)
	Validates bool   // dry-run: the device itself validated the change, then discarded it
	DryRun    bool
}

// PlanOptions controls BuildPlan.
type PlanOptions struct {
	DryRun bool
	Token  string // makes device-side session names unique (Arista config sessions)
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
	dryRun        []Step // nil: vendor has no way to validate without applying
	dryRunCleanup []Step
}

var (
	reIOSPrompt        = regexp.MustCompile(`^[\w.\-/:~()]+[#>]\s*$`)
	reIOSUserPrompt    = regexp.MustCompile(`^[\w.\-/:~()]+>\s*$`)
	reJunosPrompt      = regexp.MustCompile(`^[\w.\-]+@[\w.\-:]+[>#%]\s*$`)
	reHuaweiPrompt     = regexp.MustCompile(`^[<\[][~*\w.\-/:]+[>\]]\s*$`)
	reFortiPrompt      = regexp.MustCompile(`^\S+(?: \([^()]+\))? ?[#$]\s*$`)
	reVyOSPrompt       = regexp.MustCompile(`^[\w.\-]+@[\w.\-]+(?:(?::\S*)?[$#]|#)\s*$`)
	reCheckPointPrompt = regexp.MustCompile(`^[\w.\-]+>\s*$`)

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
	expand := func(tmpl []Step) []Step {
		var out []Step
		for _, s := range tmpl {
			if s.Kind == StepBody {
				for _, c := range commands {
					out = append(out, Step{Kind: StepBody, Line: c})
				}
				continue
			}
			s.Line = strings.ReplaceAll(s.Line, "{token}", token)
			out = append(out, s)
		}
		return out
	}

	if !opts.DryRun {
		return Plan{Steps: expand(p.apply), Cleanup: expand(p.applyCleanup)}
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

func newCisco() *Profile {
	return ciscoLike(Cisco, "Cisco IOS/IOS-XE", reCiscoErr)
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

var registry = map[string]*Profile{}

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
}

func init() {
	for _, p := range []*Profile{
		newCisco(), newJunos(), newHuawei(), newFortinet(), newArista(),
		newVyOS(), newRuijie(), newAruba(), newCheckPoint(),
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

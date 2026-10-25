package task

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"netops/internal/logging"
)

// RiskLevel ranks how much damage a command (or a whole job) can do.
type RiskLevel int

// Risk levels, lowest first.
const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

func (l RiskLevel) String() string {
	switch l {
	case RiskMedium:
		return "MEDIUM"
	case RiskHigh:
		return "HIGH"
	case RiskCritical:
		return "CRITICAL"
	}
	return "LOW"
}

// FindingKind separates what a finding protects against, because the two
// kinds are released by different flags.
type FindingKind string

// Finding kinds.
const (
	// KindLockout: the change can cut the operator's own management path.
	// CRITICAL lockouts abort the run unless -force is given.
	KindLockout FindingKind = "lockout"
	// KindDestructive: an uncontained teardown. HIGH and above abort the run
	// unless -allow-dangerous is given.
	KindDestructive FindingKind = "destructive"
	// KindImpact: disruptive but contained; reported, never blocking.
	KindImpact FindingKind = "impact"
)

// Finding is one problem the static analysis found in one command.
type Finding struct {
	Level   RiskLevel
	Kind    FindingKind
	Rule    string // stable rule id, e.g. "mgmt-ip-removed"
	Index   int    // 1-based position in the device's command list
	Command string // redacted
	Message string
}

// LintContext carries the connection parameters the commands are judged
// against: a command is a lockout when it breaks *this* session's path.
type LintContext struct {
	Hostname string
	Address  string // management address / name the session connects to
	Port     int    // SSH port of the session (0 means 22)
	Username string // login user, when known without prompting
	Vendor   string // canonical vendor name
	OpMode   bool   // operational commands: only destructive rules apply
}

// LintReport is the outcome for one device.
type LintReport struct {
	Findings   []Finding
	Subsystems []string  // impacted subsystems, e.g. BGP, Interface
	Level      RiskLevel // highest finding level (RiskLow when clean)
	Err        error     // non-nil: the analysis itself failed; the report is empty
}

// SafetyPolicy decides which findings abort a run.
type SafetyPolicy struct {
	Strict         bool // -strict-safety
	Force          bool // -force: accept CRITICAL lockout risks
	AllowDangerous bool // -allow-dangerous: accept destructive commands
}

// Blocks reports whether f aborts the run under p.
func (p SafetyPolicy) Blocks(f Finding) bool {
	if !p.Strict {
		return false
	}
	switch f.Kind {
	case KindLockout:
		return f.Level == RiskCritical && !p.Force
	case KindDestructive:
		return f.Level >= RiskHigh && !p.AllowDangerous
	}
	return false
}

// Blocking returns the findings that abort the run under p.
func (r LintReport) Blocking(p SafetyPolicy) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if p.Blocks(f) {
			out = append(out, f)
		}
	}
	return out
}

// Log writes the report to the run log: a failed analysis and every finding
// of MEDIUM or above.
func (r LintReport) Log(log *logging.Logger, host string) {
	if r.Err != nil {
		log.Warnf(host, "static safety lint failed (%v); continuing without pre-flight analysis for this device", r.Err)
		return
	}
	for _, f := range r.Findings {
		if f.Level < RiskMedium {
			continue
		}
		msg := fmt.Sprintf("LINT %s [%s] command %d %q: %s", f.Level, f.Rule, f.Index, f.Command, f.Message)
		if f.Level == RiskCritical {
			log.Errorf(host, "%s", msg)
		} else {
			log.Warnf(host, "%s", msg)
		}
	}
}

// LintJob analyses one device's commands against its connection parameters.
// It never panics: an internal failure yields a report with Err set.
func LintJob(j Job, username string, opMode bool) LintReport {
	ctx := LintContext{
		Hostname: j.Device.Hostname,
		Address:  j.Device.Address,
		Port:     j.Device.Port,
		Username: username,
		OpMode:   opMode,
	}
	if j.Profile != nil {
		ctx.Vendor = j.Profile.Name
	}
	return LintCommands(ctx, j.Commands)
}

// LintCommands statically inspects commands before any session is opened. A
// panic in a rule is contained to this one analysis.
func LintCommands(ctx LintContext, commands []string) (rep LintReport) {
	defer func() {
		if rec := recover(); rec != nil {
			rep = LintReport{Err: fmt.Errorf("internal error: %v", rec)}
		}
	}()
	l := &linter{ctx: ctx}
	if ctx.Address != "" {
		l.addrRe = regexp.MustCompile(`(?:^|[^0-9a-z.:-])` + regexp.QuoteMeta(strings.ToLower(ctx.Address)) + `(?:[^0-9a-z-]|\.?$)`)
	}
	var block, rawBlock string
	var cmds []cmdInfo
	for i, raw := range commands {
		c := parseCmd(i+1, raw, block, rawBlock, ctx.Vendor)
		block, rawBlock = c.nextBlock, c.nextRawBlock
		cmds = append(cmds, c)
		l.check(c)
	}
	sort.SliceStable(l.findings, func(a, b int) bool { return l.findings[a].Level > l.findings[b].Level })
	rep.Findings = l.findings
	rep.Subsystems = subsystemsOf(cmds)
	for _, f := range rep.Findings {
		if f.Level > rep.Level {
			rep.Level = f.Level
		}
	}
	return rep
}

// cmdInfo is a command normalised for matching.
type cmdInfo struct {
	idx       int
	raw       string
	full      string // lower case, whitespace collapsed, quotes removed
	body      string // full without negation prefix and a leading "set"
	neg       bool   // no / undo / delete / unset
	block     string // enclosing block when the command was entered
	nextBlock string // enclosing block after it
	readOnly  bool

	rawFull      string // full as typed (case preserved), for messages
	rawBlock     string // block as typed
	nextRawBlock string
}

// orig returns name as the operator typed it. name is always a suffix of the
// lower-cased block or command (it comes from an end-anchored match), so the
// original spelling is the same-length tail of the case-preserved text.
func (c cmdInfo) orig(name string) string {
	for _, p := range [][2]string{{c.block, c.rawBlock}, {c.full, c.rawFull}} {
		if len(p[0]) == len(p[1]) && strings.HasSuffix(p[0], name) {
			return p[1][len(p[1])-len(name):]
		}
	}
	return name
}

var (
	reNegation  = regexp.MustCompile(`^(?:no|undo|delete|unset)(?:\s+|$)`)
	reReadOnly  = regexp.MustCompile(`^(?:(?:do|run)\s+)?(?:show|display|get|ping|traceroute|tracert|trace|monitor|diagnose|dir|more)\b`)
	reBlockEnd  = regexp.MustCompile(`^(?:exit|end|quit|return|abort|next)$`)
	reBlockOpen = regexp.MustCompile(`^(?:interface|int|line|router|management|user-interface|aaa|vlan|route-map|policy-map|class-map|vrf definition|control-plane|config|edit)\b`)
	reMgmtName  = regexp.MustCompile(`(?:^|[^a-z])(?:mgmt|mgt|management|oob|oobm|fxp|em|me)\d*(?:[^a-z]|$)`)
)

func parseCmd(idx int, raw, block, rawBlock, vendorName string) cmdInfo {
	rawFull := strings.Join(strings.Fields(strings.NewReplacer("'", "", `"`, "").Replace(raw)), " ")
	full := strings.ToLower(rawFull)
	c := cmdInfo{idx: idx, raw: raw, full: full, block: block, nextBlock: block,
		rawFull: rawFull, rawBlock: rawBlock, nextRawBlock: rawBlock}
	c.readOnly = reReadOnly.MatchString(full)
	c.body = full
	if loc := reNegation.FindStringIndex(full); loc != nil {
		c.neg = true
		c.body = full[loc[1]:]
	}
	c.body = strings.TrimPrefix(c.body, "set ")
	switch {
	case reBlockEnd.MatchString(full):
		if vendorName == "fortinet" && full == "next" {
			if i := strings.Index(block, " | "); i >= 0 {
				c.nextBlock, c.nextRawBlock = block[:i], rawBlock[:i]
			}
		} else {
			c.nextBlock, c.nextRawBlock = "", ""
		}
	case vendorName == "fortinet" && strings.HasPrefix(full, "edit "):
		base, rawBase := block, rawBlock
		if i := strings.Index(base, " | "); i >= 0 {
			base, rawBase = base[:i], rawBase[:i]
		}
		c.nextBlock = base + " | " + strings.TrimPrefix(full, "edit ")
		c.nextRawBlock = rawBase + " | " + strings.TrimPrefix(rawFull, rawFull[:5])
	case !c.neg && reBlockOpen.MatchString(full):
		c.nextBlock, c.nextRawBlock = full, rawFull
	}
	return c
}

type linter struct {
	ctx      LintContext
	addrRe   *regexp.Regexp
	findings []Finding
}

func (l *linter) add(c cmdInfo, level RiskLevel, kind FindingKind, rule, msg string) {
	l.findings = append(l.findings, Finding{
		Level: level, Kind: kind, Rule: rule, Index: c.idx,
		Command: logging.RedactCommand(c.raw), Message: msg,
	})
}

func (l *linter) mentionsAddr(s string) bool {
	return l.addrRe != nil && l.addrRe.MatchString(s)
}

func (l *linter) port() int {
	if l.ctx.Port > 0 {
		return l.ctx.Port
	}
	return 22
}

func (l *linter) ciscoLike() bool {
	switch l.ctx.Vendor {
	case "cisco", "cisco_sb", "cisco_asa", "arista", "ruijie", "aruba", "huawei":
		return true
	}
	return false
}

// lintTestHook lets tests inject a fault into the analysis; nil in production.
var lintTestHook func(c cmdInfo)

func (l *linter) check(c cmdInfo) {
	if lintTestHook != nil {
		lintTestHook(c)
	}
	if c.readOnly {
		return
	}
	l.destructive(c)
	if l.ctx.OpMode {
		return
	}
	l.mgmtAddress(c)
	l.defaultRoute(c)
	l.ssh(c)
	l.aaa(c)
	l.vtyAccess(c)
	l.interfaces(c)
	l.routing(c)
}

var (
	reRoutingProc  = regexp.MustCompile(`^router\s+(?:bgp|ospf|ospfv3|eigrp|isis|rip|ripng)(?:\s+\S+){0,3}$`)
	reProtoWhole   = regexp.MustCompile(`^protocols\s+(?:bgp|ospf|ospf3|isis|rip|ldp|mpls|rsvp|pim|evpn)(?:\s+\d+)?$`)
	reProtoPart    = regexp.MustCompile(`^protocols\s+(?:bgp|ospf|ospf3|isis|rip|ldp|mpls|rsvp|pim|evpn)\s+\S`)
	reClearBGP     = regexp.MustCompile(`^(?:clear\s+(?:ip\s+|ipv6\s+)?bgp|reset\s+bgp)\s+(?:vrf\s+\S+\s+)?(?:\*|all)(\s.*)?$`)
	reClearOSPF    = regexp.MustCompile(`^clear\s+ip\s+ospf\s+(?:\d+\s+)?(?:process|\*)`)
	reClearRoute   = regexp.MustCompile(`^clear\s+ip\s+route\s+\*`)
	reEraseConfig  = regexp.MustCompile(`^(?:write\s+erase|erase\s+(?:startup-config|nvram:?|all|flash:?)|erase-all|reset\s+saved-configuration|factory-?reset|execute\s+factoryreset|request\s+system\s+zeroize|load\s+(?:override|factory-default))`)
	reDeleteFile   = regexp.MustCompile(`^delete\s+(?:/\S+\s+)*(?:flash|bootflash|nvram|disk\d?|usb\d?|sdflash):\S*`)
	reRebootCmd    = regexp.MustCompile(`^(?:reboot|halt|request\s+system\s+(?:reboot|halt|power-off))\b`)
	reIfaceWhole   = regexp.MustCompile(`^interfaces?(?:\s+\S+){0,2}$`)
	reDefaultIface = regexp.MustCompile(`^default\s+interface\s+(\S.*)$`)
	reNoIface      = regexp.MustCompile(`^interface\s+(\S+(?:\s+\S+)?)$`)
)

// destructive flags uncontained teardown operations.
func (l *linter) destructive(c cmdInfo) {
	full, body := c.full, c.body
	switch {
	case c.neg && body == "" && !l.ciscoLike():
		l.add(c, RiskCritical, KindDestructive, "wipe-configuration", "deletes the entire configuration hierarchy")
	case c.neg && reRoutingProc.MatchString(body):
		l.add(c, RiskCritical, KindDestructive, "teardown-routing-process",
			"removes the whole routing process: every neighbour/adjacency it carries drops")
	case c.neg && reProtoWhole.MatchString(body):
		l.add(c, RiskCritical, KindDestructive, "teardown-routing-process",
			"removes the whole routing protocol configuration: every neighbour/adjacency it carries drops")
	case c.neg && strings.HasPrefix(body, "interfaces") && len(strings.Fields(body)) == 1:
		l.add(c, RiskCritical, KindDestructive, "delete-all-interfaces", "deletes every interface configuration")
	case c.neg && reIfaceWhole.MatchString(body) && strings.HasPrefix(body, "interfaces "):
		name := strings.TrimPrefix(body, "interfaces ")
		if reMgmtName.MatchString(name) {
			l.add(c, RiskCritical, KindLockout, "mgmt-interface-removed", "deletes management interface "+c.orig(name))
		} else {
			l.add(c, RiskHigh, KindDestructive, "delete-interface", "deletes all configuration of interface "+c.orig(name))
		}
	case c.neg && reNoIface.MatchString(body) && l.ciscoLike():
		name := reNoIface.FindStringSubmatch(body)[1]
		if reMgmtName.MatchString(name) {
			l.add(c, RiskCritical, KindLockout, "mgmt-interface-removed", "removes management interface "+c.orig(name))
		} else {
			l.add(c, RiskHigh, KindDestructive, "delete-interface", "removes interface "+c.orig(name)+" and all of its configuration")
		}
	case !c.neg && reDefaultIface.MatchString(full):
		name := reDefaultIface.FindStringSubmatch(full)[1]
		if reMgmtName.MatchString(name) {
			l.add(c, RiskCritical, KindLockout, "mgmt-interface-reset", "resets management interface "+c.orig(name)+" to factory defaults")
		} else {
			l.add(c, RiskHigh, KindDestructive, "default-interface",
				"resets interface "+c.orig(name)+" to factory defaults (address, description and every setting are removed)")
		}
	case reEraseConfig.MatchString(full):
		l.add(c, RiskCritical, KindDestructive, "erase-configuration", "erases device configuration")
	case reDeleteFile.MatchString(full):
		l.add(c, RiskHigh, KindDestructive, "delete-file", "deletes files from device storage")
	case reRebootCmd.MatchString(full), isImmediateReload(full):
		l.add(c, RiskHigh, KindDestructive, "reload", "reboots the device and ends the session")
	}
	if m := reClearBGP.FindStringSubmatch(full); m != nil {
		if reSoftReset.MatchString(m[1]) {
			l.add(c, RiskMedium, KindImpact, "bgp-soft-reset", "soft-resets all BGP sessions (non-disruptive)")
		} else {
			l.add(c, RiskHigh, KindDestructive, "clear-bgp-all", "hard-resets every BGP session")
		}
	}
	if reClearOSPF.MatchString(full) {
		l.add(c, RiskHigh, KindDestructive, "clear-ospf", "restarts OSPF: every adjacency drops")
	}
	if reClearRoute.MatchString(full) {
		l.add(c, RiskMedium, KindImpact, "clear-routes", "flushes the routing table")
	}
	if c.neg && reProtoPart.MatchString(body) {
		if strings.Contains(body, "neighbor") {
			l.add(c, RiskHigh, KindImpact, "routing-neighbor-removed", "removes a routing neighbour: its session drops")
		} else {
			l.add(c, RiskMedium, KindImpact, "routing-config-removed", "removes part of a routing protocol configuration")
		}
	}
}

func isImmediateReload(full string) bool {
	f := strings.Fields(full)
	if len(f) == 0 || f[0] != "reload" {
		return false
	}
	return len(f) == 1 || (f[1] != "in" && f[1] != "at" && f[1] != "cancel")
}

var (
	reAddressWord  = regexp.MustCompile(`\baddress(?:\s|$)`)
	reIPAddrAssign = regexp.MustCompile(`^ip(?:v4)?\s+address\s+(\S+)`)
	reVRFMove      = regexp.MustCompile(`^(?:ip\s+)?vrf\s+(?:forwarding|member)\s+\S+`)
	reIfaceBlock   = regexp.MustCompile(`^(?:interface|int)\s+(\S+(?:\s+\S+)?)$`)
)

// mgmtAddress detects changes to the address the session is connected to.
func (l *linter) mgmtAddress(c cmdInfo) {
	ifName := ""
	if m := reIfaceBlock.FindStringSubmatch(c.block); m != nil {
		ifName = m[1]
	}
	switch {
	case c.neg && reAddressWord.MatchString(c.body):
		if l.mentionsAddr(c.body) {
			l.add(c, RiskCritical, KindLockout, "mgmt-ip-removed",
				"removes "+l.ctx.Address+", the management address this session is connected to")
		} else {
			l.add(c, RiskHigh, KindLockout, "interface-address-removed",
				"removes an interface address; if that interface carries "+l.ctx.Address+" the session is lost")
		}
	case !c.neg && l.ciscoLike() && ifName != "" && reIPAddrAssign.MatchString(c.body):
		if l.mentionsAddr(c.body) {
			return // re-asserting the current address
		}
		if reMgmtName.MatchString(ifName) {
			l.add(c, RiskCritical, KindLockout, "mgmt-ip-changed",
				"re-addresses management interface "+c.orig(ifName)+"; "+l.ctx.Address+" stops answering")
		} else {
			l.add(c, RiskMedium, KindLockout, "interface-readdressed",
				"replaces the primary address of "+c.orig(ifName)+"; if it carries "+l.ctx.Address+" the session is lost")
		}
	case !c.neg && ifName != "" && reVRFMove.MatchString(c.body):
		l.add(c, RiskHigh, KindLockout, "interface-vrf-moved",
			"moving "+c.orig(ifName)+" into a VRF removes its IP address")
	case l.ctx.Vendor == "fortinet" && strings.Contains(c.block, "system interface") && c.neg && c.body == "ip":
		l.add(c, RiskHigh, KindLockout, "interface-address-removed", "unsets the interface address")
	}
}

var (
	reRouteWord    = regexp.MustCompile(`\broute(?:-static)?\b|\bstatic-route\b`)
	reDefaultDst   = regexp.MustCompile(`(?:^|\s|/)(?:0\.0\.0\.0(?:/0|\s+0\.0\.0\.0|\s+0)|::/0)(?:\s|$)`)
	reDefaultGW    = regexp.MustCompile(`^ip\s+default-gateway\b`)
	reBlackholeHop = regexp.MustCompile(`\b(?:null0|discard|reject|blackhole)\b`)
)

// defaultRoute detects changes to the default gateway (0.0.0.0/0).
func (l *linter) defaultRoute(c cmdInfo) {
	isDefault := (reRouteWord.MatchString(c.body) && reDefaultDst.MatchString(c.body)) || reDefaultGW.MatchString(c.body)
	switch {
	case isDefault && c.neg:
		l.add(c, RiskCritical, KindLockout, "default-route-removed",
			"removes the default route (0.0.0.0/0); management reachability from remote networks usually depends on it")
	case isDefault && reBlackholeHop.MatchString(c.body):
		l.add(c, RiskHigh, KindLockout, "default-route-blackholed", "points the default route at a discard next hop")
	case isDefault && reDefaultGW.MatchString(c.body):
		l.add(c, RiskHigh, KindLockout, "default-gateway-changed", "replaces the device's only default gateway")
	case isDefault:
		l.add(c, RiskMedium, KindLockout, "default-route-changed", "adds or changes a default route; verify its next hop is reachable")
	case l.ctx.Vendor == "fortinet" && strings.Contains(c.block, "router static") && c.neg:
		l.add(c, RiskHigh, KindLockout, "static-route-deleted", "deletes a static route; it may be the default route")
	}
}

var (
	rePortSet = regexp.MustCompile(`(?:^|\s)(?:ip\s+ssh\s+port|ssh\s+server\s+port|services\s+ssh\s+port|service\s+ssh\s+port|admin-ssh-port)(?:\s+(\d+))?`)
	reSrvPort = regexp.MustCompile(`^server-port\s+(\d+)`)
	reSSHRoot = regexp.MustCompile(`^(?:ip\s+ssh(?:\s+server)?(?:\s+enable)?|system\s+services\s+ssh|service\s+ssh|ssh\s+server(?:\s+enable)?|stelnet\s+server\s+enable|management\s+ssh)$`)
	reSSHWord = regexp.MustCompile(`\b(?:ssh|stelnet)\b|\bssh-`)
	reSSHAlgo = regexp.MustCompile(`\b(?:ciphers?|macs?|kex|key-exchange|hostkey|algorithm|cbc-cipher|hmac-md5|kex-sha1|enc-algo|mac-algo|kex-algo)\b`)
	reTransIn = regexp.MustCompile(`^transport\s+input\b(.*)$`)
)

// ssh detects changes to the SSH service the session depends on.
func (l *linter) ssh(c cmdInfo) {
	body := c.body
	if !c.neg && strings.HasPrefix(body, "crypto key zeroize") {
		l.add(c, RiskCritical, KindLockout, "ssh-keys-zeroized", "deletes the keys SSH depends on")
		return
	}
	port, portCmd := 0, false
	if m := rePortSet.FindStringSubmatch(body); m != nil {
		port, _ = strconv.Atoi(m[1])
		portCmd = true
	} else if m := reSrvPort.FindStringSubmatch(body); m != nil && strings.Contains(c.block, "ssh") {
		port, _ = strconv.Atoi(m[1])
		portCmd = true
	}
	if portCmd && c.neg {
		port = 22 // removing the setting falls back to the default port
	}
	switch {
	case portCmd && port > 0:
		if port != l.port() {
			l.add(c, RiskCritical, KindLockout, "ssh-port-changed", fmt.Sprintf(
				"moves SSH to port %d while this session uses %d; new sessions (including netconfig's own rollback and verification sessions) will fail",
				port, l.port()))
		}
	case c.neg && reSSHRoot.MatchString(body):
		l.add(c, RiskCritical, KindLockout, "ssh-disabled", "disables the SSH service this session depends on")
	case !c.neg && strings.HasPrefix(c.block, "management ssh") && body == "shutdown":
		l.add(c, RiskCritical, KindLockout, "ssh-disabled", "shuts down the SSH management service")
	case reSSHWord.MatchString(body) && reSSHAlgo.MatchString(body):
		l.add(c, RiskHigh, KindLockout, "ssh-algorithms-changed",
			"restricts SSH algorithms; clients that need a removed algorithm (see -legacy-algorithms) can no longer connect")
	}
	if m := reTransIn.FindStringSubmatch(body); m != nil && isVTYBlock(c.block) {
		if c.neg || !reSSHOrAll.MatchString(m[1]) {
			l.add(c, RiskCritical, KindLockout, "vty-ssh-disabled", "leaves the vty lines without SSH transport")
		}
	}
	if l.ctx.Vendor == "fortinet" && strings.Contains(c.block, "system interface") && strings.HasPrefix(body, "allowaccess") {
		if c.neg || !reSSHToken.MatchString(body) {
			l.add(c, RiskCritical, KindLockout, "ssh-access-removed", "removes SSH from the interface's allowed administrative access")
		}
	}
}

func isVTYBlock(block string) bool {
	return strings.HasPrefix(block, "line vty") || strings.HasPrefix(block, "line con") ||
		strings.HasPrefix(block, "line aux") || strings.HasPrefix(block, "user-interface")
}

var (
	reAAAMethod = regexp.MustCompile(`^aaa\s+(?:authentication|authorization)\s+(?:login|enable|exec)\s+\S+(?:\s+(.*))?$`)
	reAAAOrder  = regexp.MustCompile(`^system\s+authentication-order\s+(.*)$`)
	reUserCmd   = regexp.MustCompile(`^(?:username|local-user|system\s+login\s+user)\s+(\S+)(.*)$`)
	reWord      = func(w string) *regexp.Regexp { return regexp.MustCompile(`\b` + w + `\b`) }
)

// aaa detects changes to authentication that can lock the operator out.
func (l *linter) aaa(c cmdInfo) {
	body := c.body
	switch {
	case body == "aaa new-model":
		l.add(c, RiskHigh, KindLockout, "aaa-model-changed",
			"toggles AAA: logins switch to the AAA method lists; without a working local fallback nobody can log in")
	case reAAAMethod.MatchString(body) && c.neg:
		l.add(c, RiskHigh, KindLockout, "aaa-method-removed", "removes a login method list")
	case reAAAMethod.MatchString(body) && reAAAMethod.FindStringSubmatch(body)[1] != "":
		methods := reAAAMethod.FindStringSubmatch(body)[1]
		switch {
		case reWord("local").MatchString(methods):
			l.add(c, RiskHigh, KindLockout, "aaa-method-changed", "changes the login method list; verify the local fallback works")
		case reWord("none").MatchString(methods):
			l.add(c, RiskHigh, KindImpact, "aaa-auth-none", "disables authentication for this method list")
		default:
			l.add(c, RiskCritical, KindLockout, "aaa-no-fallback",
				"login method list has no local fallback: if the AAA server is unreachable nobody can log in")
		}
	case reAAAOrder.MatchString(body) && !c.neg:
		if reWord("password").MatchString(reAAAOrder.FindStringSubmatch(body)[1]) {
			l.add(c, RiskHigh, KindLockout, "aaa-order-changed", "changes the authentication order; local password fallback is kept")
		} else {
			l.add(c, RiskCritical, KindLockout, "aaa-no-fallback", "authentication order has no local password fallback")
		}
	case l.ctx.Vendor == "fortinet" && strings.Contains(c.block, "system admin") && strings.HasPrefix(body, "trusthost"):
		l.add(c, RiskHigh, KindLockout, "admin-trusthost", "restricts the admin account to specific source networks")
	}

	user := ""
	if m := reUserCmd.FindStringSubmatch(body); m != nil {
		user = m[1]
	} else if l.ctx.Vendor == "fortinet" && c.neg && strings.Contains(c.block, "system admin") {
		user = strings.Fields(body + " ")[0]
	}
	if user == "" {
		return
	}
	switch {
	case c.neg && l.ctx.Username != "" && user == l.ctx.Username:
		l.add(c, RiskCritical, KindLockout, "mgmt-user-removed", "removes "+user+", the account this session logs in with")
	case c.neg && l.ctx.Username == "":
		l.add(c, RiskHigh, KindLockout, "user-removed", "removes local user "+user+"; it may be the account used for this session")
	case c.neg:
		l.add(c, RiskMedium, KindImpact, "user-removed", "removes local user "+user)
	case user == l.ctx.Username && l.ctx.Username != "":
		l.add(c, RiskHigh, KindLockout, "mgmt-user-modified",
			"changes the account this session logs in with; stored credentials may stop working")
	}
}

var (
	reVTYACL  = regexp.MustCompile(`^(?:access-class\s+\S+|acl\s+\d+\s+inbound|ip\s+access-group\s+\S+)`)
	reVTYAuth = regexp.MustCompile(`^(?:authentication-mode\b|login\b|password\b|no login)`)
	reRE      = regexp.MustCompile(`^interfaces\s+lo0\s+.*\bfilter\s+input\b`)
)

// vtyAccess detects changes to who may reach the console/vty lines.
func (l *linter) vtyAccess(c cmdInfo) {
	inVTY := isVTYBlock(c.block) || strings.HasPrefix(c.block, "management ssh") || strings.HasPrefix(c.block, "management telnet")
	switch {
	case inVTY && reVTYACL.MatchString(c.body) && !c.neg:
		l.add(c, RiskHigh, KindLockout, "vty-acl-changed",
			"applies an access list to the management lines; a wrong entry blocks this operator")
	case inVTY && reVTYACL.MatchString(c.body):
		l.add(c, RiskMedium, KindLockout, "vty-acl-removed", "removes the access list from the management lines")
	case isVTYBlock(c.block) && reVTYAuth.MatchString(c.full):
		l.add(c, RiskHigh, KindLockout, "vty-auth-changed", "changes how the management lines authenticate")
	case !c.neg && reRE.MatchString(c.body):
		l.add(c, RiskHigh, KindLockout, "re-filter-applied",
			"applies a filter to the Routing Engine loopback; a mistake blocks management traffic")
	}
}

var (
	reTrunkList = regexp.MustCompile(`^switchport\s+trunk\s+allowed\s+vlan\s+(\S+)`)
	reIfDisable = regexp.MustCompile(`^interfaces\s+(.*?)\s+disable$`)
)

// interfaces detects shutdowns and VLAN list replacements.
func (l *linter) interfaces(c cmdInfo) {
	ifName := ""
	if m := reIfaceBlock.FindStringSubmatch(c.block); m != nil {
		ifName = m[1]
	} else if i := strings.Index(c.block, " | "); i >= 0 && strings.Contains(c.block, "system interface") {
		ifName = c.block[i+3:]
	}
	shut := func(name string) {
		if reMgmtName.MatchString(name) {
			l.add(c, RiskCritical, KindLockout, "mgmt-interface-shutdown", "shuts down management interface "+c.orig(name))
		} else {
			l.add(c, RiskHigh, KindLockout, "interface-shutdown",
				"administratively disables "+c.orig(name)+"; if it carries "+l.ctx.Address+" the session is lost")
		}
	}
	switch {
	case !c.neg && c.body == "shutdown" && ifName != "":
		shut(ifName)
	case !c.neg && reIfDisable.MatchString(c.body):
		shut(reIfDisable.FindStringSubmatch(c.body)[1])
	case !c.neg && l.ctx.Vendor == "fortinet" && ifName != "" && strings.Contains(c.block, "system interface") && c.body == "status down":
		shut(ifName)
	case !c.neg && ifName != "":
		if m := reTrunkList.FindStringSubmatch(c.body); m != nil && !reTrunkKeyword.MatchString(m[1]) {
			l.add(c, RiskHigh, KindLockout, "trunk-vlan-list-replaced",
				"replaces the trunk's allowed VLAN list; dropping the management VLAN cuts the session")
		}
	}
}

var (
	reSoftReset    = regexp.MustCompile(`\b(?:soft|in|out)\b`)
	reSSHOrAll     = regexp.MustCompile(`\b(?:ssh|all)\b`)
	reSSHToken     = regexp.MustCompile(`\bssh\b`)
	reTrunkKeyword = regexp.MustCompile(`^(?:add|remove|all|except|none)$`)
)

var reRoutingRemoval = regexp.MustCompile(`^(?:network|redistribute|area|address-family|peer-group|summary-address|default-information|aggregate-address)\b`)

// routing flags contained but disruptive routing-protocol edits.
func (l *linter) routing(c cmdInfo) {
	inRouter := strings.HasPrefix(c.block, "router ")
	switch {
	case inRouter && c.neg && strings.HasPrefix(c.body, "neighbor"):
		l.add(c, RiskHigh, KindImpact, "routing-neighbor-removed", "removes a routing neighbour: its session drops")
	case inRouter && !c.neg && strings.HasPrefix(c.body, "neighbor") && strings.HasSuffix(c.body, " shutdown"):
		l.add(c, RiskHigh, KindImpact, "routing-neighbor-shutdown", "administratively shuts a routing neighbour")
	case inRouter && !c.neg && strings.Contains(c.body, "router-id"):
		l.add(c, RiskMedium, KindImpact, "router-id-changed", "changing the router-id resets adjacencies")
	case inRouter && c.neg && reRoutingRemoval.MatchString(c.body):
		l.add(c, RiskMedium, KindImpact, "routing-config-removed", "removes routing configuration: routes or adjacencies may drop")
	case c.neg && c.body == "ip routing":
		l.add(c, RiskHigh, KindImpact, "routing-disabled", "disables IP routing on the device")
	case !c.neg && strings.HasPrefix(c.body, "spanning-tree mode"):
		l.add(c, RiskMedium, KindImpact, "stp-mode-changed", "changing the spanning-tree mode reconverges the L2 topology")
	case c.neg && strings.HasPrefix(c.body, "vlan "):
		l.add(c, RiskMedium, KindImpact, "vlan-removed", "removes a VLAN and every port membership in it")
	}
}

// subsystemTable maps command text (including its enclosing block) to the
// subsystem it touches. Order is the display order.
var subsystemTable = []struct {
	name string
	re   *regexp.Regexp
}{
	{"BGP", regexp.MustCompile(`\bbgp\b`)},
	{"OSPF", regexp.MustCompile(`\bospf(?:v3|3)?\b`)},
	{"IS-IS", regexp.MustCompile(`\bis-?is\b`)},
	{"EIGRP", regexp.MustCompile(`\beigrp\b`)},
	{"Routing", regexp.MustCompile(`\broute(?:-static|-map|-policy)?\b|\bstatic-route\b|\bdefault-gateway\b|\bprefix-list\b|\brouting-options\b|\bvrf\b`)},
	{"Interface", regexp.MustCompile(`\binterfaces?\b|\bshutdown\b|\baddress\b`)},
	{"VLAN/L2", regexp.MustCompile(`\bvlans?\b|spanning-tree|\bstp\b|switchport|port-channel|\blacp\b|etherchannel`)},
	{"ACL/Firewall", regexp.MustCompile(`access-list|access-class|access-group|\bfirewall\b|\bacl\b|security-zone|\bfilter\b`)},
	{"AAA", regexp.MustCompile(`\baaa\b|\busername\b|\bauthentication|\bradius\b|\btacacs|local-user|login user|\bsystem admin\b`)},
	{"SSH/Mgmt", regexp.MustCompile(`\bssh\b|\bstelnet\b|\bvty\b|\btransport input\b|^management\b|\bline con`)},
	{"VPN", regexp.MustCompile(`\bipsec\b|\bisakmp\b|\bike\b|crypto map|\bvpn\b|\btunnel\b`)},
	{"NAT", regexp.MustCompile(`\bnat\b`)},
	{"System", regexp.MustCompile(`\bntp\b|\bsnmp\b|\blogging\b|\bsyslog\b|\bhostname\b|host-name|\bbanner\b|\bclock\b`)},
}

// subsystemsOf lists the subsystems the commands touch, in display order.
func subsystemsOf(cmds []cmdInfo) []string {
	hit := map[string]bool{}
	allRead, any := true, false
	for _, c := range cmds {
		any = true
		if c.readOnly {
			continue
		}
		allRead = false
		text := c.block + " | " + c.full
		matched := false
		for _, s := range subsystemTable {
			if s.re.MatchString(text) {
				hit[s.name] = true
				matched = true
			}
		}
		if !matched {
			hit["Other"] = true
		}
	}
	if any && allRead {
		return []string{"Read-only"}
	}
	var out []string
	for _, s := range subsystemTable {
		if hit[s.name] {
			out = append(out, s.name)
		}
	}
	if hit["Other"] && len(out) == 0 {
		out = append(out, "Other")
	}
	return out
}

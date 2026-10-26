// ==============================================================================
// File name:     simulate.go
// Description:   Predicts the configuration a command list would produce on
//
//	platforms with no candidate datastore, and diffs it.
//
// License:       MIT
// ==============================================================================
package task

import (
	"strings"

	"netops/internal/vendor"
)

// The simulator parses a running configuration into a tree (by indentation),
// replays the commands against the tree and diffs the two trees, so a change
// to "switchport access vlan" is shown under the interface it belongs to.
//
// It is a PREDICTION, not the device's answer. It knows which commands open a
// sub-mode, that "no X"/"undo X" removes X, and which well-known commands hold
// a single value (a new "description" replaces the old one). It cannot know a
// platform's defaults (a "no ip http server" that the device would print as a
// line is not added) or semantic side effects. Treat it as a review aid.

type cfgFamily int

const (
	famIOS    cfgFamily = iota // IOS-style: Cisco, Ruijie, Aruba CX, ASA
	famHuawei                  // VRP: "undo", "quit", "#" separators
	famForti                   // FortiOS: config/edit/set/next/end
)

// simulationFamily reports how (and whether) configs of a platform can be simulated.
func simulationFamily(vendorName string) (cfgFamily, bool) {
	switch vendorName {
	case vendor.Cisco, vendor.CiscoSB, vendor.CiscoASA, vendor.Ruijie, vendor.Aruba:
		return famIOS, true
	case vendor.Huawei:
		return famHuawei, true
	case vendor.Fortinet:
		return famForti, true
	}
	return 0, false
}

// SimulationCapability admits platforms the simulator understands.
func SimulationCapability(p *vendor.Profile) (bool, string) {
	if _, ok := simulationFamily(p.Name); !ok {
		return false, "it has neither a native candidate diff nor a configuration format the local simulator understands"
	}
	return true, ""
}

type cfgNode struct {
	line     string
	children []*cfgNode
}

// parseConfig builds the tree from a configuration dump.
func parseConfig(text string, fam cfgFamily) *cfgNode {
	root := &cfgNode{}
	type frame struct {
		indent int
		node   *cfgNode
	}
	stack := []frame{{indent: -1, node: root}}
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		switch {
		case trimmed == "#" && fam == famHuawei, trimmed == "!" && fam == famIOS:
			stack = stack[:1]
			continue
		case fam == famIOS && strings.HasPrefix(trimmed, "!"):
			continue // comment
		case fam == famIOS && trimmed == "end", fam == famHuawei && trimmed == "return":
			continue
		case fam == famForti && (trimmed == "next" || trimmed == "end"):
			continue
		}
		for len(stack) > 1 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		n := &cfgNode{line: trimmed}
		parent := stack[len(stack)-1].node
		parent.children = append(parent.children, n)
		stack = append(stack, frame{indent, n})
	}
	return root
}

// ---- applying commands -----------------------------------------------------

var noOpCommands = map[string]bool{
	"configure terminal": true, "conf t": true, "configure": true, "system-view": true,
	"commit": true, "write": true, "write memory": true, "save": true, "wr": true,
	"copy running-config startup-config": true, "do write memory": true,
}

// blockHeaders are the commands that open a sub-mode.
var blockHeaders = map[cfgFamily][]string{
	famIOS: {"interface ", "router ", "line ", "ip access-list ", "ipv6 access-list ", "route-map ", "class-map ",
		"policy-map ", "vrf definition ", "ip dhcp pool ", "aaa group server ", "key chain ", "address-family ",
		"control-plane", "management ", "ip sla ", "event manager applet ", "spanning-tree mst configuration", "vlan ", "vrf context "},
	famHuawei: {"interface ", "vlan ", "aaa", "ospf ", "bgp ", "isis ", "acl ", "user-interface ", "route-policy ",
		"traffic classifier ", "traffic behavior ", "traffic policy ", "ip vpn-instance ", "stp region-configuration"},
}

func opensBlock(cmd string, fam cfgFamily) bool {
	for _, p := range blockHeaders[fam] {
		h := strings.TrimSpace(p)
		if cmd != h && !strings.HasPrefix(cmd, h+" ") {
			continue
		}
		if h == "vlan" { // "vlan 10" opens the VLAN; "vlan dot1q tag native" does not
			f := strings.Fields(cmd)
			return len(f) == 2 && startsWithDigit(f[1])
		}
		return true
	}
	return false
}

func startsWithDigit(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

// singleValued commands: a new value replaces the old one in the same block.
// keyed entries also take the next n tokens as part of the identity.
var singleValued = []struct {
	prefix string
	keyed  int
}{
	{"switchport trunk native vlan", 0}, {"switchport access vlan", 0}, {"switchport mode", 0},
	{"snmp-server community", 1}, {"snmp-server location", 0}, {"snmp-server contact", 0},
	{"ip default-gateway", 0}, {"ip domain-name", 0}, {"ip domain name", 0},
	{"ip access-group", 1}, {"ip address", 0}, {"ip ospf cost", 0},
	{"enable secret", 0}, {"enable password", 0}, {"logging buffered", 0}, {"logging trap", 0},
	{"spanning-tree mode", 0}, {"clock timezone", 0}, {"exec-timeout", 0}, {"ssh timeout", 0},
	{"transport input", 0}, {"transport output", 0}, {"idle-timeout", 0}, {"protocol inbound", 0},
	{"authentication-mode", 0}, {"port default vlan", 0}, {"port link-type", 0},
	{"local-user", 2}, {"username", 1}, {"hostname", 0}, {"sysname", 0}, {"description", 0},
	{"duplex", 0}, {"speed", 0}, {"mtu", 0}, {"name", 0}, {"password", 0},
}

func replaceKey(cmd string) (string, bool) {
	best, bestLen := "", -1
	for _, sv := range singleValued {
		if cmd != sv.prefix && !strings.HasPrefix(cmd, sv.prefix+" ") {
			continue
		}
		if sv.prefix == "ip address" && strings.HasSuffix(cmd, " secondary") {
			continue // secondary addresses accumulate
		}
		if len(sv.prefix) <= bestLen {
			continue
		}
		key := sv.prefix
		if sv.keyed > 0 {
			f := strings.Fields(cmd)
			n := len(strings.Fields(sv.prefix)) + sv.keyed
			if n > len(f) {
				n = len(f)
			}
			key = strings.Join(f[:n], " ")
		}
		best, bestLen = key, len(sv.prefix)
	}
	return best, bestLen >= 0
}

func (n *cfgNode) find(line string) int {
	for i, c := range n.children {
		if c.line == line {
			return i
		}
	}
	return -1
}

func (n *cfgNode) remove(i int) { n.children = append(n.children[:i], n.children[i+1:]...) }

// removeMatching deletes the child equal to target, else every child that
// starts with target as whole words ("no ntp server" clears all NTP servers).
func (n *cfgNode) removeMatching(target string) {
	if i := n.find(target); i >= 0 {
		n.remove(i)
		return
	}
	kept := n.children[:0]
	for _, c := range n.children {
		if !strings.HasPrefix(c.line, target+" ") {
			kept = append(kept, c)
		}
	}
	n.children = kept
}

func simulate(root *cfgNode, commands []string, fam cfgFamily) {
	if fam == famForti {
		simulateForti(root, commands)
		return
	}
	negation := "no "
	if fam == famHuawei {
		negation = "undo "
	}
	path := []*cfgNode{root}
	for _, raw := range commands {
		cmd := strings.Join(strings.Fields(raw), " ")
		cur := path[len(path)-1]
		switch {
		case cmd == "" || strings.HasPrefix(cmd, "!") || strings.HasPrefix(cmd, "#") || noOpCommands[cmd]:
		case cmd == "end" || cmd == "return":
			path = path[:1]
		case cmd == "exit" || cmd == "quit":
			if len(path) > 1 {
				path = path[:len(path)-1]
			}
		case strings.HasPrefix(cmd, negation):
			cur.removeMatching(strings.TrimPrefix(cmd, negation))
		default:
			if i := cur.find(cmd); i >= 0 {
				if opensBlock(cmd, fam) {
					path = append(path, cur.children[i])
				}
				continue
			}
			if key, ok := replaceKey(cmd); ok {
				for i := 0; i < len(cur.children); i++ {
					if k, ok2 := replaceKey(cur.children[i].line); ok2 && k == key {
						cur.remove(i)
						break
					}
				}
			}
			n := &cfgNode{line: cmd}
			cur.children = append(cur.children, n)
			if opensBlock(cmd, fam) {
				path = append(path, n)
			}
		}
	}
}

func stripQuotes(s string) string { return strings.Trim(s, `"`) }

// simulateForti replays FortiOS config / edit / set / unset / delete.
func simulateForti(root *cfgNode, commands []string) {
	path := []*cfgNode{root}
	enter := func(cur *cfgNode, line string) {
		for _, c := range cur.children {
			if stripQuotes(c.line) == stripQuotes(line) || normForti(c.line) == normForti(line) {
				path = append(path, c)
				return
			}
		}
		n := &cfgNode{line: line}
		cur.children = append(cur.children, n)
		path = append(path, n)
	}
	for _, raw := range commands {
		cmd := strings.Join(strings.Fields(raw), " ")
		cur := path[len(path)-1]
		f := strings.Fields(cmd)
		if len(f) == 0 {
			continue
		}
		arg := strings.TrimSpace(strings.TrimPrefix(cmd, f[0]))
		switch f[0] {
		case "config":
			enter(cur, cmd)
		case "edit":
			enter(cur, `edit "`+stripQuotes(arg)+`"`)
		case "set":
			if len(f) < 2 {
				continue
			}
			for i := 0; i < len(cur.children); i++ {
				if strings.HasPrefix(cur.children[i].line, "set "+f[1]+" ") || cur.children[i].line == "set "+f[1] {
					cur.remove(i)
					break
				}
			}
			cur.children = append(cur.children, &cfgNode{line: cmd})
		case "unset":
			cur.removeMatching("set " + arg)
		case "delete":
			for i := 0; i < len(cur.children); i++ {
				if normForti(cur.children[i].line) == normForti(`edit "`+stripQuotes(arg)+`"`) {
					cur.remove(i)
					break
				}
			}
		case "next", "end":
			if len(path) > 1 {
				path = path[:len(path)-1]
			}
		case "abort":
			path = path[:1]
		}
	}
}

func normForti(s string) string { return strings.ReplaceAll(s, `"`, "") }

// ---- tree diff -------------------------------------------------------------

// diffTrees lists what differs between two trees as "+"/"-" lines, with each
// changed line preceded by the (unchanged) block headers that locate it.
func diffTrees(before, after *cfgNode) (lines []string, added, removed int) {
	var walk func(a, b []*cfgNode, depth int) []string
	indent := func(d int) string { return strings.Repeat("  ", d) }

	var emitAll func(nodes []*cfgNode, sign string, depth int, out *[]string, count *int)
	emitAll = func(nodes []*cfgNode, sign string, depth int, out *[]string, count *int) {
		for _, n := range nodes {
			*out = append(*out, sign+indent(depth)+n.line)
			*count++
			emitAll(n.children, sign, depth+1, out, count)
		}
	}

	walk = func(a, b []*cfgNode, depth int) []string {
		var out []string
		used := make([]bool, len(b))
		pair := make([]int, len(a))
		for i, an := range a {
			pair[i] = -1
			for j, bn := range b {
				if !used[j] && an.line == bn.line {
					used[j], pair[i] = true, j
					break
				}
			}
		}
		for i, an := range a {
			if pair[i] < 0 {
				emitAll([]*cfgNode{an}, "-", depth, &out, &removed)
			}
		}
		for j, bn := range b {
			if !used[j] {
				emitAll([]*cfgNode{bn}, "+", depth, &out, &added)
				continue
			}
			for i, an := range a {
				if pair[i] == j {
					if sub := walk(an.children, bn.children, depth+1); len(sub) > 0 {
						out = append(out, " "+indent(depth)+bn.line)
						out = append(out, sub...)
					}
				}
			}
		}
		return out
	}
	lines = walk(before.children, after.children, 0)
	return lines, added, removed
}

// SimulateDiff predicts the diff the commands would cause on a configuration
// of the given platform. ok is false when the platform cannot be simulated.
func SimulateDiff(vendorName, running string, commands []string) (lines []string, added, removed int, ok bool) {
	fam, ok := simulationFamily(vendorName)
	if !ok {
		return nil, 0, 0, false
	}
	before := parseConfig(running, fam)
	after := parseConfig(running, fam)
	simulate(after, commands, fam)
	lines, added, removed = diffTrees(before, after)
	return lines, added, removed, true
}

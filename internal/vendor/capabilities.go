// ==============================================================================
// File name:     capabilities.go
// Description:   Optional per-vendor capabilities: user provisioning, VLAN
//
//	management, hardware facts and MAC/ARP location.
//
// License:       MIT
// ==============================================================================
package vendor

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The capability interfaces below are discovered through Profile accessors
// (Users, VLANs, Facts, Locator). A vendor that cannot do something safely over
// a CLI simply has no implementation, and the caller reports the device as
// unsupported instead of guessing at commands.

// UserProvisioner handles the local account lifecycle.
//
// The Steps returned are StepBody lines (the configuration commands only); the
// profile's BuildPlan wraps them with the vendor's enter/exit/persist steps.
// An empty result means the platform cannot honour the request (for example a
// privilege level it has no equivalent for).
type UserProvisioner interface {
	// CheckUserCommand is a read-only command whose output shows whether the account exists.
	CheckUserCommand(username string) string
	// UserExists parses the output of CheckUserCommand.
	UserExists(output, username string) bool
	CreateUserSteps(username, password string, privilege int) []Step
	DeleteUserSteps(username string) []Step
	// ChangePasswordSteps rotates a local user's password, or the enable secret
	// when isEnableSecret is set. Empty when the platform has no such secret.
	ChangePasswordSteps(username, newPassword string, isEnableSecret bool) []Step
	// RestoreUserSteps rebuilds an account from the output of CheckUserCommand
	// taken before a change (the device's own stored credential form, never a
	// plaintext password), so a failed rotation can be undone. Empty when the
	// platform relies on a candidate-config rollback instead.
	RestoreUserSteps(username, snapshot string) []Step
}

// VLANManager handles L2 VLAN provisioning.
type VLANManager interface {
	CheckVLANCommand(vlanID int) string
	VLANExists(output string, vlanID int) bool
	// VLANName extracts the VLAN's name from the output of CheckVLANCommand ("" if unknown).
	VLANName(output string, vlanID int) string
	CreateVLANSteps(vlanID int, name string) []Step
	// DeleteVLANSteps takes the device-reported name because some platforms
	// (Junos) delete a VLAN by name, not by ID. Most ignore it.
	DeleteVLANSteps(vlanID int, name string) []Step
}

// DeviceFacts is the normalised hardware/software identity of one device.
type DeviceFacts struct {
	Hostname string `json:"hostname"`
	Model    string `json:"model"`
	Serial   string `json:"serial"`
	Version  string `json:"version"`
	Uptime   string `json:"uptime"`
}

// FactsCollector extracts asset and runtime metrics.
type FactsCollector interface {
	// FactsCommand is one or more read-only commands, newline separated. The
	// combined output is passed to ParseFacts as one "=== <command> ===" block
	// per command (see CombineOutputs).
	FactsCommand() string
	ParseFacts(output string) DeviceFacts
}

// LocatorRecord is one MAC/ARP table entry.
type LocatorRecord struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Interface string `json:"interface"`
	VLAN      int    `json:"vlan"`
}

// NetworkLocator parses ARP and MAC tables. An empty command means the
// platform has no such table worth querying (for example a firewall has no
// MAC table).
type NetworkLocator interface {
	FindMACCommand(mac string) string
	ParseMAC(output string) []LocatorRecord
	FindIPCommand(ip string) string
	ParseIP(output string) []LocatorRecord
}

// TrunkDetector is implemented by locators that can tell which ports are
// uplinks, so the access port of an end host can be told from a trunk.
type TrunkDetector interface {
	TrunkPortsCommand() string
	ParseTrunkPorts(output string) []string
}

// CanRestore reports whether u can rebuild an account from a snapshot
// (UserProvisioner.RestoreUserSteps). Platforms that stage changes in a
// candidate configuration revert through commit-confirm instead.
func CanRestore(u UserProvisioner) bool {
	r, ok := u.(interface{ CanRestore() bool })
	return ok && r.CanRestore()
}

// ErrUnsupported marks an operation the platform does not offer.
var ErrUnsupported = errors.New("not supported on this platform")

// Users returns the platform's user provisioner, if it has one.
func (p *Profile) Users() (UserProvisioner, bool) { return p.users, p.users != nil }

// VLANs returns the platform's VLAN manager, if it has one.
func (p *Profile) VLANs() (VLANManager, bool) { return p.vlans, p.vlans != nil }

// Facts returns the platform's facts collector, if it has one.
func (p *Profile) Facts() (FactsCollector, bool) { return p.facts, p.facts != nil }

// Locator returns the platform's MAC/ARP locator, if it has one.
func (p *Profile) Locator() (NetworkLocator, bool) { return p.locator, p.locator != nil }

// Trunks returns the locator's trunk detector, if it implements one.
func (p *Profile) Trunks() (TrunkDetector, bool) {
	t, ok := p.locator.(TrunkDetector)
	return t, ok
}

// Lines returns the command text of steps, in order.
func Lines(steps []Step) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Line)
	}
	return out
}

// body turns configuration lines into StepBody steps.
func body(lines ...string) []Step {
	out := make([]Step, 0, len(lines))
	for _, l := range lines {
		out = append(out, Step{Kind: StepBody, Line: l})
	}
	return out
}

// SplitCommands splits a newline separated FactsCommand into its commands.
func SplitCommands(cmds string) []string {
	var out []string
	for _, c := range strings.Split(cmds, "\n") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// CombineOutputs joins per-command output into the block form ParseFacts expects.
func CombineOutputs(cmds, outputs []string) string {
	var b strings.Builder
	for i, c := range cmds {
		out := ""
		if i < len(outputs) {
			out = outputs[i]
		}
		fmt.Fprintf(&b, "=== %s ===\n%s\n", c, strings.TrimRight(out, "\r\n"))
	}
	return b.String()
}

// ---- validation ------------------------------------------------------------

var (
	reUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
	reVLANName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)
)

// ValidateUsername applies the account name limits shared by every platform:
// letters, digits and . _ -, at most 32 characters. Anything else is rejected rather than quoted, because
// quoting rules differ per vendor and a wrong guess changes which account is
// edited.
func ValidateUsername(u string) error {
	if !reUsername.MatchString(u) {
		return fmt.Errorf("invalid username %q: use 1-32 letters, digits, '.', '_' or '-', starting with a letter or digit", u)
	}
	return nil
}

// ValidatePassword rejects passwords that cannot be typed safely into an
// interactive CLI line: whitespace and control characters, quotes, backslash
// and '?' (which many shells treat as "show help" and which would silently
// truncate the secret that gets stored).
func ValidatePassword(pw string) error {
	if pw == "" {
		return errors.New("password must not be empty")
	}
	if len(pw) > 64 {
		return errors.New("password is longer than 64 characters")
	}
	for _, r := range pw {
		if r < 0x21 || r > 0x7e {
			return errors.New("password must be printable ASCII without spaces")
		}
		if strings.ContainsRune(`?"'\`, r) {
			return fmt.Errorf("password must not contain %q (it cannot be sent safely over an interactive CLI)", string(r))
		}
	}
	return nil
}

// ValidatePrivilege checks a Cisco style privilege level.
func ValidatePrivilege(p int) error {
	if p < 1 || p > 15 {
		return fmt.Errorf("privilege %d out of range 1-15", p)
	}
	return nil
}

// ValidateVLANID enforces 1-4094.
func ValidateVLANID(id int) error {
	if id < 1 || id > 4094 {
		return fmt.Errorf("VLAN ID %d out of range 1-4094", id)
	}
	return nil
}

// ValidateVLANName checks an optional VLAN name.
func ValidateVLANName(name string) error {
	if name != "" && !reVLANName.MatchString(name) {
		return fmt.Errorf("invalid VLAN name %q: use 1-32 letters, digits, '.', '_' or '-'", name)
	}
	return nil
}

// ---- MAC / IP helpers ------------------------------------------------------

// MACStyle is the notation a platform's CLI expects.
type MACStyle int

// MAC notations.
const (
	MACDotted MACStyle = iota // aabb.ccdd.eeff
	MACColon                  // aa:bb:cc:dd:ee:ff
	MACHyphen                 // aa-bb-cc-dd-ee-ff
	MACHuawei                 // aabb-ccdd-eeff
)

// NormalizeMAC accepts aabb.ccdd.eeff, aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff,
// aabb-ccdd-eeff and bare hex, and returns 12 lower-case hex digits.
func NormalizeMAC(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	flat := strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if len(flat) != 12 {
		return "", fmt.Errorf("invalid MAC address %q", s)
	}
	for _, c := range flat {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("invalid MAC address %q", s)
		}
	}
	return flat, nil
}

// FormatMAC renders a normalised MAC in the given notation.
func FormatMAC(norm string, style MACStyle) string {
	if len(norm) != 12 {
		return norm
	}
	switch style {
	case MACColon:
		return strings.Join([]string{norm[0:2], norm[2:4], norm[4:6], norm[6:8], norm[8:10], norm[10:12]}, ":")
	case MACHyphen:
		return strings.Join([]string{norm[0:2], norm[2:4], norm[4:6], norm[6:8], norm[8:10], norm[10:12]}, "-")
	case MACHuawei:
		return norm[0:4] + "-" + norm[4:8] + "-" + norm[8:12]
	default:
		return norm[0:4] + "." + norm[4:8] + "." + norm[8:12]
	}
}

// ---- wiring ----------------------------------------------------------------

// attachCapabilities installs the capability drivers for one platform. A
// platform missing from a table below has deliberately no driver for it.
func attachCapabilities(p *Profile) {
	p.users = userDrivers[p.Name]
	p.vlans = vlanDrivers[p.Name]
	p.facts = factsDrivers[p.Name]
	p.locator = locatorDrivers[p.Name]
}

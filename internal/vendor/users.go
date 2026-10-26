// ==============================================================================
// File name:     users.go
// Description:   UserProvisioner drivers.
// License:       MIT
// ==============================================================================
package vendor

import (
	"fmt"
	"regexp"
	"strings"
)

// userDriver implements UserProvisioner from a handful of per-platform
// functions; the zero value of an optional function means "not offered".
type userDriver struct {
	check   func(u string) string
	exists  func(output, u string) bool
	create  func(u, pw string, priv int) []string
	remove  func(u string) []string
	passwd  func(u, pw string, enable bool) []string
	restore func(u, snapshot string) []string
}

func (d userDriver) CheckUserCommand(u string) string { return d.check(u) }

func (d userDriver) UserExists(output, u string) bool { return d.exists(output, u) }

func (d userDriver) CreateUserSteps(u, pw string, priv int) []Step {
	if d.create == nil {
		return nil
	}
	return body(d.create(u, pw, priv)...)
}

func (d userDriver) DeleteUserSteps(u string) []Step {
	if d.remove == nil {
		return nil
	}
	return body(d.remove(u)...)
}

func (d userDriver) ChangePasswordSteps(u, pw string, enable bool) []Step {
	if d.passwd == nil {
		return nil
	}
	return body(d.passwd(u, pw, enable)...)
}

// CanRestore reports whether the platform can rebuild an account from a snapshot.
func (d userDriver) CanRestore() bool { return d.restore != nil }

func (d userDriver) RestoreUserSteps(u, snapshot string) []Step {
	if d.restore == nil {
		return nil
	}
	return body(d.restore(u, snapshot)...)
}

// accountLine matches a configuration line that starts with prefix followed by
// the exact account name (so "bob" never matches "bobby"). The name is quoted
// with QuoteMeta and may optionally be wrapped in single or double quotes.
func accountLine(prefix, user string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\s*` + prefix + `\s+["']?` + regexp.QuoteMeta(user) + `["']?(?:\s|$)`)
}

// matchingLines returns the lines of output that re matches, in order.
func matchingLines(output string, re *regexp.Regexp) []string {
	var out []string
	for _, l := range strings.Split(output, "\n") {
		if l = strings.TrimRight(l, "\r"); re.MatchString(l) {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

// existsBy builds an exists function from a line prefix.
func existsBy(prefix string) func(output, u string) bool {
	return func(output, u string) bool { return accountLine(prefix, u).MatchString(output) }
}

// restoreLines replays the account's own configuration lines (which carry the
// stored hash, not a plaintext password).
func restoreLines(prefix string) func(u, snapshot string) []string {
	return func(u, snapshot string) []string {
		return matchingLines(snapshot, accountLine(prefix, u))
	}
}

// userDrivers maps a canonical vendor name to its driver. Check Point, Palo
// Alto, pfSense and Sophos are intentionally absent: their account commands
// are interactive or need extra mandatory parameters (UID, roles, hashes in a
// vendor specific scheme, or a menu driven shell), so automating them blindly
// could create the wrong account.
var userDrivers = map[string]UserProvisioner{
	Cisco: userDriver{
		check:  func(u string) string { return "show running-config | include ^username " + u + " " },
		exists: existsBy("username"),
		create: func(u, pw string, priv int) []string {
			return []string{fmt.Sprintf("username %s privilege %d secret 0 %s", u, priv, pw)}
		},
		remove: func(u string) []string { return []string{"no username " + u} },
		passwd: func(u, pw string, enable bool) []string {
			if enable {
				return []string{"enable secret 0 " + pw}
			}
			return []string{fmt.Sprintf("username %s secret 0 %s", u, pw)}
		},
		restore: restoreLines("username"),
	},
	CiscoSB: userDriver{
		// The SF/SG/CBS CLI has no reliable "| include", so read the whole (small) config.
		check:  func(string) string { return "show running-config" },
		exists: existsBy("username"),
		create: func(u, pw string, priv int) []string {
			return []string{fmt.Sprintf("username %s password %s privilege %d", u, pw, priv)}
		},
		remove: func(u string) []string { return []string{"no username " + u} },
		passwd: func(u, pw string, enable bool) []string {
			if enable {
				return []string{"enable password " + pw}
			}
			return []string{fmt.Sprintf("username %s password %s", u, pw)}
		},
		restore: restoreLines("username"),
	},
	CiscoASA: userDriver{
		check:  func(u string) string { return "show running-config | include ^username " + u + " " },
		exists: existsBy("username"),
		create: func(u, pw string, priv int) []string {
			return []string{fmt.Sprintf("username %s password %s privilege %d", u, pw, priv)}
		},
		remove: func(u string) []string { return []string{"no username " + u} },
		passwd: func(u, pw string, enable bool) []string {
			if enable {
				return []string{"enable password " + pw}
			}
			return []string{fmt.Sprintf("username %s password %s", u, pw)}
		},
		restore: restoreLines("username"),
	},
	Arista: userDriver{
		check:  func(u string) string { return "show running-config | include ^username " + u + " " },
		exists: existsBy("username"),
		create: func(u, pw string, priv int) []string {
			return []string{fmt.Sprintf("username %s privilege %d secret 0 %s", u, priv, pw)}
		},
		remove: func(u string) []string { return []string{"no username " + u} },
		passwd: func(u, pw string, enable bool) []string {
			if enable {
				return []string{"enable secret 0 " + pw}
			}
			return []string{fmt.Sprintf("username %s secret 0 %s", u, pw)}
		},
		// EOS applies a config session atomically with a commit timer: no restore needed.
	},
	Ruijie: userDriver{
		check:  func(u string) string { return "show running-config | include ^username " + u + " " },
		exists: existsBy("username"),
		create: func(u, pw string, priv int) []string {
			return []string{fmt.Sprintf("username %s privilege %d password 0 %s", u, priv, pw)}
		},
		remove: func(u string) []string { return []string{"no username " + u} },
		passwd: func(u, pw string, enable bool) []string {
			if enable {
				return []string{"enable secret 0 " + pw}
			}
			return []string{fmt.Sprintf("username %s password 0 %s", u, pw)}
		},
		restore: restoreLines("username"),
	},
	// Aruba: AOS-CX syntax. AOS-S (ProCurve) uses "password manager user-name"
	// and is not covered. AOS-CX has no enable secret, and only the
	// "administrators" group is mapped (privilege 15).
	Aruba: userDriver{
		check:  func(u string) string { return "show running-config | include ^user " + u + " " },
		exists: existsBy("user"),
		create: func(u, pw string, priv int) []string {
			if priv != 15 {
				return nil
			}
			return []string{fmt.Sprintf("user %s group administrators password plaintext %s", u, pw)}
		},
		remove: func(u string) []string { return []string{"no user " + u} },
		passwd: func(u, pw string, enable bool) []string {
			if enable {
				return nil
			}
			return []string{fmt.Sprintf("user %s password plaintext %s", u, pw)}
		},
		restore: restoreLines("user"),
	},
	Huawei: userDriver{
		check:  func(u string) string { return "display current-configuration | include local-user " + u },
		exists: existsBy("local-user"),
		create: func(u, pw string, priv int) []string {
			return []string{
				"aaa",
				fmt.Sprintf("local-user %s password irreversible-cipher %s", u, pw),
				fmt.Sprintf("local-user %s service-type ssh", u),
				fmt.Sprintf("local-user %s privilege level %d", u, priv),
				"quit",
			}
		},
		remove: func(u string) []string { return []string{"aaa", "undo local-user " + u, "quit"} },
		passwd: func(u, pw string, enable bool) []string {
			if enable {
				return nil
			}
			return []string{"aaa", fmt.Sprintf("local-user %s password irreversible-cipher %s", u, pw), "quit"}
		},
		restore: func(u, snapshot string) []string {
			lines := matchingLines(snapshot, accountLine("local-user", u))
			if len(lines) == 0 {
				return nil
			}
			return append(append([]string{"aaa"}, lines...), "quit")
		},
	},
	Junos: userDriver{
		check: func(u string) string {
			return "show configuration system login | display set | match \"user " + u + " \""
		},
		exists: func(output, u string) bool {
			return regexp.MustCompile(`(?m)^\s*set system login user ["']?` + regexp.QuoteMeta(u) + `["']?\s`).MatchString(output)
		},
		create: func(u, pw string, priv int) []string {
			hash, err := HashPassword(pw)
			if err != nil {
				return nil
			}
			return []string{
				fmt.Sprintf("set system login user %s class %s", u, junosClass(priv)),
				fmt.Sprintf("set system login user %s authentication encrypted-password %q", u, hash),
			}
		},
		remove: func(u string) []string { return []string{"delete system login user " + u} },
		passwd: func(u, pw string, enable bool) []string {
			hash, err := HashPassword(pw)
			if enable || err != nil {
				return nil
			}
			return []string{fmt.Sprintf("set system login user %s authentication encrypted-password %q", u, hash)}
		},
		// Junos stages the change in a candidate: commit-confirm reverts it.
	},
	VyOS: userDriver{
		check: func(u string) string {
			return "show configuration commands | match \"login user " + u + " \""
		},
		exists: func(output, u string) bool {
			return regexp.MustCompile(`(?m)^\s*set system login user ["']?` + regexp.QuoteMeta(u) + `["']?\s`).MatchString(output)
		},
		// VyOS (1.3/1.4) has no per-user privilege; every local user may configure the box.
		create: func(u, pw string, _ int) []string {
			return []string{fmt.Sprintf("set system login user %s authentication plaintext-password %s", u, pw)}
		},
		remove: func(u string) []string { return []string{"delete system login user " + u} },
		passwd: func(u, pw string, enable bool) []string {
			if enable {
				return nil
			}
			return []string{fmt.Sprintf("set system login user %s authentication plaintext-password %s", u, pw)}
		},
	},
	// Fortinet: super_admin only (privilege 15); other profiles are
	// site-defined. A multi-VDOM unit needs "config global" first, which is
	// left to the operator (run the command from a global-scope admin).
	Fortinet: userDriver{
		check: func(u string) string { return "show system admin " + u },
		exists: func(output, u string) bool {
			return regexp.MustCompile(`(?m)^\s*edit\s+"?` + regexp.QuoteMeta(u) + `"?\s*$`).MatchString(output)
		},
		create: func(u, pw string, priv int) []string {
			if priv != 15 {
				return nil
			}
			return []string{"config system admin", "edit " + u, "set password " + pw, "set accprofile super_admin", "next", "end"}
		},
		remove: func(u string) []string { return []string{"config system admin", "delete " + u, "end"} },
		passwd: func(u, pw string, enable bool) []string {
			if enable {
				return nil
			}
			return []string{"config system admin", "edit " + u, "set password " + pw, "next", "end"}
		},
		restore: func(u, snapshot string) []string {
			// "show system admin <u>" prints the complete config block.
			var lines []string
			for _, l := range strings.Split(snapshot, "\n") {
				if l = strings.TrimSpace(strings.TrimRight(l, "\r")); l != "" {
					lines = append(lines, l)
				}
			}
			if len(lines) == 0 || !strings.HasPrefix(lines[0], "config system admin") {
				return nil
			}
			return lines
		},
	},
}

// junosClass maps a Cisco style privilege level onto the built-in Junos login
// classes: 15 super-user, 8-14 operator, 1-7 read-only.
func junosClass(priv int) string {
	switch {
	case priv >= 15:
		return "super-user"
	case priv >= 8:
		return "operator"
	default:
		return "read-only"
	}
}

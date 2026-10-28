// ==============================================================================
// File name:     account_cmd.go
// Description:   "netops config user add|del" and "netops config passwd".
// License:       MIT
// ==============================================================================
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"netops/internal/credentials"
	"netops/internal/task"
	"netops/internal/vendor"
)

const userUsageText = `netops config user: create or remove a local account on many devices, idempotently.

Usage:
  netops config user add -u <name> [--privilege 15] [--update-password] [flags]
  netops config user del -u <name> [flags]

"add" skips devices where the account already exists (unless --update-password
changes its password); "del" skips devices where it does not exist. Each device
is read first and only changed where it differs; the change goes through the
normal apply path (-backup, -dry-run, -canary, -rollback-on-fail, ...).

The new password comes from a hidden prompt, or NETOPS_NEW_PASSWORD.

"del" refuses, before connecting to anything, to remove the account this run
logs in with (NETOPS_USERNAME or the credential group's user). There is no
override: log in as a different administrator.

Platforms with no safe non-interactive account CLI (Check Point, Palo Alto,
pfSense, Sophos) are skipped and reported, never guessed at.
`

const rotateUsageText = `netops config passwd: rotate a local account's password, or the enable secret.

Usage:
  netops config passwd -u <name> [--auto-generate --password-file <f>] [flags]
  netops config passwd --enable [--auto-generate --password-file <f>] [flags]

Every device is verified before the change is kept: the new credentials are
tested with a fresh SSH login while the old state can still be restored.
  - Platforms with a native commit-confirm / revert timer (Junos, VyOS, Arista,
    IOS-XE) use it (--commit-confirm minutes, default 5): it reverts by itself
    if the test fails.
  - Platforms without one (classic IOS, Huawei, ASA, FortiOS, ...) are tested
    after the change but before it is saved; on failure the account's previous
    stored (hashed) credential is put back, unsaved.
A device where the previous credential cannot be captured is refused rather
than rotated without a way back.

The new password comes from a hidden prompt, or NETOPS_NEW_PASSWORD.
--auto-generate creates a random 20 character password and writes it to
--password-file (mode 0600, must not exist yet); it is never printed.

Rotating the account this run logs in with is allowed; remember to update
NETOPS_PASSWORD afterwards.

Flags:
`

// generatePassword returns n random characters containing at least one
// lower-case letter, upper-case letter, digit and symbol, all of them safe to
// type into a device CLI (see vendor.ValidatePassword).
func generatePassword(n int) (string, error) {
	if n < 4 {
		return "", errors.New("password length must be at least 4 to include all required character classes")
	}
	const (
		lower  = "abcdefghijkmnopqrstuvwxyz"
		upper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		digits = "23456789"
		symbol = "-_.@#%+="
	)
	pick := func(set string) (byte, error) {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return 0, err
		}
		return set[i.Int64()], nil
	}
	all := lower + upper + digits + symbol
	out := make([]byte, n)
	for i, set := range []string{lower, upper, digits, symbol} {
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	for i := 4; i < n; i++ {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	// shuffle so the guaranteed characters are not always first
	for i := n - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return string(out), nil
}

// newSecret obtains the new password from NETOPS_NEW_PASSWORD, then a
// hidden prompt asked twice. The result is validated and registered with the
// logger so it is masked everywhere it could be printed.
func (e *opsEnv) newSecret() (string, error) {
	var pw string
	switch {
	case os.Getenv("NETOPS_NEW_PASSWORD") != "":
		pw = os.Getenv("NETOPS_NEW_PASSWORD")
	case credentials.IsTerminal(e.stdin):
		first, err := credentials.ReadSecret(e.stdin, e.stderr, "New password: ")
		if err != nil {
			return "", err
		}
		second, err := credentials.ReadSecret(e.stdin, e.stderr, "Repeat new password: ")
		if err != nil {
			return "", err
		}
		if first != second {
			return "", errors.New("the two passwords differ")
		}
		pw = first
	default:
		return "", errors.New("no new password: set NETOPS_NEW_PASSWORD, or run on a terminal to be prompted")
	}
	if err := vendor.ValidatePassword(pw); err != nil {
		return "", err
	}
	e.log.AddSecret(pw)
	return pw, nil
}

// loginNames returns the account names this run would log in with, from the
// environment and .env alone (no prompting), so a guard can act before any
// credential is requested or any device is contacted.
func loginNames(envFile string, jobs []task.Job) map[string]string {
	names := usernameHints(envFile, jobs)
	if v := os.Getenv("NETOPS_USERNAME"); v != "" {
		names["*"] = v
	}
	return names
}

func runUser(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, userUsageText)
		return task.ExitFatal
	}
	if isHelpArg(args[0]) {
		fmt.Fprint(stdout, userUsageText)
		return task.ExitOK
	}
	action := args[0]
	if action != "add" && action != "del" {
		fmt.Fprintf(stderr, "netops config user: unknown action %q (use add or del)\n\n%s", action, userUsageText)
		return task.ExitFatal
	}

	var o opsFlags
	var username string
	var privilege int
	var updatePassword bool
	fs := flag.NewFlagSet("netops config user "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintf(stderr, "%s\nFlags:\n", userUsageText); fs.PrintDefaults() }
	fs.StringVar(&username, "u", "", "account name")
	if action == "add" {
		fs.IntVar(&privilege, "privilege", 15, "privilege level 1-15 (Junos: 15 super-user, 8-14 operator, 1-7 read-only)")
		fs.BoolVar(&updatePassword, "update-password", false, "change the password of an account that already exists instead of skipping it")
	}
	o.register(fs)
	if isHelpArg(action) {
		fmt.Fprint(stdout, userUsageText)
		return task.ExitOK
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return task.ExitOK
		}
		hintPasswordFlag(args[1:], stderr)
		return task.ExitFatal
	}
	o.noteSetFlags(fs)
	fatal := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "netops config user %s: "+format+"\n", append([]any{action}, a...)...)
		return task.ExitFatal
	}
	if fs.NArg() > 0 {
		return fatal("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := vendor.ValidateUsername(username); err != nil {
		return fatal("-u: %v", err)
	}
	if action == "add" {
		if err := vendor.ValidatePrivilege(privilege); err != nil {
			return fatal("--privilege: %v", err)
		}
	}

	env, code := newOpsEnv("user "+action, &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()

	if action == "del" {
		// Before anything is requested or contacted: never delete the account we log in with.
		probe := task.BuildCapabilityJobs(env.devs, "user del", task.UserDelCapability(username))
		if who := loginConflict(username, loginNames(o.envFile, probe)); who != "" {
			return env.die("refusing to delete %q: it is the account this run logs in with (%s). Log in as a different administrator to remove it. Nothing was contacted", username, who)
		}
		guard := func(jobs []task.Job) error {
			for _, j := range jobs {
				if j.Skip == "" && strings.EqualFold(j.Cred.Username, username) {
					return fmt.Errorf("refusing to delete %q: it is the login account for %s. Log in as a different administrator to remove it. Nothing was contacted", username, j.Device.Hostname)
				}
			}
			return nil
		}
		return env.changeRun(fmt.Sprintf("Delete user %q", username), probe, task.UserDel(username), nil, guard)
	}

	pw, err := env.newSecret()
	if err != nil {
		return env.die("%v", err)
	}
	spec := task.UserSpec{Username: username, Password: pw, Privilege: privilege, UpdatePassword: updatePassword}
	jobs := task.BuildCapabilityJobs(env.devs, "user add", task.UserAddCapability(spec))
	return env.changeRun(fmt.Sprintf("Create user %q (privilege %d)", username, privilege), jobs, task.UserAdd(spec), nil, nil)
}

// loginConflict returns a description of the login configuration that names
// username (case-insensitively), or "".
func loginConflict(username string, names map[string]string) string {
	for group, n := range names {
		if n != "" && strings.EqualFold(n, username) {
			if group == "*" {
				return "NETOPS_USERNAME"
			}
			return fmt.Sprintf("the login user of credential group %q", group)
		}
	}
	return ""
}

func isHelpArg(a string) bool { return a == "-h" || a == "-help" || a == "--help" || a == "help" }

func runPasswd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	var o opsFlags
	var username, passwordFile string
	var enable, autoGenerate bool
	var confirmMinutes int
	fs := flag.NewFlagSet("netops config passwd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, rotateUsageText); fs.PrintDefaults() }
	fs.StringVar(&username, "u", "", "local account whose password is rotated")
	fs.BoolVar(&enable, "enable", false, "rotate the enable secret instead of an account")
	fs.BoolVar(&autoGenerate, "auto-generate", false, "generate a random password (requires --password-file)")
	fs.StringVar(&passwordFile, "password-file", "", "file (mode 0600, must not exist) that receives the generated password")
	fs.IntVar(&confirmMinutes, "commit-confirm", task.DefaultConfirmMinutes, "commit-confirm window in `minutes` on platforms that apply changes at commit")
	o.register(fs)
	if len(args) > 0 && isHelpArg(args[0]) {
		fmt.Fprint(stdout, rotateUsageText)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return task.ExitOK
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return task.ExitOK
		}
		hintPasswordFlag(args, stderr)
		return task.ExitFatal
	}
	o.noteSetFlags(fs)
	fatal := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "netops config passwd: "+format+"\n", a...)
		return task.ExitFatal
	}
	switch {
	case fs.NArg() > 0:
		return fatal("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	case enable && username != "":
		return fatal("use either -u or --enable, not both")
	case !enable && username == "":
		return fatal("-u <name> (or --enable) is required")
	case autoGenerate && passwordFile == "":
		return fatal("--auto-generate needs --password-file: the generated password is never printed")
	case passwordFile != "" && !autoGenerate:
		return fatal("--password-file is only used with --auto-generate")
	case confirmMinutes < 1 || confirmMinutes > 60:
		return fatal("--commit-confirm must be between 1 and 60 minutes")
	}
	if !enable {
		if err := vendor.ValidateUsername(username); err != nil {
			return fatal("-u: %v", err)
		}
	}

	env, code := newOpsEnv("passwd", &o, stdin, stdout, stderr)
	if env == nil {
		return code
	}
	defer env.close()

	var pw string
	var err error
	if autoGenerate {
		if pw, err = generatePassword(20); err != nil {
			return env.die("generating a password: %v", err)
		}
		env.log.AddSecret(pw)
		if err = writeSecretFile(passwordFile, pw); err != nil {
			return env.die("%v", err)
		}
		env.log.Infof("", "generated password written to %s (mode 0600); it is not printed", passwordFile)
	} else if pw, err = env.newSecret(); err != nil {
		return env.die("%v", err)
	}

	spec := task.PasswdSpec{Username: username, NewPassword: pw, Enable: enable, ConfirmMinutes: confirmMinutes}
	what, target := fmt.Sprintf("Rotate the password of %q", username), username
	if enable {
		what, target = "Rotate the enable secret", "enable secret"
	}
	jobs := task.BuildCapabilityJobs(env.devs, "passwd", task.PasswdCapability(spec))
	code = env.changeRun(what, jobs, task.Passwd(spec), nil, nil)
	if !enable {
		env.warnIfLoginRotated(jobs, username, target)
	}
	return code
}

// warnIfLoginRotated reminds the operator to update stored credentials when
// the rotated account is the one this run logs in with.
func (e *opsEnv) warnIfLoginRotated(jobs []task.Job, username, target string) {
	for _, j := range jobs {
		if j.Skip == "" && strings.EqualFold(j.Cred.Username, username) {
			e.log.Warnf("", "the password of %s, the account this run logs in with, was rotated: update NETOPS_PASSWORD (or the credential group's password) before the next run", target)
			return
		}
	}
}

// writeSecretFile creates path exclusively with mode 0600 so an existing file
// is never overwritten and the secret is never world-readable.
func writeSecretFile(path, secret string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator supplied output path
	if err != nil {
		return fmt.Errorf("--password-file: %w", err)
	}
	if _, err := f.WriteString(secret + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("--password-file: %w", err)
	}
	return f.Close()
}

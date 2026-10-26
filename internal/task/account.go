// ==============================================================================
// File name:     account.go
// Description:   Local account workflows: user add / user del / passwd.
// License:       MIT
// ==============================================================================
package task

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"netops/internal/credentials"
	"netops/internal/vendor"
)

// CatPrecondition marks a device whose state does not allow the request (the
// account to rotate does not exist, no safe rollback is possible, ...).
const CatPrecondition Category = "PRECONDITION_FAILED"

var (
	reRejected = regexp.MustCompile(`(?i)invalid|incomplete|ambiguous|unrecognized|unknown command|syntax|wrong parameter|permission|authoriz|access denied|unavailable|not allowed`)
	reAbsent   = regexp.MustCompile(`(?i)not found|does not exist|doesn't exist|no such|not exist`)
)

// checkOutput returns an error when out reads as the device REJECTING a state
// check, as opposed to answering it. "VLAN does not exist" is an answer; a
// syntax error or "permission denied" is not, and must never be taken for
// "absent": that would make an add overwrite what it failed to see.
func checkOutput(prof *vendor.Profile, cmd, out string) error {
	line, bad := prof.FindError(out)
	if !bad || reAbsent.MatchString(line) {
		return nil
	}
	if reRejected.MatchString(line) {
		return fmt.Errorf("the device rejected the state check %q (%s); nothing was changed", logRedact(cmd), line)
	}
	return nil
}

// ---- user add / user del ---------------------------------------------------

// UserSpec describes the account to create.
type UserSpec struct {
	Username       string
	Password       string
	Privilege      int
	UpdatePassword bool // an existing account gets its password changed instead of being skipped
}

// UserAddCapability admits platforms that can create the requested account.
func UserAddCapability(spec UserSpec) Capability {
	return func(p *vendor.Profile) (bool, string) {
		u, ok := p.Users()
		if !ok {
			return false, "no verified non-interactive CLI for local accounts"
		}
		if len(u.CreateUserSteps(spec.Username, spec.Password, spec.Privilege)) == 0 {
			return false, fmt.Sprintf("it has no equivalent of privilege level %d", spec.Privilege)
		}
		return true, ""
	}
}

// UserDelCapability admits platforms that can delete a local account.
func UserDelCapability(username string) Capability {
	return func(p *vendor.Profile) (bool, string) {
		u, ok := p.Users()
		if !ok {
			return false, "no verified non-interactive CLI for local accounts"
		}
		if len(u.DeleteUserSteps(username)) == 0 {
			return false, "account deletion is not offered"
		}
		return true, ""
	}
}

func userExists(ctx context.Context, env *HandlerEnv, u vendor.UserProvisioner, username string) (exists bool, out string, err error) {
	cmd := u.CheckUserCommand(username)
	out, err = env.Run(ctx, cmd)
	if err != nil {
		return false, out, err
	}
	if err := checkOutput(env.Job.Profile, cmd, out); err != nil {
		return false, out, &OpError{Cat: CatSyntaxError, Err: err}
	}
	return u.UserExists(out, username), out, nil
}

// UserAdd creates the account unless it exists (idempotent).
func UserAdd(spec UserSpec) Decider {
	return func(ctx context.Context, env *HandlerEnv) (Decision, error) {
		u, ok := env.Job.Profile.Users()
		if !ok {
			return Decision{}, opErrorf(CatUnsupportedOp, "no user provisioning on %s", env.Job.Profile.Display)
		}
		exists, _, err := userExists(ctx, env, u, spec.Username)
		if err != nil {
			return Decision{}, err
		}
		switch {
		case exists && !spec.UpdatePassword:
			return Decision{Detail: fmt.Sprintf("user %q already exists", spec.Username)}, nil
		case exists:
			steps := u.ChangePasswordSteps(spec.Username, spec.Password, false)
			if len(steps) == 0 {
				return Decision{}, opErrorf(CatUnsupportedOp, "cannot change a password on %s", env.Job.Profile.Display)
			}
			return Decision{Commands: vendor.Lines(steps), Detail: fmt.Sprintf("update password of existing user %q", spec.Username)}, nil
		}
		steps := u.CreateUserSteps(spec.Username, spec.Password, spec.Privilege)
		if len(steps) == 0 {
			return Decision{}, opErrorf(CatUnsupportedOp, "cannot create a level-%d user on %s", spec.Privilege, env.Job.Profile.Display)
		}
		return Decision{Commands: vendor.Lines(steps), Detail: fmt.Sprintf("create user %q (privilege %d)", spec.Username, spec.Privilege)}, nil
	}
}

// UserDel removes the account if it exists (idempotent).
func UserDel(username string) Decider {
	return func(ctx context.Context, env *HandlerEnv) (Decision, error) {
		u, ok := env.Job.Profile.Users()
		if !ok {
			return Decision{}, opErrorf(CatUnsupportedOp, "no user provisioning on %s", env.Job.Profile.Display)
		}
		exists, _, err := userExists(ctx, env, u, username)
		if err != nil {
			return Decision{}, err
		}
		if !exists {
			return Decision{Detail: fmt.Sprintf("user %q does not exist", username)}, nil
		}
		steps := u.DeleteUserSteps(username)
		if len(steps) == 0 {
			return Decision{}, opErrorf(CatUnsupportedOp, "cannot delete a user on %s", env.Job.Profile.Display)
		}
		return Decision{Commands: vendor.Lines(steps), Detail: fmt.Sprintf("delete user %q", username)}, nil
	}
}

// ---- passwd ----------------------------------------------------------------

// DefaultConfirmMinutes is the commit-confirm window used by passwd on
// platforms whose change only takes effect at commit.
const DefaultConfirmMinutes = 5

// PasswdSpec describes one rotation.
type PasswdSpec struct {
	Username    string // the local account; unused for an enable secret
	NewPassword string
	Enable      bool // rotate the enable secret instead of an account
	// ConfirmMinutes is the commit-confirm window on platforms with a native
	// one (default DefaultConfirmMinutes).
	ConfirmMinutes int
}

// enableSpec says how to read and put back a platform's enable secret.
type enableSpec struct {
	showCmd string
	line    *regexp.Regexp // the config line that holds the secret
	remove  string         // command that clears the secret when none was set before
}

var reEnableLine = regexp.MustCompile(`^enable\s+(?:secret|password)\b`)

var enableSpecs = map[string]enableSpec{
	vendor.Cisco:    {"show running-config | include ^enable ", reEnableLine, "no enable secret"},
	vendor.Ruijie:   {"show running-config | include ^enable ", reEnableLine, "no enable secret"},
	vendor.Arista:   {"show running-config | include ^enable ", reEnableLine, "no enable secret"},
	vendor.CiscoASA: {"show running-config | include ^enable ", reEnableLine, "no enable password"},
	vendor.CiscoSB:  {"show running-config", reEnableLine, "no enable password"},
}

func immediate(p *vendor.Profile) bool { return p.Safety() != vendor.RollbackSafe }

// PasswdCapability admits platforms that can rotate the secret AND be rolled
// back safely if the new credentials turn out not to work.
func PasswdCapability(spec PasswdSpec) Capability {
	return func(p *vendor.Profile) (bool, string) {
		u, ok := p.Users()
		if !ok {
			return false, "no verified non-interactive CLI for local accounts"
		}
		if len(u.ChangePasswordSteps(spec.Username, spec.NewPassword, spec.Enable)) == 0 {
			if spec.Enable {
				return false, "it has no enable secret"
			}
			return false, "password change is not offered"
		}
		if spec.Enable {
			if _, ok := enableSpecs[p.Name]; !ok && immediate(p) {
				return false, "the previous enable secret cannot be captured for a rollback"
			}
		} else if immediate(p) && !vendor.CanRestore(u) {
			return false, "the previous credentials cannot be captured for a rollback"
		}
		return true, ""
	}
}

// Passwd rotates a local account's password (or the enable secret), checks
// that the new credentials really log in BEFORE the change is saved or
// confirmed, and puts the old state back if they do not.
//
//   - Platforms where the change only exists after commit (Junos, VyOS, Arista
//     config sessions, IOS-XE) apply it with a commit-confirm timer: the test
//     login runs while the timer is armed, and the device reverts by itself if
//     anything goes wrong.
//   - Platforms where it is live at once (classic IOS, Huawei, ASA, FortiOS,
//     ...) are checked after the change but before it is saved; on failure the
//     account's previously stored (hashed) credential is re-applied, unsaved.
func Passwd(spec PasswdSpec) Decider {
	return func(ctx context.Context, env *HandlerEnv) (Decision, error) {
		prof := env.Job.Profile
		u, ok := prof.Users()
		if !ok {
			return Decision{}, opErrorf(CatUnsupportedOp, "no user provisioning on %s", prof.Display)
		}
		steps := u.ChangePasswordSteps(spec.Username, spec.NewPassword, spec.Enable)
		if len(steps) == 0 {
			return Decision{}, opErrorf(CatUnsupportedOp, "cannot rotate this secret on %s", prof.Display)
		}
		dec := Decision{Commands: vendor.Lines(steps)}
		login := env.Job.Cred
		test := credentials.Credential{Username: login.Username, Password: login.Password, EnablePassword: login.EnablePassword}
		what := fmt.Sprintf("password of %q", spec.Username)

		if spec.Enable {
			what = "enable secret"
			test.EnablePassword = spec.NewPassword
			if immediate(prof) {
				undo, err := enableUndo(ctx, env)
				if err != nil {
					return Decision{}, err
				}
				dec.Undo = undo
			}
		} else {
			exists, snapshot, err := userExists(ctx, env, u, spec.Username)
			if err != nil {
				return Decision{}, err
			}
			if !exists {
				return Decision{}, opErrorf(CatPrecondition, "user %q does not exist (create it with 'user add')", spec.Username)
			}
			test = credentials.Credential{Username: spec.Username, Password: spec.NewPassword, EnablePassword: login.EnablePassword}
			if immediate(prof) {
				dec.Undo = vendor.Lines(u.RestoreUserSteps(spec.Username, snapshot))
			}
		}
		if immediate(prof) && len(dec.Undo) == 0 {
			return Decision{}, opErrorf(CatPrecondition, "could not capture the previous credentials on %s, so a failed rotation could not be undone; nothing was changed", prof.Display)
		}
		if !immediate(prof) {
			dec.CommitConfirm = spec.ConfirmMinutes
			if dec.CommitConfirm <= 0 {
				dec.CommitConfirm = DefaultConfirmMinutes
			}
		}

		// When the rotated secret is the one this run logs in with, every
		// session opened after the change needs the new value.
		switch {
		case spec.Enable:
			// Without a separate enable password the login password doubles as it.
			post := credentials.Credential{Username: login.Username, Password: login.Password, EnablePassword: spec.NewPassword}
			dec.PostCred = &post
		case spec.Username == login.Username:
			post := test
			dec.PostCred = &post
		}
		runner := env.Runner
		dec.PreCommitCheck = func(ctx context.Context, job Job) error {
			if err := runner.TestLogin(ctx, job, test); err != nil {
				return fmt.Errorf("the new %s was rejected: %w", what, err)
			}
			return nil
		}
		dec.Detail = "rotate " + what
		return dec, nil
	}
}

// enableUndo reads the stored enable secret line so it can be put back.
func enableUndo(ctx context.Context, env *HandlerEnv) ([]string, error) {
	es, ok := enableSpecs[env.Job.Profile.Name]
	if !ok {
		return nil, opErrorf(CatPrecondition, "cannot read the enable secret on %s", env.Job.Profile.Display)
	}
	out, err := env.Run(ctx, es.showCmd)
	if err != nil {
		return nil, err
	}
	if err := checkOutput(env.Job.Profile, es.showCmd, out); err != nil {
		return nil, &OpError{Cat: CatSyntaxError, Err: err}
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(strings.TrimRight(l, "\r")); es.line.MatchString(l) {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return []string{es.remove}, nil // none was set: undoing means clearing it again
	}
	return lines, nil
}

// logRedact masks any secret in a command before it appears in a message.
func logRedact(cmd string) string { return redactText(cmd) }

// ==============================================================================
// File name:     handler.go
// Description:   Per-device workflows that read state over an open session
//
//	(user/VLAN checks, facts, MAC/ARP lookups, audits).
//
// License:       MIT
// ==============================================================================
package task

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"netops/internal/credentials"
	"netops/internal/inventory"
	"netops/internal/logging"
	"netops/internal/vendor"
)

// Handler runs on one device's open session instead of the configuration plan.
// It returns the text for the result table; an error fails the device. A
// handler must not leave the device in configuration mode.
type Handler func(ctx context.Context, env *HandlerEnv) (string, error)

// HandlerEnv is what a Handler works with.
type HandlerEnv struct {
	Job    Job
	Sess   Session
	Log    *logging.Logger
	Runner *Runner
}

// Host is the device's inventory hostname.
func (e *HandlerEnv) Host() string { return e.Job.Device.Hostname }

// Run sends one command with the normal command timeout. A device error
// message in the output is NOT an error here: many state checks ("show vlan id
// 99") answer with one when the object is absent, and the caller parses that.
func (e *HandlerEnv) Run(ctx context.Context, line string) (string, error) {
	return e.run(ctx, line, e.Runner.Opts.CommandTimeout)
}

// RunSlow is Run with the extended budget used for configuration dumps.
func (e *HandlerEnv) RunSlow(ctx context.Context, line string) (string, error) {
	return e.run(ctx, line, e.Runner.Opts.CommandTimeout*e.Runner.slow())
}

func (e *HandlerEnv) run(ctx context.Context, line string, timeout time.Duration) (string, error) {
	shown := logging.RedactCommand(line)
	e.Log.Tracef(e.Host(), ">> %s", shown)
	out, err := e.Sess.Send(ctx, line, timeout)
	if out != "" {
		e.Log.Block(logging.LevelTrace, e.Host(), "<< ", redactText(out))
	}
	if err != nil {
		return out, fmt.Errorf("%s: %w", shown, err)
	}
	return out, nil
}

// Skipped logs an idempotent no-op ("[SKIPPED] ...") and returns the result text.
func (e *HandlerEnv) Skipped(reason string) string {
	e.Log.Infof(e.Host(), "[SKIPPED] %s", reason)
	return "skipped: " + reason
}

// OpError carries a failure category chosen by a workflow.
type OpError struct {
	Cat Category
	Err error
}

func (e *OpError) Error() string { return e.Err.Error() }
func (e *OpError) Unwrap() error { return e.Err }

// opErrorf builds an OpError.
func opErrorf(cat Category, format string, args ...any) error {
	return &OpError{Cat: cat, Err: fmt.Errorf(format, args...)}
}

func handlerCategory(err error) Category {
	var oe *OpError
	if errors.As(err, &oe) {
		return oe.Cat
	}
	return classify(err, CatSessionError)
}

// executeHandler connects to the device and runs the handler on the session.
func (r *Runner) executeHandler(ctx context.Context, job Job, res *Result) {
	host := job.Device.Hostname
	prof := job.Profile
	r.Log.Infof(host, "connecting to %s (%s)", job.Device.Endpoint(), prof.Display)
	sess, err := r.Transport.Open(ctx, Target{
		Device:         job.Device,
		Profile:        prof,
		Cred:           job.Cred,
		JumpCred:       job.JumpCred,
		ConnectTimeout: r.Opts.ConnectTimeout,
		LoginTimeout:   r.Opts.CommandTimeout,
		Logf:           func(format string, args ...any) { r.Log.Tracef(host, format, args...) },
	})
	if err != nil {
		r.fail(res, host, classify(err, CatConnectFailed), err)
		return
	}
	defer sess.Close()
	r.Log.Infof(host, "session established (user %s)", job.Cred.Username)

	detail, err := r.Handler(ctx, &HandlerEnv{Job: job, Sess: sess, Log: r.Log, Runner: r})
	if err != nil {
		r.fail(res, host, handlerCategory(err), err)
		return
	}
	res.Status = StatusSucceeded
	res.Detail = oneLine(detail, 160)
	r.Log.Infof(host, "OK: %s", res.Detail)
}

// TestLogin opens a brand-new session as cred and runs the platform's probe
// command, proving that the credentials really log in. It is independent of
// any session already open, so it exercises the same path an operator would.
func (r *Runner) TestLogin(ctx context.Context, job Job, cred credentials.Credential) error {
	host := job.Device.Hostname
	tctx, cancel := context.WithTimeout(ctx, r.Opts.ConnectTimeout+r.Opts.CommandTimeout*2)
	defer cancel()
	sess, err := r.Transport.Open(tctx, Target{
		Device:         job.Device,
		Profile:        job.Profile,
		Cred:           cred,
		JumpCred:       job.JumpCred,
		ConnectTimeout: r.Opts.ConnectTimeout,
		LoginTimeout:   r.Opts.CommandTimeout,
		Logf:           func(format string, args ...any) { r.Log.Tracef(host, "(login test) "+format, args...) },
	})
	if err != nil {
		return fmt.Errorf("login with the new credentials failed (%s): %w", classify(err, CatConnectFailed), err)
	}
	defer sess.Close()
	if _, err := sess.Send(tctx, job.Profile.ProbeCommand(), r.Opts.CommandTimeout); err != nil {
		return fmt.Errorf("new credentials logged in but the probe command failed: %w", err)
	}
	return nil
}

// Capability reports whether a platform offers an operation. The reason is
// shown for the devices that are skipped.
type Capability func(p *vendor.Profile) (ok bool, reason string)

// BuildCapabilityJobs prepares one job per device for a workflow that needs a
// platform capability. Devices with an unknown vendor, or whose platform
// lacks the capability, become skipped jobs rather than errors, so one
// firewall in the inventory never blocks a switch run.
func BuildCapabilityJobs(devs []inventory.Device, op string, capable Capability) []Job {
	jobs := make([]Job, 0, len(devs))
	for _, d := range devs {
		job := Job{Device: d}
		prof, ok := vendor.Lookup(d.Vendor)
		switch {
		case !ok:
			job.Skip = CatUnsupportedVendor
			job.SkipDetail = fmt.Sprintf("unsupported vendor %q (supported: %s)", d.Vendor, strings.Join(vendor.Names(), ", "))
		default:
			job.Profile = prof
			if ok, reason := capable(prof); !ok {
				job.Skip = CatUnsupportedOp
				job.SkipDetail = fmt.Sprintf("%s is not available on %s: %s", op, prof.Display, reason)
			}
		}
		jobs = append(jobs, job)
	}
	return jobs
}

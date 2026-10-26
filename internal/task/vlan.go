// ==============================================================================
// File name:     vlan.go
// Description:   VLAN workflows: vlan add / vlan del.
// License:       MIT
// ==============================================================================
package task

import (
	"context"
	"fmt"

	"netops/internal/vendor"
)

// VLANSpec describes one VLAN.
type VLANSpec struct {
	ID   int
	Name string // optional on add; ignored on delete
}

// VLANCapability admits platforms that have a global VLAN database.
func VLANCapability(p *vendor.Profile) (bool, string) {
	if _, ok := p.VLANs(); !ok {
		return false, "it has no global VLAN database to manage over the CLI (a VLAN there is a sub-interface of a named parent port)"
	}
	return true, ""
}

func vlanExists(ctx context.Context, env *HandlerEnv, v vendor.VLANManager, id int) (exists bool, name string, err error) {
	cmd := v.CheckVLANCommand(id)
	out, err := env.Run(ctx, cmd)
	if err != nil {
		return false, "", err
	}
	if err := checkOutput(env.Job.Profile, cmd, out); err != nil {
		return false, "", &OpError{Cat: CatSyntaxError, Err: err}
	}
	if !v.VLANExists(out, id) {
		return false, "", nil
	}
	return true, v.VLANName(out, id), nil
}

// VLANAdd creates the VLAN unless it exists. An existing VLAN is never
// renamed: a different name is reported, not overwritten.
func VLANAdd(spec VLANSpec) Decider {
	return func(ctx context.Context, env *HandlerEnv) (Decision, error) {
		v, ok := env.Job.Profile.VLANs()
		if !ok {
			return Decision{}, opErrorf(CatUnsupportedOp, "no VLAN management on %s", env.Job.Profile.Display)
		}
		exists, name, err := vlanExists(ctx, env, v, spec.ID)
		if err != nil {
			return Decision{}, err
		}
		if exists {
			msg := fmt.Sprintf("VLAN %d already exists", spec.ID)
			if name != "" {
				msg += fmt.Sprintf(" (name %q)", name)
			}
			if spec.Name != "" && name != "" && spec.Name != name {
				msg += fmt.Sprintf("; requested name %q not applied", spec.Name)
			}
			return Decision{Detail: msg}, nil
		}
		steps := v.CreateVLANSteps(spec.ID, spec.Name)
		if len(steps) == 0 {
			return Decision{}, opErrorf(CatUnsupportedOp, "cannot create a VLAN on %s", env.Job.Profile.Display)
		}
		detail := fmt.Sprintf("create VLAN %d", spec.ID)
		if spec.Name != "" {
			detail += fmt.Sprintf(" (%s)", spec.Name)
		}
		return Decision{Commands: vendor.Lines(steps), Detail: detail}, nil
	}
}

// VLANDel removes the VLAN if it exists. VLAN 1 is never deleted.
func VLANDel(id int) Decider {
	return func(ctx context.Context, env *HandlerEnv) (Decision, error) {
		if id == 1 {
			return Decision{}, opErrorf(CatPrecondition, "VLAN 1 is the default VLAN and cannot be deleted")
		}
		v, ok := env.Job.Profile.VLANs()
		if !ok {
			return Decision{}, opErrorf(CatUnsupportedOp, "no VLAN management on %s", env.Job.Profile.Display)
		}
		exists, name, err := vlanExists(ctx, env, v, id)
		if err != nil {
			return Decision{}, err
		}
		if !exists {
			return Decision{Detail: fmt.Sprintf("VLAN %d does not exist", id)}, nil
		}
		steps := v.DeleteVLANSteps(id, name)
		if len(steps) == 0 {
			return Decision{}, opErrorf(CatPrecondition, "VLAN %d exists but its name could not be read, and %s deletes by name", id, env.Job.Profile.Display)
		}
		return Decision{Commands: vendor.Lines(steps), Detail: fmt.Sprintf("delete VLAN %d", id)}, nil
	}
}

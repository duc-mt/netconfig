package main

import (
	"context"

	"netconfig/internal/sshclient"
	"netconfig/internal/task"
)

// sshTransport adapts sshclient to task.Transport. It lives here so that
// package task never imports the SSH library and stays testable with fakes.
type sshTransport struct {
	hostKey     sshclient.HostKeyCallback
	legacy      bool
	autoConfirm bool
}

func (t sshTransport) Open(ctx context.Context, tgt task.Target) (task.Session, error) {
	sh, err := sshclient.Connect(ctx, sshclient.Config{
		Address:          tgt.Device.Endpoint(),
		Username:         tgt.Cred.Username,
		Password:         tgt.Cred.Password,
		EnablePassword:   tgt.Cred.EnablePassword,
		Profile:          tgt.Profile,
		ConnectTimeout:   tgt.ConnectTimeout,
		LoginTimeout:     tgt.LoginTimeout,
		HostKey:          t.hostKey,
		LegacyAlgorithms: t.legacy,
		AutoConfirm:      t.autoConfirm,
		Logf:             tgt.Logf,
	})
	if err != nil {
		return nil, err // explicit nil: never wrap a nil *Shell in the interface
	}
	return sh, nil
}

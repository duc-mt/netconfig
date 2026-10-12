// ==============================================================================
// Package main implements Implementation and logic for transport..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run transport.go [options]
// Notes:         Go package implementation
// ==============================================================================
package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"netconfig/internal/sshclient"
	"netconfig/internal/task"
)

// jumpPool maintains lazily-initialised, shared *ssh.Client bastions.
type jumpPool struct {
	mu      sync.Mutex
	clients map[string]*ssh.Client
	hostKey sshclient.HostKeyCallback
	legacy  bool
}

func newJumpPool(hk sshclient.HostKeyCallback, legacy bool) *jumpPool {
	return &jumpPool{
		clients: make(map[string]*ssh.Client),
		hostKey: hk,
		legacy:  legacy,
	}
}

func (p *jumpPool) get(ctx context.Context, addr, username, password string, timeout time.Duration) (*ssh.Client, error) {
	p.mu.Lock()
	if c, ok := p.clients[addr]; ok {
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()

	// Ensure port is present
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = "22"
	}
	formattedAddr := net.JoinHostPort(host, portStr)

	c, err := sshclient.ConnectJumpHost(ctx, formattedAddr, username, password, timeout, p.hostKey, p.legacy)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.clients[addr]; ok {
		_ = c.Close()
		return existing, nil
	}
	p.clients[addr] = c
	return c, nil
}

func (p *jumpPool) closeAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, c := range p.clients {
		_ = c.Close()
		delete(p.clients, addr)
	}
}

// sshTransport adapts sshclient to task.Transport. It lives here so that
// package task never imports the SSH library and stays testable with fakes.
type sshTransport struct {
	hostKey     sshclient.HostKeyCallback
	legacy      bool
	autoConfirm bool
	pool        *jumpPool
}

func (t sshTransport) Open(ctx context.Context, tgt task.Target) (task.Session, error) {
	cfg := sshclient.Config{
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
	}

	if tgt.JumpCred.Host != "" && t.pool != nil {
		jumpUser := tgt.JumpCred.Username
		if jumpUser == "" {
			jumpUser = tgt.Cred.Username
		}
		jumpPass := tgt.JumpCred.Password
		if jumpPass == "" {
			jumpPass = tgt.Cred.Password
		}

		jumpClient, err := t.pool.get(ctx, tgt.JumpCred.Host, jumpUser, jumpPass, tgt.ConnectTimeout)
		if err != nil {
			return nil, fmt.Errorf("bastion %s: %w", tgt.JumpCred.Host, err)
		}
		sh, err := sshclient.ConnectViaJump(ctx, jumpClient, cfg)
		if err != nil {
			return nil, err
		}
		return sh, nil
	}

	sh, err := sshclient.Connect(ctx, cfg)
	if err != nil {
		return nil, err // explicit nil: never wrap a nil *Shell in the interface
	}
	return sh, nil
}

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
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"netops/internal/memory"
	"netops/internal/sshclient"
	"netops/internal/task"
)

// jumpPool maintains lazily-initialised, shared *ssh.Client bastions and route memory.
type jumpPool struct {
	mu          sync.Mutex
	clients     map[string]*ssh.Client
	badBastions map[string]bool // hosts that failed direct connection (cannot serve as bastions)
	memStore    *memory.Store
	hostKey     sshclient.HostKeyCallback
	legacy      bool
}

func newJumpPool(hk sshclient.HostKeyCallback, legacy bool, memStore *memory.Store) *jumpPool {
	return &jumpPool{
		clients:     make(map[string]*ssh.Client),
		badBastions: make(map[string]bool),
		memStore:    memStore,
		hostKey:     hk,
		legacy:      legacy,
	}
}

func (p *jumpPool) markBadBastion(addr string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.badBastions[addr] = true
}

func (p *jumpPool) isBadBastion(addr string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.badBastions[addr]
}

func (p *jumpPool) get(ctx context.Context, addr, username, password, keyFile string, timeout time.Duration) (*ssh.Client, error) {
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

	c, err := sshclient.ConnectJumpHost(ctx, formattedAddr, username, password, keyFile, timeout, p.hostKey, p.legacy)
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

// sshTransport adapts sshclient to task.Transport.
type sshTransport struct {
	hostKey      sshclient.HostKeyCallback
	legacy       bool
	autoConfirm  bool
	pool         *jumpPool
	autoFallback []task.Target
	tcpMSS       int
}

func (t sshTransport) Open(ctx context.Context, tgt task.Target) (task.Session, error) {
	mss := t.tcpMSS
	if tgt.TCPMSS != 0 {
		mss = tgt.TCPMSS
	}
	cfg := sshclient.Config{
		Address:          tgt.Device.Endpoint(),
		Username:         tgt.Cred.Username,
		Password:         tgt.Cred.Password,
		KeyFile:          tgt.Cred.KeyFile,
		EnablePassword:   tgt.Cred.EnablePassword,
		Profile:          tgt.Profile,
		ConnectTimeout:   tgt.ConnectTimeout,
		LoginTimeout:     tgt.LoginTimeout,
		HostKey:          t.hostKey,
		LegacyAlgorithms: t.legacy,
		AutoConfirm:      t.autoConfirm,
		Logf:             tgt.Logf,
		TCPMSS:           mss,
	}

	// 1. Explicit jump host from inventory or CLI flags
	if tgt.JumpCred.Host != "" && t.pool != nil {
		jumpUser := tgt.JumpCred.Username
		if jumpUser == "" {
			jumpUser = tgt.Cred.Username
		}
		jumpPass := tgt.JumpCred.Password
		if jumpPass == "" {
			jumpPass = tgt.Cred.Password
		}
		jumpKey := tgt.JumpCred.KeyFile
		if jumpKey == "" && jumpPass == "" {
			jumpKey = tgt.Cred.KeyFile
		}
		jumpClient, err := t.pool.get(ctx, tgt.JumpCred.Host, jumpUser, jumpPass, jumpKey, tgt.ConnectTimeout)
		if err != nil {
			return nil, fmt.Errorf("bastion %s: %w", tgt.JumpCred.Host, err)
		}
		sh, err := sshclient.ConnectViaJump(ctx, jumpClient, cfg)
		if err != nil && !cfg.LegacyAlgorithms && isAlgorithmMismatch(err) {
			legacyCfg := cfg
			legacyCfg.LegacyAlgorithms = true
			if retrySh, retryErr := sshclient.ConnectViaJump(ctx, jumpClient, legacyCfg); retryErr == nil {
				sh = retrySh
				err = nil
			}
		}
		if err != nil {
			return nil, err
		}
		return sh, nil
	}

	// 2. Learned route memory (persisted from earlier runs)
	if t.pool != nil && t.pool.memStore != nil {
		if rec, ok := t.pool.memStore.Get(tgt.Device.Address); ok {
			for _, cand := range t.autoFallback {
				if cand.Device.Endpoint() == rec.JumpEndpoint || cand.Device.Address == rec.JumpEndpoint || cand.Device.Hostname == rec.JumpHost {
					if tgt.Logf != nil {
						tgt.Logf("learned route memory active: routing via jump host %s (%s) [learned: %s]", cand.Device.Hostname, cand.Device.Endpoint(), rec.LearnedAt.Format("2006-01-02 15:04"))
					}
					jumpClient, err := t.pool.get(ctx, cand.Device.Endpoint(), cand.Cred.Username, cand.Cred.Password, cand.Cred.KeyFile, tgt.ConnectTimeout)
					if err == nil {
						sh, err := sshclient.ConnectViaJump(ctx, jumpClient, cfg)
						if err != nil && !cfg.LegacyAlgorithms && isAlgorithmMismatch(err) {
							legacyCfg := cfg
							legacyCfg.LegacyAlgorithms = true
							sh, err = sshclient.ConnectViaJump(ctx, jumpClient, legacyCfg)
						}
						if err == nil {
							_ = t.pool.memStore.Record(tgt.Device.Hostname, tgt.Device.Address, cand.Device.Hostname, cand.Device.Endpoint(), "memory-active")
							return sh, nil
						}
					}
					if tgt.Logf != nil {
						tgt.Logf("learned jump host %s failed (%v); falling back to direct probe...", cand.Device.Hostname, err)
					}
					break
				}
			}
		}
	}

	// 3. Direct connection
	sh, directErr := sshclient.Connect(ctx, cfg)
	if directErr != nil && !cfg.LegacyAlgorithms && isAlgorithmMismatch(directErr) {
		legacyCfg := cfg
		legacyCfg.LegacyAlgorithms = true
		if retrySh, retryErr := sshclient.Connect(ctx, legacyCfg); retryErr == nil {
			sh = retrySh
			directErr = nil
		}
	}
	if directErr == nil {
		return sh, nil
	}

	// Direct connection failed; mark this host so other devices don't try to use it as a jump host
	if t.pool != nil {
		t.pool.markBadBastion(tgt.Device.Address)
	}

	// 4. Auto-fallback (Option B optimized):
	if t.pool != nil && len(t.autoFallback) > 0 && ctx.Err() == nil {
		var sshErr *sshclient.Error
		isTimeoutOrConn := false
		if errors.As(directErr, &sshErr) {
			isTimeoutOrConn = sshErr.Kind == sshclient.KindTimeout || sshErr.Kind == sshclient.KindConnect
		}
		if isTimeoutOrConn {
			targetIP := net.ParseIP(tgt.Device.Address)
			for _, cand := range t.autoFallback {
				// Don't jump through ourselves or any host that failed direct connection
				if cand.Device.Address == tgt.Device.Address || cand.Device.Hostname == tgt.Device.Hostname || t.pool.isBadBastion(cand.Device.Address) {
					continue
				}
				candIP := net.ParseIP(cand.Device.Address)
				// Prefer candidates in the same /24 subnet or internal mgmt scope
				sameSubnet := targetIP != nil && candIP != nil && targetIP.To4() != nil && candIP.To4() != nil &&
					targetIP.To4()[0] == candIP.To4()[0] && targetIP.To4()[1] == candIP.To4()[1] && targetIP.To4()[2] == candIP.To4()[2]

				if !sameSubnet && len(t.autoFallback) > 5 {
					continue
				}

				if tgt.Logf != nil {
					tgt.Logf("direct connection failed (%v); auto-falling back via neighbor %s (%s)...", directErr, cand.Device.Hostname, cand.Device.Endpoint())
				}

				candUser := cand.Cred.Username
				candPass := cand.Cred.Password
				candKey := cand.Cred.KeyFile

				// Fast jump dial timeout: 2.5s instead of stalling 10s per unresponsive neighbor
				jumpDialTO := 2500 * time.Millisecond
				if tgt.ConnectTimeout < jumpDialTO {
					jumpDialTO = tgt.ConnectTimeout
				}
				jumpClient, err := t.pool.get(ctx, cand.Device.Endpoint(), candUser, candPass, candKey, jumpDialTO)
				if err != nil {
					continue
				}
				sh, err := sshclient.ConnectViaJump(ctx, jumpClient, cfg)
				if err != nil && !cfg.LegacyAlgorithms && isAlgorithmMismatch(err) {
					legacyCfg := cfg
					legacyCfg.LegacyAlgorithms = true
					sh, err = sshclient.ConnectViaJump(ctx, jumpClient, legacyCfg)
				}
				if err == nil {
					if t.pool.memStore != nil {
						_ = t.pool.memStore.Record(tgt.Device.Hostname, tgt.Device.Address, cand.Device.Hostname, cand.Device.Endpoint(), "auto-fallback")
					}
					if tgt.Logf != nil {
						tgt.Logf("auto-fallback connection to %s succeeded via neighbor %s (learned and saved to memory)", tgt.Device.Hostname, cand.Device.Hostname)
					}
					return sh, nil
				}
			}
		}
	}

	return nil, directErr
}

func isAlgorithmMismatch(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no common algorithm") ||
		strings.Contains(s, "handshake failed: eof") ||
		strings.Contains(s, "no matching")
}

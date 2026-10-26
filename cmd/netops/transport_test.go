// ==============================================================================
// File name:     transport_test.go
// Description:   Unit tests for transport jumpPool management and eviction.
// License:       MIT
// ==============================================================================
package main

import (
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestJumpPoolEvict(t *testing.T) {
	pool := newJumpPool(nil, false, nil)

	// Test nil pool safety
	var nilPool *jumpPool
	nilPool.evict("10.0.0.1:22", nil)
	nilPool.markBadBastion("10.0.0.1:22")
	if nilPool.isBadBastion("10.0.0.1:22") {
		t.Error("expected false for nil pool")
	}

	// Add dummy dummy client to pool
	c1 := &ssh.Client{}
	c2 := &ssh.Client{}

	pool.clients["host1:22"] = c1
	pool.clients["host2:22"] = c2

	// Evict with mismatched client should not remove it
	pool.evict("host1:22", c2)
	if pool.clients["host1:22"] != c1 {
		t.Errorf("expected host1:22 to still have c1")
	}

	// Evict with matching client should remove it
	pool.evict("host1:22", c1)
	if _, ok := pool.clients["host1:22"]; ok {
		t.Errorf("expected host1:22 to be evicted")
	}

	// Evict with nil client should unconditionally remove it
	pool.evict("host2:22", nil)
	if _, ok := pool.clients["host2:22"]; ok {
		t.Errorf("expected host2:22 to be evicted")
	}

	// Bad bastion tracking
	pool.markBadBastion("badhost:22")
	if !pool.isBadBastion("badhost:22") {
		t.Errorf("expected badhost:22 to be marked bad")
	}
	if pool.isBadBastion("goodhost:22") {
		t.Errorf("expected goodhost:22 to not be marked bad")
	}
}

func TestIsJumpHostDead(t *testing.T) {
	if isJumpHostDead(nil) {
		t.Error("expected nil error to return false")
	}

	// EOF errors
	if !isJumpHostDead(io.EOF) {
		t.Error("expected io.EOF to return true")
	}
	if !isJumpHostDead(errors.New("read tcp 127.0.0.1:5000: use of closed network connection")) {
		t.Error("expected closed network connection to return true")
	}
	if !isJumpHostDead(errors.New("ssh: client is closed")) {
		t.Error("expected client is closed to return true")
	}
	if !isJumpHostDead(errors.New("write: broken pipe")) {
		t.Error("expected broken pipe to return true")
	}

	// OpenChannelError should return false (target host unreachable, bastion is alive)
	ocErr := &ssh.OpenChannelError{
		Reason:  ssh.ConnectionFailed,
		Message: "connect failed",
	}
	if isJumpHostDead(ocErr) {
		t.Error("expected OpenChannelError to return false")
	}

	// Normal errors
	if isJumpHostDead(errors.New("authentication failed")) {
		t.Error("expected auth error to return false")
	}
}

// ==============================================================================
// Package main implements Implementation and logic for hostkey..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run hostkey.go [options]
// Notes:         Go package implementation
// ==============================================================================
package sshclient

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyCallback is the verification hook handed to Config.HostKey.
type HostKeyCallback = ssh.HostKeyCallback

// HostKeyPolicy selects how unknown or changed host keys are treated.
type HostKeyPolicy string

const (
	// PolicyStrict accepts only hosts already present in the known_hosts file.
	PolicyStrict HostKeyPolicy = "strict"
	// PolicyAcceptNew enrolls hosts seen for the first time (trust on first
	// use) but still rejects a key that differs from the recorded one.
	PolicyAcceptNew HostKeyPolicy = "accept-new"
	// PolicyInsecure performs no verification at all.
	PolicyInsecure HostKeyPolicy = "insecure"
)

// ParsePolicy validates a -host-key-policy value.
func ParsePolicy(s string) (HostKeyPolicy, error) {
	switch p := HostKeyPolicy(strings.ToLower(strings.TrimSpace(s))); p {
	case PolicyStrict, PolicyAcceptNew, PolicyInsecure:
		return p, nil
	}
	return "", fmt.Errorf("invalid host key policy %q (use strict, accept-new or insecure)", s)
}

// HostKeyError reports a failed host key verification.
type HostKeyError struct {
	Host   string
	Reason string
	Err    error
}

func (e *HostKeyError) Error() string {
	return fmt.Sprintf("host key verification failed for %s: %s", e.Host, e.Reason)
}

func (e *HostKeyError) Unwrap() error { return e.Err }

// NewHostKeyCallback builds the callback for policy using the OpenSSH-format
// known_hosts file at path.
func NewHostKeyCallback(path string, policy HostKeyPolicy) (HostKeyCallback, error) {
	if policy == PolicyInsecure {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // explicitly requested by the operator
	}
	if policy == PolicyAcceptNew {
		if err := ensureFile(path); err != nil {
			return nil, err
		}
	}
	check, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %q: %w (create it, or use -host-key-policy accept-new to enroll devices on first contact)", path, err)
	}

	var mu sync.Mutex // serialises appends to the file
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := check(hostname, remote, key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if !errors.As(err, &ke) {
			return &HostKeyError{Host: hostname, Reason: err.Error(), Err: err}
		}
		if len(ke.Want) > 0 {
			return &HostKeyError{
				Host:   hostname,
				Reason: "the host key CHANGED since it was recorded in " + path + " (possible man-in-the-middle, or the device was replaced/re-keyed)",
				Err:    err,
			}
		}
		// Unknown host.
		if policy != PolicyAcceptNew {
			return &HostKeyError{
				Host:   hostname,
				Reason: "host is not in " + path + "; enroll it with -host-key-policy accept-new (first contact is trusted) or add its key manually",
				Err:    err,
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if aerr := appendKnownHost(path, hostname, key); aerr != nil {
			return &HostKeyError{Host: hostname, Reason: "could not record new host key: " + aerr.Error(), Err: aerr}
		}
		return nil
	}, nil
}

func ensureFile(path string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create known_hosts directory: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create known_hosts %q: %w", path, err)
	}
	return f.Close()
}

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	line := knownhosts.Line([]string{hostname}, key)
	if _, err := fmt.Fprintln(f, line); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

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
	"runtime"
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

// DefaultKnownHostsFile returns the default user OpenSSH known_hosts path
// for the current OS (Linux/macOS: ~/.ssh/known_hosts, Windows: %USERPROFILE%\.ssh\known_hosts).
func DefaultKnownHostsFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "known_hosts"
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// SystemKnownHostsFiles returns the standard system-wide known_hosts file paths
// for the current OS if they exist.
// Linux/macOS: /etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2
// Windows: %ProgramData%\ssh\ssh_known_hosts
func SystemKnownHostsFiles() []string {
	var candidates []string
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			candidates = append(candidates, filepath.Join(pd, "ssh", "ssh_known_hosts"))
		}
	} else {
		candidates = append(candidates, "/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2")
	}

	var existing []string
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			existing = append(existing, c)
		}
	}
	return existing
}

// ExpandHome resolves a leading "~/" or "~\" against the current user's home directory.
func ExpandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			rest := filepath.FromSlash(strings.ReplaceAll(path[2:], `\`, "/"))
			return filepath.Join(home, rest)
		}
	}
	return path
}

// NewHostKeyCallback builds the callback for policy using the OpenSSH-format
// known_hosts file at path (with system-wide known_hosts consulted as read-only fallbacks
// when path points to the standard user known_hosts file).
func NewHostKeyCallback(path string, policy HostKeyPolicy) (HostKeyCallback, error) {
	if policy == PolicyInsecure {
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // explicitly requested by the operator
	}

	path = ExpandHome(path)

	if policy == PolicyAcceptNew {
		if err := ensureFile(path); err != nil {
			return nil, err
		}
	}

	readFiles := []string{}
	// If path exists or was ensured, include it
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		readFiles = append(readFiles, path)
	}

	// If using the default user known_hosts file, also load system-wide known_hosts if available
	defUser := DefaultKnownHostsFile()
	if filepath.Clean(path) == filepath.Clean(defUser) {
		for _, sysFile := range SystemKnownHostsFiles() {
			if filepath.Clean(sysFile) != filepath.Clean(path) {
				readFiles = append(readFiles, sysFile)
			}
		}
	}

	var check ssh.HostKeyCallback
	if len(readFiles) == 0 {
		if policy == PolicyStrict {
			return nil, fmt.Errorf("load known_hosts %q: open %s: no such file or directory (create it, or use -host-key-policy accept-new to enroll devices on first contact)", path, path)
		}
		var err error
		check, err = knownhosts.New()
		if err != nil {
			return nil, fmt.Errorf("init known_hosts check: %w", err)
		}
	} else {
		var err error
		check, err = knownhosts.New(readFiles...)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts %q: %w (create it, or use -host-key-policy accept-new to enroll devices on first contact)", path, err)
		}
	}

	var mu sync.Mutex // serialises appends to the file and protects accepted map
	accepted := make(map[string]ssh.PublicKey)

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

		// Unknown host in initial known_hosts file. Check in-memory session cache.
		mu.Lock()
		defer mu.Unlock()

		if prevKey, ok := accepted[hostname]; ok {
			if string(prevKey.Marshal()) == string(key.Marshal()) {
				return nil
			}
			return &HostKeyError{
				Host:   hostname,
				Reason: "the host key CHANGED during this run for " + hostname,
				Err:    err,
			}
		}
		if remote != nil {
			if prevKey, ok := accepted[remote.String()]; ok {
				if string(prevKey.Marshal()) == string(key.Marshal()) {
					return nil
				}
				return &HostKeyError{
					Host:   hostname,
					Reason: "the host key CHANGED during this run for " + hostname,
					Err:    err,
				}
			}
		}

		if policy != PolicyAcceptNew {
			return &HostKeyError{
				Host:   hostname,
				Reason: "host is not in " + path + "; enroll it with -host-key-policy accept-new (first contact is trusted) or add its key manually",
				Err:    err,
			}
		}

		if !isHostKeyRecorded(path, hostname, remote, key) {
			if aerr := appendKnownHost(path, hostname, key); aerr != nil {
				return &HostKeyError{Host: hostname, Reason: "could not record new host key: " + aerr.Error(), Err: aerr}
			}
		}
		accepted[hostname] = key
		if remote != nil {
			accepted[remote.String()] = key
		}
		return nil
	}, nil
}

func isHostKeyRecorded(path string, hostname string, remote net.Addr, key ssh.PublicKey) bool {
	cb, err := knownhosts.New(path)
	if err != nil {
		return false
	}
	if remote == nil {
		if host, port, err := net.SplitHostPort(hostname); err == nil {
			var p int
			_, _ = fmt.Sscanf(port, "%d", &p)
			remote = &net.TCPAddr{IP: net.ParseIP(host), Port: p}
		}
	}
	return cb(hostname, remote, key) == nil
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


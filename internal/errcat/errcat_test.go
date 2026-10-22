// ==============================================================================
// Package main implements Implementation and logic for errcat_test..
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go run errcat_test.go [options]
// Notes:         Go package implementation
// ==============================================================================
package errcat

import (
	"errors"
	"fmt"
	"testing"
)

type dummyTimeoutError struct{}

func (d dummyTimeoutError) Error() string   { return "i/o timeout" }
func (d dummyTimeoutError) Timeout() bool   { return true }
func (d dummyTimeoutError) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	tests := []struct {
		device   string
		stage    string
		err      error
		expected Category
	}{
		{"sw01", "connect", dummyTimeoutError{}, CategoryUnreachable},
		{"sw01", "command", dummyTimeoutError{}, CategoryTimeout},
		{"sw01", "command", errors.New("command timed out after 30s"), CategoryTimeout},
		{"sw01", "connect", errors.New("connection refused"), CategoryUnreachable},
		{"sw01", "connect", errors.New("ssh: handshake failed: permission denied"), CategoryAuthFailed},
		{"sw01", "connect", errors.New("ssh: unable to authenticate, attempted methods [password], no supported methods remain"), CategoryAuthFailed},
		{"sw01", "connect", errors.New("ssh: handshake failed: read tcp 10.0.0.1:22: connection reset by peer"), CategorySessionError},
		{"sw01", "connect", errors.New("ssh: handshake failed: no common algorithm for host key"), CategorySessionError},
		{"sw01", "command", errors.New("process exited with status 1"), CategoryCommandFailed},
		{"sw01", "connect", errors.New("ssh: unexpected packet type"), CategorySessionError},
		{"sw01", "validate", errors.New("backup appears truncated or incomplete: expected end marker not found"), CategoryTruncatedOutput},
		{"sw01", "write", errors.New("something totally random"), CategoryUnknown},
	}

	for _, tt := range tests {
		cerr := Classify(tt.device, tt.stage, tt.err)
		if cerr.Category != tt.expected {
			t.Errorf("Classify(%s, %s, %v): expected category %s, got %s", tt.device, tt.stage, tt.err, tt.expected, cerr.Category)
		}
	}

	// Verify AuditReason mappings
	auditTests := map[Category]string{
		CategoryAuthFailed:      "AUTH_FAILED",
		CategoryUnreachable:     "CONNECT_FAILED",
		CategoryConnectFailed:   "CONNECT_FAILED",
		CategoryTimeout:         "TIMEOUT",
		CategoryTruncatedOutput: "TRUNCATED_OUTPUT",
		CategoryUnknown:         "FAILED",
	}
	for cat, expected := range auditTests {
		if got := cat.AuditReason(); got != expected {
			t.Errorf("cat.AuditReason() for %s: expected %s, got %s", cat, expected, got)
		}
	}
}

// kindError mimics netconfig's sshclient.Error: a typed failure whose kind is
// available through ErrorKind() without importing the SSH package.
type kindError struct{ kind, msg string }

func (e *kindError) Error() string     { return e.msg }
func (e *kindError) ErrorKind() string { return e.kind }

// Errors from netconfig's SSH engine say what went wrong in ErrorKind(); that
// is more reliable than matching words in the message, which can be anything
// (a prompt that never came, a host key policy, ...).
func TestClassifyUsesErrorKind(t *testing.T) {
	wrap := func(e error) error { return fmt.Errorf("fetching: %w", e) }
	tests := []struct {
		name     string
		stage    string
		err      error
		expected Category
	}{
		{"auth", "connect", &kindError{"auth", "connect: rejected"}, CategoryAuthFailed},
		{"auth, wrapped", "connect", wrap(&kindError{"auth", "connect: rejected"}), CategoryAuthFailed},
		{"enable rejected", "connect", &kindError{"auth", "enable: access denied"}, CategoryAuthFailed},
		{"host key", "connect", &kindError{"hostkey", "knownhosts: key mismatch"}, CategoryConnectFailed},
		{"session", "command", &kindError{"session", "send: connection dropped"}, CategorySessionError},
		{"timeout while waiting for the prompt", "connect", &kindError{"timeout", "login: no prompt within 10s"}, CategoryUnreachable},
		{"timeout during the backup command", "command", &kindError{"timeout", "send: no prompt within 90s"}, CategoryTimeout},
		{"connect, refused", "connect", &kindError{"connect", "dial tcp 10.0.0.1:22: connection refused"}, CategoryUnreachable},
		{"connect, other", "connect", &kindError{"connect", "dial tcp: lookup failed badly"}, CategoryConnectFailed},
		// no kind: the message heuristics still apply
		{"plain error", "connect", errors.New("connection refused"), CategoryUnreachable},
		// a truncated backup is classified by its stage, never by a kind
		{"validate", "validate", errors.New("backup appears truncated"), CategoryTruncatedOutput},
	}
	for _, tt := range tests {
		if got := Classify("sw01", tt.stage, tt.err).Category; got != tt.expected {
			t.Errorf("%s: Classify(%s, %v) = %s, want %s", tt.name, tt.stage, tt.err, got, tt.expected)
		}
	}
}

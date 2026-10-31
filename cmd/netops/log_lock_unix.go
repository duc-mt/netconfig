//go:build !windows

// ==============================================================================
// File name:     log_lock_unix.go
// Description:   Advisory data-directory locks for "netops log" (Unix). One collector per
//                data directory and one listener per data directory; the
//                kernel drops a lock when its process dies.
// License:       MIT
// ==============================================================================

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockLogDataDir takes an exclusive, non-blocking flock on <dir>/.netlog.lock and
// returns the function that releases it. The kernel drops the lock if the
// process dies, so a crashed run never leaves the directory locked.
func lockLogDataDir(dir string) (func(), error) {
	return lockLogFile(filepath.Join(dir, ".netlog.lock"))
}

// lockLogListener is the same for "netops log listen", on its own lock file: one
// listener per data directory, but a listener and a collect/monitor run may
// share it (they append whole batches to the daily JSONL files).
func lockLogListener(dir string) (func(), error) {
	return lockLogFile(filepath.Join(dir, ".netlog-listen.lock"))
}

func lockLogFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errLogAlreadyRunning
		}
		return nil, fmt.Errorf("locking data directory: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

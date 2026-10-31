//go:build windows

// ==============================================================================
// File name:     log_lock_windows.go
// Description:   Advisory data-directory locks for "netops log" (Windows). One collector per
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

	"golang.org/x/sys/windows"
)

// lockLogDataDir takes an exclusive, non-blocking lock on <dir>/.netops_log.lock via
// LockFileEx and returns the function that releases it. The Windows kernel
// automatically releases file locks if the process dies or exits.
func lockLogDataDir(dir string) (func(), error) {
	return lockLogFile(filepath.Join(dir, ".netops_log.lock"))
}

// lockLogListener is the same for "netops log listen", on its own lock file: one
// listener per data directory, but a listener and a collect/monitor run may
// share it (they append whole batches to the daily JSONL files).
func lockLogListener(dir string) (func(), error) {
	return lockLogFile(filepath.Join(dir, ".netops_log_listen.lock"))
}

func lockLogFile(p string) (func(), error) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}

	h := windows.Handle(f.Fd())
	var ol windows.Overlapped
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	err = windows.LockFileEx(h, flags, 0, 1, 0, &ol)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errLogAlreadyRunning
		}
		return nil, fmt.Errorf("locking data directory: %w", err)
	}

	return func() {
		var uol windows.Overlapped
		_ = windows.UnlockFileEx(h, 0, 1, 0, &uol)
		_ = f.Close()
	}, nil
}

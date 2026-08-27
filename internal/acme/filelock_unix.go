//go:build !windows

package acme

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive advisory lock on path, creating the file if
// it doesn't exist, and returns a function that releases it.
//
// The lock lives on the open file description, so the kernel drops it if
// the process dies — a crash mid-save can't leave a stale lock behind
// that wedges every later save.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		// Closing the descriptor releases the lock on its own; the
		// explicit unlock just makes the intent obvious.
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

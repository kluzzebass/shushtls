//go:build windows

package acme

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive lock on path, creating the file if it
// doesn't exist, and returns a function that releases it. Windows
// releases the lock when the handle closes, including on process exit,
// so a crash can't leave a stale lock behind.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped)); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(h, 0, 1, 0, new(windows.Overlapped))
		_ = f.Close()
	}, nil
}

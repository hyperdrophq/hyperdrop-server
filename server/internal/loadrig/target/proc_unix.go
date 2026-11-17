//go:build unix

package target

import (
	"errors"
	"syscall"
)

// processAlive reports whether a process numbered pid exists.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

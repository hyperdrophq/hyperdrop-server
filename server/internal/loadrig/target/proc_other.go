//go:build !unix

package target

import (
	"errors"
	"syscall"
)

// serverProcAttr has nothing to set on this system.
func serverProcAttr() *syscall.SysProcAttr { return nil }

// processAlive cannot tell on this system, so a pid file is taken as stale.
func processAlive(int) bool { return false }

func processName(int) (string, error) { return "", errors.New("not available on this system") }

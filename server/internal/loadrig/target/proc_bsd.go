//go:build unix && !linux

package target

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// serverProcAttr puts the server in a process group of its own, so a
// terminal's Ctrl-C reaches the rig alone and the rig stops the server
// itself.
func serverProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

// processName is the command name ps reports for process pid.
func processName(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

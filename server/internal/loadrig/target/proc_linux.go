package target

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// serverProcAttr puts the server in a process group of its own, so a
// terminal's Ctrl-C reaches the rig alone and the rig stops the server
// itself, and has the kernel send it SIGTERM if the rig dies first.
func serverProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
}

// processName is the command name of process pid: the first 15 bytes of its
// program's name.
func processName(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

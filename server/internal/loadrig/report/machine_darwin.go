//go:build darwin

package report

import (
	"os/exec"
	"strings"
	"syscall"
)

func cpuAndMemory() (string, int64) {
	out := func(key string) string {
		b, err := exec.Command("sysctl", "-n", key).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return out("machdep.cpu.brand_string"), atoi(out("hw.memsize"))
}

func fileSystemOf(dir string) string {
	var st syscall.Statfs_t
	if dir == "" || syscall.Statfs(dir, &st) != nil {
		return ""
	}
	var b []byte
	for _, c := range st.Fstypename {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

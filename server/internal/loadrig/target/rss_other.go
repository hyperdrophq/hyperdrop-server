//go:build !linux

package target

import (
	"os/exec"
	"strconv"
	"strings"
)

// rssOf asks ps for a process's resident set, which it reports in KiB.
func rssOf(pid int) (int64, bool) {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, false
	}
	kb, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || kb <= 0 {
		return 0, false
	}
	return kb * 1024, true
}

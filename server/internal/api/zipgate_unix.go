//go:build unix

package api

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// zipFilesSpare is how many open files a new zip leaves for everything else.
const zipFilesSpare = 64

// filesToSpare reports whether the process is far enough from its open-file limit
// to start another zip, which holds two. A system with no /proc to count them says
// yes.
func filesToSpare() bool {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return true
	}
	open, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return true
	}
	return uint64(len(open))+zipFilesSpare < uint64(lim.Cur)
}

// machineMemory reads the machine's total and available memory, 0 on a system with
// neither /proc/meminfo nor a cgroup limit. Inside a container whose limit is below
// the host's memory, the limit is the machine: /proc/meminfo describes the host.
func machineMemory() (total, available int64) {
	total, available = procMemory()
	if limit, left := cgroupMemory("/sys/fs/cgroup"); limit > 0 && (total == 0 || limit < total) {
		total, available = limit, left
	}
	return total, available
}

func procMemory() (total, available int64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() && (total == 0 || available == 0) {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		kb, _ := strconv.ParseInt(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = kb << 10
		case "MemAvailable:":
			available = kb << 10
		}
	}
	return total, available
}

package api

import (
	"os"
	"strconv"
	"strings"
)

// Server health beyond disk: memory and load. Both are read from /proc and
// both are host-wide by design, because the server runs under systemd with no
// cgroup limit of its own and what it competes for is the whole box.
// Everything is best-effort: on platforms without /proc the fields simply
// stay zero and the client treats them as unknown.

// memInfo reports the host's total and available memory in bytes, or zeroes
// where /proc is unavailable (macOS dev machines, tests).
func memInfo() (totalBytes, availableBytes int64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	return parseMemInfo(data)
}

func parseMemInfo(data []byte) (totalBytes, availableBytes int64) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalBytes = kb * 1024
		case "MemAvailable:":
			availableBytes = kb * 1024
		}
	}
	return totalBytes, availableBytes
}

func parseLoad1(data []byte) float64 {
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return v
}

func readSysinfo() (memTotal, memAvailable int64, load1 float64) {
	memTotal, memAvailable = memInfo()
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		load1 = parseLoad1(data)
	}
	return memTotal, memAvailable, load1
}

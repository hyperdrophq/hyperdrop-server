package api

import (
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
)

// The server's memory reading, which the load guard and the zip gate size
// themselves by.

// MemoryReading is how much memory the server and its machine have left. A field
// the system cannot report is 0.
type MemoryReading struct {
	// Used is what the Go runtime holds from the system beyond the heap it has freed
	// and could reuse at once, and Limit what it may hold: GOMEMLIMIT, or else the
	// machine's memory.
	Used, Limit int64
	// Total is the machine's memory (a container's limit, inside one), and Available
	// what the kernel could give to a process without swapping.
	Total, Available int64
}

// ReadMemory reads the server's memory now. It opens files, so it runs a few times a
// second at most, never once a request.
func ReadMemory() MemoryReading {
	sample := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"},
		{Name: "/memory/classes/heap/free:bytes"}}
	metrics.Read(sample)
	r := MemoryReading{Used: int64(sample[0].Value.Uint64()) - int64(sample[1].Value.Uint64()) - int64(sample[2].Value.Uint64())}
	r.Total, r.Available = machineMemory()
	r.Limit = debug.SetMemoryLimit(-1)
	if r.Limit <= 0 || r.Limit == math.MaxInt64 {
		r.Limit = r.Total
	}
	return r
}

// cgroupMemory reads a cgroup directory's memory limit, and what is left of it once
// the file cache and slab the kernel could take back are set aside, as /proc/meminfo's
// MemAvailable sets them aside. A limit of 0 means none is set or none can be read.
func cgroupMemory(dir string) (limit, available int64) {
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return ""
		}
		return string(b)
	}
	limit, err := strconv.ParseInt(strings.TrimSpace(read("memory.max")), 10, 64)
	if err != nil || limit <= 0 {
		return 0, 0
	}
	current, _ := strconv.ParseInt(strings.TrimSpace(read("memory.current")), 10, 64)
	var reclaimable int64
	for line := range strings.Lines(read("memory.stat")) {
		name, value, _ := strings.Cut(line, " ")
		switch name {
		case "active_file", "inactive_file", "slab_reclaimable":
			n, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			reclaimable += n
		}
	}
	return limit, max(0, limit-(current-reclaimable))
}

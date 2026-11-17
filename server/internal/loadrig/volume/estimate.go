package volume

import (
	"os"
	"path/filepath"
)

// diskBytesPerFile is what one generated file costs the file system on
// average, rows and directory entries included: the blob pool's bytes are
// shared by every placed file, so the cost follows the file count, not the
// bytes the files appear to hold.
const diskBytesPerFile = 950

// EstimateDisk is the disk a volume of the plan is expected to take.
func EstimateDisk(p Plan) int64 {
	files, _ := p.Totals()
	return files * diskBytesPerFile
}

// FreeBytes is the free space on the file system that holds dir, or on the
// nearest existing parent when dir does not exist yet; false when it cannot
// be read.
func FreeBytes(dir string) (int64, bool) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return 0, false
	}
	for {
		if _, err := os.Stat(dir); err == nil {
			free, _, ok := fsState(dir)
			return free, ok
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return 0, false
		}
		dir = parent
	}
}

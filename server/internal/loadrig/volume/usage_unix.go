//go:build darwin || linux

package volume

import "syscall"

// fsState answers the free bytes and the inodes in use on the file system
// holding dir, and false when it cannot tell. Free space rather than used
// space: an APFS volume's size moves with its container's other volumes,
// its free space is what a write takes.
func fsState(dir string) (freeBytes, usedInodes int64, ok bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return 0, 0, false
	}
	return int64(st.Bfree) * int64(st.Bsize), int64(st.Files) - int64(st.Ffree), true
}

// syncAll asks the system to write every buffered change to disk.
func syncAll() { syscall.Sync() }

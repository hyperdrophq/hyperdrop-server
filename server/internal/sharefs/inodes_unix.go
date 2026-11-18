//go:build unix

package sharefs

import "syscall"

// statfsInodes reads the free and total inodes of the filesystem holding dir. A
// filesystem that allots them as it goes, Btrfs among them, reports a total of 0.
func statfsInodes(dir string) (free, total int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Ffree), int64(st.Files), nil
}

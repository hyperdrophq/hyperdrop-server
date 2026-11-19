//go:build unix && !linux

package linked

import "golang.org/x/sys/unix"

// ancestryOpenFlags opens each ".." of a root's ancestry for reading: these
// systems have no path-only descriptor, so a root under a parent the
// service account may enter but not read is refused here.
const ancestryOpenFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC

// statFD answers the identity of the directory fd holds.
func statFD(fd int) (dirID, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return dirID{}, err
	}
	return dirID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, nil
}

//go:build linux

package linked

import "golang.org/x/sys/unix"

// ancestryOpenFlags opens each ".." of a root's ancestry as a path-only
// descriptor, which needs search permission on the directory and not read,
// so a root under a parent the service account may enter but not list
// opens. An O_PATH descriptor serves as an openat directory and for
// fstatat with AT_EMPTY_PATH from Linux 2.6.39, the kernel O_PATH arrived
// in, and handleAncestry makes no other use of it.
const ancestryOpenFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC

// statFD answers the identity of the directory fd holds. It uses fstatat
// with AT_EMPTY_PATH rather than fstat, which refuses an O_PATH descriptor
// on kernels before 3.6.
func statFD(fd int) (dirID, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(fd, "", &st, unix.AT_EMPTY_PATH); err != nil {
		return dirID{}, err
	}
	return dirID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, nil
}

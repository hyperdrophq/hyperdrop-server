//go:build unix

package linked

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var errAncestryTooDeep = errors.New("linked roots: directory ancestry deeper than the walk allows")

// dirID is a directory's filesystem identity: its device and inode.
type dirID struct{ dev, ino uint64 }

// statID answers the identity of the directory at path, read with the same
// stat structure statFD reads, so the two always compare.
func statID(path string) (dirID, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return dirID{}, err
	}
	return dirID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, nil
}

func sameDir(a, b dirID) bool { return a == b }

// handleAncestry answers the identities of the directory the handle or holds
// and of each directory above it, read through the handle's own ".." chain
// with openat, up to the filesystem root (the step where the identity stops
// changing). It reads no path, so a rename or a symlink swapped in after the
// open does not change what it answers. More than max hops is an error.
// Each ".." opens with ancestryOpenFlags as a bare descriptor, which the walk
// uses only as the next openat's directory, for statFD and for close.
func handleAncestry(or *os.Root, max int) ([]dirID, error) {
	f, err := or.Open(".")
	if err != nil {
		return nil, err
	}
	self, err := statFD(int(f.Fd()))
	if err != nil {
		f.Close()
		return nil, err
	}
	out := []dirID{self}
	fd, err := openParent(int(f.Fd()))
	f.Close()
	for range max {
		if err != nil {
			return nil, err
		}
		id, serr := statFD(fd)
		if serr != nil {
			unix.Close(fd)
			return nil, serr
		}
		if id == out[len(out)-1] {
			unix.Close(fd)
			return out, nil
		}
		out = append(out, id)
		var next int
		next, err = openParent(fd)
		unix.Close(fd)
		fd = next
	}
	if err == nil {
		unix.Close(fd)
	}
	return nil, errAncestryTooDeep
}

// openParent opens ".." of the directory dirfd holds.
func openParent(dirfd int) (int, error) {
	for {
		fd, err := unix.Openat(dirfd, "..", ancestryOpenFlags, 0)
		if !errors.Is(err, unix.EINTR) {
			return fd, err
		}
	}
}

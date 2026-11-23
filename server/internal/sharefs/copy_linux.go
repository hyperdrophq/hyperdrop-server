//go:build linux

package sharefs

import (
	"os"

	"golang.org/x/sys/unix"
)

// cloneFileOS asks the filesystem to make dst share src's blocks (FICLONE).
// A filesystem without reflinks, or two files on different filesystems, is
// refused with an error cloneRefused recognizes.
func cloneFileOS(dst, src *os.File) error {
	return unix.IoctlFileClone(int(dst.Fd()), int(src.Fd()))
}

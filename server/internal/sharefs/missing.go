package sharefs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"syscall"

	"hyperdrop/server/internal/shareid"
)

// FileMissing answers whether a stored file's bytes are absent: its share
// directory or the file itself does not exist, or what stands there is not a
// regular file. Any other failure to look (permission, I/O) is returned as an
// error and says nothing about the file.
func (f *FS) FileMissing(id, rel string) (bool, error) {
	if !shareid.ValidRelPath(rel) {
		return false, ErrBadPath
	}
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer root.Close()
	return exactCheck(root, rel)
}

// missingIn is FileMissing's verdict for rel through a share's open root.
func missingIn(root *os.Root, rel string) (bool, error) {
	fi, err := root.Stat(fileRel(rel))
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return !fi.Mode().IsRegular(), nil
}

// exactCheck is the per-file check MissingAmong falls back to. A variable so
// a test can count the fallbacks.
var exactCheck = missingIn

// listChunk is how many entries one read of a directory listing takes, so a
// directory of many files is never held in memory whole.
const listChunk = 512

// listDir calls fn with each entry of the directory dir under root. The open
// does not block on a FIFO standing where the directory belongs; reading one
// fails like reading any other non-directory. A variable so a test can count
// the listings.
var listDir = func(root *os.Root, dir string, fn func(os.DirEntry)) error {
	d, err := root.OpenFile(dir, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer d.Close()
	for {
		entries, err := d.ReadDir(listChunk)
		for _, e := range entries {
			fn(e)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// MissingAmong answers which of rels, stored files of share id, are missing,
// with the verdict FileMissing gives each, at the cost of one root for the
// share and one listing per distinct directory the rels name rather than a
// lookup per file. A rel the listing shows as a regular file is present;
// every other rel (absent from the listing, a directory, a symlink, any other
// type, or under a directory whose listing failed) takes FileMissing's exact
// check through the same root. missing keeps rels' order. err is the first
// rel that could not be checked, which is in neither answer, as FileMissing's
// error says nothing about its file; a share root that cannot be opened for
// any reason but absence checks none.
func (f *FS) MissingAmong(id string, rels []string) (missing []string, err error) {
	var firstErr error
	fail := func(rel string, err error) {
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", rel, err)
		}
	}
	valid := make([]bool, len(rels))
	for i, rel := range rels {
		if valid[i] = shareid.ValidRelPath(rel); !valid[i] {
			fail(rel, ErrBadPath)
		}
	}
	root, err := f.root(id)
	if errors.Is(err, ErrNotFound) {
		for i, rel := range rels {
			if valid[i] {
				missing = append(missing, rel)
			}
		}
		return missing, firstErr
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()

	// Each directory's wanted names, to the indexes of the rels naming them,
	// in the order the directories first appear.
	var order []string
	wanted := map[string]map[string][]int{}
	for i, rel := range rels {
		if !valid[i] {
			continue
		}
		dir, name := path.Split(rel)
		names, ok := wanted[dir]
		if !ok {
			names = map[string][]int{}
			wanted[dir] = names
			order = append(order, dir)
		}
		names[name] = append(names[name], i)
	}
	present := make([]bool, len(rels))
	for _, dir := range order {
		names := wanted[dir]
		// A failed listing leaves its rels unmarked, which the exact check
		// below then answers.
		_ = listDir(root, fileRel(dir), func(e os.DirEntry) {
			if !e.Type().IsRegular() {
				return
			}
			for _, i := range names[e.Name()] {
				present[i] = true
			}
		})
	}
	for i, rel := range rels {
		if !valid[i] || present[i] {
			continue
		}
		gone, err := exactCheck(root, rel)
		switch {
		case err != nil:
			fail(rel, err)
		case gone:
			missing = append(missing, rel)
		}
	}
	return missing, firstErr
}

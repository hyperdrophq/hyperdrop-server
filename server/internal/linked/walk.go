package linked

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
)

type Entry struct {
	Rel     string
	Size    int64
	ModTime time.Time
}

const MaxWalk = 10000

// Hidden reports whether rel holds a segment a share never shows: any
// segment beginning ".", "@" or "#", at any depth. It is the ONE definition
// of that rule, and it is the same rule the root scan applies to a volume's
// top level, so the system directories a NAS is full of stay out of a
// listing whether they sit beside a shared folder or inside one: Synology
// keeps thumbnails in @eaDir, a shared folder's deleted files in #recycle
// and its snapshots in #snapshot. Walk skips these names, so every reader
// resolving a relpath must refuse them too, or a path the listing cannot
// produce still serves its bytes.
func Hidden(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if strings.HasPrefix(seg, ".") || strings.HasPrefix(seg, "@") || strings.HasPrefix(seg, "#") {
			return true
		}
	}
	return false
}

// ReadDirCapped reads at most budget+1 listable entries of dir inside root,
// dropping the names Hidden refuses, and reports whether the directory held
// more than it returned. A directory is read a chunk at a time and never
// materialised whole, so a folder holding a million files costs the budget
// rather than the folder. The hidden names it drops count too (readBudget),
// so a directory of a million hidden entries costs no more than a listable
// one.
//
// Entries come back in DIRECTORY order, never sorted: a chunked read cannot
// sort what it has not read, so the caller sorts what it is given. A
// directory that fit entirely therefore orders exactly as a whole read
// would; one that did not fit orders the window it was handed.
func ReadDirCapped(root *os.Root, dir string, budget int) ([]fs.DirEntry, bool, error) {
	directory, err := openDirectory(root, dir)
	if err != nil {
		return nil, false, err
	}
	defer directory.Close()
	ents, more, _, err := readDir(directory, budget, readBudget(budget+1))
	return ents, more, err
}

// readBudget is how many directory entries a read that may return n of them
// may read in all: readSlack per entry, for the hidden names it drops (a NAS
// keeps an @eaDir in every folder) and, in a walk, the directories it
// descends into, plus a floor so a small cap is not spent on a folder's few
// system entries alone.
func readBudget(n int) int { return readSlack*n + readFloor }

const (
	readSlack = 2
	readFloor = 256
)

// readDir reads directory a chunk at a time, keeping at most budget+1
// listable entries and reading at most reads entries in all, hidden ones
// included. It answers how many it read and whether the directory held more
// than it returned.
func readDir(directory *os.Root, budget, reads int) ([]fs.DirEntry, bool, int, error) {
	f, err := directory.Open(".")
	if err != nil {
		return nil, false, 0, err
	}
	defer f.Close()
	want := budget + 1
	out := make([]fs.DirEntry, 0, min(want, 512))
	read := 0
	for len(out) < want && read < reads {
		ents, err := f.ReadDir(min(want-len(out), reads-read))
		read += len(ents)
		for _, e := range ents {
			if !Hidden(e.Name()) {
				out = append(out, e)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, false, read, nil
			}
			return nil, false, read, err
		}
		if len(ents) == 0 {
			return out, false, read, nil
		}
	}
	return out, true, read, nil
}

// Walk lists the regular files inside root, depth-first, sorted by name at
// each level, skipping the names Hidden refuses, never entering a symlinked
// directory, stopping after max entries. A FIFO, a socket or a device is
// never listed: nothing can serve its bytes.
//
// Only the source itself failing is an error: a subdirectory that cannot be
// read is skipped, so one folder whose permission was withdrawn leaves the
// rest of the share listed rather than making the whole share unreadable.
//
// Each directory is read a budget at a time (readDir), so a folder far
// larger than max costs the cap rather than the folder, and the whole walk
// reads at most readBudget(max) directory entries, the hidden ones and the
// directories it descends into counted with the files: a tree of many
// folders and few files costs the cap too, and runs out marked truncated.
// Each subdirectory is opened from its parent's open handle, one component
// at a time. The sort is over what was read, which means a directory that
// overran the budget lists a window of itself, marked truncated, not the
// alphabetically first names in it.
func Walk(root *os.Root, max int) ([]Entry, bool, error) {
	var out []Entry
	truncated := false
	reads := readBudget(max)
	// rel is the directory's path inside root, "" for root itself.
	var visit func(directory *os.Root, rel string) error
	visit = func(directory *os.Root, rel string) error {
		if len(out) >= max || reads <= 0 {
			truncated = true
			return nil
		}
		ents, more, read, err := readDir(directory, max-len(out), reads)
		reads -= read
		if err != nil {
			return err
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
		for _, e := range ents {
			// Checked before acting on the entry at all, so a directory entry
			// past the cap is never recursed into (no ReadDir on its subtree).
			if len(out) >= max || reads <= 0 {
				truncated = true
				return nil
			}
			name := e.Name()
			if e.Type()&fs.ModeSymlink != 0 {
				// A symlinked directory is never entered; a symlinked file is
				// left to Open, where os.Root decides whether it stays inside,
				// and is listed only when no hop of the way to it passes a
				// name Hidden refuses.
				target := path.Join(rel, name)
				info, err := root.Stat(target)
				if err != nil || !info.Mode().IsRegular() || throughHidden(root, target) {
					continue
				}
				out = append(out, Entry{Rel: target, Size: info.Size(), ModTime: info.ModTime()})
				continue
			}
			if e.IsDir() {
				// An unreadable subdirectory is skipped, not fatal: the error
				// return belongs to the source itself.
				reads--
				if child, err := openDirectory(directory, name); err == nil {
					_ = visit(child, path.Join(rel, name))
					child.Close()
				}
				continue
			}
			if !e.Type().IsRegular() {
				continue
			}
			info, err := e.Info()
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			out = append(out, Entry{Rel: path.Join(rel, name), Size: info.Size(), ModTime: info.ModTime()})
		}
		if more {
			truncated = true
		}
		return nil
	}
	if err := visit(root, ""); err != nil {
		return nil, false, err
	}
	if out == nil {
		out = []Entry{}
	}
	return out, truncated, nil
}

// maxLinks bounds how many symlinks throughHidden follows, the kernel's own
// order of magnitude, so a cycle of links ends.
const maxLinks = 40

// throughHidden reports whether resolving name inside root passes through a
// segment Hidden refuses, at any hop (resolveLinks). A file link with an
// ordinary name pointing into .secret or #recycle would otherwise publish
// what Hidden keeps out of every share.
func throughHidden(root *os.Root, name string) bool {
	_, ok := resolveLinks(root, name)
	return !ok
}

// resolveLinks answers the path name resolves to inside root, every link on
// the way replaced by its target, and ok false when the way passes through a
// segment Hidden refuses at any hop: each component is Lstat'ed, a symlink's
// target is spliced in where it stood, and a target that leaves root, is
// absolute, cannot be read or loops past maxLinks counts as hidden, since
// nothing can serve it anyway. Every component of the answer was a real
// directory or file when it was read; a caller opening it checks that again
// on the handles it opens (OpenEntry).
func resolveLinks(root *os.Root, name string) (string, bool) {
	todo := strings.Split(name, "/")
	var done []string
	links := 0
	for len(todo) > 0 {
		seg := todo[0]
		todo = todo[1:]
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(done) == 0 {
				return "", false
			}
			done = done[:len(done)-1]
			continue
		}
		if Hidden(seg) {
			return "", false
		}
		cur := path.Join(append(slices.Clone(done), seg)...)
		info, err := root.Lstat(cur)
		if err != nil {
			return "", false
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			done = append(done, seg)
			continue
		}
		links++
		if links > maxLinks {
			return "", false
		}
		target, err := root.Readlink(cur)
		if err != nil || path.IsAbs(target) {
			return "", false
		}
		todo = append(strings.Split(target, "/"), todo...)
	}
	if len(done) == 0 {
		return "", false
	}
	return path.Join(done...), true
}

// FolderDateBudget bounds how much of a folder FolderDate reads to date it.
const FolderDateBudget = 2048

// FolderDate is the date a listing shows for a folder: the newest
// modification time among the files directly inside it, or the folder's own
// when it holds no file. A folder's own mtime says when an entry was last
// added or removed, which on a NAS is whenever the indexer rewrote its
// thumbnail directory, so it tells nothing about what the folder holds; the
// files' dates do. Subfolders are not dated: one level down is what the
// listing shows, and dating a tree would read the whole tree. At most
// FolderDateBudget entries are read, so a folder of a million files costs
// the budget; a folder larger than that is dated by that window.
func FolderDate(root *os.Root, dir string, own time.Time) time.Time {
	ents, _, err := ReadDirCapped(root, dir, FolderDateBudget)
	if err != nil {
		return own
	}
	var newest time.Time
	for _, e := range ents {
		if e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if newest.IsZero() {
		return own
	}
	return newest
}

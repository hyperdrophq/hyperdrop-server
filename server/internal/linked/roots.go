// Package linked resolves the server-side folders a linked share may point at.
//
// Two boundaries decide what a linked share can serve. This package owns the
// first: the roots the SERVER process may read, configured by the operator
// (fixed directories) or discovered (every readable top-level directory of a
// scanned volume, which on Synology is every shared folder the package user
// was granted). The second, which account may share from which root, is the
// per-user allowlist in allow.go. Bytes always open through os.Root, so a
// symlink planted inside a root cannot reach outside it.
//
// The server's own data folder is never a root. List leaves out a directory
// that is, holds or lies inside it, judged by path, and Open judges every
// root it opens again by the filesystem identity of the directory it opened,
// so a root whose path is swapped for a link after the listing still never
// reaches the data folder.
package linked

import (
	"errors"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"hyperdrop/server/internal/shareid"
)

type Root struct {
	Name string
	Dir  string
}

var (
	ErrBadPath = errors.New("bad source path")
	ErrNoRoot  = errors.New("no such root")
)

const cacheTTL = time.Minute

// Roots is the set of folders the server process may serve linked shares
// from. A nil *Roots is a server with none: every method answers as it would
// for an empty set, so callers never guard it.
type Roots struct {
	fixed []Root
	scan  []string
	// exclude are folders no root may be, contain or lie inside: the
	// server's own data folder.
	exclude []string
	Now     func() time.Time

	mu     sync.Mutex
	cached []Root
	at     time.Time
	// refused holds each root directory whose refusal by admitOpened has
	// been logged.
	refused sync.Map
}

// ValidRel accepts a clean, slash-separated, root-relative path: the first
// segment names a root and the rest descends into it.
//
// It is the wire relpath rule, shareid.ValidRelPath: a leading "/" is not
// local and a trailing "/" is not clean, so both are refused there.
func ValidRel(rel string) bool {
	return shareid.ValidRelPath(rel)
}

// ValidHide accepts what a source's filter may hide: any path Walk can list,
// which is ValidRel with a backslash taken as the ordinary byte it is in a
// Linux name. Nothing composes a filesystem path from a hidden path (Skipped
// only compares it with what the walk listed), and it is still clean and
// local, so it can name nothing outside the source.
func ValidHide(rel string) bool {
	if rel == "" || rel == "." || len(rel) > shareid.MaxRelPathBytes || strings.ContainsRune(rel, 0) {
		return false
	}
	if !filepath.IsLocal(rel) || path.Clean(rel) != rel {
		return false
	}
	for seg := range strings.SplitSeq(rel, "/") {
		if len(seg) > shareid.MaxNameBytes {
			return false
		}
	}
	return true
}

// NewRoots builds the root set from fixed directories and scanned volumes. A
// directory that equals, contains or lies inside any exclude path is never
// listed, so a linked share cannot reach what the server keeps for itself.
func NewRoots(fixed, scan, exclude []string) (*Roots, error) {
	r := &Roots{scan: scan, Now: time.Now}
	for _, dir := range exclude {
		if dir = strings.TrimSpace(dir); dir != "" {
			r.exclude = append(r.exclude, filepath.Clean(dir))
		}
	}
	seen := map[string]bool{}
	for _, dir := range fixed {
		dir = filepath.Clean(dir)
		name := filepath.Base(dir)
		if seen[name] {
			return nil, errors.New("linked roots: two roots named " + name)
		}
		seen[name] = true
		r.fixed = append(r.fixed, Root{Name: name, Dir: dir})
		if r.excluded(dir) {
			log.Printf("linked roots: %s is, holds or lies inside the server's data folder and is never listed", dir)
		}
	}
	return r, nil
}

func FromEnv(getenv func(string) string) (*Roots, error) {
	data := getenv("HYPERDROP_DATA")
	if data == "" {
		data = "/data"
	}
	return NewRoots(splitList(getenv("HYPERDROP_LINKED_ROOTS")), splitList(getenv("HYPERDROP_LINKED_SCAN")), []string{data})
}

// realPath is dir with symlinks resolved, or dir cleaned when it cannot be.
func realPath(dir string) string {
	if p, err := filepath.EvalSymlinks(dir); err == nil {
		return p
	}
	return filepath.Clean(dir)
}

// within reports whether child is parent or lies below it.
func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// excluded reports whether dir equals, contains or lies inside an excluded
// folder, comparing the resolved spellings of both.
func (r *Roots) excluded(dir string) bool {
	if len(r.exclude) == 0 {
		return false
	}
	d := realPath(dir)
	for _, x := range r.exclude {
		x = realPath(x)
		if within(x, d) || within(d, x) {
			return true
		}
	}
	return false
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ":") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (r *Roots) Enabled() bool { return len(r.List()) > 0 }

// List answers the current roots, sorted by name, re-scanned at most once a
// minute. A fixed root is listed whether or not it is readable right now, so
// a misconfiguration shows up as a root that refuses rather than one that
// vanishes; a scanned directory is listed only while it can be opened.
//
// The answer is a COPY of the cache: callers hold it while other goroutines
// re-scan, and a caller that sorted or trimmed the cached slice in place
// would edit every other caller's view of the roots.
func (r *Roots) List() []Root {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.Now()
	if r.cached != nil && now.Sub(r.at) < cacheTTL {
		return slices.Clone(r.cached)
	}
	byName := map[string]Root{}
	for _, f := range r.fixed {
		if !r.excluded(f.Dir) {
			byName[f.Name] = f
		}
	}
	for _, vol := range r.scan {
		ents, err := os.ReadDir(vol)
		if err != nil {
			continue
		}
		for _, e := range ents {
			name := e.Name()
			if !e.IsDir() || Hidden(name) {
				continue
			}
			if _, taken := byName[name]; taken {
				continue
			}
			dir := filepath.Join(vol, name)
			if r.excluded(dir) {
				continue
			}
			f, err := os.Open(dir)
			if err != nil {
				continue
			}
			_, rerr := f.Readdirnames(1)
			f.Close()
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				continue
			}
			byName[name] = Root{Name: name, Dir: dir}
		}
	}
	out := make([]Root, 0, len(byName))
	for _, v := range byName {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	r.cached, r.at = out, now
	return slices.Clone(out)
}

// Resolve splits a root-relative path into its root and the sub-path below
// it ("." for the root itself).
func (r *Roots) Resolve(rel string) (Root, string, error) {
	if !ValidRel(rel) {
		return Root{}, "", ErrBadPath
	}
	name, sub, _ := strings.Cut(rel, "/")
	if sub == "" {
		sub = "."
	}
	for _, root := range r.List() {
		if root.Name == name {
			return root, sub, nil
		}
	}
	return Root{}, "", ErrNoRoot
}

// Open opens the selected source's boundary: the directory itself, or the
// parent of a regular file. No component below the configured root may be a
// symlink. File symlinks INSIDE a directory source remain supported by os.Root.
// The returned sub-path is "." for a directory or the file's base name.
//
// The configured root's own path may be a symlink, so the directory it
// opened is judged on that handle (admitOpened) before anything else reads
// it: one that is, holds or lies inside the data folder answers ErrNoRoot.
func (r *Roots) Open(rel string) (*os.Root, string, error) {
	root, sub, err := r.Resolve(rel)
	if err != nil {
		return nil, "", err
	}
	or, err := os.OpenRoot(root.Dir)
	if err != nil {
		return nil, "", err
	}
	if err := r.admitOpened(or); err != nil {
		or.Close()
		return nil, "", err
	}
	if sub == "." {
		return or, sub, nil
	}
	parent, err := openDirectory(or, path.Dir(sub))
	or.Close()
	if err != nil {
		return nil, "", err
	}
	name := path.Base(sub)
	info, err := parent.Lstat(name)
	if err != nil {
		parent.Close()
		return nil, "", err
	}
	if info.IsDir() {
		dir, err := openDirectory(parent, name)
		parent.Close()
		if err != nil {
			return nil, "", err
		}
		return dir, ".", nil
	}
	if !info.Mode().IsRegular() {
		parent.Close()
		return nil, "", os.ErrNotExist
	}
	return parent, name, nil
}

// maxAncestry bounds the ".." walk handleAncestry takes from an opened root
// up to the filesystem root.
var maxAncestry = 4096

// admitOpened answers ErrNoRoot when the directory the handle or holds is an
// excluded folder, holds one or lies inside one. It compares filesystem
// identities read from the handle itself and from each excluded folder's
// resolved path, so no path the handle was opened by is trusted between the
// open and the check. An excluded folder that cannot be stat'ed has nothing
// to reach, and a handle whose ancestry cannot be read is refused.
func (r *Roots) admitOpened(or *os.Root) error {
	if len(r.exclude) == 0 {
		return nil
	}
	self, err := or.Stat(".")
	if err != nil {
		r.refuseOnce(or.Name(), err)
		return ErrNoRoot
	}
	var ancestry []dirID
	for _, x := range r.exclude {
		x = realPath(x)
		// The handle is the excluded folder or one of its ancestors.
		for p := x; ; p = filepath.Dir(p) {
			if info, err := os.Stat(p); err == nil && os.SameFile(self, info) {
				return ErrNoRoot
			}
			if filepath.Dir(p) == p {
				break
			}
		}
		// The excluded folder is one of the handle's ancestors.
		xid, err := statID(x)
		if err != nil {
			continue
		}
		if ancestry == nil {
			if ancestry, err = handleAncestry(or, maxAncestry); err != nil {
				r.refuseOnce(or.Name(), err)
				return ErrNoRoot
			}
		}
		for _, a := range ancestry {
			if sameDir(a, xid) {
				return ErrNoRoot
			}
		}
	}
	return nil
}

// refuseOnce tells the operator, once per root directory, that the root is
// refused because it cannot be checked against the data folder. Open runs
// on every request, so a root that keeps failing logs only its first cause.
func (r *Roots) refuseOnce(dir string, cause error) {
	if _, told := r.refused.LoadOrStore(dir, true); !told {
		log.Printf("linked roots: %s cannot be checked against the server's data folder and is refused: %v", dir, cause)
	}
}

// openDirectory descends through real directories, keeping each parent handle
// alive until its child is open. Checking the opened directory's identity is
// essential: an Lstat check followed by an unchecked OpenRoot would allow a
// concurrent symlink replacement to move the boundary to a sibling directory.
func openDirectory(root *os.Root, rel string) (*os.Root, error) {
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return current, nil
	}
	if !ValidRel(rel) {
		current.Close()
		return nil, ErrBadPath
	}
	for _, name := range strings.Split(rel, "/") {
		before, err := current.Lstat(name)
		if err != nil || !before.IsDir() {
			current.Close()
			return nil, os.ErrNotExist
		}
		next, err := current.OpenRoot(name)
		if err != nil {
			current.Close()
			return nil, err
		}
		after, err := next.Stat(".")
		current.Close()
		if err != nil || !os.SameFile(before, after) {
			next.Close()
			return nil, os.ErrNotExist
		}
		current = next
	}
	return current, nil
}

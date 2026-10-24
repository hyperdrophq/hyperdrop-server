package api

import (
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/mimetype"
)

const browseLimit = 1000

type sourceRootOut struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// listSources answers the folders the caller may share from: every root for
// an admin, the allowlist entries that currently resolve for a user. ?all=1
// is the users editor's request for every server root; an admin's own list
// already is that, so the flag only refuses a caller who is not an admin.
func (h *handler) listSources(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	if r.URL.Query().Get("all") == "1" && !u.IsAdmin() {
		writeErrorCode(w, http.StatusForbidden, "source-forbidden", "admin only")
		return
	}
	roots := h.roots.List()
	paths := linked.VisibleRoots(u.IsAdmin(), u.SourceRoots, roots)
	out := make([]sourceRootOut, 0, len(paths))
	for _, p := range paths {
		out = append(out, sourceRootOut{Path: p, Name: path.Base(p)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"roots": out})
}

// sourceRefusal applies both boundaries to a root-relative path: 400 for a
// malformed path, 403 when the account may not reach it, nil when the
// account may share from it.
//
// An admin reaches every root, so its 403 says which boundary refused: no
// root the server lists holds the path. An account with an allowlist is
// told only that it may not share from the path, whether or not a root
// holds it, so a guess at a folder's name (a NAS shared folder called
// "finance") learns nothing listSources does not already show it.
func (h *handler) sourceRefusal(u metadb.User, rel string) error {
	if err := sourceShapeRefusal(rel); err != nil {
		return err
	}
	if !linked.Allowed(u.IsAdmin(), u.SourceRoots, h.roots.List(), rel) {
		if u.IsAdmin() {
			return refuse(http.StatusForbidden, "source-forbidden", "no folder this server shares holds "+rel)
		}
		return refuse(http.StatusForbidden, "source-forbidden", "this account may not share from "+rel)
	}
	return nil
}

// sourceShapeRefusal is the half of sourceRefusal that asks nothing of the
// account or the roots: the path's shape and its hidden segments.
func sourceShapeRefusal(rel string) error {
	if !linked.ValidRel(rel) {
		return refuse(http.StatusBadRequest, "bad-source", "source must be a clean root-relative path")
	}
	// A hidden segment is refused at the SOURCE too, not only inside a walk:
	// a share pointed straight at #recycle or .git would otherwise publish
	// what the listing rule exists to keep out of every share.
	if linked.Hidden(rel) {
		return refuse(http.StatusBadRequest, "bad-source", "source names a hidden folder")
	}
	return nil
}

type browseDir struct {
	Name  string    `json:"name"`
	MTime time.Time `json:"mtime"`
}

type browseFile struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	MTime    time.Time `json:"mtime"`
	Viewable bool      `json:"viewable"`
}

// browseSource lists ONE level below path: the folders and files an admin,
// or a user's allowlisted root, can turn into a linked share right there,
// not a recursive walk.
func (h *handler) browseSource(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	if err := h.sourceRefusal(reqUser(r), rel); err != nil {
		writeRefusal(w, err)
		return
	}
	root, sub, err := h.roots.Open(rel)
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "source-missing", "no such folder")
		return
	}
	defer root.Close()
	// Read a budget at a time and sort what came back: a shared folder with
	// a million files in it costs the cap, not the folder. A listing that
	// overran the cap is a window of the directory rather than its
	// alphabetical head, which is what truncated tells the client.
	ents, more, err := linked.ReadDirCapped(root, sub, browseLimit)
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "source-missing", "no such folder")
		return
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	dirs, files := []browseDir{}, []browseFile{}
	truncated := more
	for _, e := range ents {
		name := e.Name()
		// A symlink cannot be selected as its own source boundary. In-bound
		// file links remain visible inside a shared directory's live walk.
		if e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		if len(dirs)+len(files) >= browseLimit {
			truncated = true
			break
		}
		info, err := root.Stat(path.Join(sub, name))
		if err != nil {
			continue
		}
		if info.IsDir() {
			// A folder is dated by what it holds (linked.FolderDate): its
			// own mtime moves whenever a NAS indexer rewrites its thumbnail
			// folder, which is no date a person sorting by date wants.
			dirs = append(dirs, browseDir{Name: name,
				MTime: linked.FolderDate(root, path.Join(sub, name), info.ModTime()).UTC()})
			continue
		}
		if !info.Mode().IsRegular() {
			continue // a FIFO, socket or device has no bytes a share can serve
		}
		files = append(files, browseFile{Name: name, Size: info.Size(), MTime: info.ModTime().UTC(),
			Viewable: mimetype.Viewable(mimetype.ByName(name))})
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": rel, "dirs": dirs, "files": files, "truncated": truncated})
}

// serveSource streams ONE file's bytes to the account that may share it, so
// a client can look at a pick before it becomes a share. The same two
// boundaries as browse gate it, and the answer is always an attachment, so a
// client that asked for bytes never saves a page under the file's name. A
// folder is refused rather than zipped: browse is what a folder has.
func (h *handler) serveSource(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	u := reqUser(r)
	if err := h.sourceRefusal(u, rel); err != nil {
		writeRefusal(w, err)
		return
	}
	grant := linked.GrantFor(u.IsAdmin(), u.SourceRoots, rel)
	root, sub, err := h.roots.Open(grant)
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "source-missing", "no such file")
		return
	}
	defer root.Close()
	fileGrant := sub != "."
	if rel != grant {
		if fileGrant {
			writeErrorCode(w, http.StatusNotFound, "source-missing", "no such file")
			return
		}
		sub = strings.TrimPrefix(rel, grant+"/")
	}
	// A file grant names the file itself, never a link to it: Roots.Open
	// resolved it without following one, and the open is pinned to that.
	stat := root.Stat
	if fileGrant {
		stat = root.Lstat
	}
	st, err := stat(sub)
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "source-missing", "no such file")
		return
	}
	if st.IsDir() {
		writeErrorCode(w, http.StatusBadRequest, "bad-source", "a folder has no bytes to serve; browse it instead")
		return
	}
	f, _, err := linked.OpenRegular(root, sub, st)
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "source-missing", "no such file")
		return
	}
	defer f.Close()
	name := path.Base(rel)
	mimeType := mimetype.ByName(name)
	if mimeType == "" {
		mimeType = mimetype.Detect(f, name)
	}
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Disposition", dispositionHeader(false, name))
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	http.ServeContent(w, r, "", st.ModTime(), f)
}

// sourceListRefusal applies both boundaries to every source and resolves
// each: a share of "what could be read" would list something other than
// what was picked, so one failing source refuses the whole list. Two
// sources of one base name would list on top of each other once prefixed,
// so they are refused too. Answers whether any is a folder.
func (h *handler) sourceListRefusal(u metadb.User, sources []string) (anyDir bool, err error) {
	missing := refuse(http.StatusNotFound, "source-missing", "no such file or folder on the server")
	names := map[string]bool{}
	for _, source := range sources {
		if err := h.sourceRefusal(u, source); err != nil {
			return false, err
		}
		root, sub, err := h.roots.Open(source)
		if err != nil {
			return false, missing
		}
		info, err := root.Stat(sub)
		root.Close()
		if err != nil {
			return false, missing
		}
		if info.IsDir() {
			anyDir = true
		}
		base := path.Base(source)
		if names[base] {
			return false, refuse(http.StatusBadRequest, "bad-source", "two sources share the name "+base)
		}
		names[base] = true
	}
	return anyDir, nil
}

// realignSlugs answers how a linked share's slug map moves onto the names its
// NEW source list produces. A share of one folder lists that folder's entries bare; a
// second source joining lists each source under its base name, and the last
// extra source leaving un-prefixes the one that stays. The slug is keyed by
// the name the share LISTS an entry under, so without this every entry is
// minted a fresh slug on the next read and every link copied before the edit
// dies.
//
// Only a change in whether the share prefixes moves anything: several sources
// before and after list the same way, and so do one and one. A FILE source
// lists as its own name either way, so nothing moves for it.
//
// The answer is the rekey metadb.SetSources applies inside the transaction
// that changes the rows, or nil when nothing moves.
func (h *handler) realignSlugs(before, after []string) func(rel string) string {
	prefixed := len(after) > 1
	if len(before) > 1 == prefixed {
		return nil
	}
	single := before
	if len(after) == 1 {
		single = after
	}
	if len(single) != 1 {
		return nil
	}
	root, sub, err := h.roots.Open(single[0])
	if err != nil {
		return nil
	}
	st, err := root.Stat(sub)
	root.Close()
	if err != nil || !st.IsDir() {
		return nil
	}
	base := path.Base(single[0]) + "/"
	return func(rel string) string {
		switch {
		case prefixed && !strings.HasPrefix(rel, base):
			return base + rel
		case !prefixed && strings.HasPrefix(rel, base):
			return strings.TrimPrefix(rel, base)
		}
		return rel
	}
}

// sourceNameRefusal answers the 400 an upload named rel earns when it
// would list on top of an entry one of the share's sources already serves,
// or beneath one of its files (linked.Collides). A folder the source serves
// is open: an upload inside it lists beside the folder's own files. ONE
// rule, so the single-file PUT, the batch, a new folder and a move refuse
// the same names.
func (h *handler) sourceNameRefusal(v shareView, rel string) error {
	if !v.Linked() {
		return nil
	}
	specs, err := h.dbSpecs(v.Share)
	if err != nil {
		return err
	}
	return h.sourceSpecNameRefusal(specs, v.Prefixed(), rel)
}

// sourceSpecNameRefusal is sourceNameRefusal over specs a caller composed
// itself, for the create path, which has no share to read them off yet.
func (h *handler) sourceSpecNameRefusal(specs []linked.SourceSpec, prefixed bool, rel string) error {
	if !linked.Collides(h.roots, specs, prefixed, rel) {
		return nil
	}
	return refuse(http.StatusBadRequest, "path-taken", "a source already lists under the name "+rel)
}

// errShareLinked refuses a write that would put bytes into, or take them
// out of, what a linked share's folder holds: its content is the folder's,
// never uploaded.
var errShareLinked = refuse(http.StatusConflict, "share-linked",
	"this share serves a server folder; add files there instead")

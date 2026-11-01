package metadb

import (
	"database/sql"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"hyperdrop/server/internal/shareid"
)

// CommitInput is what sharefs.Commit learned about the staged bytes plus who
// is committing. Anonymous marks the public inbox PUT, which is capped by
// the share's own limits as well as the owner's. Replaces names the file an
// upload takes the place of once it commits (?replaces=), and ReplaceAll
// marks one that becomes the share's only file (?replaceAll=1): the one way
// a text share's file changes.
type CommitInput struct {
	ShareID, Path string
	Size          int64
	SHA256, Mime  string
	UploadSession string
	Anonymous     bool
	Replaces      string
	ReplaceAll    bool
}

// shareHead is the part of a share the write paths consult before touching files.
type shareHead struct {
	owner     string
	inbox     bool
	text      bool
	closed    bool
	maxBytes  int64
	maxFiles  int
	bytes     int64
	committed int
}

func readHead(tx *sql.Tx, id string) (shareHead, error) {
	if !shareid.ValidID(id) {
		return shareHead{}, ErrNotFound
	}
	var h shareHead
	err := tx.QueryRow(`SELECT owner, inbox, text, closed, max_bytes, max_files, bytes, committed FROM shares WHERE id = ?`, id).
		Scan(&h.owner, &h.inbox, &h.text, &h.closed, &h.maxBytes, &h.maxFiles, &h.bytes, &h.committed)
	if errors.Is(err, sql.ErrNoRows) {
		return shareHead{}, ErrNotFound
	}
	return h, err
}

// clearDanglingEntry clears an entry naming a path the share no longer holds,
// so a share cannot go on claiming it opens a page that is not there.
func clearDanglingEntry(tx *sql.Tx, shareID string) error {
	_, err := tx.Exec(`UPDATE shares SET entry = '' WHERE id = ? AND entry <> ''
		AND entry NOT IN (SELECT path FROM files WHERE share_id = ?)`, shareID, shareID)
	return err
}

func touch(tx *sql.Tx, id string, now time.Time) error {
	_, err := tx.Exec(`UPDATE shares SET modified_at = ? WHERE id = ?`, toNS(now), id)
	return err
}

// finishShareWrite ends a share mutation: it stamps modified_at, inserts the
// changes row every mutation owes, and reads the share back with at most
// maxFiles file entries, every one when maxFiles <= 0. A content change
// (files, folders, moves) answers with every entry, which the route sends
// back; a settings edit answers with editWindow of them.
func finishShareWrite(tx *sql.Tx, h shareHead, id string, maxFiles int) (Share, error) {
	now := time.Now()
	if err := touch(tx, id, now); err != nil {
		return Share{}, err
	}
	if err := recordChange(tx, h.owner, id, false, now); err != nil {
		return Share{}, err
	}
	return scanShare(tx, id, maxFiles)
}

// editWindow is how many file entries a settings edit (UpdateShare,
// Schedule, CancelScheduled, the source and filter edits, ApplyDue) reads
// back: the listing's window. Every write on the server queues behind the
// one write transaction, and an edit that changes no file has no reason to
// hold it for a read of the share's whole file table; the PATCH route
// answers from its own read after the edit commits.
const editWindow = DefaultMaxFilesPerShare

const fileCols = `path, slug, size, sha256, mime, pending, committed_at, added_at, upload_session`

// scanFileRow maps one files row selected in fileCols order onto a File.
// extra receives any columns the query selects after them.
func scanFileRow(sc rowScanner, extra ...any) (File, error) {
	var f File
	var sha sql.NullString
	var ca, aa sql.NullInt64
	dest := append([]any{&f.Path, &f.Slug, &f.Size, &sha, &f.Mime, &f.Pending, &ca, &aa, &f.UploadSession}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return File{}, err
	}
	f.SHA256 = sha.String
	f.CommittedAt, f.AddedAt = fromNSPtr(ca), fromNSPtr(aa)
	return f, nil
}

func scanFile(tx *sql.Tx, shareID, path string) (File, error) {
	f, err := scanFileRow(tx.QueryRow(`SELECT `+fileCols+` FROM files WHERE share_id = ? AND path = ?`, shareID, path))
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, notFound("file " + path)
	}
	return f, err
}

// File answers one manifest entry, ErrNotFound when the share does not hold
// that path. The bounded read the upload path wants: an admission check and
// a refused commit each need one row's size and state, and reading the
// whole file table for it would undo the windowed read they gate.
func (db *DB) File(shareID, path string) (f File, err error) {
	if !shareid.ValidID(shareID) || !shareid.ValidRelPath(path) {
		return File{}, ErrNotFound
	}
	err = db.read(func(tx *sql.Tx) error { f, err = scanFile(tx, shareID, path); return err })
	return
}

// PathsWithPrefix answers the paths of a share's file rows, pending or
// committed, that begin with prefix, in one walk of the share's path index:
// how a caller numbering a name learns every candidate taken at once.
func (db *DB) PathsWithPrefix(shareID, prefix string) (paths map[string]bool, err error) {
	if !shareid.ValidID(shareID) {
		return nil, ErrNotFound
	}
	err = db.read(func(tx *sql.Tx) error { paths, err = pathsWithPrefix(tx, shareID, prefix); return err })
	return
}

// pathsWithPrefix is PathsWithPrefix inside a transaction.
func pathsWithPrefix(tx *sql.Tx, shareID, prefix string) (map[string]bool, error) {
	rows, err := tx.Query(`SELECT path FROM files WHERE share_id = ? AND path >= ? ORDER BY path`, shareID, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	paths := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(p, prefix) {
			break
		}
		paths[p] = true
	}
	return paths, rows.Err()
}

// DeclareFile adds a pending entry (an early link) to an existing share. A
// path that already exists keeps its slug and its bytes; only a missing path
// gets a row. On a volume that folds case the path takes the share's own
// spelling first (Spelling), so a path folding onto a file is that file.
func (db *DB) DeclareFile(shareID, path string, size int64) (f File, err error) {
	if !shareid.ValidRelPath(path) || size < 0 {
		return File{}, fmt.Errorf("%w: declare %q", ErrBadRequest, path)
	}
	err = db.commit(func(tx *sql.Tx) error {
		h, err := readHead(tx, shareID)
		if err != nil {
			return err
		}
		if path, err = db.spell(tx, shareID, path, ""); err != nil {
			return err
		}
		if f, err = scanFile(tx, shareID, path); err == nil {
			return nil
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		now := time.Now()
		if err := insertPending(tx, shareID, path, size, now); err != nil {
			return err
		}
		if err := recordChange(tx, h.owner, shareID, false, now); err != nil {
			return err
		}
		f, err = scanFile(tx, shareID, path)
		return err
	})
	return
}

// insertPending adds a pending row, with a fresh slug, for a path declared
// at now and not yet uploaded.
func insertPending(tx *sql.Tx, shareID, path string, size int64, now time.Time) error {
	_, err := tx.Exec(`INSERT INTO files(share_id, path, slug, size, pending, declared_at, fold_key) VALUES(?, ?, ?, ?, 1, ?, ?)`,
		shareID, path, newSlug(), size, toNS(now), foldKey(path))
	return err
}

// checkLimits applies the owner's quota, and for an anonymous inbox upload
// the link's own caps, given the share's counters before the commit and the
// size the path held before (0 for a new or pending path). becomingCommitted
// counts both new paths and pending rows, never other uploads still in flight.
func checkLimits(tx *sql.Tx, h shareHead, in CommitInput, oldSize int64, becomingCommitted bool) error {
	if in.Anonymous {
		if !h.inbox {
			return fmt.Errorf("%w: not an inbox", ErrBadRequest)
		}
		if h.closed {
			return fmt.Errorf("%w: inbox is closed", ErrConflict)
		}
		if h.maxBytes > 0 && h.bytes-oldSize+in.Size > h.maxBytes {
			return fmt.Errorf("%w: this link accepts %d bytes in total", ErrInboxFull, h.maxBytes)
		}
		if limit := InboxFileCap(h.maxFiles); becomingCommitted && h.committed+1 > limit {
			return fmt.Errorf("%w: this link accepts %d files", ErrInboxFull, limit)
		}
	}
	var quota int64
	if err := tx.QueryRow(`SELECT quota_bytes FROM users WHERE username = ?`, h.owner).Scan(&quota); err != nil {
		return err
	}
	if quota > 0 {
		var used int64
		if err := tx.QueryRow(`SELECT coalesce((SELECT bytes FROM owner_stats WHERE owner = ?), 0)`, h.owner).Scan(&used); err != nil {
			return err
		}
		if used-oldSize+in.Size > quota {
			return fmt.Errorf("%w: the account's quota is %d bytes", ErrQuota, quota)
		}
	}
	return nil
}

// CommitFile records that the bytes for one path are in place. An existing
// row (pending or committed) keeps its slug and addedAt; a new path gets
// both. On a volume that folds case the path takes the share's own spelling
// first (Spelling): the bytes landed in the file it folds onto. The caller
// has already renamed the staged part into files/.
func (db *DB) CommitFile(in CommitInput) (f File, err error) {
	if !shareid.ValidRelPath(in.Path) || in.Size < 0 {
		return File{}, fmt.Errorf("%w: commit %q", ErrBadRequest, in.Path)
	}
	err = db.commit(func(tx *sql.Tx) error {
		h, err := readHead(tx, in.ShareID)
		if err != nil {
			return err
		}
		if in.Path, err = db.spell(tx, in.ShareID, in.Path, ""); err != nil {
			return err
		}
		old, err := scanFile(tx, in.ShareID, in.Path)
		newPath := errors.Is(err, ErrNotFound)
		if err != nil && !newPath {
			return err
		}
		var oldSize int64
		if !newPath && !old.Pending {
			// An inbox is blind: a stranger's upload never replaces a file,
			// whoever committed it. The name claim keeps senders apart; this
			// is what holds against the owner's own upload of the same name.
			if in.Anonymous {
				return pathTaken(in.Path)
			}
			oldSize = old.Size
		}
		if err := checkLimits(tx, h, in, oldSize, newPath || old.Pending); err != nil {
			return err
		}
		// A text share holds one file. The upload paths refuse a second
		// against a snapshot; this holds against two arriving at once. A
		// replace is exempt only for the committed file it names, so of two
		// uploads replacing the same file the second finds the first beside
		// it, or finds the named file already gone, and is refused.
		if h.text && !in.ReplaceAll && (newPath || old.Pending) {
			replaced := ""
			if in.Replaces != "" {
				if r, err := scanFile(tx, in.ShareID, in.Replaces); err == nil && !r.Pending {
					replaced = r.Path
				} else if err != nil && !errors.Is(err, ErrNotFound) {
					return err
				}
			}
			var other bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM files WHERE share_id = ? AND path <> ? AND path <> ? AND pending = 0)`,
				in.ShareID, in.Path, replaced).Scan(&other); err != nil {
				return err
			}
			if other {
				return ErrTextShare
			}
		}
		now := time.Now()
		ns := toNS(now)
		// A hash the caller does not have is NULL, the one value the sha
		// index treats as absent.
		sha := nullIfEmpty(in.SHA256)
		if newPath {
			_, err = tx.Exec(`INSERT INTO files(share_id, path, slug, size, sha256, mime, pending, committed_at, added_at, upload_session, fold_key)
				VALUES(?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`, in.ShareID, in.Path, newSlug(), in.Size, sha, in.Mime, ns, ns, in.UploadSession, foldKey(in.Path))
		} else {
			added := toNSPtr(old.AddedAt)
			if added == nil {
				added = ns
			}
			_, err = tx.Exec(`UPDATE files SET size = ?, sha256 = ?, mime = ?, pending = 0, committed_at = ?, added_at = ?, upload_session = ?
				WHERE share_id = ? AND path = ?`, in.Size, sha, in.Mime, ns, added, in.UploadSession, in.ShareID, in.Path)
		}
		if err != nil {
			return err
		}
		if err := touch(tx, in.ShareID, now); err != nil {
			return err
		}
		if err := recordChange(tx, h.owner, in.ShareID, false, now); err != nil {
			return err
		}
		f, err = scanFile(tx, in.ShareID, in.Path)
		return err
	})
	return
}

// RemoveFiles deletes rows; the caller removes the bytes afterwards. Every
// path must exist, or nothing is removed. slugs holds the removed rows'
// slugs in paths order, for the caller to remove the tiles they named; it is
// nil whenever err is set.
func (db *DB) RemoveFiles(shareID string, paths []string) (d Share, slugs []string, err error) {
	err = db.commit(func(tx *sql.Tx) error {
		h, err := readHead(tx, shareID)
		if err != nil {
			return err
		}
		for _, p := range paths {
			var slug string
			err := tx.QueryRow(`DELETE FROM files WHERE share_id = ? AND path = ? RETURNING slug`, shareID, p).Scan(&slug)
			if errors.Is(err, sql.ErrNoRows) {
				return notFound("file " + p)
			}
			if err != nil {
				return err
			}
			slugs = append(slugs, slug)
		}
		if err := pruneGalleryRows(tx, shareID); err != nil {
			return err
		}
		if err := clearDanglingEntry(tx, shareID); err != nil {
			return err
		}
		d, err = finishShareWrite(tx, h, shareID, 0)
		return err
	})
	if err != nil {
		slugs = nil
	}
	return
}

// ReplaceEntry commits newPath, gives it oldPath's slug and addedAt, and
// deletes oldPath's row. oldPath == newPath is a no-op. A share whose entry
// is oldPath opens newPath instead: the entry follows the link it opens.
//
// The donated slug's gallery row goes with the old bytes: its width, height,
// duration and date describe the file that just left the share, and keeping it
// would hand the new file's link the old one's measurements. The app re-sends
// the new bytes' metadata through PUT /api/shares/{id}/gallery.
func (db *DB) ReplaceEntry(shareID, newPath, oldPath string) (d Share, err error) {
	if !shareid.ValidRelPath(newPath) || !shareid.ValidRelPath(oldPath) {
		return Share{}, fmt.Errorf("%w: replace", ErrBadRequest)
	}
	if newPath == oldPath {
		return db.Share(shareID)
	}
	err = db.commit(func(tx *sql.Tx) error {
		h, err := readHead(tx, shareID)
		if err != nil {
			return err
		}
		old, err := scanFile(tx, shareID, oldPath)
		if err != nil {
			return err
		}
		if _, err := scanFile(tx, shareID, newPath); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM files WHERE share_id = ? AND path = ?`, shareID, oldPath); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM gallery WHERE share_id = ? AND slug = ?`, shareID, old.Slug); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE files SET slug = ?, added_at = ? WHERE share_id = ? AND path = ?`, old.Slug, toNSPtr(old.AddedAt), shareID, newPath); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE shares SET entry = ? WHERE id = ? AND entry = ?`, newPath, shareID, oldPath); err != nil {
			return err
		}
		if err := pruneGalleryRows(tx, shareID); err != nil {
			return err
		}
		d, err = finishShareWrite(tx, h, shareID, 0)
		return err
	})
	return
}

// ReplaceAll commits newPath and removes every other row. Exactly one
// removed file sharing newPath's base name donates its slug to newPath;
// failing that, a sole removed file donates; otherwise newPath keeps its
// fresh slug. A donated slug's gallery row goes with the bytes that left,
// the same way ReplaceEntry prunes one. If the share's name equalled its single removed file's base
// name, the share is renamed to newPath's base name.
func (db *DB) ReplaceAll(shareID, newPath string) (d Share, err error) {
	if !shareid.ValidRelPath(newPath) {
		return Share{}, fmt.Errorf("%w: replace-all", ErrBadRequest)
	}
	err = db.commit(func(tx *sql.Tx) error {
		h, err := readHead(tx, shareID)
		if err != nil {
			return err
		}
		if _, err := scanFile(tx, shareID, newPath); err != nil {
			return err
		}
		cur, err := scanShare(tx, shareID, 0)
		if err != nil {
			return err
		}
		var removed []File
		for _, f := range cur.Files {
			if f.Path != newPath {
				removed = append(removed, f)
			}
		}
		donor := ""
		var sameName []File
		for _, f := range removed {
			if path.Base(f.Path) == path.Base(newPath) {
				sameName = append(sameName, f)
			}
		}
		switch {
		case len(sameName) == 1:
			donor = sameName[0].Slug
		case len(removed) == 1:
			donor = removed[0].Slug
		}
		if _, err := tx.Exec(`DELETE FROM files WHERE share_id = ? AND path <> ?`, shareID, newPath); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM folders WHERE share_id = ?`, shareID); err != nil {
			return err
		}
		if donor != "" {
			// The donated slug now carries newPath's link, so the row measuring
			// the donor's own bytes goes before the UPDATE holds that slug and
			// the dangling prune below stops seeing it.
			if _, err := tx.Exec(`DELETE FROM gallery WHERE share_id = ? AND slug = ?`, shareID, donor); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE files SET slug = ? WHERE share_id = ? AND path = ?`, donor, shareID, newPath); err != nil {
				return err
			}
		}
		if err := pruneGalleryRows(tx, shareID); err != nil {
			return err
		}
		if err := clearDanglingEntry(tx, shareID); err != nil {
			return err
		}
		if len(removed) == 1 && cur.Name == path.Base(removed[0].Path) {
			if err := setName(tx, shareID, path.Base(newPath)); err != nil {
				return err
			}
		}
		d, err = finishShareWrite(tx, h, shareID, 0)
		return err
	})
	return
}

// under reports whether p is rel itself or lies beneath it.
func under(p, rel string) bool { return p == rel || strings.HasPrefix(p, rel+"/") }

// MoveEntries renames every file and folder record at or beneath from to
// the same relative path under to, and moves the share's entry along with
// it when the entry lay under from. It refuses with ErrPathTaken when an
// entry that stays stands at or beneath to, or a file that stays stands
// above it.
func (db *DB) MoveEntries(shareID, from, to string) (d Share, err error) {
	if !shareid.ValidRelPath(from) || !shareid.ValidRelPath(to) {
		return Share{}, fmt.Errorf("%w: move", ErrBadRequest)
	}
	if under(to, from) {
		return Share{}, ErrIntoItself
	}
	err = db.commit(func(tx *sql.Tx) error {
		h, err := readHead(tx, shareID)
		if err != nil {
			return err
		}
		// On a volume that folds case, to takes the spelling of what stays
		// (Spelling), so a destination the volume takes for a staying entry
		// meets it exactly below; and a destination the volume puts beneath
		// from is beneath it on disk. A rename that changes only case names
		// from itself and is a rename.
		if db.folds() {
			if to, err = db.spell(tx, shareID, to, from); err != nil {
				return err
			}
			if db.underFolded(shareID, to, from) {
				return ErrIntoItself
			}
		}
		if under(to, from) {
			return ErrIntoItself
		}
		cur, err := scanShare(tx, shareID, 0)
		if err != nil {
			return err
		}
		var moving []File
		for _, f := range cur.Files {
			if under(f.Path, from) {
				if f.Pending {
					return ErrMovePending
				}
				moving = append(moving, f)
			}
		}
		var movingFolders []string
		for _, p := range cur.Folders {
			if under(p, from) {
				movingFolders = append(movingFolders, p)
			}
		}
		if len(moving) == 0 && len(movingFolders) == 0 {
			return notFound("file or folder " + from)
		}
		// A folder is never merged into another: nothing that stays may
		// stand at or beneath to, every destination lying there. And a file
		// that stays cannot hold the folder to needs above it. The rule is
		// judged here, inside the write, so a folder added since the caller
		// read the share is judged with the rest.
		for _, f := range cur.Files {
			switch {
			case under(f.Path, from):
			case under(f.Path, to):
				return pathTaken(to)
			case under(to, f.Path):
				return pathTaken(f.Path)
			}
		}
		for _, p := range cur.Folders {
			if !under(p, from) && under(p, to) {
				return pathTaken(to)
			}
		}
		rename := func(p string) string { return to + strings.TrimPrefix(p, from) }
		for _, m := range moving {
			if _, err := tx.Exec(`UPDATE files SET path = ?1, fold_key = ?2 WHERE share_id = ?3 AND path = ?4`, rename(m.Path), foldKey(rename(m.Path)), shareID, m.Path); err != nil {
				return err
			}
		}
		for _, p := range movingFolders {
			if _, err := tx.Exec(`UPDATE folders SET path = ?1, fold_key = ?2 WHERE share_id = ?3 AND path = ?4`, rename(p), foldKey(rename(p)), shareID, p); err != nil {
				return err
			}
		}
		if cur.Entry != "" && under(cur.Entry, from) {
			if _, err := tx.Exec(`UPDATE shares SET entry = ? WHERE id = ?`, rename(cur.Entry), shareID); err != nil {
				return err
			}
		}
		d, err = finishShareWrite(tx, h, shareID, 0)
		return err
	})
	return
}

// ResolveSlug answers the public routes: which stored file a slug names, in
// one seek down files_slug whatever the share holds. ErrNotFound when no
// stored file of the share carries it.
func (db *DB) ResolveSlug(shareID, slug string) (f File, err error) {
	if !shareid.ValidID(shareID) {
		return File{}, ErrNotFound
	}
	err = db.read(func(tx *sql.Tx) error { f, err = scanSlug(tx, shareID, slug); return err })
	return
}

func scanSlug(tx *sql.Tx, shareID, slug string) (File, error) {
	f, err := scanFileRow(tx.QueryRow(`SELECT `+fileCols+` FROM files WHERE share_id = ? AND slug = ?`, shareID, slug))
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, ErrNotFound
	}
	return f, err
}

// Progress is a share's upload state as one snapshot: the counters, the
// declared size of the files still pending, the first files by path and,
// when asked for, the one file a slug names.
type Progress struct {
	Files, Committed int
	Bytes            int64  // committed bytes
	PendingBytes     int64  // what the pending files declared
	Window           []File // the first files by path, at most the window asked for
	Wanted           *File  // the file the slug names, nil when none does
}

// UploadProgress reads Progress for the waiting page's poll without reading
// the share's whole file table: the counters come from the share row, the
// window is one seek down the primary key stopped at window rows, and the
// slug is one seek down files_slug. PendingBytes is summed from the window
// when the window holds every file and otherwise by SQLite over the share's
// rows, and only while a file is pending at all. An empty slug names no
// file. ErrNotFound when the share does not exist.
func (db *DB) UploadProgress(shareID string, window int, slug string) (p Progress, err error) {
	if !shareid.ValidID(shareID) {
		return Progress{}, ErrNotFound
	}
	err = db.read(func(tx *sql.Tx) error {
		p = Progress{}
		err := tx.QueryRow(`SELECT files, committed, bytes FROM shares WHERE id = ?`, shareID).
			Scan(&p.Files, &p.Committed, &p.Bytes)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT `+fileCols+` FROM files WHERE share_id = ? ORDER BY path LIMIT ?`, shareID, window)
		if err != nil {
			return err
		}
		err = eachRow(rows, func() error {
			f, err := scanFileRow(rows)
			if err != nil {
				return err
			}
			p.Window = append(p.Window, f)
			if f.Pending {
				p.PendingBytes += f.Size
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(p.Window) < p.Files && p.Committed < p.Files {
			if err := tx.QueryRow(`SELECT coalesce(sum(size), 0) FROM files WHERE share_id = ? AND pending = 1`,
				shareID).Scan(&p.PendingBytes); err != nil {
				return err
			}
		}
		if slug == "" {
			return nil
		}
		for i := range p.Window {
			if p.Window[i].Slug == slug {
				p.Wanted = &p.Window[i]
				return nil
			}
		}
		f, err := scanSlug(tx, shareID, slug)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err == nil {
			p.Wanted = &f
		}
		return err
	})
	return
}

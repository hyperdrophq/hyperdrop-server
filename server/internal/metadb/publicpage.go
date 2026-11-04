package metadb

import (
	"database/sql"
	"strings"

	"hyperdrop/server/internal/shareid"
)

// The reads a public share page makes: the row without its files, and then
// only the files the page shows. A share of 100,000 files answers a page in
// what that page holds, never in its file count.
//
// Every bound is a parameter. A keyset value comes from a stranger's query
// string, so it only ever bounds a range of the (share_id, path) key and
// never reaches the statement text.

// ShareWithoutFiles reads one share's row with its folders, sources and
// schedules and none of its files: the counters say how many there are.
// Truncated reports that the share holds any.
func (db *DB) ShareWithoutFiles(id string) (d Share, err error) {
	if !shareid.ValidID(id) {
		return Share{}, ErrNotFound
	}
	err = db.read(func(tx *sql.Tx) error {
		// A one-file window with no page budget reads no file row.
		shares, err := fetchPage(tx, []string{id}, 1, 0)
		if err != nil {
			return err
		}
		if len(shares) == 0 {
			return ErrNotFound
		}
		d = shares[0]
		return nil
	})
	return
}

// ShareFilesAfter answers a share's stored files whose relpath sorts after
// after in byte order, at most limit of them, in that order. more reports
// that further files follow the last one.
func (db *DB) ShareFilesAfter(id, after string, limit int) (files []File, more bool, err error) {
	if !shareid.ValidID(id) {
		return nil, false, ErrNotFound
	}
	err = db.read(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT `+fileCols+` FROM files WHERE share_id = ? AND path > ? ORDER BY path LIMIT ?`,
			id, after, limit+1)
		if err != nil {
			return err
		}
		return eachRow(rows, func() error {
			f, err := scanFileRow(rows)
			if err != nil {
				return err
			}
			files = append(files, f)
			return nil
		})
	})
	if len(files) > limit {
		files, more = files[:limit], true
	}
	return
}

// FolderChild is one direct child of a share folder as its file rows imply
// it: a file directly in the folder, or a subfolder with at least one file
// beneath it.
type FolderChild struct {
	Name string // the base name within the folder
	Dir  bool
	File File // the row, for a file
}

// Key is the child's place in its folder: its name, with a slash after a
// subfolder's. Children sort by their keys exactly as their relpaths sort,
// which is what lets a page of them be read down the path key: "a-x" and
// "a.txt" sort before the folder "a/", and "a0" after it.
func (c FolderChild) Key() string { return ChildKey(c.Name, c.Dir) }

// ChildKey is FolderChild.Key for a name and a kind.
func ChildKey(name string, dir bool) string {
	if dir {
		return name + "/"
	}
	return name
}

// ChildRange is the relpath range of the children of folder dir ("" for the
// root) whose keys sort after after: from is the first relpath that may hold
// one (inclusive says whether from itself may), and below, when not empty,
// is the first relpath past the folder. A subfolder key's whole subtree is
// skipped, since "0" is the byte after "/".
func ChildRange(dir, after string) (from string, inclusive bool, below string) {
	prefix := ""
	if dir != "" {
		prefix, below = dir+"/", dir+"0"
	}
	switch name, isDir := strings.CutSuffix(after, "/"); {
	case after == "":
		return prefix, true, below
	case isDir:
		return prefix + name + "0", true, below
	default:
		return prefix + after, false, below
	}
}

// FolderChildren answers the direct children of folder dir ("" for the
// root) whose keys sort after after, at most limit of them in key order;
// more reports that further children follow. A subfolder costs one seek past
// its subtree, so a page reads at most limit file rows plus one per
// subfolder, whatever the subfolders hold. A folder with no file beneath it
// answers nothing.
func (db *DB) FolderChildren(id, dir, after string, limit int) (children []FolderChild, more bool, err error) {
	if !shareid.ValidID(id) {
		return nil, false, ErrNotFound
	}
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	from, inclusive, below := ChildRange(dir, after)
	// The statement is one of four fixed texts: which comparison opens the
	// range and whether one closes it.
	query := func(inclusive bool) string {
		q := `SELECT ` + fileCols + ` FROM files WHERE share_id = ? AND path `
		if inclusive {
			q += `>= ?`
		} else {
			q += `> ?`
		}
		if below != "" {
			q += ` AND path < ?`
		}
		return q + ` ORDER BY path LIMIT ?`
	}
	err = db.read(func(tx *sql.Tx) error {
		for len(children) <= limit {
			args := []any{id, from}
			if below != "" {
				args = append(args, below)
			}
			want := limit + 1 - len(children)
			rows, err := tx.Query(query(inclusive), append(args, want)...)
			if err != nil {
				return err
			}
			jumped := false
			for rows.Next() {
				f, err := scanFileRow(rows)
				if err != nil {
					rows.Close()
					return err
				}
				rest := strings.TrimPrefix(f.Path, prefix)
				if i := strings.IndexByte(rest, '/'); i >= 0 {
					children = append(children, FolderChild{Name: rest[:i], Dir: true})
					from, inclusive, _ = ChildRange(dir, rest[:i]+"/")
					jumped = true
					break
				}
				children = append(children, FolderChild{Name: rest, File: f})
				from, inclusive = f.Path, false
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			// A batch that ran out of rows, or filled the page, ends it; one
			// that met a subfolder seeks past it and reads on.
			if !jumped {
				return nil
			}
		}
		return nil
	})
	if len(children) > limit {
		children, more = children[:limit], true
	}
	return
}

// FolderTotal is how many files lie anywhere beneath a folder and their
// bytes.
type FolderTotal struct {
	Files int
	Bytes int64
}

// FolderTotals answers each named folder's stored files beneath it, at any
// depth: one range aggregate per folder down the (share_id, path) key, which
// reads that folder's rows and no other. A folder holding none answers the
// zero total.
func (db *DB) FolderTotals(id string, dirs []string) (totals map[string]FolderTotal, err error) {
	if !shareid.ValidID(id) {
		return nil, ErrNotFound
	}
	totals = make(map[string]FolderTotal, len(dirs))
	err = db.read(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`SELECT count(*), coalesce(sum(size), 0) FROM files WHERE share_id = ? AND path >= ? AND path < ?`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, dir := range dirs {
			var t FolderTotal
			if err := stmt.QueryRow(id, dir+"/", dir+"0").Scan(&t.Files, &t.Bytes); err != nil {
				return err
			}
			totals[dir] = t
		}
		return nil
	})
	return
}

// StoredPaths answers which of paths the share holds as file rows, pending
// or committed: one seek per path, the paths carried as one JSON parameter.
func (db *DB) StoredPaths(id string, paths []string) (stored map[string]bool, err error) {
	if !shareid.ValidID(id) {
		return nil, ErrNotFound
	}
	stored = map[string]bool{}
	if len(paths) == 0 {
		return stored, nil
	}
	err = db.read(func(tx *sql.Tx) error {
		found, err := queryStrings(tx, `SELECT f.path FROM json_each(?) j JOIN files f ON f.share_id = ? AND f.path = j.value`,
			idSet(paths), id)
		for _, p := range found {
			stored[p] = true
		}
		return err
	})
	return
}

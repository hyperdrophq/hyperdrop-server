package metadb

import (
	"database/sql"
	"testing"
)

// rawFileRow is a files row as stored, the columns a commit writes.
type rawFileRow struct {
	slug          string
	size          int64
	sha           sql.NullString
	mime          string
	pending       bool
	committedAt   sql.NullInt64
	addedAt       sql.NullInt64
	uploadSession string
	foldKey       sql.NullString
}

func readRawFileRow(t *testing.T, db *DB, id, path string) rawFileRow {
	t.Helper()
	var r rawFileRow
	if err := db.read(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT slug, size, sha256, mime, pending, committed_at, added_at, upload_session, fold_key FROM files WHERE share_id = ? AND path = ?`, id, path).
			Scan(&r.slug, &r.size, &r.sha, &r.mime, &r.pending, &r.committedAt, &r.addedAt, &r.uploadSession, &r.foldKey)
	}); err != nil {
		t.Fatalf("row %q: %v", path, err)
	}
	return r
}

// CommitFile and PublishFiles write one row the same way: a new path gets a
// fresh slug and its commit time as its added time, a pending row keeps its
// slug, a replace keeps slug and added time, an empty hash is NULL, and the
// upload session is the commit's (a publish has none).
func TestBothCommitPathsWriteTheSameRow(t *testing.T) {
	sides := []struct {
		name    string
		session string
		write   func(db *DB, id, path string, size int64, sha string) error
	}{
		{"commit", "visitor-1", func(db *DB, id, path string, size int64, sha string) error {
			_, err := db.CommitFile(CommitInput{ShareID: id, Path: path, Size: size, SHA256: sha, Mime: "text/plain", UploadSession: "visitor-1"})
			return err
		}},
		{"publish", "", func(db *DB, id, path string, size int64, sha string) error {
			_, err := db.PublishFiles(id, []PublishCommit{{Path: path, Size: size, SHA256: sha, Mime: "text/plain"}}, nil, nil)
			return err
		}},
	}
	for _, side := range sides {
		t.Run(side.name, func(t *testing.T) {
			db := openTest(t)
			if _, err := db.CreateUser("alice", "alice-password-1", RoleUser, Settings{}); err != nil {
				t.Fatal(err)
			}
			sh := mustShare(t, db, CreateOptions{Owner: "alice", Name: "s", Files: []PendingFile{{Path: "Pend.txt", Size: 4}}})
			declared := readRawFileRow(t, db, sh.ID, "Pend.txt")

			if err := side.write(db, sh.ID, "New.txt", 3, ""); err != nil {
				t.Fatal(err)
			}
			n := readRawFileRow(t, db, sh.ID, "New.txt")
			if n.slug == "" || n.size != 3 || n.sha.Valid || n.mime != "text/plain" || n.pending ||
				!n.committedAt.Valid || n.addedAt != n.committedAt || n.uploadSession != side.session ||
				n.foldKey.String != foldKey("New.txt") {
				t.Fatalf("new row: %+v", n)
			}

			if err := side.write(db, sh.ID, "Pend.txt", 4, "h"); err != nil {
				t.Fatal(err)
			}
			p := readRawFileRow(t, db, sh.ID, "Pend.txt")
			if p.slug != declared.slug || p.size != 4 || p.sha.String != "h" || p.pending ||
				!p.committedAt.Valid || p.addedAt != p.committedAt || p.uploadSession != side.session {
				t.Fatalf("pending row committed: %+v, declared %+v", p, declared)
			}

			if err := side.write(db, sh.ID, "New.txt", 5, "h2"); err != nil {
				t.Fatal(err)
			}
			r := readRawFileRow(t, db, sh.ID, "New.txt")
			if r.slug != n.slug || r.size != 5 || r.sha.String != "h2" || r.addedAt != n.addedAt ||
				r.committedAt.Int64 < n.committedAt.Int64 || r.uploadSession != side.session || r.foldKey != n.foldKey {
				t.Fatalf("replaced row: %+v, was %+v", r, n)
			}
		})
	}
}

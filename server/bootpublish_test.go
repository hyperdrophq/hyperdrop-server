package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// foldingVolume is a data directory served as one whose volume folds case
// (sharefs.SetFoldsCase, metadb.SetFoldCase), holding alice's share with
// the stored files named in stored, and a publish open on it.
type foldingVolume struct {
	t       *testing.T
	dir, id string
	pid     string
	db      *metadb.DB
	fs      *sharefs.FS
}

func openFoldingVolume(t *testing.T, stored map[string]string) *foldingVolume {
	t.Helper()
	v := &foldingVolume{t: t, dir: t.TempDir()}
	v.open()
	if _, err := v.db.CreateUser("alice", "pw", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	d, err := v.db.CreateShare(metadb.CreateOptions{Name: "site", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	v.id = d.ID
	for rel, body := range stored {
		v.upload(rel, body)
	}
	v.pid = shareid.NewPublishID()
	if err := v.fs.OpenStage(v.id, v.pid, "alice"); err != nil {
		t.Fatal(err)
	}
	return v
}

// open is a serving process's database and file layer over the volume.
func (v *foldingVolume) open() {
	v.t.Helper()
	db, err := metadb.Open(v.dir)
	if err != nil {
		v.t.Fatal(err)
	}
	v.t.Cleanup(func() { db.Close() })
	fs, err := sharefs.Open(v.dir)
	if err != nil {
		v.t.Fatal(err)
	}
	fs.SetFoldsCase(true)
	db.SetFoldCase(fs.SamePath)
	v.db, v.fs = db, fs
}

// upload stores rel as an ordinary upload does: the bytes, then the row.
func (v *foldingVolume) upload(rel, body string) {
	v.t.Helper()
	if _, err := v.fs.Write(v.id, rel, strings.NewReader(body)); err != nil {
		v.t.Fatal(err)
	}
	c, err := v.fs.Commit(v.id, rel, int64(len(body)), nil)
	if err != nil {
		v.t.Fatal(err)
	}
	if _, err := v.db.CommitFile(metadb.CommitInput{ShareID: v.id, Path: rel, Size: c.Size, SHA256: c.SHA256, Mime: c.Mime}); err != nil {
		v.t.Fatal(err)
	}
}

// commit writes the journal of a publish making files live and deleting
// deletes, and its rows; marked, the journal is rewritten with what the
// rows hold, as the commit handler does before its first rename.
func (v *foldingVolume) commit(files map[string]string, deletes []string, marked bool) {
	v.t.Helper()
	j := sharefs.Journal{Delete: deletes}
	var commits []metadb.PublishCommit
	for rel, body := range files {
		s, err := v.fs.WriteStaged(v.id, v.pid, rel, strings.NewReader(body))
		if err != nil {
			v.t.Fatal(err)
		}
		j.Files = append(j.Files, rel)
		commits = append(commits, metadb.PublishCommit{Path: rel, Size: s.Size, SHA256: s.SHA256, Mime: s.Mime})
	}
	if err := v.fs.WriteJournal(v.id, v.pid, j); err != nil {
		v.t.Fatal(err)
	}
	res, err := v.db.PublishFiles(v.id, commits, deletes, nil)
	if err != nil {
		v.t.Fatal(err)
	}
	if !marked {
		return
	}
	j.Rows = &sharefs.JournalRows{}
	for i, rel := range j.Files {
		j.Rows.Renames = append(j.Rows.Renames, sharefs.Rename{From: rel, To: res.Files[i].Path})
	}
	for _, f := range res.Deleted {
		j.Rows.Deleted = append(j.Rows.Deleted, f.Path)
	}
	if err := v.fs.WriteJournal(v.id, v.pid, j); err != nil {
		v.t.Fatal(err)
	}
}

// boot is main's boot sequence over the volume after a restart: a fresh
// database and file layer, as main opens them, the boot pass over shares/
// and the settling of the journals it found.
func (v *foldingVolume) boot() (finished, reopened int) {
	v.t.Helper()
	v.db.Close()
	db, err := metadb.Open(v.dir)
	if err != nil {
		v.t.Fatal(err)
	}
	v.t.Cleanup(func() { db.Close() })
	fs, err := sharefs.Open(v.dir)
	if err != nil {
		v.t.Fatal(err)
	}
	fs.SetFoldsCase(true)
	if _, err := fs.Orphans(func(string) bool { return true }); err != nil {
		v.t.Fatal(err)
	}
	v.db, v.fs = db, fs
	finished, reopened, err = bootPublishes(db, fs)
	if err != nil {
		v.t.Fatalf("bootPublishes: %v", err)
	}
	return finished, reopened
}

// everyRowHoldsItsBytes fails unless each of the share's rows names bytes
// under files/ whose digest is the row's.
func (v *foldingVolume) everyRowHoldsItsBytes() {
	v.t.Helper()
	d, err := v.db.Share(v.id)
	if err != nil {
		v.t.Fatal(err)
	}
	for _, f := range d.Files {
		data, err := os.ReadFile(filepath.Join(v.dir, "shares", v.id, "files", filepath.FromSlash(f.Path)))
		sum := sha256.Sum256(data)
		if err != nil || hex.EncodeToString(sum[:]) != f.SHA256 {
			v.t.Errorf("row %s (sha256 %s) names %q (%v)", f.Path, f.SHA256, data, err)
		}
	}
}

// On a volume that folds case, a path a marked journal deleted and a user
// uploaded again under another case before the restart keeps the new
// upload's bytes: the boot pass looks the deleted path up under the
// share's spelling, which finds the new row.
func TestTheBootPassKeepsADeletedPathReuploadedInAnotherCase(t *testing.T) {
	v := openFoldingVolume(t, map[string]string{"a.txt": "old a", "b.txt": "old b"})
	v.commit(map[string]string{"a.txt": "new a"}, []string{"b.txt"}, true)
	v.upload("B.TXT", "upper b")
	if finished, _ := v.boot(); finished != 1 {
		t.Fatalf("finished %d, want 1", finished)
	}
	v.everyRowHoldsItsBytes()
	if f, err := v.db.File(v.id, "B.TXT"); err != nil || f.Pending {
		t.Fatalf("the row of the new upload: %+v %v", f, err)
	}
}

// On a volume that folds case, a commit of a.txt over a stored A.txt is
// spelled A.txt by its transaction; a crash before the journal is marked
// leaves the rows-only verdict, which finds the row under the share's
// spelling and rolls the commit forward.
func TestTheBootPassSpellsAnUnmarkedJournalsPaths(t *testing.T) {
	v := openFoldingVolume(t, map[string]string{"A.txt": "old a"})
	v.commit(map[string]string{"a.txt": "new a"}, nil, false)
	if finished, reopened := v.boot(); finished != 1 || reopened != 0 {
		t.Fatalf("finished %d, reopened %d; want 1 and 0", finished, reopened)
	}
	v.everyRowHoldsItsBytes()
	if f, err := v.db.File(v.id, "A.txt"); err != nil {
		t.Fatalf("A.txt's row: %v", err)
	} else if sum := sha256.Sum256([]byte("new a")); f.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("A.txt's row holds %s", f.SHA256)
	}
}

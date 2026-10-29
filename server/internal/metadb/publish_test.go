package metadb

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func pc(path string, size int64, sha string) PublishCommit {
	return PublishCommit{Path: path, Size: size, SHA256: sha, Mime: "text/plain"}
}

func commitSHA(t *testing.T, db *DB, id, path string, size int64, sha string) File {
	t.Helper()
	f, err := db.CommitFile(CommitInput{ShareID: id, Path: path, Size: size, SHA256: sha, Mime: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func changeSeqs(t *testing.T, db *DB) (n int) {
	t.Helper()
	if err := db.read(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT coalesce(max(seq), 0) FROM changes`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return
}

// snapshot is everything a refused publish must leave as it was.
func snapshot(t *testing.T, db *DB, id string) (Share, int) {
	t.Helper()
	d, err := db.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	return d, changeSeqs(t, db)
}

func TestPublishFilesCommitsEveryRowInOneTransaction(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	keep := commitSHA(t, db, sh.ID, "keep.txt", 3, "k1")
	gone := commitSHA(t, db, sh.ID, "gone.html", 4, "g1")
	if err := db.SetGallery(sh.ID, map[string]GalleryItem{gone.Slug: {Width: 1, Height: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateShare(sh.ID, UpdateOptions{SetEntry: true, Entry: "gone.html"}); err != nil {
		t.Fatal(err)
	}
	before, seq := snapshot(t, db, sh.ID)

	res, err := db.PublishFiles(sh.ID,
		[]PublishCommit{pc("keep.txt", 9, "k2"), pc("new/a.txt", 5, "n1")},
		[]string{"gone.html"},
		map[string]string{"keep.txt": "k1", "gone.html": "g1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 2 || res.Files[0].Path != "keep.txt" || res.Files[0].Slug != keep.Slug ||
		!res.Files[0].AddedAt.Equal(*keep.AddedAt) || res.Files[0].Size != 9 || res.Files[0].SHA256 != "k2" {
		t.Fatalf("replaced row: %+v", res.Files)
	}
	if res.Files[1].Path != "new/a.txt" || res.Files[1].Slug == "" || res.Files[1].Slug == keep.Slug {
		t.Fatalf("new row: %+v", res.Files[1])
	}
	if len(res.Deleted) != 1 || res.Deleted[0].Path != "gone.html" || res.Deleted[0].Slug != gone.Slug {
		t.Fatalf("deleted: %+v", res.Deleted)
	}
	after, seq2 := snapshot(t, db, sh.ID)
	if seq2 != seq+1 {
		t.Fatalf("changes rows added: %d, want 1", seq2-seq)
	}
	if after.Entry != "" || after.Committed != 2 || after.Bytes != 14 {
		t.Fatalf("share after: entry=%q committed=%d bytes=%d", after.Entry, after.Committed, after.Bytes)
	}
	if after.ModifiedAt == nil || (before.ModifiedAt != nil && !after.ModifiedAt.After(*before.ModifiedAt)) {
		t.Fatalf("modified_at: %v -> %v", before.ModifiedAt, after.ModifiedAt)
	}
	g, err := db.Gallery(sh.ID)
	if err != nil || len(g) != 0 {
		t.Fatalf("gallery rows of the deleted file: %v, %v", g, err)
	}
}

func TestPublishFilesChecksTheNetQuota(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{QuotaBytes: ptr(int64(100))}); err != nil {
		t.Fatal(err)
	}
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	commitSHA(t, db, sh.ID, "big", 90, "b")
	commitSHA(t, db, sh.ID, "other", 10, "o")
	// at the edge: 100 used, replace 90 with 5 and add 90 elsewhere = 100
	if _, err := db.PublishFiles(sh.ID, []PublishCommit{pc("big", 5, "b2"), pc("more", 85, "m")}, nil, nil); err != nil {
		t.Fatalf("at the edge: %v", err)
	}
	if _, err := db.PublishFiles(sh.ID, []PublishCommit{pc("big", 6, "b3")}, nil, nil); !errors.Is(err, ErrQuota) {
		t.Fatalf("one byte past: %v", err)
	}
	// deleting frees what a larger commit needs
	if _, err := db.PublishFiles(sh.ID, []PublishCommit{pc("big", 6, "b3")}, []string{"more"}, nil); err != nil {
		t.Fatalf("a delete pays for the growth: %v", err)
	}
}

func TestPublishFilesRefusalChangesNothing(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{QuotaBytes: ptr(int64(100))}); err != nil {
		t.Fatal(err)
	}
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	commitSHA(t, db, sh.ID, "a.txt", 10, "a1")
	commitSHA(t, db, sh.ID, "b.txt", 10, "b1")
	if _, err := db.AddFolder(sh.ID, "dir"); err != nil {
		t.Fatal(err)
	}
	if err := db.commit(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO linked_slugs(share_id, rel, slug) VALUES(?, 'linked.txt', 'ls1')`, sh.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	text := mustShare(t, db, CreateOptions{Name: "t", Owner: "alice", Text: true,
		Files: []PendingFile{{Path: "note.txt", Size: 1}}})

	cases := []struct {
		name    string
		id      string
		commits []PublishCommit
		deletes []string
		base    map[string]string
		check   func(error) bool
	}{
		{"quota", sh.ID, []PublishCommit{pc("new", 1, "n"), pc("huge", 81, "h")}, nil, nil,
			func(e error) bool { return errors.Is(e, ErrQuota) }},
		{"base conflict", sh.ID, []PublishCommit{pc("new", 1, "n"), pc("a.txt", 1, "x")}, []string{"b.txt"},
			map[string]string{"a.txt": "stale", "b.txt": "b1"},
			func(e error) bool {
				var c *ErrPublishConflict
				return errors.As(e, &c) && reflect.DeepEqual(c.Conflicts, []string{"a.txt"})
			}},
		{"a path expected new is held", sh.ID, []PublishCommit{pc("new", 1, "n"), pc("a.txt", 1, "x")}, nil,
			map[string]string{"new": "", "a.txt": ""},
			func(e error) bool {
				var c *ErrPublishConflict
				return errors.As(e, &c) && reflect.DeepEqual(c.Conflicts, []string{"a.txt"})
			}},
		{"deleted path already gone", sh.ID, []PublishCommit{pc("new", 1, "n")}, []string{"b.txt", "ghost.txt"}, nil,
			func(e error) bool {
				var c *ErrPublishConflict
				return errors.As(e, &c) && reflect.DeepEqual(c.Conflicts, []string{"ghost.txt"})
			}},
		{"text share", text.ID, []PublishCommit{pc("two.txt", 1, "t")}, nil, nil,
			func(e error) bool { return errors.Is(e, ErrTextShare) }},
		{"linked entry", sh.ID, []PublishCommit{pc("new", 1, "n"), pc("linked.txt", 1, "l")}, nil, nil,
			func(e error) bool { return errors.Is(e, ErrPathTaken) }},
		{"folder", sh.ID, []PublishCommit{pc("dir", 1, "d")}, nil, nil,
			func(e error) bool { return errors.Is(e, ErrPathTaken) }},
		{"under a file", sh.ID, []PublishCommit{pc("a.txt/inner", 1, "d")}, nil, nil,
			func(e error) bool { return errors.Is(e, ErrPathTaken) }},
		{"same path twice", sh.ID, []PublishCommit{pc("n", 1, "d"), pc("n", 2, "e")}, nil, nil,
			func(e error) bool { return errors.Is(e, ErrPathTaken) }},
	}
	for _, c := range cases {
		beforeS, beforeSeq := snapshot(t, db, c.id)
		_, err := db.PublishFiles(c.id, c.commits, c.deletes, c.base)
		if err == nil || !c.check(err) {
			t.Errorf("%s: err = %v", c.name, err)
			continue
		}
		afterS, afterSeq := snapshot(t, db, c.id)
		if !reflect.DeepEqual(beforeS, afterS) || beforeSeq != afterSeq {
			t.Errorf("%s: the refusal changed the share or the change feed", c.name)
		}
	}
}

func TestPublishFilesSpellsOnAFoldingVolume(t *testing.T) {
	db := openTest(t)
	db.SetFoldCase(bySegment(fullFold))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	old := commitSHA(t, db, sh.ID, "photo.jpg", 1, "p1")
	res, err := db.PublishFiles(sh.ID, []PublishCommit{pc("Photo.jpg", 2, "p2")}, nil, map[string]string{"Photo.jpg": "p1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != "photo.jpg" || res.Files[0].Slug != old.Slug || res.Files[0].Size != 2 {
		t.Fatalf("result: %+v", res.Files)
	}
	if got := paths(t, db, sh.ID); got != "photo.jpg" {
		t.Fatalf("paths = %s", got)
	}
}

func TestPublishFilesRefusesTwoSpellingsOfOneNewNameOnAFoldingVolume(t *testing.T) {
	db := openTest(t)
	db.SetFoldCase(bySegment(fullFold))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	if _, err := db.PublishFiles(sh.ID, []PublishCommit{pc("A.txt", 1, "a"), pc("a.txt", 1, "b")}, nil, nil); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("two spellings of one file: %v", err)
	}
	if got := paths(t, db, sh.ID); got != "" {
		t.Fatalf("a refusal left %q", got)
	}
	res, err := db.PublishFiles(sh.ID, []PublishCommit{pc("Dir/x", 1, "a"), pc("dir/y", 1, "b")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Files[0].Path != "Dir/x" || res.Files[1].Path != "Dir/y" {
		t.Fatalf("spelled %q and %q, want one folder", res.Files[0].Path, res.Files[1].Path)
	}
}

func TestPublishFilesRefusesAFolderRecordBeneathACommit(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	if _, err := db.AddFolder(sh.ID, "x/sub"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PublishFiles(sh.ID, []PublishCommit{pc("x", 1, "a")}, nil, nil); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("file over a folder record's parent: %v", err)
	}
}

func TestPublishFilesAcceptsACommitOverADeletedShape(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	commitSHA(t, db, sh.ID, "x/y", 1, "a")
	commitSHA(t, db, sh.ID, "p", 1, "b")
	if _, err := db.PublishFiles(sh.ID, []PublishCommit{pc("x", 1, "c"), pc("p/q", 1, "d")}, []string{"x/y", "p"}, nil); err != nil {
		t.Fatalf("shapes the publish deletes: %v", err)
	}
}

// The prefix checks stay linear in the commit's size: committing four
// times the files into a share holding four times the rows takes about
// four times as long, where a check scanning every row per path would take
// about sixteen. The ratio, not a wall-clock bound, is what is pinned, so
// a slow machine or the race detector cannot fail it.
func TestPublishFilesPrefixChecksStayLinear(t *testing.T) {
	timed := func(n int) time.Duration {
		db := openTest(t)
		mustUser(t, db, "alice")
		sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
		var held, fresh []PublishCommit
		for i := 0; i < n; i++ {
			held = append(held, pc(fmt.Sprintf("old/d%d/f%d.txt", i%50, i), 1, "o"))
			fresh = append(fresh, pc(fmt.Sprintf("new/d%d/f%d.txt", i%50, i), 1, "n"))
		}
		if _, err := db.PublishFiles(sh.ID, held, nil, nil); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := db.PublishFiles(sh.ID, fresh, nil, nil); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	const small, large = 500, 2000
	timed(small) // warms the statement cache and the allocator
	a, b := timed(small), timed(large)
	if ratio := float64(b) / float64(a); ratio > 8 {
		t.Fatalf("%d commits took %v and %d took %v: %.1fx for 4x the files", small, a, large, b, ratio)
	}
}

// A base of "" says the client expects no file at the path: a path no row
// holds commits as new, and a path the share holds is a conflict.
func TestPublishFilesTakesAnEmptyBaseAsNew(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	commitSHA(t, db, sh.ID, "held.txt", 1, "h")
	if _, err := db.PublishFiles(sh.ID, []PublishCommit{pc("fresh.txt", 1, "f")}, nil, map[string]string{"fresh.txt": ""}); err != nil {
		t.Fatalf("a new path with an empty base: %v", err)
	}
	_, err := db.PublishFiles(sh.ID, []PublishCommit{pc("held.txt", 1, "x")}, nil, map[string]string{"held.txt": ""})
	var c *ErrPublishConflict
	if !errors.As(err, &c) || !reflect.DeepEqual(c.Conflicts, []string{"held.txt"}) {
		t.Fatalf("a held path with an empty base: %v", err)
	}
}

// On a volume that folds case, a base of "" speaks of the path exactly as
// sent: A.txt expected new over a stored a.txt is a replace of a.txt (its
// slug kept, the new bytes taken), while a.txt expected new over a.txt is
// a conflict.
func TestPublishFilesTakesAnEmptyBaseAsTheExactPathOnAFoldingVolume(t *testing.T) {
	db := openTest(t)
	db.SetFoldCase(bySegment(fullFold))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	old := commitSHA(t, db, sh.ID, "a.txt", 1, "a1")
	res, err := db.PublishFiles(sh.ID, []PublishCommit{pc("A.txt", 2, "a2")}, nil, map[string]string{"A.txt": ""})
	if err != nil {
		t.Fatalf("A.txt expected new over a.txt: %v", err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != "a.txt" || res.Files[0].Slug != old.Slug || res.Files[0].SHA256 != "a2" || res.Files[0].Size != 2 {
		t.Fatalf("result: %+v", res.Files)
	}
	_, err = db.PublishFiles(sh.ID, []PublishCommit{pc("a.txt", 3, "a3")}, nil, map[string]string{"a.txt": ""})
	var c *ErrPublishConflict
	if !errors.As(err, &c) || !reflect.DeepEqual(c.Conflicts, []string{"a.txt"}) {
		t.Fatalf("a.txt expected new over a.txt: %v", err)
	}
}

package metadb

import (
	"database/sql"
	"errors"
	"testing"
)

func commit(t *testing.T, db *DB, id, path string, size int64) File {
	t.Helper()
	f, err := db.CommitFile(CommitInput{ShareID: id, Path: path, Size: size, SHA256: "abc", Mime: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCommitFileUpsertsAndKeepsTheSlugOfAPendingEntry(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 5}}})
	pending := d.Files[0]
	f := commit(t, db, d.ID, "a.txt", 7)
	if f.Slug != pending.Slug || f.Pending || f.Size != 7 || f.SHA256 != "abc" || f.Mime != "text/plain" || f.CommittedAt == nil || f.AddedAt == nil {
		t.Fatalf("committed: %+v (pending slug %s)", f, pending.Slug)
	}
	got, _ := db.Share(d.ID)
	if got.Committed != 1 || got.Bytes != 7 || got.FileCount != 1 || got.ModifiedAt == nil {
		t.Fatalf("counters: %+v", got)
	}
	late := commit(t, db, d.ID, "new.txt", 3)
	if late.Slug == "" || late.Slug == f.Slug {
		t.Fatal("a late add mints its own slug")
	}
	again := commit(t, db, d.ID, "a.txt", 9)
	if again.Slug != f.Slug || !again.AddedAt.Equal(*f.AddedAt) {
		t.Fatal("a re-upload keeps slug and addedAt")
	}
	got, _ = db.Share(d.ID)
	if got.Committed != 2 || got.Bytes != 12 {
		t.Fatalf("after re-upload: committed=%d bytes=%d", got.Committed, got.Bytes)
	}
	if r, err := db.ResolveSlug(d.ID, f.Slug); err != nil || r.Path != "a.txt" {
		t.Fatalf("ResolveSlug: %+v, %v", r, err)
	}
	if _, err := db.ResolveSlug(d.ID, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown slug must be ErrNotFound")
	}
	if _, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: "../x", Size: 1}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad path: %v", err)
	}
}

func TestCommitFileEnforcesTheOwnerQuotaInsideTheTransaction(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("alice", "pw", RoleUser, Settings{QuotaBytes: ptr(int64(100))}); err != nil {
		t.Fatal(err)
	}
	a := mustShare(t, db, CreateOptions{Name: "a", Owner: "alice"})
	b := mustShare(t, db, CreateOptions{Name: "b", Owner: "alice"})
	commit(t, db, a.ID, "one", 50)
	commit(t, db, b.ID, "one", 45)
	if _, err := db.CommitFile(CommitInput{ShareID: b.ID, Path: "two", Size: 6}); !errors.Is(err, ErrQuota) {
		t.Fatalf("quota: %v", err)
	}
	commit(t, db, a.ID, "one", 40) // a re-upload that shrinks frees quota
	commit(t, db, b.ID, "two", 6)
}

func TestCommitFileEnforcesInboxCapsForAnonymousSenders(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	c := mustShare(t, db, CreateOptions{Name: "inbox", Owner: "alice", Inbox: true, MaxBytes: 10, MaxFiles: 2})
	anon := func(path string, size int64) error {
		_, err := db.CommitFile(CommitInput{ShareID: c.ID, Path: path, Size: size, Anonymous: true, UploadSession: "v1"})
		return err
	}
	if err := anon("a", 6); err != nil {
		t.Fatal(err)
	}
	if err := anon("b", 5); !errors.Is(err, ErrInboxFull) {
		t.Fatalf("bytes cap: %v", err)
	}
	if err := anon("b", 4); err != nil {
		t.Fatal(err)
	}
	if err := anon("c", 0); !errors.Is(err, ErrInboxFull) {
		t.Fatalf("files cap: %v", err)
	}
	commit(t, db, c.ID, "owner-file", 100) // the owner is not capped by the link's limits
	got, _ := db.Share(c.ID)
	if got.Files[0].UploadSession != "v1" {
		t.Fatalf("upload session not recorded: %+v", got.Files[0])
	}
	if _, err := db.UpdateShare(c.ID, UpdateOptions{SetClosed: true, Closed: true}); err != nil {
		t.Fatal(err)
	}
	if err := anon("d", 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("closed inbox: %v", err)
	}
}

func TestRemoveFilesUpdatesCountersAndRefusesUnknownPaths(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	a := commit(t, db, d.ID, "a", 1)
	commit(t, db, d.ID, "b", 2)
	got, slugs, err := db.RemoveFiles(d.ID, []string{"a"})
	if err != nil || len(got.Files) != 1 || got.Bytes != 2 || got.Committed != 1 {
		t.Fatalf("remove: %+v, %v", got, err)
	}
	if len(slugs) != 1 || slugs[0] != a.Slug {
		t.Fatalf("removed slugs = %v, want [%s]", slugs, a.Slug)
	}
	if _, _, err := db.RemoveFiles(d.ID, []string{"zzz"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown path: %v", err)
	}
	// Create, two commits and the remove all touch one share back to back,
	// so the journal coalesces them into a single row.
	if n, _ := changeRows(t, db); n != 1 {
		t.Fatalf("changes = %d, want one coalesced row", n)
	}
}

func TestReplaceEntryDonatesTheSlug(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	old := commit(t, db, d.ID, "v1.pdf", 10)
	commit(t, db, d.ID, "v2.pdf", 12)
	got, err := db.ReplaceEntry(d.ID, "v2.pdf", "v1.pdf")
	if err != nil || len(got.Files) != 1 || got.Files[0].Path != "v2.pdf" || got.Files[0].Slug != old.Slug || got.Bytes != 12 {
		t.Fatalf("replace: %+v, %v", got, err)
	}
	if _, err := db.ReplaceEntry(d.ID, "v2.pdf", "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing old: %v", err)
	}
	if _, err := db.ReplaceEntry(d.ID, "v2.pdf", "v2.pdf"); err != nil {
		t.Fatal("same path is a no-op")
	}
}

// TestReplaceEntryMovesTheEntryWithTheSlug pins that a share opening a page
// opens the page that inherited the link: the entry follows the replaced path
// onto the new one rather than naming a path the share no longer holds.
func TestReplaceEntryMovesTheEntryWithTheSlug(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "site", Owner: "alice", Entry: "index.html"})
	commit(t, db, d.ID, "index.html", 10)
	commit(t, db, d.ID, "index2.html", 12)
	got, err := db.ReplaceEntry(d.ID, "index2.html", "index.html")
	if err != nil || got.Entry != "index2.html" {
		t.Fatalf("replace: entry %q, %v", got.Entry, err)
	}
	other := mustShare(t, db, CreateOptions{Name: "site", Owner: "alice", Entry: "index.html"})
	commit(t, db, other.ID, "index.html", 1)
	commit(t, db, other.ID, "a.html", 1)
	commit(t, db, other.ID, "b.html", 1)
	if got, err = db.ReplaceEntry(other.ID, "b.html", "a.html"); err != nil || got.Entry != "index.html" {
		t.Fatalf("replacing another file: entry %q, %v", got.Entry, err)
	}
}

func TestReplaceAllFollowsTheDonationRules(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	// One removed file with the same base name donates.
	d := mustShare(t, db, CreateOptions{Name: "report.pdf", Owner: "alice"})
	old := commit(t, db, d.ID, "old/report.pdf", 1)
	commit(t, db, d.ID, "other.txt", 1)
	commit(t, db, d.ID, "new/report.pdf", 5)
	if err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO gallery(share_id, slug, width) VALUES(?, ?, 10)`, d.ID, old.Slug)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := db.ReplaceAll(d.ID, "new/report.pdf")
	if err != nil || len(got.Files) != 1 || got.Files[0].Slug != old.Slug || got.Name != "report.pdf" {
		t.Fatalf("same-name donation: %+v, %v", got, err)
	}
	var gallerySlugs []string
	if err := db.read(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT slug FROM gallery WHERE share_id = ?`, d.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			gallerySlugs = append(gallerySlugs, s)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	// The donated slug now names the SURVIVING file, so the row measuring the
	// donor's own bytes goes with it rather than following the link onto bytes
	// it never described.
	if len(gallerySlugs) != 0 {
		t.Fatalf("gallery row must go with the donated slug: %v", gallerySlugs)
	}
	// A sole removed file donates and the share named after it is renamed.
	e := mustShare(t, db, CreateOptions{Name: "a.txt", Owner: "alice"})
	sole := commit(t, db, e.ID, "a.txt", 1)
	fresh := commit(t, db, e.ID, "b.txt", 1)
	got, err = db.ReplaceAll(e.ID, "b.txt")
	if err != nil || got.Files[0].Slug != sole.Slug || got.Name != "b.txt" || fresh.Slug == sole.Slug {
		t.Fatalf("sole donation: %+v, %v", got, err)
	}
	// Several removed files, none matching: the fresh slug stands.
	g := mustShare(t, db, CreateOptions{Name: "many", Owner: "alice"})
	commit(t, db, g.ID, "p", 1)
	commit(t, db, g.ID, "q", 1)
	n := commit(t, db, g.ID, "r", 1)
	got, err = db.ReplaceAll(g.ID, "r")
	if err != nil || got.Files[0].Slug != n.Slug || got.Name != "many" {
		t.Fatalf("no donation: %+v, %v", got, err)
	}
}

func TestMoveEntriesMovesFilesFoldersAndTheEntry(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "site", Owner: "alice", Entry: "src/index.html"})
	idx := commit(t, db, d.ID, "src/index.html", 1)
	commit(t, db, d.ID, "src/css/a.css", 1)
	commit(t, db, d.ID, "readme", 1)
	if _, err := db.AddFolder(d.ID, "src/empty"); err != nil {
		t.Fatal(err)
	}
	got, err := db.MoveEntries(d.ID, "src", "www")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, f := range got.Files {
		paths[f.Path] = f.Slug
	}
	if paths["www/index.html"] != idx.Slug || paths["www/css/a.css"] == "" || paths["readme"] == "" || len(paths) != 3 {
		t.Fatalf("moved files: %v", paths)
	}
	if got.Entry != "www/index.html" || len(got.Folders) != 1 || got.Folders[0] != "www/empty" {
		t.Fatalf("entry/folders: %q %v", got.Entry, got.Folders)
	}
	for name, tc := range map[string][2]string{"into itself": {"www", "www/x"}, "same": {"www", "www"}} {
		if _, err := db.MoveEntries(d.ID, tc[0], tc[1]); !errors.Is(err, ErrIntoItself) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := db.MoveEntries(d.ID, "nothing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nothing at from: %v", err)
	}
	if _, err := db.MoveEntries(d.ID, "readme", "www/index.html"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("taken: %v", err)
	}
	if _, err := db.MoveEntries(d.ID, "readme", "www/index.html/under"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("beneath a file: %v", err)
	}
	if _, err := db.AddFolder(d.ID, "taken"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MoveEntries(d.ID, "readme", "taken"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("folder record at destination: %v", err)
	}
	if _, err := db.DeclareFile(d.ID, "up.bin", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MoveEntries(d.ID, "up.bin", "moved.bin"); !errors.Is(err, ErrMovePending) {
		t.Fatalf("pending: %v", err)
	}
}

// TestMoveEntriesNeverMergesAFolder pins the one collision rule inside the
// write: nothing that stays may stand at or beneath the destination, and no
// file that stays may stand where the destination needs a folder.
func TestMoveEntriesNeverMergesAFolder(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	cases := []struct {
		name     string
		files    []string
		folders  []string
		from, to string
		taken    string
	}{
		{"a file onto a folder record", []string{"a/f"}, []string{"b/f"}, "a/f", "b/f", "b/f"},
		{"a folder into one holding a record", []string{"a/g"}, []string{"b/f"}, "a", "b", "b"},
		{"a record onto a record", nil, []string{"a/x", "b/x"}, "a", "b", "b"},
		{"a file into one holding a file", []string{"a/g", "b/h"}, nil, "a", "b", "b"},
		{"records beneath a file", []string{"x"}, []string{"a/r"}, "a", "x/y", "x"},
		{"a file beneath a file", []string{"x", "a/g"}, nil, "a", "x/y", "x"},
	}
	for _, tc := range cases {
		d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
		for _, f := range tc.files {
			commit(t, db, d.ID, f, 1)
		}
		for _, f := range tc.folders {
			if _, err := db.AddFolder(d.ID, f); err != nil {
				t.Fatalf("%s: folder %s: %v", tc.name, f, err)
			}
		}
		_, err := db.MoveEntries(d.ID, tc.from, tc.to)
		if !errors.Is(err, ErrPathTaken) || err.Error() != "a file or folder already stands at "+tc.taken {
			t.Errorf("%s: %v, want path taken at %s", tc.name, err, tc.taken)
		}
	}
}

// TestRemovingTheEntryPageClearsIt pins that the View answer never outlives
// the file it names, whichever route removed that file.
func TestRemovingTheEntryPageClearsIt(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "site", Owner: "alice", Entry: "index.html"})
	commit(t, db, d.ID, "index.html", 1)
	commit(t, db, d.ID, "other.html", 1)
	got, _, err := db.RemoveFiles(d.ID, []string{"index.html"})
	if err != nil || got.Entry != "" {
		t.Fatalf("remove: entry = %q, %v", got.Entry, err)
	}

	e := mustShare(t, db, CreateOptions{Name: "site", Owner: "alice", Entry: "index.html"})
	commit(t, db, e.ID, "index.html", 1)
	commit(t, db, e.ID, "next.html", 1)
	got, err = db.ReplaceAll(e.ID, "next.html")
	if err != nil || got.Entry != "" {
		t.Fatalf("replace all: entry = %q, %v", got.Entry, err)
	}

	f := mustShare(t, db, CreateOptions{Name: "site", Owner: "alice", Entry: "index.html",
		Files: []PendingFile{{Path: "index.html", Size: 1}}})
	if err := db.RemovePending(f.ID, "index.html"); err != nil {
		t.Fatal(err)
	}
	if got, _ = db.Share(f.ID); got.Entry != "" {
		t.Fatalf("remove pending: entry = %q", got.Entry)
	}

	// An entry the share still holds is left alone.
	g := mustShare(t, db, CreateOptions{Name: "site", Owner: "alice", Entry: "index.html"})
	commit(t, db, g.ID, "index.html", 1)
	commit(t, db, g.ID, "spare.html", 1)
	got, _, err = db.RemoveFiles(g.ID, []string{"spare.html"})
	if err != nil || got.Entry != "index.html" {
		t.Fatalf("kept entry: %q, %v", got.Entry, err)
	}
}

// TestAMissingHashIsStoredAsNULL pins that a file committed without a hash
// holds no hash at all, which is what keeps it out of the sha index.
func TestAMissingHashIsStoredAsNULL(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	if _, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: "a", Size: 1}); err != nil {
		t.Fatal(err)
	}
	commit(t, db, d.ID, "b", 1)
	// A re-upload that loses the hash clears it too.
	if _, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: "b", Size: 2}); err != nil {
		t.Fatal(err)
	}
	isNull := func(path string) bool {
		t.Helper()
		var null bool
		if err := db.read(func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT sha256 IS NULL FROM files WHERE share_id = ? AND path = ?`, d.ID, path).Scan(&null)
		}); err != nil {
			t.Fatal(err)
		}
		return null
	}
	if !isNull("a") || !isNull("b") {
		t.Fatalf("sha256 IS NULL: a=%v b=%v, want both", isNull("a"), isNull("b"))
	}
	commit(t, db, d.ID, "c", 1)
	if isNull("c") {
		t.Fatal("a hash the caller has must be stored")
	}
}

func TestFileAnswersOneRow(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "waiting.bin", Size: 9}}})
	landed := commit(t, db, d.ID, "a.txt", 7)

	got, err := db.File(d.ID, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got.Slug != landed.Slug || got.Size != 7 || got.Pending || got.SHA256 != "abc" {
		t.Fatalf("committed row = %+v", got)
	}
	waiting, err := db.File(d.ID, "waiting.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !waiting.Pending || waiting.Size != 9 {
		t.Fatalf("pending row = %+v", waiting)
	}
	if _, err := db.File(d.ID, "nothing.txt"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a path the share does not hold = %v, want ErrNotFound", err)
	}
	if _, err := db.File("no-such-id", "a.txt"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown share = %v, want ErrNotFound", err)
	}
	// A path no relpath check would pass never reaches the query.
	if _, err := db.File(d.ID, "../escape"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a traversal = %v, want ErrNotFound", err)
	}
}

// UploadProgress answers the waiting page's poll from one snapshot: the
// counters, a window of the first files by path, the declared size of every
// pending file whether or not the window holds it, and the file a slug names
// inside or outside the window.
func TestUploadProgressAnswersTheWholeShareFromAWindow(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{
		{Path: "a", Size: 1}, {Path: "b", Size: 2}, {Path: "c", Size: 4}, {Path: "d", Size: 8}, {Path: "e", Size: 16}}})
	commit(t, db, d.ID, "a", 1)
	commit(t, db, d.ID, "d", 8)
	slug := func(p string) string { return fileSlug(t, db, d.ID, p) }

	p, err := db.UploadProgress(d.ID, 2, slug("e"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Files != 5 || p.Committed != 2 || p.Bytes != 9 || p.PendingBytes != 22 {
		t.Fatalf("totals: files=%d committed=%d bytes=%d pending=%d, want 5 2 9 22",
			p.Files, p.Committed, p.Bytes, p.PendingBytes)
	}
	if len(p.Window) != 2 || p.Window[0].Path != "a" || p.Window[1].Path != "b" || !p.Window[1].Pending {
		t.Fatalf("window: %+v", p.Window)
	}
	if p.Wanted == nil || p.Wanted.Path != "e" || !p.Wanted.Pending || p.Wanted.Size != 16 {
		t.Fatalf("the slug outside the window: %+v", p.Wanted)
	}
	if p, _ := db.UploadProgress(d.ID, 2, slug("b")); p.Wanted == nil || p.Wanted.Path != "b" {
		t.Fatalf("the slug inside the window: %+v", p.Wanted)
	}
	// A window holding every file sums the pending sizes itself.
	if p, _ := db.UploadProgress(d.ID, 10, ""); len(p.Window) != 5 || p.PendingBytes != 22 || p.Wanted != nil {
		t.Fatalf("whole window: %d files, pending=%d, wanted=%+v", len(p.Window), p.PendingBytes, p.Wanted)
	}
	for _, s := range []string{"", "nope", slug("a") + "x"} {
		if p, err := db.UploadProgress(d.ID, 2, s); err != nil || p.Wanted != nil {
			t.Errorf("slug %q: wanted=%+v err=%v", s, p.Wanted, err)
		}
	}
	for _, p := range []string{"b", "c", "e"} {
		commit(t, db, d.ID, p, 3)
	}
	if p, _ := db.UploadProgress(d.ID, 2, ""); p.Committed != 5 || p.Bytes != 18 || p.PendingBytes != 0 {
		t.Fatalf("every file landed: committed=%d bytes=%d pending=%d", p.Committed, p.Bytes, p.PendingBytes)
	}
	for _, id := range []string{"abcdefghjk", "../x", ""} {
		if _, err := db.UploadProgress(id, 2, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("UploadProgress(%q) = %v, want ErrNotFound", id, err)
		}
	}
}

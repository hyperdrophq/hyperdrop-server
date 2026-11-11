package metadb

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/shareid"
)

// fileLinkShare is a share of alice's holding committed a.txt and b.txt.
func fileLinkShare(t *testing.T, db *DB) Share {
	t.Helper()
	if _, err := db.CreateUser("alice", "pw-alice", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	files := []PendingFile{{Path: "a.txt", Size: 1}, {Path: "b.txt", Size: 1}}
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice", Folder: true, Files: files})
	for _, f := range files {
		if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: f.Path, Size: f.Size, Mime: "text/plain"}); err != nil {
			t.Fatal(err)
		}
	}
	return sh
}

func fileKeyRows(t *testing.T, db *DB) (n int) {
	t.Helper()
	err := db.read(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM file_links`).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMintFileKeysIsIdempotent(t *testing.T) {
	db := openTest(t)
	sh := fileLinkShare(t, db)
	slug := fileSlug(t, db, sh.ID, "a.txt")
	first, err := db.MintFileKeys(sh.ID, []string{slug}, time.Now())
	if err != nil || !shareid.ValidFileKey(first[slug]) {
		t.Fatalf("first mint: %v, %v", first, err)
	}
	second, err := db.MintFileKeys(sh.ID, []string{slug}, time.Now())
	if err != nil || second[slug] != first[slug] {
		t.Fatalf("second mint: %v, %v, want %s", second, err, first[slug])
	}
	if keys, err := db.FileKeys(sh.ID); err != nil || len(keys) != 1 || keys[slug] != first[slug] {
		t.Fatalf("FileKeys = %v, %v", keys, err)
	}
	gotShare, gotSlug, err := db.ResolveFileKey(first[slug])
	if err != nil || gotShare != sh.ID || gotSlug != slug {
		t.Fatalf("ResolveFileKey = %s, %s, %v", gotShare, gotSlug, err)
	}
}

func TestMintFileKeysLeavesOutUnknownSlugs(t *testing.T) {
	db := openTest(t)
	sh := fileLinkShare(t, db)
	slug := fileSlug(t, db, sh.ID, "a.txt")
	keys, err := db.MintFileKeys(sh.ID, []string{slug, shareid.NewSlug(), "not-a-slug"}, time.Now())
	if err != nil || len(keys) != 1 || keys[slug] == "" {
		t.Fatalf("keys = %v, %v", keys, err)
	}
	if n := fileKeyRows(t, db); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
	if _, err := db.MintFileKeys("nope", []string{slug}, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a bad share id: %v, want ErrNotFound", err)
	}
}

func TestMintFileKeysRefusesAnInbox(t *testing.T) {
	db := openTest(t)
	fileLinkShare(t, db)
	in := mustShare(t, db, CreateOptions{Name: "in", Owner: "alice", Inbox: true})
	if _, err := db.MintFileKeys(in.ID, []string{shareid.NewSlug()}, time.Now()); !errors.Is(err, ErrInbox) {
		t.Fatalf("err = %v, want ErrInbox", err)
	}
	if n := fileKeyRows(t, db); n != 0 {
		t.Fatalf("rows = %d, want none", n)
	}
}

func TestMintFileKeysCoversPendingAndLinkedEntries(t *testing.T) {
	db := openTest(t)
	sh := fileLinkShare(t, db)
	if _, err := db.CreateUser("bob", "pw-bob", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	pend := mustShare(t, db, CreateOptions{Name: "p", Owner: "bob", Folder: true, Files: []PendingFile{{Path: "p.txt", Size: 1}}})
	pendSlug := fileSlug(t, db, pend.ID, "p.txt")
	linkedSlug := shareid.NewSlug()
	err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO linked_slugs(share_id, rel, slug) VALUES(?, 'x/y.txt', ?)`, sh.ID, linkedSlug)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if keys, err := db.MintFileKeys(pend.ID, []string{pendSlug}, time.Now()); err != nil || keys[pendSlug] == "" {
		t.Fatalf("a pending file: %v, %v", keys, err)
	}
	if keys, err := db.MintFileKeys(sh.ID, []string{linkedSlug}, time.Now()); err != nil || keys[linkedSlug] == "" {
		t.Fatalf("a linked entry: %v, %v", keys, err)
	}
	if keys, err := db.MintFileKeys(sh.ID, []string{pendSlug}, time.Now()); err != nil || len(keys) != 0 {
		t.Fatalf("another share's slug: %v, %v", keys, err)
	}
}

func TestStopFileKeyThenMintMakesANewKey(t *testing.T) {
	db := openTest(t)
	sh := fileLinkShare(t, db)
	slug := fileSlug(t, db, sh.ID, "a.txt")
	first, err := db.MintFileKeys(sh.ID, []string{slug}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.StopFileKey(sh.ID, slug, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.StopFileKey(sh.ID, slug, time.Now()); err != nil {
		t.Fatalf("stopping a file with no key: %v", err)
	}
	if _, _, err := db.ResolveFileKey(first[slug]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the stopped key resolves: %v", err)
	}
	second, err := db.MintFileKeys(sh.ID, []string{slug}, time.Now())
	if err != nil || second[slug] == "" || second[slug] == first[slug] {
		t.Fatalf("new key %v, old %v, %v", second, first, err)
	}
}

// newestChange answers the newest journal row's seq and share.
func newestChange(t *testing.T, db *DB) (seq int64, shareID string) {
	t.Helper()
	err := db.read(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT seq, share_id FROM changes ORDER BY seq DESC LIMIT 1`).Scan(&seq, &shareID)
	})
	if err != nil {
		t.Fatal(err)
	}
	return seq, shareID
}

func shareModifiedAt(t *testing.T, db *DB, id string) time.Time {
	t.Helper()
	d, err := db.Share(id)
	if err != nil || d.ModifiedAt == nil {
		t.Fatalf("share %s: %v, %v", id, d.ModifiedAt, err)
	}
	return *d.ModifiedAt
}

// A mint that inserts and a stop that deletes each write one journal row
// (a write to the same share coalesces into the newest row under a new
// seq); a repeat mint and a stop of a file with no key write none.
func TestMintAndStopRecordAJournalRowWithoutMovingModifiedAt(t *testing.T) {
	db := openTest(t)
	sh := fileLinkShare(t, db)
	slug := fileSlug(t, db, sh.ID, "a.txt")
	modified := shareModifiedAt(t, db, sh.ID)
	base, _ := newestChange(t, db)
	later := modified.Add(time.Hour)

	if _, err := db.MintFileKeys(sh.ID, []string{slug}, later); err != nil {
		t.Fatal(err)
	}
	minted, id := newestChange(t, db)
	if minted <= base || id != sh.ID {
		t.Fatalf("after a mint the newest row is %d for %s, want past %d for %s", minted, id, base, sh.ID)
	}
	if _, deleted := changeRows(t, db); deleted {
		t.Fatal("a mint recorded a deletion")
	}
	if _, err := db.MintFileKeys(sh.ID, []string{slug}, later); err != nil {
		t.Fatal(err)
	}
	if seq, _ := newestChange(t, db); seq != minted {
		t.Fatalf("a repeat mint moved the journal to %d from %d", seq, minted)
	}

	if err := db.StopFileKey(sh.ID, slug, later); err != nil {
		t.Fatal(err)
	}
	stopped, id := newestChange(t, db)
	if stopped <= minted || id != sh.ID {
		t.Fatalf("after a stop the newest row is %d for %s, want past %d for %s", stopped, id, minted, sh.ID)
	}
	if _, deleted := changeRows(t, db); deleted {
		t.Fatal("a stop recorded a deletion")
	}
	if err := db.StopFileKey(sh.ID, slug, later); err != nil {
		t.Fatal(err)
	}
	if seq, _ := newestChange(t, db); seq != stopped {
		t.Fatalf("stopping a file with no key moved the journal to %d from %d", seq, stopped)
	}

	if got := shareModifiedAt(t, db, sh.ID); !got.Equal(modified) {
		t.Fatalf("modifiedAt moved to %v from %v", got, modified)
	}
}

func TestResolveFileKeyRefusesABadShapeWithoutQuerying(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// On a closed database any query fails with something other than
	// ErrNotFound, so ErrNotFound proves the shape check answered alone.
	if _, _, err := db.ResolveFileKey(shareid.NewFileKey()); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("a well-formed key on a closed database: %v, want a query error", err)
	}
	for _, k := range []string{"", "short", strings.Repeat("0", 22), shareid.NewSlug(), strings.Repeat("A", 19) + "%2F"} {
		if _, _, err := db.ResolveFileKey(k); !errors.Is(err, ErrNotFound) {
			t.Errorf("%q: %v, want ErrNotFound", k, err)
		}
	}
}

func TestFileKeyFollowsAReplaceButNotAReupload(t *testing.T) {
	db := openTest(t)
	sh := fileLinkShare(t, db)
	slug := fileSlug(t, db, sh.ID, "a.txt")
	keys, err := db.MintFileKeys(sh.ID, []string{slug}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key := keys[slug]

	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "c.txt", Size: 2, Mime: "text/plain", Replaces: "a.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReplaceEntry(sh.ID, "c.txt", "a.txt"); err != nil {
		t.Fatal(err)
	}
	gotShare, gotSlug, err := db.ResolveFileKey(key)
	if err != nil || gotShare != sh.ID || gotSlug != slug {
		t.Fatalf("after the replace: %s, %s, %v", gotShare, gotSlug, err)
	}
	f, err := db.ResolveSlug(sh.ID, gotSlug)
	if err != nil || f.Path != "c.txt" {
		t.Fatalf("the slug names %+v, %v", f, err)
	}

	if _, _, err := db.RemoveFiles(sh.ID, []string{"c.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "c.txt", Size: 2, Mime: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	if _, slug2, err := db.ResolveFileKey(key); err != nil || slug2 != slug {
		t.Fatalf("the key row is untouched until the sweep: %s, %v", slug2, err)
	}
	if _, err := db.ResolveSlug(sh.ID, slug); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the old slug resolves after a fresh upload: %v", err)
	}
	if n, err := db.PruneOrphanFileLinks(); err != nil || n != 1 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	if _, _, err := db.ResolveFileKey(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the key outlives the sweep: %v", err)
	}
}

func TestFileKeysCascadeWithTheShare(t *testing.T) {
	db := openTest(t)
	sh := fileLinkShare(t, db)
	slug := fileSlug(t, db, sh.ID, "a.txt")
	keys, err := db.MintFileKeys(sh.ID, []string{slug}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteShare(sh.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ResolveFileKey(keys[slug]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the key outlives its share: %v", err)
	}
	if n := fileKeyRows(t, db); n != 0 {
		t.Fatalf("rows = %d", n)
	}
}

func TestPruneOrphanFileLinksKeepsHiddenLinkedEntries(t *testing.T) {
	db := openTest(t)
	sh := fileLinkShare(t, db)
	hidden := shareid.NewSlug()
	err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO linked_slugs(share_id, rel, slug) VALUES(?, 'h.txt', ?)`, sh.ID, hidden)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	aSlug := fileSlug(t, db, sh.ID, "a.txt")
	keys, err := db.MintFileKeys(sh.ID, []string{hidden, aSlug}, time.Now())
	if err != nil || len(keys) != 2 {
		t.Fatalf("mint: %v, %v", keys, err)
	}
	if _, _, err := db.RemoveFiles(sh.ID, []string{"a.txt"}); err != nil {
		t.Fatal(err)
	}
	if n, err := db.PruneOrphanFileLinks(); err != nil || n != 1 {
		t.Fatalf("prune = %d, %v, want the deleted file's key only", n, err)
	}
	if _, _, err := db.ResolveFileKey(keys[hidden]); err != nil {
		t.Fatalf("the hidden linked entry's key: %v", err)
	}
	if _, _, err := db.ResolveFileKey(keys[aSlug]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the deleted file's key: %v", err)
	}
}

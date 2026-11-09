package metadb

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"hyperdrop/server/internal/shareid"
)

func mustUser(t *testing.T, db *DB, name string) User {
	t.Helper()
	u, err := db.CreateUser(name, "pw", RoleUser, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustShare(t *testing.T, db *DB, o CreateOptions) Share {
	t.Helper()
	d, err := db.CreateShare(o)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func changeRows(t *testing.T, db *DB) (n int, lastDeleted bool) {
	t.Helper()
	err := db.read(func(tx *sql.Tx) error {
		if err := tx.QueryRow(`SELECT count(*) FROM changes`).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		return tx.QueryRow(`SELECT deleted FROM changes ORDER BY seq DESC LIMIT 1`).Scan(&lastDeleted)
	})
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestCreateShareMintsAnIDDeclaresFilesAndRecordsAChange(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	exp := at.Add(time.Hour)
	d := mustShare(t, db, CreateOptions{Name: "Trip", Owner: "alice", Folder: true, ExpiresAt: &exp,
		Files: []PendingFile{{Path: "a.jpg", Size: 10}, {Path: "sub/b.jpg", Size: 20}}})
	if !shareid.ValidID(d.ID) || d.Name != "Trip" || d.Owner != "alice" || !d.Folder || d.ExpiresAt == nil {
		t.Fatalf("created: %+v", d)
	}
	if d.FileCount != 2 || d.Committed != 0 || d.Bytes != 0 || len(d.Files) != 2 || !d.Files[0].Pending || d.Files[0].Slug == "" || d.Files[0].Size != 10 {
		t.Fatalf("pending files: %+v", d.Files)
	}
	if d.Files[0].Slug == d.Files[1].Slug {
		t.Fatal("slugs must differ")
	}
	got, err := db.Share(d.ID)
	if err != nil || got.ID != d.ID || len(got.Files) != 2 || got.CreatedAt.IsZero() {
		t.Fatalf("Share(): %+v, %v", got, err)
	}
	if n, del := changeRows(t, db); n != 1 || del {
		t.Fatalf("changes: n=%d deleted=%v", n, del)
	}
	if _, err := db.Share("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid id: %v", err)
	}
	if _, err := db.Share("abcdefghjk"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing id: %v", err)
	}
}

func TestCreateShareValidatesItsInputs(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	for name, o := range map[string]CreateOptions{
		"no owner":          {Name: "x"},
		"unknown owner":     {Name: "x", Owner: "ghost"},
		"bad entry":         {Name: "x", Owner: "alice", Entry: "../a"},
		"two view answers":  {Name: "x", Owner: "alice", Media: true, Listing: true},
		"bad manifest":      {Name: "x", Owner: "alice", Files: []PendingFile{{Path: "../a", Size: 1}}},
		"dup manifest":      {Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a", Size: 1}, {Path: "a", Size: 2}}},
		"negative size":     {Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a", Size: -1}}},
		"caller id invalid": {ID: "bad", Name: "x", Owner: "alice"},
	} {
		if _, err := db.CreateShare(o); err == nil {
			t.Errorf("%s: created", name)
		}
	}
	d := mustShare(t, db, CreateOptions{ID: "abcdefghjk", Name: "kept", Owner: "alice", CreatedAt: at})
	if d.ID != "abcdefghjk" || !d.CreatedAt.Equal(at) {
		t.Fatalf("caller id/time not kept: %+v", d)
	}
	if _, err := db.CreateShare(CreateOptions{ID: "abcdefghjk", Name: "again", Owner: "alice"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate id: %v", err)
	}
}

func TestCreateShareStoresInboxAndLinkedShapes(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	c := mustShare(t, db, CreateOptions{Name: "Inbox", Owner: "alice", Inbox: true, Note: "send it", MaxBytes: 100, MaxFiles: 3})
	if !c.Inbox || c.Note != "send it" || c.MaxBytes != 100 || c.MaxFiles != 3 || c.Closed || c.NotifyOff {
		t.Fatalf("inbox: %+v", c)
	}
	l := mustShare(t, db, CreateOptions{Name: "Photos", Owner: "alice", Sources: []string{"photos/2026", "docs"}})
	if !l.Linked() || len(l.Sources) != 2 || l.Sources[0].Path != "photos/2026" || l.Sources[1].Path != "docs" {
		t.Fatalf("linked: %+v", l.Sources)
	}
}

func TestDeleteShareRemovesEverythingAndRecordsADeletion(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a", Size: 1}}})
	if err := db.DeleteShare(d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Share(d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("still readable")
	}
	if err := db.DeleteShare(d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if n, del := changeRows(t, db); n != 2 || !del {
		t.Fatalf("changes: n=%d lastDeleted=%v", n, del)
	}
	if shares, _ := ownerStats(t, db, "alice"); shares != 0 {
		t.Fatalf("owner_stats.shares = %d", shares)
	}
}

func TestShareCappedWindowsFilesAndReportsTrueTotals(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	var files []PendingFile
	for i := 0; i < 7; i++ {
		files = append(files, PendingFile{Path: string(rune('a' + i)), Size: 1})
	}
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: files})
	got, err := db.ShareCapped(d.ID, 3)
	if err != nil || len(got.Files) != 3 || !got.Truncated || got.FileCount != 7 {
		t.Fatalf("capped: files=%d truncated=%v count=%d, %v", len(got.Files), got.Truncated, got.FileCount, err)
	}
	got, _ = db.ShareCapped(d.ID, 7)
	if got.Truncated || len(got.Files) != 7 {
		t.Fatal("exact cap must not mark truncation")
	}
}

// TestSharesByIDMatchesShareCapped pins that the batched read gives every share
// the window ShareCapped gives it alone, skips ids naming no share and answers
// each id once, in the order first asked.
func TestSharesByIDMatchesShareCapped(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	var files []PendingFile
	for i := 0; i < 7; i++ {
		files = append(files, PendingFile{Path: string(rune('a' + i)), Size: 1})
	}
	a := mustShare(t, db, CreateOptions{Name: "a", Owner: "alice", Files: files})
	b := mustShare(t, db, CreateOptions{Name: "b", Owner: "alice", Files: files})
	got, err := db.SharesByID([]string{b.ID, shareid.NewID(), a.ID, b.ID, "../x"}, 3)
	if err != nil || len(got) != 2 || got[0].ID != b.ID || got[1].ID != a.ID {
		t.Fatalf("shares: %+v, %v", got, err)
	}
	for _, d := range got {
		want, _ := db.ShareCapped(d.ID, 3)
		if len(d.Files) != len(want.Files) || d.Truncated != want.Truncated || d.FileCount != want.FileCount {
			t.Fatalf("%s: files=%d truncated=%v, ShareCapped files=%d truncated=%v",
				d.Name, len(d.Files), d.Truncated, len(want.Files), want.Truncated)
		}
		for i := range d.Files {
			if d.Files[i].Path != want.Files[i].Path || d.Files[i].Slug != want.Files[i].Slug {
				t.Fatalf("%s: file %d = %+v, want %+v", d.Name, i, d.Files[i], want.Files[i])
			}
		}
	}
}

func TestCreateAndDeleteWakeSubscribers(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	ch, cancel := db.Subscribe()
	defer cancel()
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	select {
	case <-ch:
	default:
		t.Fatal("no wake after create")
	}
	db.DeleteShare(d.ID)
	select {
	case <-ch:
	default:
		t.Fatal("no wake after delete")
	}
}

// A share that gains a folder reads as one: the flag says how a listing page
// draws the share, so an edit that changes what the share points at can set it.
func TestUpdateShareSetsTheFolderFlag(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "one", Owner: "alice", Sources: []string{"photos/a.jpg"}})
	if d.Folder {
		t.Fatalf("created as a folder: %+v", d)
	}
	got, err := db.UpdateShare(d.ID, UpdateOptions{SetFolder: true, Folder: true})
	if err != nil || !got.Folder {
		t.Fatalf("set: %+v %v", got, err)
	}
	again, err := db.Share(d.ID)
	if err != nil || !again.Folder {
		t.Fatalf("read back: %+v %v", again, err)
	}
	if got, err := db.UpdateShare(d.ID, UpdateOptions{SetFolder: true, Folder: false}); err != nil || got.Folder {
		t.Fatalf("clear: %+v %v", got, err)
	}
}

// A View answer is one question with four answers, and every surface sends
// all three fields together, so an update that swaps the answer must be
// judged on the state it leaves behind rather than on the order the columns
// happen to be written in.
func TestUpdateShareSwapsTheViewAnswerInEitherDirection(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	answers := map[string]UpdateOptions{
		"file":    {},
		"listing": {Listing: true},
		"media":   {Media: true},
		"page":    {Entry: "index.html"},
	}
	for from, a := range answers {
		for to, b := range answers {
			if from == to {
				continue
			}
			d := mustShare(t, db, CreateOptions{Name: from, Owner: "alice",
				Entry: a.Entry, Media: a.Media, Listing: a.Listing})
			o := UpdateOptions{
				SetEntry: true, Entry: b.Entry,
				SetMedia: true, Media: b.Media,
				SetListing: true, Listing: b.Listing,
			}
			got, err := db.UpdateShare(d.ID, o)
			if err != nil {
				t.Errorf("%s to %s: %v", from, to, err)
				continue
			}
			if got.Entry != b.Entry || got.Media != b.Media || got.Listing != b.Listing {
				t.Errorf("%s to %s: entry=%q media=%v listing=%v", from, to, got.Entry, got.Media, got.Listing)
			}
		}
	}
}

// Two answers at once are still refused, on the resulting state.
func TestUpdateShareRefusesTwoViewAnswers(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Listing: true})
	for name, o := range map[string]UpdateOptions{
		"media beside the stored listing": {SetMedia: true, Media: true},
		"entry beside the stored listing": {SetEntry: true, Entry: "index.html"},
		"media and entry at once":         {SetListing: true, Listing: false, SetMedia: true, Media: true, SetEntry: true, Entry: "index.html"},
	} {
		if _, err := db.UpdateShare(d.ID, o); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	got, err := db.Share(d.ID)
	if err != nil || !got.Listing || got.Media || got.Entry != "" {
		t.Fatalf("refused updates changed the share: %+v %v", got, err)
	}
}

func TestATextShareIsOneAnswerAndKeepsIt(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	textShareRefusalCases(t, db, "alice")
}

// textShareRefusalCases drives the same refusal table against db, whose
// owner is already seeded: every combination that would widen a text share
// past one answer or one file is refused with ErrBadRequest at creation or
// ErrTextShare on update, and name, password and expiry stay editable. Go
// enforces this rather than a CHECK constraint because SQLite cannot add
// one to a table an earlier stamp already created, so the rule has to hold
// whether the shares table was created fresh at this stamp or upgraded into
// it from an older volume; both callers run this same table for that
// reason.
func textShareRefusalCases(t *testing.T, db *DB, owner string) {
	t.Helper()
	for name, o := range map[string]CreateOptions{
		"text+inbox":   {Name: "n", Owner: owner, Text: true, Inbox: true},
		"text+media":   {Name: "n", Owner: owner, Text: true, Media: true},
		"text+listing": {Name: "n", Owner: owner, Text: true, Listing: true},
		"text+entry":   {Name: "n", Owner: owner, Text: true, Entry: "index.html"},
		"text+source":  {Name: "n", Owner: owner, Text: true, Sources: []string{"docs"}},
		"text+2files": {Name: "n", Owner: owner, Text: true, Files: []PendingFile{
			{Path: "a.txt", Size: 1}, {Path: "b.txt", Size: 1}}},
	} {
		if _, err := db.CreateShare(o); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: err = %v, want ErrBadRequest", name, err)
		}
	}
	d := mustShare(t, db, CreateOptions{Name: "Note", Owner: owner, Text: true})
	if !d.Text {
		t.Fatal("Text not stored")
	}
	got, err := db.Share(d.ID)
	if err != nil || !got.Text {
		t.Fatalf("read back: %v text=%v", err, got.Text)
	}
	for name, o := range map[string]UpdateOptions{
		"listing": {SetListing: true, Listing: true},
		"media":   {SetMedia: true, Media: true},
		"entry":   {SetEntry: true, Entry: "a.txt"},
	} {
		if _, err := db.UpdateShare(d.ID, o); !errors.Is(err, ErrTextShare) {
			t.Errorf("%s on a text share: err = %v, want ErrTextShare", name, err)
		}
	}
	// Name, password and expiry stay editable.
	if _, err := db.UpdateShare(d.ID, UpdateOptions{SetName: true, Name: "Renamed"}); err != nil {
		t.Fatalf("rename: %v", err)
	}
}

// perTableShare reads one share the plain way, one query per table with no
// counter shortcut, as the oracle scanShare is held to. maxFiles <= 0 reads
// every file.
func perTableShare(t *testing.T, db *DB, id string, maxFiles int) Share {
	t.Helper()
	var d Share
	err := db.read(func(tx *sql.Tx) error {
		var err error
		if d, err = scanShareRow(tx.QueryRow(`SELECT `+shareCols+` FROM shares WHERE id = ?`, id)); err != nil {
			return err
		}
		var stored int
		if err := tx.QueryRow(`SELECT count(*) FROM files WHERE share_id = ?`, id).Scan(&stored); err != nil {
			return err
		}
		if stored != d.FileCount {
			t.Errorf("share %s: files counter %d, rows %d", id, d.FileCount, stored)
		}
		limit := -1
		if maxFiles > 0 {
			limit = maxFiles
		}
		rows, err := tx.Query(`SELECT `+fileCols+` FROM files WHERE share_id = ? ORDER BY path LIMIT ?`, id, limit)
		if err != nil {
			return err
		}
		if err := eachRow(rows, func() error {
			f, err := scanFileRow(rows)
			d.Files = append(d.Files, f)
			return err
		}); err != nil {
			return err
		}
		d.Truncated = maxFiles > 0 && stored > len(d.Files)
		if rows, err = tx.Query(`SELECT path FROM folders WHERE share_id = ? ORDER BY path`, id); err != nil {
			return err
		}
		if d.Folders, err = scanStrings(rows); err != nil {
			return err
		}
		if rows, err = tx.Query(`SELECT `+scheduledCols+` FROM scheduled WHERE share_id = ? ORDER BY kind`, id); err != nil {
			return err
		}
		if err := eachRow(rows, func() error {
			s, err := scanScheduledRow(rows)
			d.Scheduled = append(d.Scheduled, s)
			return err
		}); err != nil {
			return err
		}
		if rows, err = tx.Query(`SELECT `+sourceCols+` FROM share_sources s WHERE s.share_id = ? ORDER BY s.position`, id); err != nil {
			return err
		}
		return eachRow(rows, func() error {
			src, err := scanSourceRow(rows)
			d.Sources = append(d.Sources, src)
			return err
		})
	})
	if err != nil {
		t.Fatalf("per-table read of %s: %v", id, err)
	}
	return d
}

// TestScanShareMatchesAPerTableRead pins that a share read through fetchPage is
// exactly what one query per table reads: every file or the capped window in
// path order, Truncated only on a capped read, and the folders, scheduled
// rows and sources in their own orders, with nothing of a neighbouring share.
func TestScanShareMatchesAPerTableRead(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	full := mustShare(t, db, CreateOptions{Name: "full", Owner: "alice", Sources: []string{"photos/b", "photos/a"},
		Files: []PendingFile{{Path: "z/late.bin", Size: 9}, {Path: "m.txt", Size: 4}}})
	for _, p := range []string{"c.txt", "a.txt", "b/inner.txt"} {
		commit(t, db, full.ID, p, 3)
	}
	for _, f := range []string{"zeta", "alpha", "b/empty"} {
		if _, err := db.AddFolder(full.ID, f); err != nil {
			t.Fatal(err)
		}
	}
	later := at.Add(time.Hour)
	if _, err := db.Schedule(full.ID,
		Scheduled{Kind: ScheduledPassword, ApplyAt: at, PasswordHash: "hash"},
		Scheduled{Kind: ScheduledExpiry, ApplyAt: at, ExpiresAt: &later}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.EditFilter(full.ID, []FilterEdit{{Source: "photos/a", Hide: []string{"x.jpg", "y"}}}); err != nil {
		t.Fatal(err)
	}
	n := 4
	if _, err := db.UpdateUserAccess("alice", Settings{}, []SourceAccess{{ShareID: full.ID, Source: "photos/b", Revoke: true, Files: &n}}, false); err != nil {
		t.Fatal(err)
	}
	neighbour := mustShare(t, db, CreateOptions{Name: "neighbour", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 1}}})
	if _, err := db.AddFolder(neighbour.ID, "other"); err != nil {
		t.Fatal(err)
	}
	empty := mustShare(t, db, CreateOptions{Name: "empty", Owner: "alice"})

	for _, id := range []string{full.ID, neighbour.ID, empty.ID} {
		for _, maxFiles := range []int{0, -1, 1, 2, 5, 6, 100} {
			var got Share
			err := db.read(func(tx *sql.Tx) error {
				var err error
				got, err = scanShare(tx, id, maxFiles)
				return err
			})
			if err != nil {
				t.Fatalf("scanShare(%s, %d): %v", id, maxFiles, err)
			}
			if want := perTableShare(t, db, id, maxFiles); !reflect.DeepEqual(got, want) {
				t.Fatalf("scanShare(%s, %d)\n got %+v\nwant %+v", id, maxFiles, got, want)
			}
		}
	}
	d, _ := db.Share(full.ID)
	if len(d.Files) != 5 || len(d.Folders) != 3 || len(d.Scheduled) != 2 || len(d.Sources) != 2 ||
		d.Sources[0].Path != "photos/b" || !d.Sources[0].Revoked() || d.Sources[1].Hidden != 2 {
		t.Fatalf("the fixture did not land: %+v", d)
	}
	if c, _ := db.ShareCapped(full.ID, 2); !c.Truncated || len(c.Files) != 2 || c.FileCount != 5 {
		t.Fatalf("capped: files=%d truncated=%v count=%d", len(c.Files), c.Truncated, c.FileCount)
	}
	for _, id := range []string{shareid.NewID(), "../escape"} {
		if _, err := db.Share(id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Share(%q) = %v, want ErrNotFound", id, err)
		}
	}
}

// TestASettingsEditReadsTheListingWindowBack pins that an edit that changes no
// file holds the write lock for the listing's window of file entries, never
// for the share's whole file table.
func TestASettingsEditReadsTheListingWindowBack(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Inbox: true})
	if err := db.write(func(tx *sql.Tx) error {
		for i := 0; i <= editWindow; i++ {
			if _, err := tx.Exec(`INSERT INTO files(share_id, path, slug, size, pending, declared_at) VALUES(?, ?, ?, 0, 1, 1)`,
				d.ID, fmt.Sprintf("f%04d", i), newSlug()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	seen := time.Now()
	edits := map[string]func() (Share, error){
		"UpdateShare": func() (Share, error) { return db.UpdateShare(d.ID, UpdateOptions{SeenAt: &seen}) },
		"Schedule": func() (Share, error) {
			return db.Schedule(d.ID, Scheduled{Kind: ScheduledExpiry, ApplyAt: seen.Add(time.Hour), Clear: true})
		},
		"CancelScheduled": func() (Share, error) { return db.CancelScheduled(d.ID, "all") },
	}
	for name, edit := range edits {
		got, err := edit()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got.Files) != editWindow || !got.Truncated || got.FileCount != editWindow+1 {
			t.Fatalf("%s read back %d files (truncated %v) of %d, want the %d-file window",
				name, len(got.Files), got.Truncated, got.FileCount, editWindow)
		}
	}
}

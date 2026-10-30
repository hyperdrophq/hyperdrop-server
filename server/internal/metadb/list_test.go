package metadb

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func seedListing(t *testing.T, db *DB, n int) {
	t.Helper()
	mustUser(t, db, "alice")
	mustUser(t, db, "bob")
	for i := 0; i < n; i++ {
		owner := "alice"
		if i%5 == 0 {
			owner = "bob"
		}
		name := fmt.Sprintf("quiet river %d", i)
		if i%3 == 0 {
			name = fmt.Sprintf("Loud Harbor %d", i)
		}
		d := mustShare(t, db, CreateOptions{Name: name, Owner: owner, CreatedAt: at.Add(time.Duration(i) * time.Second), Inbox: i%7 == 0})
		commit(t, db, d.ID, "a", int64(i))
	}
}

func TestListPagesNewestFirstWithinOwnerAndKind(t *testing.T) {
	db := openTest(t)
	seedListing(t, db, 40)
	p, err := db.List(ListQuery{Owner: "alice", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Shares) != 10 || p.NextCursor == "" {
		t.Fatalf("page: %d rows, cursor %q", len(p.Shares), p.NextCursor)
	}
	for i := 1; i < len(p.Shares); i++ {
		if p.Shares[i].CreatedAt.After(p.Shares[i-1].CreatedAt) {
			t.Fatal("not newest first")
		}
	}
	for _, d := range p.Shares {
		if d.Owner != "alice" || d.Inbox {
			t.Fatalf("row outside the filter: %+v", d)
		}
	}
	wantTotal := 0
	var wantBytes int64
	for i := 0; i < 40; i++ {
		if i%5 != 0 && i%7 != 0 {
			wantTotal++
			wantBytes += int64(i)
		}
	}
	if p.Total != wantTotal || p.TotalBytes != wantBytes {
		t.Fatalf("total=%d bytes=%d, want %d %d", p.Total, p.TotalBytes, wantTotal, wantBytes)
	}
	sum := 0
	for _, owner := range []string{"alice", "bob"} {
		for _, kind := range []string{"", "receive"} {
			p, err := db.List(ListQuery{Owner: owner, Kind: kind, Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			sum += p.Total
		}
	}
	if sum != 40 {
		t.Fatalf("shares and inboxes of both owners = %d, want 40", sum)
	}
}

// TestListRefusesAQueryNamingNoOwner pins that every listing is one
// account's: no query reads every owner's shares, and a kind the store does
// not know is refused rather than read as "shares".
func TestListRefusesAQueryNamingNoOwner(t *testing.T) {
	db := openTest(t)
	seedListing(t, db, 5)
	if _, err := db.List(ListQuery{}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("no owner: %v", err)
	}
	if _, err := db.List(ListQuery{Owner: "alice", Kind: "recieve"}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("unknown kind: %v", err)
	}
}

func TestListOffsetAndCursorWalksAgree(t *testing.T) {
	db := openTest(t)
	seedListing(t, db, 53)
	var byOffset []string
	for off := 0; ; off += 7 {
		p, err := db.List(ListQuery{Owner: "alice", Offset: off, Limit: 7})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range p.Shares {
			byOffset = append(byOffset, d.ID)
		}
		if len(p.Shares) < 7 {
			break
		}
	}
	var byCursor []string
	cursor := ""
	for {
		p, err := db.List(ListQuery{Owner: "alice", After: cursor, Limit: 7})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range p.Shares {
			byCursor = append(byCursor, d.ID)
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if len(byOffset) == 0 || fmt.Sprint(byOffset) != fmt.Sprint(byCursor) {
		t.Fatalf("offset walk %v\ncursor walk %v", byOffset, byCursor)
	}
	if _, err := db.List(ListQuery{Owner: "alice", After: "garbage"}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad cursor: %v", err)
	}
}

func TestListSearchIsCaseInsensitiveSubstring(t *testing.T) {
	db := openTest(t)
	seedListing(t, db, 30)
	p, _ := db.List(ListQuery{Owner: "alice", Name: "HARBOR", Limit: 100})
	for _, d := range p.Shares {
		if d.Name[:4] != "Loud" {
			t.Fatalf("search returned %q", d.Name)
		}
	}
	if p.Total != len(p.Shares) || p.Total == 0 {
		t.Fatalf("total %d rows %d", p.Total, len(p.Shares))
	}
	if q, _ := db.List(ListQuery{Owner: "alice", Name: "d har", Limit: 100}); q.Total != p.Total {
		t.Fatal("a substring across words must match the same rows")
	}
}

// TestListSearchFoldsEveryCapital pins that ?q= folds a capital outside ASCII
// the way it folds an ASCII one, whichever path wrote the name: a create, a
// rename, a whole-share replace, or a row an earlier release keyed with
// SQLite's ASCII-only lower(), which the serving open keys again.
func TestListSearchFoldsEveryCapital(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustUser(t, db, "alice")
	mustShare(t, db, CreateOptions{Name: "ÉCOLE photos", Owner: "alice"})
	renamed := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	if _, err := db.UpdateShare(renamed.ID, UpdateOptions{SetName: true, Name: "ÉCOLE notes"}); err != nil {
		t.Fatal(err)
	}
	replaced := mustShare(t, db, CreateOptions{Name: "old.txt", Owner: "alice"})
	commit(t, db, replaced.ID, "old.txt", 1)
	commit(t, db, replaced.ID, "ÉCOLE.txt", 1)
	if _, err := db.ReplaceAll(replaced.ID, "ÉCOLE.txt"); err != nil {
		t.Fatal(err)
	}
	keyedByOldRelease := mustShare(t, db, CreateOptions{Name: "ÉCOLE old", Owner: "alice"})
	if err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE shares SET name_lower = lower(name) WHERE id = ?`, keyedByOldRelease.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if db, err = Open(dir); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{"ÉCOLE", "école", "École"} {
		p, err := db.List(ListQuery{Owner: "alice", Name: q})
		if err != nil {
			t.Fatal(err)
		}
		if p.Total != 4 {
			var names []string
			for _, d := range p.Shares {
				names = append(names, d.Name)
			}
			t.Fatalf("search %q matched %d: %v, want all four", q, p.Total, names)
		}
	}
}

func TestListCapsFilesPerRowAndPerPage(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	for i := 0; i < 3; i++ {
		var files []PendingFile
		for j := 0; j < 5; j++ {
			files = append(files, PendingFile{Path: fmt.Sprintf("f%d", j), Size: 1})
		}
		mustShare(t, db, CreateOptions{Name: fmt.Sprint(i), Owner: "alice", Files: files})
	}
	p, _ := db.List(ListQuery{Owner: "alice", MaxFiles: 2})
	for _, d := range p.Shares {
		if len(d.Files) != 2 || !d.Truncated || d.FileCount != 5 {
			t.Fatalf("row cap: %+v", d)
		}
	}
	p, _ = db.List(ListQuery{Owner: "alice", MaxFiles: 5, MaxPageFiles: 7})
	total := 0
	for _, d := range p.Shares {
		total += len(d.Files)
	}
	if total > 7 || !p.Shares[2].Truncated {
		t.Fatalf("page cap: %d files loaded, last truncated=%v", total, p.Shares[2].Truncated)
	}
	if _, err := db.List(ListQuery{Owner: "alice", Limit: 5000}); err != nil {
		t.Fatal("an oversized limit is capped, not refused")
	}
}

// TestListAttachesFoldersScheduledAndSourcesLikeShare pins the batched page
// against the single-share read on the three child rows a listing page
// carries beside its files.
func TestListAttachesFoldersScheduledAndSourcesLikeShare(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	rich := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", CreatedAt: at, Sources: []string{"photos", "docs"}})
	commit(t, db, rich.ID, "a.jpg", 7)
	if _, err := db.AddFolder(rich.ID, "empty"); err != nil {
		t.Fatal(err)
	}
	exp := at.Add(72 * time.Hour)
	if _, err := db.Schedule(rich.ID,
		Scheduled{Kind: ScheduledExpiry, ApplyAt: at.Add(time.Hour), ExpiresAt: &exp},
		Scheduled{Kind: ScheduledPassword, ApplyAt: at.Add(2 * time.Hour), PasswordHash: "hash"},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.EditFilter(rich.ID, []FilterEdit{{Source: "photos", Hide: []string{"private"}}}); err != nil {
		t.Fatal(err)
	}
	plain := mustShare(t, db, CreateOptions{Name: "plain", Owner: "alice", CreatedAt: at.Add(time.Minute)})

	p, err := db.List(ListQuery{Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Shares) != 2 {
		t.Fatalf("page holds %d shares, want 2", len(p.Shares))
	}
	byID := map[string]Share{}
	for _, got := range p.Shares {
		byID[got.ID] = got
		want, err := db.Share(got.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Folders, want.Folders) {
			t.Errorf("%s folders: page %v, Share %v", got.ID, got.Folders, want.Folders)
		}
		if !reflect.DeepEqual(got.Scheduled, want.Scheduled) {
			t.Errorf("%s scheduled: page %+v, Share %+v", got.ID, got.Scheduled, want.Scheduled)
		}
		if !reflect.DeepEqual(got.Sources, want.Sources) {
			t.Errorf("%s sources: page %+v, Share %+v", got.ID, got.Sources, want.Sources)
		}
	}

	got := byID[rich.ID]
	if len(got.Folders) != 1 || got.Folders[0] != "empty" {
		t.Fatalf("folders: %v", got.Folders)
	}
	if len(got.Scheduled) != 2 {
		t.Fatalf("scheduled: %+v", got.Scheduled)
	}
	if s := got.Scheduled[0]; s.Kind != ScheduledExpiry || !s.ApplyAt.Equal(at.Add(time.Hour)) || s.Clear ||
		s.PasswordHash != "" || s.ExpiresAt == nil || !s.ExpiresAt.Equal(exp) {
		t.Fatalf("scheduled expiry: %+v", s)
	}
	if s := got.Scheduled[1]; s.Kind != ScheduledPassword || !s.ApplyAt.Equal(at.Add(2*time.Hour)) || s.Clear ||
		s.PasswordHash != "hash" || s.ExpiresAt != nil {
		t.Fatalf("scheduled password: %+v", s)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("sources: %+v", got.Sources)
	}
	if s := got.Sources[0]; s.Path != "photos" || s.Fixed || s.Hidden != 1 {
		t.Fatalf("first source: %+v", s)
	}
	if s := got.Sources[1]; s.Path != "docs" || s.Fixed || s.Hidden != 0 {
		t.Fatalf("second source: %+v", s)
	}
	if bare := byID[plain.ID]; len(bare.Folders) != 0 || len(bare.Scheduled) != 0 || len(bare.Sources) != 0 {
		t.Fatalf("a plain share carries no child rows: %+v", bare)
	}
}

// TestListWindowCostDoesNotScaleWithASharesFileCount pins that a page holding
// one enormous share pays for the window it shows, not for the share's files.
func TestListWindowCostDoesNotScaleWithASharesFileCount(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	small := mustShare(t, db, CreateOptions{Name: "small", Owner: "alice", CreatedAt: at})
	commit(t, db, small.ID, "a", 1)
	middling := mustShare(t, db, CreateOptions{Name: "middling", Owner: "alice", CreatedAt: at.Add(time.Second)})
	commit(t, db, middling.ID, "b", 2)
	big := mustShare(t, db, CreateOptions{Name: "big", Owner: "alice", CreatedAt: at.Add(2 * time.Second)})
	if err := db.write(func(tx *sql.Tx) error {
		ins, err := tx.Prepare(`INSERT INTO files(share_id, path, slug, size, pending) VALUES(?, ?, ?, 1, 1)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for i := 0; i < 50000; i++ {
			if _, err := ins.Exec(big.ID, fmt.Sprintf("f%06d.bin", i), newSlug()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	p, err := db.List(ListQuery{Owner: "alice", MaxFiles: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Shares) != 3 {
		t.Fatalf("page holds %d shares, want 3", len(p.Shares))
	}
	got := p.Shares[0]
	if got.ID != big.ID || len(got.Files) != 100 || !got.Truncated || got.FileCount != 50000 {
		t.Fatalf("big row: id=%s files=%d truncated=%v count=%d", got.ID, len(got.Files), got.Truncated, got.FileCount)
	}
	want, err := db.ShareCapped(big.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the page's window differs from ShareCapped's:\npage %+v\nshare %+v", got.Files[:3], want.Files[:3])
	}
	if len(p.Shares[1].Files) != 1 || len(p.Shares[2].Files) != 1 {
		t.Fatalf("the ordinary rows kept their files: %d %d", len(p.Shares[1].Files), len(p.Shares[2].Files))
	}

	// The page is timed against reading the whole 50,000-file share on the
	// same machine, so the bound holds on a fast laptop and on a slow CI
	// runner under -race alike: a page that scaled with the share's file
	// count would cost about as much as the full read.
	median := func(f func() error) time.Duration {
		var ds []time.Duration
		for i := 0; i < 5; i++ {
			s := time.Now()
			if err := f(); err != nil {
				t.Fatal(err)
			}
			ds = append(ds, time.Since(s))
		}
		slices.Sort(ds)
		return ds[len(ds)/2]
	}
	page := median(func() error {
		_, err := db.List(ListQuery{Owner: "alice", MaxFiles: 100})
		return err
	})
	whole := median(func() error {
		_, err := db.Share(big.ID)
		return err
	})
	t.Logf("a page over a 50,000-file share: median %v; the whole share: %v", page.Round(time.Microsecond), whole.Round(time.Microsecond))
	if page*4 > whole {
		t.Errorf("a page costs %v, more than a quarter of reading the whole share (%v)", page, whole)
	}
}

// pathsOf is the relpaths of files, in order.
func pathsOf(files []File) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}

// The gallery's keyset: files after a relpath in byte order, so "B" sorts
// before "a", and a page's last relpath picks up exactly where it stopped.
func TestShareFilesAfterIsAKeyset(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	for _, p := range []string{"a", "B", "c/d", "c/e", "Z", "b", "c.txt"} {
		commit(t, db, d.ID, p, 1)
	}
	first, more, err := db.ShareFilesAfter(d.ID, "", 3)
	if err != nil || !more || !slices.Equal(pathsOf(first), []string{"B", "Z", "a"}) {
		t.Fatalf("first page %v more=%v err=%v", pathsOf(first), more, err)
	}
	rest, more, err := db.ShareFilesAfter(d.ID, first[2].Path, 3)
	if err != nil || !more || !slices.Equal(pathsOf(rest), []string{"b", "c.txt", "c/d"}) {
		t.Fatalf("second page %v more=%v err=%v", pathsOf(rest), more, err)
	}
	last, more, err := db.ShareFilesAfter(d.ID, "c/d", 3)
	if err != nil || more || !slices.Equal(pathsOf(last), []string{"c/e"}) {
		t.Fatalf("last page %v more=%v err=%v", pathsOf(last), more, err)
	}
	if none, more, err := db.ShareFilesAfter(d.ID, "c/e", 3); err != nil || more || len(none) != 0 {
		t.Fatalf("past the end %v more=%v err=%v", pathsOf(none), more, err)
	}
	if _, _, err := db.ShareFilesAfter("../x", "", 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
}

// childKeys renders children as their keys, a folder's with its slash.
func childKeys(children []FolderChild) []string {
	out := make([]string, 0, len(children))
	for _, c := range children {
		out = append(out, c.Key())
	}
	return out
}

// A folder's page is its direct children, each subfolder once however much
// it holds, in the order their paths sort: "a-x" and "a.txt" sort before
// the folder "a/", whose own files are never read past the first.
func TestFolderChildrenListsOneFolderInPathOrder(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	for _, p := range []string{"a/1", "a/2", "a/deep/3", "a-x", "a.txt", "b", "c/1", "d/e/f", "d/g", "d0"} {
		commit(t, db, d.ID, p, 1)
	}
	all, more, err := db.FolderChildren(d.ID, "", "", 100)
	if err != nil || more || !slices.Equal(childKeys(all), []string{"a-x", "a.txt", "a/", "b", "c/", "d/", "d0"}) {
		t.Fatalf("root %v more=%v err=%v", childKeys(all), more, err)
	}
	if all[0].Dir || all[0].File.Path != "a-x" || !all[2].Dir || all[2].Name != "a" {
		t.Fatalf("children %+v", all)
	}
	page, more, err := db.FolderChildren(d.ID, "", "", 3)
	if err != nil || !more || !slices.Equal(childKeys(page), []string{"a-x", "a.txt", "a/"}) {
		t.Fatalf("first page %v more=%v err=%v", childKeys(page), more, err)
	}
	page, more, err = db.FolderChildren(d.ID, "", page[2].Key(), 3)
	if err != nil || !more || !slices.Equal(childKeys(page), []string{"b", "c/", "d/"}) {
		t.Fatalf("second page %v more=%v err=%v", childKeys(page), more, err)
	}
	page, more, err = db.FolderChildren(d.ID, "", page[2].Key(), 3)
	if err != nil || more || !slices.Equal(childKeys(page), []string{"d0"}) {
		t.Fatalf("last page %v more=%v err=%v", childKeys(page), more, err)
	}
	sub, more, err := db.FolderChildren(d.ID, "d", "", 100)
	if err != nil || more || !slices.Equal(childKeys(sub), []string{"e/", "g"}) {
		t.Fatalf("d %v more=%v err=%v", childKeys(sub), more, err)
	}
	for _, junk := range []string{"zz-missing", "../x", "a/", strings.Repeat("a", 10<<10), "\x00"} {
		got, _, err := db.FolderChildren(d.ID, "", junk, 100)
		if err != nil {
			t.Fatalf("after %.20q: %v", junk, err)
		}
		for _, c := range got {
			if c.Key() <= junk {
				t.Fatalf("after %.20q answered %q", junk, c.Key())
			}
		}
	}
	if none, _, err := db.FolderChildren(d.ID, "nope", "", 100); err != nil || len(none) != 0 {
		t.Fatalf("missing folder %v %v", childKeys(none), err)
	}
}

// A folder's totals are everything beneath it, and only that: "a-x" and
// "a.txt" sort beside "a/" without being in it.
func TestFolderTotalsCountEverythingBeneath(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	for p, n := range map[string]int64{"a/1": 1, "a/deep/2": 2, "a-x": 4, "a.txt": 8, "b/c": 16} {
		commit(t, db, d.ID, p, n)
	}
	got, err := db.FolderTotals(d.ID, []string{"a", "b", "a/deep", "none"})
	want := map[string]FolderTotal{"a": {Files: 2, Bytes: 3}, "b": {Files: 1, Bytes: 16}, "a/deep": {Files: 1, Bytes: 2}, "none": {}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("totals %+v, %v", got, err)
	}
}

// StoredPaths answers which of the named relpaths are file rows.
func TestStoredPathsAnswersTheRowsAmongThePaths(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice"})
	commit(t, db, d.ID, "a.jpg", 1)
	commit(t, db, d.ID, "b/c.jpg", 1)
	got, err := db.StoredPaths(d.ID, []string{"a.jpg", "b/c.jpg", "z.jpg", "'; DROP TABLE files; --"})
	if err != nil || !reflect.DeepEqual(got, map[string]bool{"a.jpg": true, "b/c.jpg": true}) {
		t.Fatalf("stored %v, %v", got, err)
	}
}

// The share without its files: every other part of the row, and no file read.
func TestShareWithoutFilesReadsNoFile(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Folder: true})
	if _, err := db.AddFolder(d.ID, "empty"); err != nil {
		t.Fatal(err)
	}
	commit(t, db, d.ID, "a", 3)
	got, err := db.ShareWithoutFiles(d.ID)
	if err != nil || len(got.Files) != 0 || got.FileCount != 1 || got.Bytes != 3 || !slices.Equal(got.Folders, []string{"empty"}) {
		t.Fatalf("head %+v, %v", got, err)
	}
}

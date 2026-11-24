package metadb

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"hyperdrop/server/internal/shareid"
)

// duplicate copies src under a fresh id and fails the test on an error.
func duplicate(t *testing.T, db *DB, src string, o DuplicateOptions) (Share, []CopyJob) {
	t.Helper()
	if o.NewID == "" {
		o.NewID = shareid.NewID()
	}
	d, err := db.DuplicateShare(src, o)
	if err != nil {
		t.Fatalf("DuplicateShare(%s): %v", src, err)
	}
	return d, allCopyJobs(t, db, d.ID, 2)
}

// allCopyJobs reads every job of the copy id, limit at a time.
func allCopyJobs(t *testing.T, db *DB, id string, limit int) []CopyJob {
	t.Helper()
	var all []CopyJob
	after := ""
	for {
		page, err := db.CopyJobs(id, after, limit)
		if err != nil {
			t.Fatalf("CopyJobs(%s, %q): %v", id, after, err)
		}
		if len(page) > limit {
			t.Fatalf("CopyJobs answered %d jobs, past its limit %d", len(page), limit)
		}
		all = append(all, page...)
		if len(page) < limit {
			return all
		}
		after = page[len(page)-1].Cursor()
	}
}

// scalar reads one integer the query answers.
func scalar(t *testing.T, db *DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.read(func(tx *sql.Tx) error { return tx.QueryRow(q, args...).Scan(&n) }); err != nil {
		t.Fatal(err)
	}
	return n
}

func boolPtr(b bool) *bool { return &b }

// A duplicate carries every setting the original has: the same password (hash
// and generation, so a cookie minted against the original's generation means
// the same number), expiry, View answer, folders, scheduled changes and links
// state, and names itself "<name> copy". Its files are the original's paths,
// pending under new slugs, each with a job naming both slugs.
func TestDuplicateCopiesTheSettings(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	exp := at.Add(72 * time.Hour)
	src := mustShare(t, db, CreateOptions{Name: "site", Owner: "alice", Folder: true, Entry: "index.html",
		ExpiresAt: &exp, LinksOff: true,
		Files: []PendingFile{{Path: "index.html", Size: 3}, {Path: "css/a.css", Size: 5}}})
	idx := commit(t, db, src.ID, "index.html", 3)
	css := commit(t, db, src.ID, "css/a.css", 5)
	if _, err := db.AddFolder(src.ID, "empty"); err != nil {
		t.Fatal(err)
	}
	sealed := []byte("sealed-for-src")
	for _, hash := range []string{"hash-1", "hash-2"} { // two sets: the generation is 2
		if _, err := db.UpdateShare(src.ID, UpdateOptions{SetPassword: true, PasswordHash: hash, PasswordSealed: sealed}); err != nil {
			t.Fatal(err)
		}
	}
	applyAt := at.Add(24 * time.Hour)
	if _, err := db.Schedule(src.ID,
		Scheduled{Kind: ScheduledPassword, ApplyAt: applyAt, PasswordHash: "hash-3", PasswordSealed: []byte("sched-sealed")},
		Scheduled{Kind: ScheduledExpiry, ApplyAt: applyAt, Clear: true}); err != nil {
		t.Fatal(err)
	}
	src, err := db.Share(src.ID)
	if err != nil {
		t.Fatal(err)
	}

	// With no Reseal the sealed copies stay behind: they are bound to the
	// original's id, and a copy that does not open is worse than none.
	d, jobs := duplicate(t, db, src.ID, DuplicateOptions{})
	if d.ID == src.ID || d.Owner != "alice" || d.Name != "site copy" {
		t.Fatalf("copy is %s %q of %s, want a new id named %q", d.ID, d.Name, d.Owner, "site copy")
	}
	if d.CopyingFrom != src.ID {
		t.Fatalf("copyingFrom = %q, want %q", d.CopyingFrom, src.ID)
	}
	if d.PasswordHash != src.PasswordHash || d.PasswordGen != 2 || d.PasswordGen != src.PasswordGen {
		t.Fatalf("password %q gen %d, want %q gen %d", d.PasswordHash, d.PasswordGen, src.PasswordHash, src.PasswordGen)
	}
	if d.PasswordSealed != nil {
		t.Fatalf("a copy with no Reseal kept the original's sealed bytes")
	}
	if !sameTime(d.ExpiresAt, src.ExpiresAt) || d.Entry != "index.html" || !d.Folder || d.Media || d.Listing || d.Text {
		t.Fatalf("settings: expires %v entry %q folder %v media %v listing %v text %v",
			d.ExpiresAt, d.Entry, d.Folder, d.Media, d.Listing, d.Text)
	}
	if !d.LinksOff() {
		t.Fatalf("the original's links are off; the copy's must be too")
	}
	if !slices.Equal(d.Folders, src.Folders) || len(d.Folders) != 1 {
		t.Fatalf("folders %v, want %v", d.Folders, src.Folders)
	}
	if len(d.Scheduled) != 2 {
		t.Fatalf("scheduled: %+v", d.Scheduled)
	}
	for _, s := range d.Scheduled {
		want := src.Scheduled[slices.IndexFunc(src.Scheduled, func(x Scheduled) bool { return x.Kind == s.Kind })]
		if !s.ApplyAt.Equal(want.ApplyAt) || s.Clear != want.Clear || s.PasswordHash != want.PasswordHash || s.PasswordSealed != nil {
			t.Fatalf("scheduled %s: %+v, want %+v without its sealed copy", s.Kind, s, want)
		}
	}
	if d.Committed != 0 || d.FileCount != 2 || d.Bytes != 0 {
		t.Fatalf("counters: committed %d files %d bytes %d, want every file pending", d.Committed, d.FileCount, d.Bytes)
	}
	slugOf := map[string]string{idx.Path: idx.Slug, css.Path: css.Slug}
	sizeOf := map[string]int64{idx.Path: 3, css.Path: 5}
	if len(jobs) != 2 {
		t.Fatalf("jobs: %+v", jobs)
	}
	for _, j := range jobs {
		if j.Linked || j.OldSlug != slugOf[j.Rel] || j.Size != sizeOf[j.Rel] || j.NewSlug == j.OldSlug || !shareid.ValidSlug(j.NewSlug) {
			t.Fatalf("job %+v, want old slug %s and a new one", j, slugOf[j.Rel])
		}
		if j.SHA256 != "abc" || j.Mime != "text/plain" {
			t.Fatalf("job %+v does not carry the committed file's hash and type", j)
		}
		if got := fileSlug(t, db, d.ID, j.Rel); got != j.NewSlug {
			t.Fatalf("the copy's %s holds slug %s, its job names %s", j.Rel, got, j.NewSlug)
		}
	}
	for _, f := range d.Files {
		if !f.Pending {
			t.Fatalf("the copy's %s is not pending", f.Path)
		}
	}
	if n := scalar(t, db, `SELECT count(*) FROM changes WHERE share_id = ?`, d.ID); n != 1 {
		t.Fatalf("the copy's creation recorded %d journal rows, want 1", n)
	}
	// The original is untouched.
	again, err := db.Share(src.ID)
	if err != nil || again.Committed != 2 || again.CopyingFrom != "" || again.Name != "site" {
		t.Fatalf("the original after the copy: %+v, %v", again, err)
	}

	// The override wins over the original's links state, either way.
	on, _ := duplicate(t, db, src.ID, DuplicateOptions{LinksOff: boolPtr(false), Name: "mine"})
	if on.LinksOff() || on.Name != "mine" {
		t.Fatalf("override on: links off %v, name %q", on.LinksOff(), on.Name)
	}
	if _, err := db.UpdateShare(src.ID, UpdateOptions{SetLinksOff: true, LinksOff: false}); err != nil {
		t.Fatal(err)
	}
	if follows, _ := duplicate(t, db, src.ID, DuplicateOptions{}); follows.LinksOff() {
		t.Fatalf("the original's links are on; the copy's are off")
	}
	if off, _ := duplicate(t, db, src.ID, DuplicateOptions{LinksOff: boolPtr(true)}); !off.LinksOff() {
		t.Fatalf("override off: the copy's links are on")
	}

	// A Reseal re-seals each copy for the new share, the hash beside it.
	type call struct {
		hash   string
		sealed []byte
	}
	var calls []call
	resealed, _ := duplicate(t, db, src.ID, DuplicateOptions{Reseal: func(hash string, sealed []byte) ([]byte, error) {
		calls = append(calls, call{hash, sealed})
		return append([]byte("new:"), sealed...), nil
	}})
	if !bytes.Equal(resealed.PasswordSealed, []byte("new:sealed-for-src")) {
		t.Fatalf("resealed copy %q", resealed.PasswordSealed)
	}
	for _, s := range resealed.Scheduled {
		if s.Kind == ScheduledPassword && !bytes.Equal(s.PasswordSealed, []byte("new:sched-sealed")) {
			t.Fatalf("resealed scheduled copy %q", s.PasswordSealed)
		}
	}
	if len(calls) != 2 || calls[0].hash != "hash-2" || calls[1].hash != "hash-3" {
		t.Fatalf("Reseal calls: %+v", calls)
	}
	// A Reseal that fails creates nothing.
	before := scalar(t, db, `SELECT count(*) FROM shares`)
	boom := errors.New("boom")
	if _, err := db.DuplicateShare(src.ID, DuplicateOptions{NewID: shareid.NewID(),
		Reseal: func(string, []byte) ([]byte, error) { return nil, boom }}); !errors.Is(err, boom) {
		t.Fatalf("failing Reseal: %v", err)
	}
	if after := scalar(t, db, `SELECT count(*) FROM shares`); after != before {
		t.Fatalf("a failed duplicate left %d shares behind", after-before)
	}
}

// A text share's copy is a text share holding the same .txt path; a name at
// the length limit is shortened so "<name> copy" still fits it.
func TestDuplicateOfATextShareAndOfALongName(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	long := strings.Repeat("é", 120)
	src := mustShare(t, db, CreateOptions{Name: long, Owner: "alice", Text: true,
		Files: []PendingFile{{Path: "note.txt", Size: 4}}})
	commit(t, db, src.ID, "note.txt", 4)
	d, jobs := duplicate(t, db, src.ID, DuplicateOptions{})
	if !d.Text || len(jobs) != 1 || jobs[0].Rel != "note.txt" || len(d.Files) != 1 || d.Files[0].Path != "note.txt" {
		t.Fatalf("text copy: text %v jobs %+v files %+v", d.Text, jobs, d.Files)
	}
	if n := utf8.RuneCountInString(d.Name); n > 120 || !strings.HasSuffix(d.Name, " copy") {
		t.Fatalf("copy name %q is %d characters", d.Name, n)
	}
}

// What belongs to the original's life rather than its content stays behind:
// its direct file links, its visitors, its pin, its seen mark and its
// notification switch.
func TestDuplicateCopiesNoFileLinksVisitsOrPin(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	src := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 1}}})
	a := commit(t, db, src.ID, "a.txt", 1)
	if _, err := db.MintFileKeys(src.ID, []string{a.Slug}, at); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordVisits([]Visit{{ShareID: src.ID, Token: [32]byte{1}}}); err != nil {
		t.Fatal(err)
	}
	seen := at
	if _, err := db.UpdateShare(src.ID, UpdateOptions{SetPinned: true, Pinned: true, SeenAt: &seen, SetNotify: true, Notify: false}); err != nil {
		t.Fatal(err)
	}
	src, _ = db.Share(src.ID)
	if src.PinnedAt == nil || src.SeenAt == nil || !src.NotifyOff || src.Visitors != 1 {
		t.Fatalf("setup: %+v", src)
	}
	d, _ := duplicate(t, db, src.ID, DuplicateOptions{})
	if d.PinnedAt != nil || d.SeenAt != nil || d.NotifyOff || d.Visitors != 0 {
		t.Fatalf("copy pinned %v seen %v notifyOff %v visitors %d", d.PinnedAt, d.SeenAt, d.NotifyOff, d.Visitors)
	}
	if n := scalar(t, db, `SELECT count(*) FROM file_links WHERE share_id = ?`, d.ID); n != 0 {
		t.Fatalf("the copy holds %d file links", n)
	}
	if n := scalar(t, db, `SELECT count(*) FROM visitors WHERE share_id = ?`, d.ID); n != 0 {
		t.Fatalf("the copy holds %d visitor rows", n)
	}
}

// Every gallery row follows its file onto the new slug, with its numbers.
func TestDuplicateRekeysTheGallery(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	src := mustShare(t, db, CreateOptions{Name: "pics", Owner: "alice", Media: true})
	a := commit(t, db, src.ID, "a.jpg", 1)
	b := commit(t, db, src.ID, "b.mp4", 1)
	taken := at
	if err := db.SetGallery(src.ID, map[string]GalleryItem{
		a.Slug: {Width: 10, Height: 20, TakenAt: &taken},
		b.Slug: {DurationMS: 3000},
	}); err != nil {
		t.Fatal(err)
	}
	d, jobs := duplicate(t, db, src.ID, DuplicateOptions{})
	if !d.Media {
		t.Fatalf("the copy is not a gallery")
	}
	newSlug := map[string]string{}
	for _, j := range jobs {
		newSlug[j.OldSlug] = j.NewSlug
	}
	g, err := db.allGalleryRows(d.ID)
	if err != nil || len(g) != 2 {
		t.Fatalf("copy gallery: %+v, %v", g, err)
	}
	if it := g[newSlug[a.Slug]]; it.Width != 10 || it.Height != 20 || it.TakenAt == nil || !it.TakenAt.Equal(at) {
		t.Fatalf("a.jpg's row: %+v", it)
	}
	if it := g[newSlug[b.Slug]]; it.DurationMS != 3000 {
		t.Fatalf("b.mp4's row: %+v", it)
	}
	if _, ok := g[a.Slug]; ok {
		t.Fatalf("the copy's gallery is keyed by the original's slug")
	}
	if orig, _ := db.allGalleryRows(src.ID); len(orig) != 2 {
		t.Fatalf("the original's gallery after the copy: %+v", orig)
	}
}

// Four refusals, each writing nothing: an inbox, a share with a file still
// uploading, a linked share with a revoked source, and a new id that is taken.
func TestDuplicateRefusesAnInboxABusyShareAndARevokedSource(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	inbox := mustShare(t, db, CreateOptions{Name: "in", Owner: "alice", Inbox: true})
	busy := mustShare(t, db, CreateOptions{Name: "busy", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 1}, {Path: "b.txt", Size: 1}}})
	commit(t, db, busy.ID, "a.txt", 1)
	linked := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Sources: []string{"photos", "docs"}})
	if err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE share_sources SET revoked_at = ? WHERE share_id = ? AND source = 'docs'`, toNS(at), linked.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := scalar(t, db, `SELECT count(*) FROM shares`)
	for _, c := range []struct {
		name, id string
		newID    string
		want     error
	}{
		{"inbox", inbox.ID, "", ErrDuplicateUnsupported},
		{"pending", busy.ID, "", ErrShareBusy},
		{"revoked", linked.ID, "", ErrSourceRevoked},
		{"missing", shareid.NewID(), "", ErrNotFound},
		{"taken id", inbox.ID, busy.ID, ErrConflict},
		{"bad id", busy.ID, "../x", ErrBadRequest},
	} {
		newID := c.newID
		if newID == "" {
			newID = shareid.NewID()
		}
		if c.name == "taken id" {
			c.id = mustShare(t, db, CreateOptions{Name: "plain", Owner: "alice"}).ID
			before++
		}
		if _, err := db.DuplicateShare(c.id, DuplicateOptions{NewID: newID}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if after := scalar(t, db, `SELECT count(*) FROM shares`); after != before {
		t.Fatalf("refused duplicates left %d shares behind", after-before)
	}
}

// A linked share's copy links the same folders with the same filters (fixed
// lists and hidden entries), copies its uploads beside them, and gives every
// linked entry that had a slug a new one, re-keying the gallery rows on them.
// A linked entry copies no bytes, so its job is marked Linked.
func TestDuplicateOfALinkedShareCopiesItsSourcesAndFilter(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	src := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Sources: []string{"photos", "docs"}})
	if _, err := db.EditFilter(src.ID, []FilterEdit{
		{Source: "photos", SetFixed: true, Fixed: true, FixedList: []string{"a.jpg", "b.jpg"}},
		{Source: "docs", Hide: []string{"secret.txt"}},
	}); err != nil {
		t.Fatal(err)
	}
	rels := []string{"photos/a.jpg", "photos/b.jpg", "docs/readme.txt"}
	oldLinked, err := db.AssignSlugs(src.ID, rels)
	if err != nil {
		t.Fatal(err)
	}
	upload := commit(t, db, src.ID, "notes.txt", 2)
	if err := db.SetGallery(src.ID, map[string]GalleryItem{oldLinked["photos/a.jpg"]: {Width: 640, Height: 480}}); err != nil {
		t.Fatal(err)
	}
	src, _ = db.Share(src.ID)

	d, jobs := duplicate(t, db, src.ID, DuplicateOptions{})
	if len(d.Sources) != 2 {
		t.Fatalf("copy sources: %+v", d.Sources)
	}
	for i, s := range d.Sources {
		w := src.Sources[i]
		if s.Path != w.Path || s.Fixed != w.Fixed || s.Hidden != w.Hidden || s.Revoked() {
			t.Fatalf("source %d: %+v, want %+v", i, s, w)
		}
	}
	srcF, err := db.Filters(src.ID)
	if err != nil {
		t.Fatal(err)
	}
	dupF, err := db.Filters(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	for s, w := range srcF {
		g := dupF[s]
		if (g.Fixed == nil) != (w.Fixed == nil) || (g.Fixed != nil && !slices.Equal(*g.Fixed, *w.Fixed)) || !slices.Equal(g.Hidden, w.Hidden) {
			t.Fatalf("filter of %s: %+v, want %+v", s, g, w)
		}
	}

	var stored []CopyJob
	linked := map[string]CopyJob{}
	for _, j := range jobs {
		if j.Linked {
			linked[j.Rel] = j
		} else {
			stored = append(stored, j)
		}
	}
	if len(stored) != 1 || stored[0].Rel != "notes.txt" || stored[0].OldSlug != upload.Slug || stored[0].Size != 2 {
		t.Fatalf("stored jobs: %+v", stored)
	}
	if len(linked) != len(rels) {
		t.Fatalf("linked jobs: %+v", linked)
	}
	newLinked, err := db.Slugs(d.ID, rels)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range rels {
		j := linked[rel]
		if j.OldSlug != oldLinked[rel] || j.NewSlug == j.OldSlug || newLinked[rel] != j.NewSlug || j.Size != 0 {
			t.Fatalf("linked job %+v: old %s, copy holds %s", j, oldLinked[rel], newLinked[rel])
		}
	}
	g, err := db.allGalleryRows(d.ID)
	if err != nil || len(g) != 1 || g[newLinked["photos/a.jpg"]].Width != 640 {
		t.Fatalf("copy gallery: %+v, %v", g, err)
	}
	if d.FileCount != 1 || d.Committed != 0 {
		t.Fatalf("copy files %d committed %d: only the upload is a file row", d.FileCount, d.Committed)
	}
}

// A copy still filling holds no committed file for a while, and a slow copy
// can outlast the grace period: the empty sweep must leave it to its worker.
// Once the copy finishes it is an ordinary share again, and the boot list of
// unfinished copies no longer names it.
func TestAnEmptySweepSkipsACopyInProgress(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	src := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 1}}})
	commit(t, db, src.ID, "a.txt", 1)
	d, _ := duplicate(t, db, src.ID, DuplicateOptions{})
	later := time.Now().Add(time.Hour)

	ids, err := db.EmptyShares(later)
	if err != nil || slices.Contains(ids, d.ID) {
		t.Fatalf("EmptyShares lists the copy in progress: %v, %v", ids, err)
	}
	if deleted, err := db.DeleteEmptyShare(d.ID, later); err != nil || deleted {
		t.Fatalf("DeleteEmptyShare took the copy in progress: %v, %v", deleted, err)
	}
	copying, err := db.CopyingShares()
	if err != nil || !slices.Equal(copying, []string{d.ID}) {
		t.Fatalf("CopyingShares = %v, %v", copying, err)
	}

	if err := db.FinishCopy(d.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.Share(d.ID); got.CopyingFrom != "" {
		t.Fatalf("FinishCopy left copyingFrom %q", got.CopyingFrom)
	}
	if copying, _ := db.CopyingShares(); len(copying) != 0 {
		t.Fatalf("CopyingShares after FinishCopy = %v", copying)
	}
	if ids, _ := db.EmptyShares(later); !slices.Contains(ids, d.ID) {
		t.Fatalf("a finished copy with nothing committed is an ordinary empty share: %v", ids)
	}
	if err := db.FinishCopy(shareid.NewID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FinishCopy of no share: %v", err)
	}
}

// The stalled-upload sweep's candidates leave out a copy in progress: its
// pending rows wait on the copy worker, not on a client, and a long copy must
// not lose them. Once the copy finishes they are candidates like any other.
func TestPendingFilesSkipACopyInProgress(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	src := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 1}}})
	commit(t, db, src.ID, "a.txt", 1)
	d, _ := duplicate(t, db, src.ID, DuplicateOptions{})
	later := time.Now().Add(time.Hour)

	if refs, err := db.PendingFiles(later, PendingRef{}, 10000); err != nil || len(refs) != 0 {
		t.Fatalf("PendingFiles lists the copy in progress: %v, %v", refs, err)
	}
	if err := db.FinishCopy(d.ID); err != nil {
		t.Fatal(err)
	}
	refs, err := db.PendingFiles(later, PendingRef{}, 10000)
	if err != nil || len(refs) != 1 || refs[0].ShareID != d.ID || refs[0].Path != "a.txt" {
		t.Fatalf("PendingFiles after FinishCopy = %v, %v", refs, err)
	}
}

// The copy's jobs come a page at a time, the stored files in path order and
// then the linked entries, each page after the cursor of the last: every
// entry exactly once, so the worker never holds more than a page. A stored
// file already committed in the copy is no longer a job, a share that is not
// copying has none, and a share that does not exist is ErrNotFound.
func TestCopyJobsPageTheCopy(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	src := mustShare(t, db, CreateOptions{Name: "nas", Owner: "alice", Sources: []string{"photos"}})
	rels := []string{"photos/a.jpg", "photos/b.jpg", "photos/c.jpg"}
	if _, err := db.AssignSlugs(src.ID, rels); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"x1.txt", "x2.txt", "x3.txt", "x4.txt", "x5.txt"} {
		commit(t, db, src.ID, p, 1)
	}
	d, err := db.DuplicateShare(src.ID, DuplicateOptions{NewID: shareid.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{1, 2, 3, 100} {
		jobs := allCopyJobs(t, db, d.ID, limit)
		var order []string
		for _, j := range jobs {
			order = append(order, j.Rel)
		}
		want := []string{"x1.txt", "x2.txt", "x3.txt", "x4.txt", "x5.txt", "photos/a.jpg", "photos/b.jpg", "photos/c.jpg"}
		if !slices.Equal(order, want) {
			t.Fatalf("limit %d: jobs %v, want %v", limit, order, want)
		}
		for i, j := range jobs {
			if j.Linked != (i >= 5) {
				t.Fatalf("limit %d: %s linked %v", limit, j.Rel, j.Linked)
			}
		}
	}

	// A file the worker committed is no longer a job; the rest still are.
	if _, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: "x2.txt", Size: 1, SHA256: "abc", Mime: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	jobs := allCopyJobs(t, db, d.ID, 2)
	if len(jobs) != 7 || slices.ContainsFunc(jobs, func(j CopyJob) bool { return j.Rel == "x2.txt" }) {
		t.Fatalf("after one commit: %+v", jobs)
	}

	// The poster's slug is found by the same pairing.
	x1, err := db.File(src.ID, "x1.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := db.CopiedSlug(d.ID, x1.Slug); err != nil || got != fileSlug(t, db, d.ID, "x1.txt") {
		t.Fatalf("CopiedSlug(x1) = %q, %v", got, err)
	}
	srcLinked, _ := db.Slugs(src.ID, rels)
	dupLinked, _ := db.Slugs(d.ID, rels)
	if got, err := db.CopiedSlug(d.ID, srcLinked["photos/b.jpg"]); err != nil || got != dupLinked["photos/b.jpg"] {
		t.Fatalf("CopiedSlug(linked b) = %q, %v", got, err)
	}
	if _, err := db.CopiedSlug(d.ID, shareid.NewSlug()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CopiedSlug of a slug the original lacks = %v", err)
	}

	if _, err := db.CopyJobs(d.ID, "bogus", 2); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a cursor CopyJobs never answered: %v", err)
	}
	if err := db.FinishCopy(d.ID); err != nil {
		t.Fatal(err)
	}
	if jobs, err := db.CopyJobs(d.ID, "", 10); err != nil || len(jobs) != 0 {
		t.Fatalf("a finished copy's jobs: %+v, %v", jobs, err)
	}
	if _, err := db.CopyJobs(shareid.NewID(), "", 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no such share: %v", err)
	}
}

// DuplicateShare reads and writes the original's rows a page at a time, and
// a share several pages long is copied whole: every stored file pending
// under a new slug, every linked entry with a new slug, every gallery row on
// its entry's new slug.
func TestDuplicateCopiesEveryPage(t *testing.T) {
	old := copyPage
	copyPage = 2
	t.Cleanup(func() { copyPage = old })
	db := openTest(t)
	mustUser(t, db, "alice")
	src := mustShare(t, db, CreateOptions{Name: "big", Owner: "alice", Media: true, Sources: []string{"photos"}})
	rels := []string{"photos/a.jpg", "photos/b.jpg", "photos/c.jpg", "photos/d.jpg", "photos/e.jpg"}
	linked, err := db.AssignSlugs(src.ID, rels)
	if err != nil {
		t.Fatal(err)
	}
	items := map[string]GalleryItem{}
	for i := range 7 {
		f := commit(t, db, src.ID, fmt.Sprintf("f%d.jpg", i), 1)
		items[f.Slug] = GalleryItem{Width: 10 + i}
	}
	for _, rel := range rels {
		items[linked[rel]] = GalleryItem{Width: 100}
	}
	if err := db.SetGallery(src.ID, items); err != nil {
		t.Fatal(err)
	}
	d, jobs := duplicate(t, db, src.ID, DuplicateOptions{})
	if d.FileCount != 7 || len(jobs) != 12 {
		t.Fatalf("copy holds %d files and %d jobs, want 7 and 12", d.FileCount, len(jobs))
	}
	g, err := db.allGalleryRows(d.ID)
	if err != nil || len(g) != 12 {
		t.Fatalf("copy gallery: %d rows, %v", len(g), err)
	}
	for _, j := range jobs {
		if it, ok := g[j.NewSlug]; !ok || it.Width != items[j.OldSlug].Width {
			t.Fatalf("%s: gallery row %+v, want %+v", j.Rel, it, items[j.OldSlug])
		}
	}
}

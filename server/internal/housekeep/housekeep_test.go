package housekeep

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

type fixture struct {
	dir string
	db  *metadb.DB
	fs  *sharefs.FS
	now time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs, err := sharefs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("alice", "pw", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	return &fixture{dir: dir, db: db, fs: fs, now: time.Now()}
}

func (x *fixture) pass(at time.Time) Result {
	return (&Pass{DB: x.db, FS: x.fs, Now: func() time.Time { return at }}).Run()
}

func (x *fixture) share(t *testing.T, o metadb.CreateOptions) metadb.Share {
	t.Helper()
	o.Owner = "alice"
	if o.Name == "" {
		o.Name = "d"
	}
	d, err := x.db.CreateShare(o)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (x *fixture) upload(t *testing.T, id, rel, body string) {
	t.Helper()
	if _, err := x.fs.Write(id, rel, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	c, err := x.fs.Commit(id, rel, int64(len(body)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.db.CommitFile(metadb.CommitInput{ShareID: id, Path: rel, Size: c.Size, SHA256: c.SHA256, Mime: c.Mime}); err != nil {
		t.Fatal(err)
	}
}

func (x *fixture) shareDir(id string) string { return filepath.Join(x.dir, "shares", id) }

func gone(t *testing.T, x *fixture, id string) {
	t.Helper()
	if _, err := x.db.Share(id); err == nil {
		t.Fatalf("%s rows still there", id)
	}
	if _, err := os.Stat(x.shareDir(id)); err == nil {
		t.Fatalf("%s directory still there", id)
	}
}

func TestExpiredSharesLoseRowsThenDirectory(t *testing.T) {
	x := setup(t)
	soon := x.now.Add(time.Hour)
	d := x.share(t, metadb.CreateOptions{ExpiresAt: &soon})
	x.upload(t, d.ID, "a", "bytes")
	keep := x.share(t, metadb.CreateOptions{})
	x.upload(t, keep.ID, "a", "bytes")
	res := x.pass(x.now)
	if res.Expired != 0 || res.ExpiredErr != nil {
		t.Fatalf("not yet: %+v", res)
	}
	res = x.pass(x.now.Add(2 * time.Hour))
	if res.Expired != 1 || res.ExpiredErr != nil {
		t.Fatalf("expired: %+v", res)
	}
	gone(t, x, d.ID)
	if _, err := x.db.Share(keep.ID); err != nil {
		t.Fatal("an unexpired share was removed")
	}
	if len(res.Lines()) != 1 || !strings.Contains(res.Lines()[0], "expired") {
		t.Fatalf("Lines = %v", res.Lines())
	}
}

func TestDueScheduledChangesAreApplied(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a", "b")
	if _, err := x.db.Schedule(d.ID, metadb.Scheduled{Kind: metadb.ScheduledPassword, ApplyAt: x.now.Add(time.Hour), PasswordHash: "h"}); err != nil {
		t.Fatal(err)
	}
	if res := x.pass(x.now); res.Due != 0 {
		t.Fatalf("not due: %+v", res)
	}
	res := x.pass(x.now.Add(2 * time.Hour))
	if res.Due != 1 || res.DueErr != nil {
		t.Fatalf("due: %+v", res)
	}
	got, _ := x.db.Share(d.ID)
	if !got.HasPassword() || len(got.Scheduled) != 0 {
		t.Fatalf("after apply: %+v", got)
	}
}

func TestStalledUploadsLoseTheirPartsAndRows(t *testing.T) {
	x := setup(t)
	window := sharefs.DefaultAbandonedUpload
	d := x.share(t, metadb.CreateOptions{Files: []metadb.PendingFile{{Path: "dead", Size: 4}, {Path: "live", Size: 4}, {Path: "never", Size: 4}}})
	if _, err := x.fs.WriteRange(d.ID, "dead", strings.NewReader("ab"), sharefs.Range{Start: 0, End: 2}, 4, "s", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := x.fs.WriteRange(d.ID, "live", strings.NewReader("abc"), sharefs.Range{Start: 0, End: 3}, 4, "s", nil); err != nil {
		t.Fatal(err)
	}
	sizeBefore, _ := x.fs.PartSize(d.ID, "dead")
	// The part's own age is what decides, so the dead one is backdated. The
	// two staged bodies have different lengths, so backdatePart tells them
	// apart by size.
	old := time.Now().Add(-2 * window)
	backdatePart(t, x, d.ID, "dead", old)
	later := x.now.Add(2 * window)
	res := x.pass(later)
	if res.StalledErr != nil || res.StalledParts != 1 || res.StalledRows != 1 {
		t.Fatalf("stalled: %+v (dead part and row gone, live and never kept)", res)
	}
	got, err := x.db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, f := range got.Files {
		kept[f.Path] = true
	}
	if len(kept) != 2 || !kept["live"] || !kept["never"] {
		t.Fatalf("rows after sweep: %+v", got.Files)
	}
	if size, _ := x.fs.PartSize(d.ID, "live"); size != 3 {
		t.Fatal("the live part was discarded")
	}
	if size, _ := x.fs.PartSize(d.ID, "dead"); size != 0 || sizeBefore != 2 {
		t.Fatal("the dead part survived")
	}
	if res.Empty != 0 {
		t.Fatal("a share with a live upload is not empty")
	}
}

// A pending row can name a file that already landed under files/: the
// commit renamed the part and the row write never happened. The sweep that
// gives up on the row removes that file with it.
func TestAStalledRowLosesTheFileItNames(t *testing.T) {
	x := setup(t)
	window := sharefs.DefaultAbandonedUpload
	d := x.share(t, metadb.CreateOptions{Files: []metadb.PendingFile{{Path: "stray", Size: 5}}})
	// A committed file keeps the share off the empty sweep, so what the
	// stalled sweep did to the pending row stays readable on disk.
	x.upload(t, d.ID, "kept", "bytes")
	if _, err := x.fs.Write(d.ID, "stray", strings.NewReader("bytes")); err != nil {
		t.Fatal(err)
	}
	if _, err := x.fs.Commit(d.ID, "stray", 5, nil); err != nil {
		t.Fatal(err)
	}
	res := x.pass(x.now.Add(2 * window))
	if res.StalledErr != nil || res.StalledRows != 1 || res.StalledParts != 0 {
		t.Fatalf("stalled: %+v (the row and its file go, no part was staged)", res)
	}
	if _, err := os.Stat(filepath.Join(x.shareDir(d.ID), "files", "stray")); err == nil {
		t.Fatal("the file the pending row named survived the sweep")
	}
	if _, err := os.Stat(filepath.Join(x.shareDir(d.ID), "files", "kept")); err != nil {
		t.Fatalf("the committed file was removed: %v", err)
	}
	got, err := x.db.Share(d.ID)
	if err != nil || len(got.Files) != 1 || got.Files[0].Path != "kept" {
		t.Fatalf("rows after sweep: %+v, %v", got.Files, err)
	}
}

// A manifest row nothing was ever uploaded into is not a stalled upload:
// no part was staged and no file stands for it, its slug may already be in
// a link a client is holding, and expiry and the empty sweep own it.
func TestAManifestRowWithNothingStagedKeepsItsRowAndSlug(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{Files: []metadb.PendingFile{{Path: "later", Size: 4}}})
	// A committed file keeps the share off the empty sweep, so the pending
	// row is the only thing a pass could take.
	x.upload(t, d.ID, "kept", "bytes")
	before, err := x.db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	slug := ""
	for _, f := range before.Files {
		if f.Path == "later" {
			slug = f.Slug
		}
	}
	if slug == "" {
		t.Fatal("the declared row has no slug")
	}
	res := x.pass(x.now.Add(4 * time.Hour))
	if res.StalledErr != nil || res.StalledRows != 0 || res.StalledParts != 0 {
		t.Fatalf("stalled: %+v (nothing was ever staged for the row)", res)
	}
	got, err := x.db.Share(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range got.Files {
		if f.Path == "later" {
			found = f.Slug == slug && f.Pending
		}
	}
	if !found {
		t.Fatalf("the declared row lost its place: %+v", got.Files)
	}
}

// A part no pending row leads to (its upload's row was withdrawn, or it is
// an overwrite of a committed file abandoned midway) is swept once nothing
// has written to it for the window, sidecars and all, where only the next
// boot would otherwise remove it. A fresh one is resume state and stays.
func TestAPartNoPendingRowLeadsToIsSweptPastTheWindow(t *testing.T) {
	x := setup(t)
	window := sharefs.DefaultAbandonedUpload
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "kept", "bytes")
	for rel, body := range map[string]string{"orphan": "ab", "kept": "abcd", "fresh": "abc"} {
		if _, err := x.fs.WriteRange(d.ID, rel, strings.NewReader(body), sharefs.Range{Start: 0, End: int64(len(body))}, 10, "session", nil); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * window)
	backdatePart(t, x, d.ID, "orphan", old)
	backdatePart(t, x, d.ID, "kept", old)
	res := x.pass(x.now)
	if res.StalledErr != nil || res.StalledParts != 2 || res.StalledRows != 0 {
		t.Fatalf("stalled: %+v (two rowless or committed-row parts, no pending row)", res)
	}
	for rel, want := range map[string]int64{"orphan": 0, "kept": 0, "fresh": 3} {
		if size, _ := x.fs.PartSize(d.ID, rel); size != want {
			t.Errorf("%s staged %d bytes after the sweep, want %d", rel, size, want)
		}
	}
	entries, err := os.ReadDir(filepath.Join(x.shareDir(d.ID), "parts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), entries[0].Name()) {
			t.Errorf("%s survived its part (only the fresh part's files remain: %s)", e.Name(), entries[0].Name())
		}
	}
	if _, err := os.Stat(filepath.Join(x.shareDir(d.ID), "files", "kept")); err != nil {
		t.Fatalf("the committed file went with its abandoned overwrite: %v", err)
	}
}

// backdatePart sets rel's staged part mtime; the part's name is the hash of
// the relpath, which is the file layer's business, so the test finds it by
// asking the layer for rel's staged size and matching that size on disk.
func backdatePart(t *testing.T, x *fixture, id, rel string, to time.Time) {
	t.Helper()
	dir := filepath.Join(x.shareDir(id), "parts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x.fs.PartSize(id, rel)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".part") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.Size() == want {
			if err := os.Chtimes(p, to, to); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("no part for %s", rel)
}

func TestEmptySharesAreSweptAfterTheGraceUnlessSomethingKeepsThem(t *testing.T) {
	x := setup(t)
	empty := x.share(t, metadb.CreateOptions{Files: []metadb.PendingFile{{Path: "p", Size: 1}}})
	if _, err := x.fs.Write(empty.ID, "p", strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	inbox := x.share(t, metadb.CreateOptions{Inbox: true})
	full := x.share(t, metadb.CreateOptions{})
	x.upload(t, full.ID, "a", "b")
	uploading := x.share(t, metadb.CreateOptions{Files: []metadb.PendingFile{{Path: "u", Size: 4}}})
	if _, err := x.fs.WriteRange(uploading.ID, "u", strings.NewReader("ab"), sharefs.Range{Start: 0, End: 2}, 4, "s", nil); err != nil {
		t.Fatal(err)
	}
	folderFirst := x.share(t, metadb.CreateOptions{})
	if _, err := x.db.AddFolder(folderFirst.ID, "docs"); err != nil {
		t.Fatal(err)
	}
	if res := x.pass(x.now); res.Empty != 0 {
		t.Fatalf("inside the grace: %+v", res)
	}
	window := sharefs.DefaultAbandonedUpload
	backdatePart(t, x, empty.ID, "p", time.Now().Add(-2*window))
	res := x.pass(x.now.Add(2 * window))
	if res.EmptyErr != nil || res.Empty != 1 {
		t.Fatalf("empty sweep: %+v", res)
	}
	gone(t, x, empty.ID)
	for name, id := range map[string]string{"receive": inbox.ID, "full": full.ID, "uploading": uploading.ID, "folderFirst": folderFirst.ID} {
		if _, err := x.db.Share(id); err != nil {
			t.Fatalf("%s was swept", name)
		}
	}
}

func TestJournalRowsAgeOut(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a", "b")
	time.Sleep(20 * time.Millisecond)
	// The create and the upload touch one share back to back, so the
	// journal holds the single row they coalesced into.
	res := x.pass(time.Now().Add(metadb.ChangesRetention + time.Hour))
	if res.Changes < 1 || res.ChangesErr != nil || res.OptimizeErr != nil {
		t.Fatalf("aging: %+v", res)
	}
	if b, _ := x.db.Since("0", "alice", 10); !b.Reset {
		t.Fatal("a cursor from before the prune must reset")
	}
}

func TestAPassBacksUpTheDatabaseOncePerDay(t *testing.T) {
	x := setup(t)
	backups := filepath.Join(x.dir, "backups")
	p := &Pass{DB: x.db, FS: x.fs, DataDir: x.dir, Now: func() time.Time { return x.now }}
	if res := p.Run(); !res.BackedUp || res.BackupErr != nil {
		t.Fatalf("first pass: %+v", res)
	}
	if res := p.Run(); res.BackedUp {
		t.Fatal("a second pass the same day backed up again")
	}
	p.Now = func() time.Time { return x.now.Add(25 * time.Hour) }
	if res := p.Run(); !res.BackedUp {
		t.Fatal("a pass a day later did not back up")
	}
	names, _ := filepath.Glob(filepath.Join(backups, "hyperdrop-*.db"))
	if len(names) != 2 {
		t.Fatalf("backups: %v", names)
	}
}

func TestARecoveredMarkerIsRemovedAfterAWeek(t *testing.T) {
	x := setup(t)
	os.WriteFile(filepath.Join(x.dir, metadb.RecoveredMarker),
		[]byte(`{"at":"`+x.now.Add(-6*24*time.Hour).UTC().Format(time.RFC3339)+`","backup":"b","corrupt":"c"}`), 0o644)
	p := &Pass{DB: x.db, FS: x.fs, DataDir: x.dir, Now: func() time.Time { return x.now }}
	p.Run()
	if _, ok := metadb.ReadRecovered(x.dir); !ok {
		t.Fatal("a six-day-old marker was removed")
	}
	p.Now = func() time.Time { return x.now.Add(2 * 24 * time.Hour) }
	p.Run()
	if _, ok := metadb.ReadRecovered(x.dir); ok {
		t.Fatal("an eight-day-old marker survived")
	}
}

// A declared share whose sender is still making the bytes has no part and
// no file, so only its preparing reports say it is alive. The sweep asks
// Alive with the grace cutoff and keeps the share while the answer is yes.
func TestAFreshPreparingReportKeepsAnEmptyShare(t *testing.T) {
	x := setup(t)
	declared := x.share(t, metadb.CreateOptions{Files: []metadb.PendingFile{{Path: "a.mp4", Size: 10}}})
	at := x.now.Add(2 * EmptyGrace)
	var asked []time.Time
	alive := func(id string, since time.Time) bool {
		if id == declared.ID {
			asked = append(asked, since)
		}
		return true
	}
	res := (&Pass{DB: x.db, FS: x.fs, Now: func() time.Time { return at }, Alive: alive}).Run()
	if res.EmptyErr != nil || res.Empty != 0 {
		t.Fatalf("a reported-on share was swept: %+v", res)
	}
	if len(asked) != 1 || !asked[0].Equal(at.Add(-EmptyGrace)) {
		t.Fatalf("Alive asked with %v, want the grace cutoff %v", asked, at.Add(-EmptyGrace))
	}
	dead := func(string, time.Time) bool { return false }
	res = (&Pass{DB: x.db, FS: x.fs, Now: func() time.Time { return at }, Alive: dead}).Run()
	if res.EmptyErr != nil || res.Empty != 1 {
		t.Fatalf("a share nobody reports on survived: %+v", res)
	}
	gone(t, x, declared.ID)
}

func TestThePassPrunesExpiredWebSessions(t *testing.T) {
	x := setup(t)
	if _, err := x.db.MintWebSession("alice", "Web browser · Firefox on Linux", false, x.now); err != nil {
		t.Fatal(err)
	}
	if res := x.pass(x.now.Add(29 * time.Minute)); res.WebSessions != 0 || res.WebSessionsErr != nil {
		t.Fatalf("within the idle limit: %+v", res)
	}
	res := x.pass(x.now.Add(31 * time.Minute))
	if res.WebSessions != 1 || res.WebSessionsErr != nil {
		t.Fatalf("past the idle limit: %+v", res)
	}
	if !slices.ContainsFunc(res.Lines(), func(l string) bool { return strings.Contains(l, "web sessions") && strings.Contains(l, "1") }) {
		t.Fatalf("lines %q name no web session", res.Lines())
	}
}

func TestThePassPrunesOldDeviceLinks(t *testing.T) {
	x := setup(t)
	if _, err := x.db.MintToken("alice", "desktop"); err != nil {
		t.Fatal(err)
	}
	alice, err := x.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.db.MintDeviceLink("alice", alice.Tokens[0].ID, "203.0.113.7", false, x.now); err != nil {
		t.Fatal(err)
	}
	if res := x.pass(x.now.Add(23 * time.Hour)); res.DeviceLinks != 0 || res.DeviceLinksErr != nil {
		t.Fatalf("within the day: %+v", res)
	}
	res := x.pass(x.now.Add(24*time.Hour + time.Minute))
	if res.DeviceLinks != 1 || res.DeviceLinksErr != nil {
		t.Fatalf("a day and a minute later: %+v", res)
	}
	named := false
	for _, l := range res.Lines() {
		if strings.Contains(l, "device links") && strings.Contains(l, "1") {
			named = true
		}
	}
	if !named {
		t.Fatalf("Lines = %v, want the device-link sweep named with its count", res.Lines())
	}
}

func TestThePassPrunesTheKeysOfDeletedFiles(t *testing.T) {
	x := setup(t)
	files := []metadb.PendingFile{{Path: "a.txt", Size: 1}, {Path: "b.txt", Size: 1}}
	sh := x.share(t, metadb.CreateOptions{Folder: true, Files: files})
	for _, f := range files {
		if _, err := x.db.CommitFile(metadb.CommitInput{ShareID: sh.ID, Path: f.Path, Size: 1, Mime: "text/plain"}); err != nil {
			t.Fatal(err)
		}
	}
	d, err := x.db.Share(sh.ID)
	if err != nil {
		t.Fatal(err)
	}
	var slugs []string
	for _, f := range d.Files {
		slugs = append(slugs, f.Slug)
	}
	keys, err := x.db.MintFileKeys(sh.ID, slugs, x.now)
	if err != nil || len(keys) != 2 {
		t.Fatalf("mint: %v, %v", keys, err)
	}
	if res := x.pass(x.now); res.FileLinks != 0 || res.FileLinksErr != nil {
		t.Fatalf("both files present: %+v", res)
	}
	if _, _, err := x.db.RemoveFiles(sh.ID, []string{"a.txt"}); err != nil {
		t.Fatal(err)
	}
	res := x.pass(x.now)
	if res.FileLinks != 1 || res.FileLinksErr != nil {
		t.Fatalf("after a delete: %+v", res)
	}
	if !slices.ContainsFunc(res.Lines(), func(l string) bool { return strings.Contains(l, "file links") && strings.Contains(l, "1") }) {
		t.Fatalf("Lines = %v, want the file-link sweep named with its count", res.Lines())
	}
	if left, err := x.db.FileKeys(sh.ID); err != nil || len(left) != 1 {
		t.Fatalf("keys left: %v, %v", left, err)
	}
}

func TestThePassPrunesOldSignInEvents(t *testing.T) {
	x := setup(t)
	if _, err := x.db.MintToken("alice", "phone"); err != nil {
		t.Fatal(err)
	}
	alice, err := x.db.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.db.MintDesktopSignIn("alice", alice.Tokens[0].ID, "Mac", "macos", "m", x.now); err != nil {
		t.Fatal(err)
	}
	if res := x.pass(x.now.Add(metadb.SignInEventsFor - time.Hour)); res.SignInEvents != 0 || res.SignInEventsErr != nil {
		t.Fatalf("within the 90 days: %+v", res)
	}
	res := x.pass(x.now.Add(metadb.SignInEventsFor + time.Minute))
	if res.SignInEvents != 1 || res.SignInEventsErr != nil {
		t.Fatalf("past the 90 days: %+v", res)
	}
	if !slices.ContainsFunc(res.Lines(), func(l string) bool { return strings.Contains(l, "sign-in records") && strings.Contains(l, "1") }) {
		t.Fatalf("lines %q name no sign-in record", res.Lines())
	}
}

func TestPassCountsStoredFilesMissingFromDisk(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a.txt", "a")
	x.upload(t, d.ID, "dir/b.txt", "b")
	x.upload(t, d.ID, "c.txt", "c")
	if r := x.pass(x.now); !r.MissingChecked || r.MissingFiles != 0 {
		t.Fatalf("intact volume: checked=%v missing=%d, want true 0", r.MissingChecked, r.MissingFiles)
	}
	if err := os.Remove(filepath.Join(x.shareDir(d.ID), "files", "dir", "b.txt")); err != nil {
		t.Fatal(err)
	}
	p := &Pass{DB: x.db, FS: x.fs, Now: func() time.Time { return x.now }}
	if r := p.Run(); r.MissingFiles != 1 {
		t.Fatalf("one file deleted: missing=%d, want 1", r.MissingFiles)
	}
	// A second pass inside the interval does not scan again.
	if r := p.Run(); r.MissingChecked {
		t.Fatal("scanned twice within a day")
	}
	p.Now = func() time.Time { return x.now.Add(MissingInterval) }
	if r := p.Run(); !r.MissingChecked || r.MissingFiles != 1 {
		t.Fatalf("a day later: checked=%v missing=%d, want true 1", r.MissingChecked, r.MissingFiles)
	}
}

// A share deleted after the scan read its rows is gone on purpose, and its
// files are not counted as missing.
func TestMissingFilesSkipsAShareDeletedDuringTheScan(t *testing.T) {
	x := setup(t)
	kept := x.share(t, metadb.CreateOptions{})
	x.upload(t, kept.ID, "a.txt", "a")
	x.upload(t, kept.ID, "b.txt", "b")
	gone := x.share(t, metadb.CreateOptions{})
	x.upload(t, gone.ID, "c.txt", "c")
	x.upload(t, gone.ID, "d.txt", "d")
	if err := os.Remove(filepath.Join(x.shareDir(kept.ID), "files", "b.txt")); err != nil {
		t.Fatal(err)
	}
	p := &Pass{DB: x.db, FS: x.fs, Now: func() time.Time { return x.now }}
	deleted := false
	p.beforeStat = func(shareID, rel string) {
		if shareID != gone.ID || deleted {
			return
		}
		deleted = true
		if err := x.db.DeleteShare(gone.ID); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(x.shareDir(gone.ID)); err != nil {
			t.Fatal(err)
		}
	}
	if r := p.Run(); r.MissingFiles != 1 || !deleted {
		t.Fatalf("missing=%d deleted=%v, want 1 true (only kept/b.txt)", r.MissingFiles, deleted)
	}
}

func TestMissingFilesIgnoresPendingRowsAndPublishesTheCount(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a.txt", "a")
	if _, err := x.db.DeclareFile(d.ID, "pending.txt", 5); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(x.shareDir(d.ID), "files", "a.txt")); err != nil {
		t.Fatal(err)
	}
	var shared atomic.Int64
	p := &Pass{DB: x.db, FS: x.fs, Now: func() time.Time { return x.now }, MissingFiles: &shared}
	if r := p.Run(); r.MissingFiles != 1 || shared.Load() != 1 {
		t.Fatalf("missing=%d shared=%d, want 1 1 (the pending row is not counted)", r.MissingFiles, shared.Load())
	}
}

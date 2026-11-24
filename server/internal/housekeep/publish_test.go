package housekeep

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// publishFixture is a share holding a.txt and b.txt with a publish open on
// it, staging a new a.txt and d/c.txt, and the journal of the commit that
// replaces a.txt, adds d/c.txt and deletes b.txt.
type publishFixture struct {
	*fixture
	id, pid string
	staged  map[string]sharefs.Staged
	journal sharefs.Journal
}

func setupPublish(t *testing.T) *publishFixture {
	t.Helper()
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	x.upload(t, d.ID, "a.txt", "old a")
	x.upload(t, d.ID, "b.txt", "old b")
	pid := shareid.NewPublishID()
	if err := x.fs.OpenStage(d.ID, pid, "alice"); err != nil {
		t.Fatal(err)
	}
	staged := map[string]sharefs.Staged{}
	for rel, body := range map[string]string{"a.txt": "new a, longer", "d/c.txt": "new c"} {
		s, err := x.fs.WriteStaged(d.ID, pid, rel, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		staged[rel] = s
	}
	return &publishFixture{fixture: x, id: d.ID, pid: pid, staged: staged,
		journal: sharefs.Journal{Files: []string{"a.txt", "d/c.txt"}, Delete: []string{"b.txt"}}}
}

// commitRows is the commit's transaction for journal j.
func (x *publishFixture) commitRows(t *testing.T, j sharefs.Journal) metadb.PublishResult {
	t.Helper()
	var commits []metadb.PublishCommit
	for _, p := range j.Files {
		s := x.staged[p]
		commits = append(commits, metadb.PublishCommit{Path: p, Size: s.Size, SHA256: s.SHA256, Mime: s.Mime})
	}
	res, err := x.db.PublishFiles(x.id, commits, j.Delete, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// commitMarked is the commit up to its renames: the journal, the rows, and
// the journal marked with what the rows hold, as the commit handler writes
// them.
func (x *publishFixture) commitMarked(t *testing.T) {
	t.Helper()
	if err := x.fs.WriteJournal(x.id, x.pid, x.journal); err != nil {
		t.Fatal(err)
	}
	res := x.commitRows(t, x.journal)
	marked := x.journal
	marked.Rows = &sharefs.JournalRows{}
	for i, p := range x.journal.Files {
		marked.Rows.Renames = append(marked.Rows.Renames, sharefs.Rename{From: p, To: res.Files[i].Path})
	}
	for _, f := range res.Deleted {
		marked.Rows.Deleted = append(marked.Rows.Deleted, f.Path)
	}
	if err := x.fs.WriteJournal(x.id, x.pid, marked); err != nil {
		t.Fatal(err)
	}
}

// restart is a fresh process's file layer over the same data directory,
// after the boot pass's sweep of shares/ and its settling of journals.
func (x *publishFixture) restart(t *testing.T) (finished, reopened int) {
	t.Helper()
	fs, err := sharefs.Open(x.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Orphans(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	x.fs = fs
	finished, reopened, err = FinishPublishes(x.db, fs)
	if err != nil {
		t.Fatalf("FinishPublishes: %v", err)
	}
	return finished, reopened
}

// stored is rel's bytes under files/, and false when there are none.
func (x *publishFixture) stored(rel string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(x.shareDir(x.id), "files", filepath.FromSlash(rel)))
	return string(data), err == nil
}

// everyRowHoldsItsBytes fails unless each of the share's file rows names
// bytes under files/ whose digest is the row's.
func (x *publishFixture) everyRowHoldsItsBytes(t *testing.T) {
	t.Helper()
	d, err := x.db.Share(x.id)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Files {
		data, ok := x.stored(f.Path)
		sum := sha256.Sum256([]byte(data))
		if !ok || hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Errorf("row %s (sha256 %s) names %q (present %v)", f.Path, f.SHA256, data, ok)
		}
	}
}

// A crash after the journal and before the rows: the rows do not name the
// publish, so the boot pass removes the journal and leaves the publish
// open, committable again, with the share as it stood.
func TestTheBootPassReopensAPublishBeforeItsRows(t *testing.T) {
	x := setupPublish(t)
	if err := x.fs.WriteJournal(x.id, x.pid, x.journal); err != nil {
		t.Fatal(err)
	}
	if finished, reopened := x.restart(t); finished != 0 || reopened != 1 {
		t.Fatalf("finished %d, reopened %d; want 0 and 1", finished, reopened)
	}
	if _, ok, _ := x.fs.ReadJournal(x.id, x.pid); ok {
		t.Fatal("the journal survived")
	}
	if files, err := x.fs.StagedFiles(x.id, x.pid); err != nil || len(files) != 2 {
		t.Fatalf("the reopened publish: %v, %v", files, err)
	}
	for rel, want := range map[string]string{"a.txt": "old a", "b.txt": "old b"} {
		if got, _ := x.stored(rel); got != want {
			t.Fatalf("%s = %q, want %q", rel, got, want)
		}
	}
	if _, ok := x.stored("d/c.txt"); ok {
		t.Fatal("d/c.txt went live without its row")
	}
	x.everyRowHoldsItsBytes(t)
	if n := x.fs.OpenPublishes("alice"); n != 1 {
		t.Fatalf("open publishes = %d, want 1", n)
	}
}

// A crash after the rows, before any rename and midway through the
// renames: the boot pass renames every part still staged and removes the
// deleted file, so each row's bytes are in files/ with its hash, and the
// publish is gone.
func TestTheBootPassFinishesACommit(t *testing.T) {
	for _, midway := range []bool{false, true} {
		x := setupPublish(t)
		if err := x.fs.WriteJournal(x.id, x.pid, x.journal); err != nil {
			t.Fatal(err)
		}
		x.commitRows(t, x.journal)
		if midway {
			if err := x.fs.SwapIn(x.id, x.pid, []sharefs.Rename{{From: "a.txt", To: "a.txt"}}, nil); err != nil {
				t.Fatal(err)
			}
		}
		if finished, reopened := x.restart(t); finished != 1 || reopened != 0 {
			t.Fatalf("midway %v: finished %d, reopened %d; want 1 and 0", midway, finished, reopened)
		}
		x.everyRowHoldsItsBytes(t)
		if got, _ := x.stored("a.txt"); got != "new a, longer" {
			t.Fatalf("midway %v: a.txt = %q", midway, got)
		}
		if _, ok := x.stored("b.txt"); ok {
			t.Fatalf("midway %v: the deleted file is still there", midway)
		}
		if x.fs.StageExists(x.id, x.pid) {
			t.Fatalf("midway %v: the publish survived its commit", midway)
		}
		if n := x.fs.OpenPublishes("alice"); n != 0 {
			t.Fatalf("midway %v: open publishes = %d, want 0", midway, n)
		}
	}
}

// A journal that only deletes rolls forward only once its rows are gone:
// before the transaction every file it names still stands, and with no
// commit path to compare, nothing else says the rows were written.
func TestADeleteOnlyJournalRollsForwardOnlyAfterItsRows(t *testing.T) {
	for _, committed := range []bool{false, true} {
		x := setupPublish(t)
		j := sharefs.Journal{Delete: []string{"b.txt"}}
		if err := x.fs.WriteJournal(x.id, x.pid, j); err != nil {
			t.Fatal(err)
		}
		if committed {
			x.commitRows(t, j)
		}
		finished, reopened := x.restart(t)
		_, stored := x.stored("b.txt")
		switch {
		case !committed && (finished != 0 || reopened != 1 || !stored || !x.fs.StageExists(x.id, x.pid)):
			t.Fatalf("before the rows: finished %d, reopened %d, b.txt stored %v", finished, reopened, stored)
		case committed && (finished != 1 || reopened != 0 || stored || x.fs.StageExists(x.id, x.pid)):
			t.Fatalf("after the rows: finished %d, reopened %d, b.txt stored %v", finished, reopened, stored)
		}
		x.everyRowHoldsItsBytes(t)
	}
}

// A journal whose commit paths match but whose deleted row still stands
// is a commit that never ran: replacing a.txt with the bytes it already
// holds matches the row, and only the delete tells the two apart.
func TestARowThatAlreadyMatchesIsNotTakenForTheCommit(t *testing.T) {
	x := setupPublish(t)
	s, err := x.fs.WriteStaged(x.id, x.pid, "a.txt", strings.NewReader("old a"))
	if err != nil {
		t.Fatal(err)
	}
	x.staged["a.txt"] = s
	if err := x.fs.WriteJournal(x.id, x.pid, sharefs.Journal{Files: []string{"a.txt"}, Delete: []string{"b.txt"}}); err != nil {
		t.Fatal(err)
	}
	if finished, reopened := x.restart(t); finished != 0 || reopened != 1 {
		t.Fatalf("finished %d, reopened %d; want 0 and 1", finished, reopened)
	}
	if got, _ := x.stored("b.txt"); got != "old b" {
		t.Fatalf("b.txt = %q", got)
	}
}

// The pass sweeps a publish nothing has written to for the window, and says
// so; a fresh one stays.
func TestThePassSweepsAQuietPublish(t *testing.T) {
	x := setupPublish(t)
	if res := x.pass(x.now); res.Publishes != 0 {
		t.Fatalf("a fresh publish was swept: %+v", res)
	}
	backdateStage(t, x.fixture, x.id, x.pid, time.Now().Add(-2*sharefs.DefaultAbandonedUpload))
	res := x.pass(x.now)
	if res.Publishes != 1 || x.fs.StageExists(x.id, x.pid) {
		t.Fatalf("the quiet publish: %+v, exists %v", res, x.fs.StageExists(x.id, x.pid))
	}
	if lines := strings.Join(res.Lines(), "\n"); !strings.Contains(lines, "publish sweep") {
		t.Fatalf("the pass logged %q", lines)
	}
	if n := x.fs.OpenPublishes("alice"); n != 0 {
		t.Fatalf("open publishes = %d, want 0", n)
	}
}

// A share whose only activity is an open publish is being built: the
// empty sweep spares it while the publish is written within the window,
// and takes it once the publish has gone quiet and been swept.
func TestTheEmptySweepSparesAShareBuiltByAPublish(t *testing.T) {
	x := setup(t)
	d := x.share(t, metadb.CreateOptions{})
	pid := shareid.NewPublishID()
	if err := x.fs.OpenStage(d.ID, pid, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.fs.WriteStaged(d.ID, pid, "index.html", strings.NewReader("<p>")); err != nil {
		t.Fatal(err)
	}
	later := x.now.Add(2 * EmptyGrace)
	if res := x.pass(later); res.Empty != 0 {
		t.Fatalf("the empty sweep took a share a publish is building: %+v", res)
	}
	if _, err := x.db.Share(d.ID); err != nil {
		t.Fatal("the share is gone")
	}
	backdateStage(t, x, d.ID, pid, time.Now().Add(-2*sharefs.DefaultAbandonedUpload))
	if res := x.pass(later); res.Publishes != 1 || res.Empty != 1 {
		t.Fatalf("a quiet publish and its empty share: %+v", res)
	}
	gone(t, x, d.ID)
}

// backdateStage sets every file of publish pid on share id, and its
// directory, to the time to.
func backdateStage(t *testing.T, x *fixture, id, pid string, to time.Time) {
	t.Helper()
	dir := filepath.Join(x.shareDir(id), "stage", pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Chtimes(filepath.Join(dir, e.Name()), to, to); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(dir, to, to); err != nil {
		t.Fatal(err)
	}
}

// A journal marked after its rows rolls forward whole when nothing
// superseded it, whatever the renames had done: none, or some.
func TestAMarkedJournalRollsForwardCompletely(t *testing.T) {
	for _, midway := range []bool{false, true} {
		x := setupPublish(t)
		x.commitMarked(t)
		if midway {
			if err := x.fs.SwapIn(x.id, x.pid, []sharefs.Rename{{From: "d/c.txt", To: "d/c.txt"}}, nil); err != nil {
				t.Fatal(err)
			}
		}
		if finished, reopened := x.restart(t); finished != 1 || reopened != 0 {
			t.Fatalf("midway %v: finished %d, reopened %d; want 1 and 0", midway, finished, reopened)
		}
		x.everyRowHoldsItsBytes(t)
		for rel, want := range map[string]string{"a.txt": "new a, longer", "d/c.txt": "new c"} {
			if got, _ := x.stored(rel); got != want {
				t.Fatalf("midway %v: %s = %q, want %q", midway, rel, got, want)
			}
		}
		if _, ok := x.stored("b.txt"); ok {
			t.Fatalf("midway %v: the deleted file is still there", midway)
		}
		if x.fs.StageExists(x.id, x.pid) || x.fs.OpenPublishes("alice") != 0 {
			t.Fatalf("midway %v: the publish survived its commit", midway)
		}
	}
}

// The rows were written and the renames failed; before the restart an
// ordinary upload replaced a.txt. The marked journal still rolls forward:
// d/c.txt's part goes into place, a.txt's part, superseded, is dropped,
// and the sweep that follows loses nothing.
func TestAMarkedJournalDropsASupersededPart(t *testing.T) {
	x := setupPublish(t)
	x.commitMarked(t)
	x.upload(t, x.id, "a.txt", "newest a")
	if finished, reopened := x.restart(t); finished != 1 || reopened != 0 {
		t.Fatalf("finished %d, reopened %d; want 1 and 0", finished, reopened)
	}
	x.everyRowHoldsItsBytes(t)
	for rel, want := range map[string]string{"a.txt": "newest a", "d/c.txt": "new c"} {
		if got, _ := x.stored(rel); got != want {
			t.Fatalf("%s = %q, want %q", rel, got, want)
		}
	}
	if x.fs.StageExists(x.id, x.pid) {
		t.Fatal("the publish survived its commit")
	}
	x.fs.AbandonedWindow = time.Nanosecond
	x.pass(x.now.Add(24 * time.Hour))
	x.everyRowHoldsItsBytes(t)
	if got, _ := x.stored("d/c.txt"); got != "new c" {
		t.Fatalf("d/c.txt after the sweep = %q", got)
	}
}

// A path the commit deleted and an upload created again before the
// restart keeps the new upload's bytes: a marked journal removes a
// deleted path only where no row stands now.
func TestAMarkedJournalKeepsAReuploadedDeletedPath(t *testing.T) {
	x := setupPublish(t)
	x.commitMarked(t)
	x.upload(t, x.id, "b.txt", "b again")
	if finished, _ := x.restart(t); finished != 1 {
		t.Fatalf("finished %d, want 1", finished)
	}
	if got, ok := x.stored("b.txt"); !ok || got != "b again" {
		t.Fatalf("b.txt = %q %v, want the new upload", got, ok)
	}
	x.everyRowHoldsItsBytes(t)
}

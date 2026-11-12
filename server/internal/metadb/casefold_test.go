package metadb

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"hyperdrop/server/internal/shareid"
)

// A name the volume keeps apart from a stored one keeps its own spelling,
// whatever the fold key says, and a name it merges takes the stored one:
// straße and strasse are two files on an upcase volume and one on a fully
// folding one.
func TestTheVolumeDecidesWhetherANameIsAStoredOne(t *testing.T) {
	for _, v := range []struct {
		name string
		same func(a, b string) bool
		want string
	}{
		{"upcase", upcaseFold, "strasse.pdf,straße.pdf"},
		{"full", fullFold, "straße.pdf"},
	} {
		t.Run(v.name, func(t *testing.T) {
			db := openTest(t)
			db.SetFoldCase(bySegment(v.same))
			mustUser(t, db, "alice")
			sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
			for _, p := range []string{"straße.pdf", "strasse.pdf"} {
				if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: p, Size: 1}); err != nil {
					t.Fatal(err)
				}
			}
			if got := paths(t, db, sh.ID); got != v.want {
				t.Fatalf("paths = %s, want %s", got, v.want)
			}
			if _, err := db.CreateShare(CreateOptions{Name: "t", Owner: "alice",
				Files: []PendingFile{{Path: "d/straße", Size: 1}, {Path: "D/strasse", Size: 1}}}); (err != nil) != (v.name == "full") {
				t.Fatalf("a manifest of d/straße and D/strasse = %v", err)
			}
		})
	}
}

// The Turkish i's land as the volume the test runs on compares them: each
// name takes the spelling of the first stored name the volume calls it.
func TestTurkishIsLandAsTheVolumeComparesThem(t *testing.T) {
	db := openTest(t)
	same := volumeSame(t)
	db.SetFoldCase(bySegment(same))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	var stored []string
	for _, name := range []string{"İ.txt", "i̇.txt", "i.txt", "ı.txt", "I.txt"} {
		want := name
		for _, s := range stored {
			if same(s, name) {
				want = s
				break
			}
		}
		f, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: name, Size: 1})
		if err != nil {
			t.Fatal(err)
		}
		if f.Path != want {
			t.Errorf("%q landed as %q, want %q", name, f.Path, want)
		}
		if want == name {
			stored = append(stored, name)
		}
	}
}

// A new name's lookup walks the index for its own spellings: it costs the
// same seeks in a share of a thousand files and in one of fifty thousand.
func TestASpellingLookupDoesNotGrowWithTheShare(t *testing.T) {
	seeks := map[int]int64{}
	for _, n := range []int{1000, 50000} {
		db := openTest(t)
		db.SetFoldCase(bySegment(fullFold))
		mustUser(t, db, "alice")
		sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
		if err := db.commit(func(tx *sql.Tx) error {
			for i := range n {
				if err := insertPending(tx, sh.ID, fmt.Sprintf("Report %d.pdf", i), 1, time.Now()); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		before := foldSeeks.Load()
		for _, rel := range []string{"report 7.PDF", "REPORT new.pdf", "other.txt"} {
			if _, err := db.Spelling(sh.ID, rel, ""); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := db.Spelling(sh.ID, "report 7.PDF", ""); err != nil || got != "Report 7.pdf" {
			t.Fatalf("Spelling = %q, %v", got, err)
		}
		seeks[n] = foldSeeks.Load() - before
	}
	t.Logf("seeks by share size: %v", seeks)
	if seeks[50000] > seeks[1000]+4 {
		t.Fatalf("seeks grew with the share: %v", seeks)
	}
}

// The inbox asks PathsHeld under its claims' lock, so on a full inbox the
// folded answer for a name and for its thousand numbered candidates costs
// the walk of the name's stem plus the rows that begin with it, whatever
// else the inbox holds.
func TestPathsHeldOnAFullInboxCostsTheStem(t *testing.T) {
	db := openTest(t)
	db.SetFoldCase(bySegment(fullFold))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "in", Owner: "alice", Inbox: true})
	if err := db.commit(func(tx *sql.Tx) error {
		for i := range InboxMaxFiles - 10 {
			if err := insertPending(tx, sh.ID, fmt.Sprintf("IMG_%05d.jpg", i), 1, time.Now()); err != nil {
				return err
			}
		}
		for i := 1; i <= 10; i++ {
			if err := insertPending(tx, sh.ID, numbered("Report.pdf", i), 1, time.Now()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var candidates []string
	for n := 2; n <= 1000; n++ {
		candidates = append(candidates, numbered("report.pdf", n))
	}
	before, start := foldSeeks.Load(), time.Now()
	one, err := db.PathsHeld(sh.ID, []string{"report.pdf"})
	if err != nil || !one["report.pdf"] {
		t.Fatalf("held %v, %v", one, err)
	}
	many, err := db.PathsHeld(sh.ID, candidates)
	if err != nil {
		t.Fatal(err)
	}
	seeks, took := foldSeeks.Load()-before, time.Since(start)
	t.Logf("a name and its numbered candidates on a full inbox: %d seeks, %v", seeks, took)
	if !many["report 10.pdf"] || many["report 11.pdf"] {
		t.Fatalf("held 10=%v 11=%v", many["report 10.pdf"], many["report 11.pdf"])
	}
	if seeks > 200 {
		t.Fatalf("%d seeks", seeks)
	}
}

func numbered(name string, n int) string {
	if n == 1 {
		return name
	}
	stem, ext, _ := strings.Cut(name, ".")
	return fmt.Sprintf("%s %d.%s", stem, n, ext)
}

// fullFold is a volume that folds the way APFS and casefold ext4 do: every
// pair with one key is one name.
func fullFold(a, b string) bool { return shareid.FoldPath(a) == shareid.FoldPath(b) }

// bySegment is a volume's answer for two relpaths whose parents are one
// folder: its answer for their last segments.
func bySegment(same func(a, b string) bool) func(shareID, held, incoming string) bool {
	return func(_, held, incoming string) bool {
		_, h := splitLast(held)
		_, i := splitLast(incoming)
		return same(h, i)
	}
}

// upcaseFold is a volume that compares names through a one-to-one upcase
// table, as exFAT does: straße and strasse are two names.
func upcaseFold(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	if len(ra) != len(rb) {
		return false
	}
	for i := range ra {
		if unicode.ToUpper(ra[i]) != unicode.ToUpper(rb[i]) {
			return false
		}
	}
	return true
}

// volumeSame asks the filesystem the test runs on, the way sharefs does.
func volumeSame(t *testing.T) func(a, b string) bool {
	dir := t.TempDir()
	return func(a, b string) bool {
		p := filepath.Join(dir, a)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(p)
		_, err := os.Stat(filepath.Join(dir, b))
		return err == nil
	}
}

func paths(t *testing.T, db *DB, id string) string {
	t.Helper()
	d, err := db.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range d.Files {
		out = append(out, f.Path)
	}
	for _, p := range d.Folders {
		out = append(out, p+"/")
	}
	return strings.Join(out, ",")
}

// On a volume that folds case, a relpath takes the spelling the share
// already holds for every prefix it folds onto, so two rows never name one
// file and a folder is spelled one way.
func TestAFoldingStoreSpellsAPathTheWayTheShareHoldsIt(t *testing.T) {
	db := openTest(t)
	db.SetFoldCase(bySegment(fullFold))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice", Files: []PendingFile{{Path: "Docs/Report.pdf", Size: 1}}})
	for rel, want := range map[string]string{
		"docs/report.PDF": "Docs/Report.pdf",
		"DOCS/new.txt":    "Docs/new.txt",
		"other/a.txt":     "other/a.txt",
	} {
		got, err := db.Spelling(sh.ID, rel, "")
		if err != nil || got != want {
			t.Errorf("Spelling(%q) = %q, %v, want %q", rel, got, err, want)
		}
	}
	if f, err := db.DeclareFile(sh.ID, "docs/REPORT.pdf", 1); err != nil || f.Path != "Docs/Report.pdf" {
		t.Fatalf("declare = %+v, %v", f, err)
	}
	if f, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "DOCS/report.pdf", Size: 1}); err != nil || f.Path != "Docs/Report.pdf" {
		t.Fatalf("commit = %+v, %v", f, err)
	}
	if f, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "docs/new.txt", Size: 1}); err != nil || f.Path != "Docs/new.txt" {
		t.Fatalf("commit new = %+v, %v", f, err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "docs/NEW.txt", Size: 1, Anonymous: true}); err == nil {
		t.Fatal("an anonymous commit replaced a file by case")
	}
	if got := paths(t, db, sh.ID); got != "Docs/Report.pdf,Docs/new.txt" {
		t.Fatalf("paths = %s", got)
	}
	if _, err := db.AddFolder(sh.ID, "DOCS"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("folder DOCS = %v, want ErrPathTaken", err)
	}
	if _, err := db.MoveEntries(sh.ID, "Docs/new.txt", "docs/report.pdf"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("move onto a file by case = %v, want ErrPathTaken", err)
	}
	if _, err := db.MoveEntries(sh.ID, "Docs", "docs/Sub"); !errors.Is(err, ErrIntoItself) {
		t.Fatalf("move into itself by case = %v, want ErrIntoItself", err)
	}
	if _, err := db.MoveEntries(sh.ID, "Docs/new.txt", "Docs/NEW.txt"); err != nil {
		t.Fatalf("a case-only rename = %v", err)
	}
	if got := paths(t, db, sh.ID); got != "Docs/NEW.txt,Docs/Report.pdf" {
		t.Fatalf("paths after the rename = %s", got)
	}
	if _, err := db.CreateShare(CreateOptions{Name: "t", Owner: "alice",
		Files: []PendingFile{{Path: "a.txt", Size: 1}, {Path: "A.TXT", Size: 1}}}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a manifest of a.txt and A.TXT = %v, want ErrBadRequest", err)
	}
}

// PathsHeld answers which candidates a row holds, folded on a volume that
// folds case and exact on one that does not.
func TestPathsHeldFoldsWhenTheStoreDoes(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "in", Owner: "alice", Inbox: true})
	for _, p := range []string{"report.pdf", "Report 2.pdf"} {
		if _, err := db.DeclareFile(sh.ID, p, 1); err != nil {
			t.Fatal(err)
		}
	}
	candidates := []string{"REPORT.pdf", "report 2.pdf", "report 3.pdf"}
	for _, folds := range []bool{false, true} {
		if folds {
			db.SetFoldCase(bySegment(fullFold))
		} else {
			db.SetFoldCase(nil)
		}
		got, err := db.PathsHeld(sh.ID, candidates)
		if err != nil {
			t.Fatal(err)
		}
		if got["REPORT.pdf"] != folds || got["report 2.pdf"] != folds || got["report 3.pdf"] {
			t.Errorf("folds=%v: held %v", folds, got)
		}
		one, err := db.PathsHeld(sh.ID, []string{"Report.PDF"})
		if err != nil || one["Report.PDF"] != folds {
			t.Errorf("folds=%v: one candidate held %v, %v", folds, one, err)
		}
		exact, err := db.PathsHeld(sh.ID, []string{"report.pdf", "Report 2.pdf"})
		if err != nil || !exact["report.pdf"] || !exact["Report 2.pdf"] {
			t.Errorf("folds=%v: exact names held %v, %v", folds, exact, err)
		}
	}
}

// A store that does not fold keeps names that differ only in case apart.
func TestAStoreThatDoesNotFoldKeepsCaseApart(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice",
		Files: []PendingFile{{Path: "a.txt", Size: 1}, {Path: "A.txt", Size: 1}}})
	if _, err := db.AddFolder(sh.ID, "Docs"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddFolder(sh.ID, "docs"); err != nil {
		t.Fatal(err)
	}
	if got, err := db.Spelling(sh.ID, "A.TXT", ""); err != nil || got != "A.TXT" {
		t.Fatalf("Spelling = %q, %v", got, err)
	}
	if got := paths(t, db, sh.ID); got != "A.txt,a.txt,Docs/,docs/" {
		t.Fatalf("paths = %s", got)
	}
}

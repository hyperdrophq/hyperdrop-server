package metadb

import (
	"errors"
	"fmt"
	"testing"
)

func TestInboxFileCapCountsPendingToCommittedTransitions(t *testing.T) {
	for _, cap := range []int{1, 2} {
		t.Run(fmt.Sprint(cap), func(t *testing.T) {
			db := openTest(t)
			mustUser(t, db, "alice")
			sh := mustShare(t, db, CreateOptions{Name: "inbox", Owner: "alice", Inbox: true, MaxFiles: cap})
			for _, path := range []string{"a", "b"} {
				if _, err := db.DeclareFile(sh.ID, path, 1); err != nil {
					t.Fatal(err)
				}
			}
			for i, path := range []string{"a", "b"} {
				_, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: path, Size: 1, Anonymous: true})
				if i < cap {
					if err != nil {
						t.Fatalf("commit %s: %v", path, err)
					}
				} else if !errors.Is(err, ErrInboxFull) {
					t.Fatalf("cap must refuse pending %s: %v", path, err)
				}
			}
			// A stranger never replaces a committed file, and owners bypass the link cap.
			if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "a", Size: 1, Anonymous: true}); !errors.Is(err, ErrPathTaken) {
				t.Fatalf("anonymous commit over a committed file = %v, want ErrPathTaken", err)
			}
			commit(t, db, sh.ID, "owner", 1)
		})
	}
}

// An inbox holds at most InboxMaxFiles files whatever its own cap, zero-byte
// ones included: they pass every byte bound, so the count is what stops a
// stranger growing the share's rows without limit.
func TestInboxFileCountIsBoundedWithoutACapOfItsOwn(t *testing.T) {
	defer func(n int) { InboxMaxFiles = n }(InboxMaxFiles)
	InboxMaxFiles = 2
	for _, own := range []int{0, 5} {
		t.Run(fmt.Sprint(own), func(t *testing.T) {
			db := openTest(t)
			mustUser(t, db, "alice")
			sh := mustShare(t, db, CreateOptions{Name: "inbox", Owner: "alice", Inbox: true, MaxFiles: own})
			for i, path := range []string{"a", "b", "c"} {
				_, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: path, Size: 0, Anonymous: true})
				if i < 2 && err != nil {
					t.Fatalf("commit %s: %v", path, err)
				}
				if i == 2 && !errors.Is(err, ErrInboxFull) {
					t.Fatalf("commit past the bound = %v, want ErrInboxFull", err)
				}
			}
		})
	}
	if InboxFileCap(1) != 1 || InboxFileCap(0) != 2 || InboxFileCap(3) != 2 {
		t.Fatal("InboxFileCap does not take the lower of the two")
	}
}

// A text share's one-file rule holds inside the commit: of two different
// paths arriving at once, the second to commit is refused, while a replace
// (which takes the first file's place) commits beside it.
func TestATextShareCommitsOneFile(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "note", Owner: "alice", Text: true})
	for _, p := range []string{"a.txt", "b.txt"} {
		if _, err := db.DeclareFile(sh.ID, p, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "a.txt", Size: 1}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "b.txt", Size: 1}); !errors.Is(err, ErrTextShare) {
		t.Fatalf("second path = %v, want ErrTextShare", err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "a.txt", Size: 2}); err != nil {
		t.Fatalf("the one file's overwrite: %v", err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "c.txt", Size: 1, Replaces: "a.txt"}); err != nil {
		t.Fatalf("a replacing upload: %v", err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "d.txt", Size: 1, ReplaceAll: true}); err != nil {
		t.Fatalf("a replace-all upload: %v", err)
	}
}

// Two uploads replacing a text share's one file at once: the first commits
// beside the file it replaces, and the second is refused whether it commits
// before the first replace lands (the first upload sits beside the file) or
// after (the file it names is gone). A replace naming nothing the share
// holds is weighed as an ordinary second file.
func TestATextShareTakesOneReplacerOfItsFile(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "note", Owner: "alice", Text: true})
	if _, err := db.DeclareFile(sh.ID, "note.txt", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "note.txt", Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "a.txt", Size: 1, Replaces: "note.txt"}); err != nil {
		t.Fatalf("first replacer: %v", err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "b.txt", Size: 1, Replaces: "note.txt"}); !errors.Is(err, ErrTextShare) {
		t.Fatalf("second replacer before the replace = %v, want ErrTextShare", err)
	}
	if _, err := db.ReplaceEntry(sh.ID, "a.txt", "note.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "b.txt", Size: 1, Replaces: "note.txt"}); !errors.Is(err, ErrTextShare) {
		t.Fatalf("second replacer after the replace = %v, want ErrTextShare", err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "c.txt", Size: 1, Replaces: "missing.txt"}); !errors.Is(err, ErrTextShare) {
		t.Fatalf("a replace naming nothing = %v, want ErrTextShare", err)
	}
	d, err := db.Share(sh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Files) != 1 || d.Files[0].Path != "a.txt" {
		t.Fatalf("text share holds %v, want a.txt alone", d.Files)
	}
}

// PathsWithPrefix answers every row beginning with the prefix, pending ones
// included, and nothing that merely sorts after it.
func TestPathsWithPrefix(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "in", Owner: "alice", Inbox: true})
	for _, p := range []string{"report.txt", "report 2.txt", "report 3.txt", "reporter.txt", "repo.txt", "z.txt"} {
		if _, err := db.DeclareFile(sh.ID, p, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "report.txt", Size: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := db.PathsWithPrefix(sh.ID, "report")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"report.txt", "report 2.txt", "report 3.txt", "reporter.txt"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, p := range want {
		if !got[p] {
			t.Fatalf("got %v, missing %s", got, p)
		}
	}
}

// A text share takes no linked source: the store refuses the write that
// would give it one, whatever route asks.
func TestATextShareTakesNoSource(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "note", Owner: "alice", Text: true})
	if _, _, err := db.SetSources(sh.ID, []string{"docs"}, nil, nil); !errors.Is(err, ErrTextShare) {
		t.Fatalf("SetSources = %v, want ErrTextShare", err)
	}
	got, err := db.Share(sh.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sources) != 0 {
		t.Fatalf("the refused write left sources %v", got.Sources)
	}
}

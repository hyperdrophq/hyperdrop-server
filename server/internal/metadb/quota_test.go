package metadb

import (
	"errors"
	"strconv"
	"testing"
)

// quotaShare opens a database holding one account with this quota (nil for
// none) and one share it owns.
func quotaShare(t *testing.T, quota *int64) (*DB, string) {
	t.Helper()
	db := openTest(t)
	if _, err := db.CreateUser("bob", "bob-password-1", RoleUser, Settings{QuotaBytes: quota}); err != nil {
		t.Fatal(err)
	}
	return db, mustShare(t, db, CreateOptions{Owner: "bob", Name: "s"}).ID
}

// wantQuota requires a refusal wrapping ErrQuota with exactly this message.
func wantQuota(t *testing.T, what string, err error, msg string) {
	t.Helper()
	if !errors.Is(err, ErrQuota) || err.Error() != msg {
		t.Fatalf("%s: %v, want ErrQuota %q", what, err, msg)
	}
}

func commitSized(db *DB, id, path string, size int64) error {
	_, err := db.CommitFile(CommitInput{ShareID: id, Path: path, Size: size, SHA256: "s" + strconv.FormatInt(size, 10), Mime: "text/plain"})
	return err
}

func publishSized(db *DB, id string, commits ...PublishCommit) error {
	_, err := db.PublishFiles(id, commits, nil, nil)
	return err
}

const quota100 = "storage quota exceeded: the account's quota is 100 bytes"

func TestACommitIsHeldToTheOwnersByteQuota(t *testing.T) {
	db, id := quotaShare(t, ptr(int64(100)))
	if err := commitSized(db, id, "a", 50); err != nil {
		t.Fatalf("under the quota: %v", err)
	}
	if err := commitSized(db, id, "b", 50); err != nil {
		t.Fatalf("exactly at the quota: %v", err)
	}
	wantQuota(t, "one byte over", commitSized(db, id, "c", 1), quota100)
	wantQuota(t, "a replace that grows by one byte", commitSized(db, id, "b", 51), quota100)
	if err := commitSized(db, id, "b", 50); err != nil {
		t.Fatalf("a replace of the same size at the quota: %v", err)
	}
}

func TestAPublishIsHeldToTheOwnersByteQuota(t *testing.T) {
	db, id := quotaShare(t, ptr(int64(100)))
	if err := publishSized(db, id, pc("a", 50, "a")); err != nil {
		t.Fatalf("under the quota: %v", err)
	}
	if err := publishSized(db, id, pc("b", 50, "b")); err != nil {
		t.Fatalf("exactly at the quota: %v", err)
	}
	wantQuota(t, "one byte over", publishSized(db, id, pc("c", 1, "c")), quota100)
	wantQuota(t, "a replace that grows by one byte", publishSized(db, id, pc("b", 51, "b2")), quota100)
	if err := publishSized(db, id, pc("b", 50, "b3")); err != nil {
		t.Fatalf("a replace of the same size at the quota: %v", err)
	}
}

// An owner whose quota was lowered below what they hold: a commit is checked
// against the whole total after it, so a replace that shrinks a file but
// leaves the owner over the quota is refused, while a publish checks bytes
// only when its net change adds some.
func TestAnOwnerOverTheQuotaShrinksAFile(t *testing.T) {
	const quota50 = "storage quota exceeded: the account's quota is 50 bytes"
	setup := func(t *testing.T) (*DB, string) {
		db, id := quotaShare(t, ptr(int64(100)))
		if err := commitSized(db, id, "big", 90); err != nil {
			t.Fatal(err)
		}
		if err := commitSized(db, id, "other", 10); err != nil {
			t.Fatal(err)
		}
		if _, err := db.UpdateUser("bob", Settings{QuotaBytes: ptr(int64(50))}); err != nil {
			t.Fatal(err)
		}
		return db, id
	}
	t.Run("commit", func(t *testing.T) {
		db, id := setup(t)
		wantQuota(t, "a shrink that stays over", commitSized(db, id, "big", 80), quota50)
		wantQuota(t, "a replace of the same size", commitSized(db, id, "big", 90), quota50)
		if err := commitSized(db, id, "big", 40); err != nil {
			t.Fatalf("a shrink that ends at the quota: %v", err)
		}
	})
	t.Run("publish", func(t *testing.T) {
		db, id := setup(t)
		if err := publishSized(db, id, pc("big", 80, "b2")); err != nil {
			t.Fatalf("a shrink that stays over: %v", err)
		}
		if err := publishSized(db, id, pc("big", 80, "b3")); err != nil {
			t.Fatalf("a replace of the same size: %v", err)
		}
		wantQuota(t, "a growth while over", publishSized(db, id, pc("big", 81, "b4")), quota50)
	})
}

// A quota of 4096*1000 bytes holds 1000 files. A new path and a pending row
// becoming committed each add one; a replace of a committed file adds none,
// and a deleted file gives its place back within the same publish.
func TestTheFileLimitCountsWhatACommitAdds(t *testing.T) {
	const files1000 = "storage quota exceeded: the account may hold 1000 files"
	setup := func(t *testing.T) (db *DB, id, pid string) {
		db, id = quotaShare(t, ptr(int64(4096*1000)))
		commits := make([]PublishCommit, 1000)
		for i := range commits {
			commits[i] = pc("f"+strconv.Itoa(i), 0, "x")
		}
		if err := publishSized(db, id, commits...); err != nil {
			t.Fatalf("1000 files: %v", err)
		}
		d, err := db.CreateShare(CreateOptions{Owner: "bob", Name: "p", Files: []PendingFile{{Path: "pending", Size: 0}}})
		if err != nil {
			t.Fatal(err)
		}
		return db, id, d.ID
	}
	t.Run("commit", func(t *testing.T) {
		db, _, pid := setup(t)
		wantQuota(t, "a new path", commitSized(db, pid, "new", 0), files1000)
		wantQuota(t, "a pending row", commitSized(db, pid, "pending", 0), files1000)
	})
	t.Run("publish", func(t *testing.T) {
		db, _, pid := setup(t)
		wantQuota(t, "a new path", publishSized(db, pid, pc("new", 0, "n")), files1000)
		wantQuota(t, "a pending row", publishSized(db, pid, pc("pending", 0, "p")), files1000)
	})
	t.Run("replace and delete", func(t *testing.T) {
		db, id, _ := setup(t)
		if err := commitSized(db, id, "f0", 0); err != nil {
			t.Fatalf("a commit replacing a file at the limit: %v", err)
		}
		if err := publishSized(db, id, pc("f1", 0, "y")); err != nil {
			t.Fatalf("a publish replacing a file at the limit: %v", err)
		}
		if _, err := db.PublishFiles(id, []PublishCommit{pc("g", 0, "g")}, []string{"f2"}, nil); err != nil {
			t.Fatalf("a publish adding one file and deleting one at the limit: %v", err)
		}
	})
	t.Run("past the limit in one publish", func(t *testing.T) {
		db, id := quotaShare(t, ptr(int64(4096*1000)))
		commits := make([]PublishCommit, 1001)
		for i := range commits {
			commits[i] = pc("f"+strconv.Itoa(i), 0, "x")
		}
		wantQuota(t, "1001 files", publishSized(db, id, commits...), files1000)
	})
}

func TestAnOwnerWithNoQuotaIsNotLimited(t *testing.T) {
	db, id := quotaShare(t, nil)
	if err := commitSized(db, id, "huge", 1<<40); err != nil {
		t.Fatalf("commit: %v", err)
	}
	commits := make([]PublishCommit, 1001)
	for i := range commits {
		commits[i] = pc("f"+strconv.Itoa(i), 1<<30, "x")
	}
	if err := publishSized(db, id, commits...); err != nil {
		t.Fatalf("publish of 1001 files: %v", err)
	}
	if err := commitSized(db, id, "one more", 1); err != nil {
		t.Fatalf("commit past 1001 files: %v", err)
	}
}

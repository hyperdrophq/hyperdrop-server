package metadb

import (
	"errors"
	"strconv"
	"testing"
)

func TestAFileLimitFollowsTheQuota(t *testing.T) {
	for quota, want := range map[int64]int64{
		0:           0,
		1:           1000,
		1 << 20:     1000,
		1 << 30:     262144,
		10 << 30:    2621440,
		4096 * 1000: 1000,
		4096 * 1001: 1001,
	} {
		if got := FileLimit(quota); got != want {
			t.Errorf("FileLimit(%d) = %d, want %d", quota, got, want)
		}
	}
}

// The limit is decided in the writing transaction, and only a new file spends it:
// replacing a file adds no inode.
func TestACommitPastTheFileLimitIsRefused(t *testing.T) {
	db := openTest(t)
	quota := int64(1 << 20)
	if _, err := db.CreateUser("bob", "bob-password-1", RoleUser, Settings{QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	d, err := db.CreateShare(CreateOptions{Owner: "bob", Name: "many"})
	if err != nil {
		t.Fatal(err)
	}
	commit := func(i int) error {
		_, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: "f" + string(rune('a'+i%26)) + strconv.Itoa(i), Size: 0, SHA256: "x"})
		return err
	}
	for i := range 1000 {
		if err := commit(i); err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
	}
	if err := commit(1000); !errors.Is(err, ErrQuota) {
		t.Fatalf("file 1001: %v, want ErrQuota", err)
	}
	if err := commit(999); err != nil {
		t.Fatalf("replacing a file at the limit: %v", err)
	}
}

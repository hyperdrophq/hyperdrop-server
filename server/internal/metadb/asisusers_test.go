package metadb

import "testing"

// The operator subcommands open a volume as is, which may be one an earlier
// build of stamp 1 made and so lack the columns only the serving open adds;
// reading its accounts still works.
func TestAnAsIsOpenOfAnOlderVolumeReadsItsAccounts(t *testing.T) {
	dir, _ := olderVolume(t)
	db, err := OpenAsIs(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.MintToken("alice", "tablet"); err != nil {
		t.Fatal(err)
	}
	u, err := db.User("alice")
	if err != nil {
		t.Fatalf("User on an as-is volume: %v", err)
	}
	if len(u.Tokens) != 1 || u.Tokens[0].ViaToken != "" {
		t.Fatalf("tokens = %+v, want one with no approver", u.Tokens)
	}
	if _, err := db.ResetAdmin("", "a-new-password"); err != nil {
		t.Fatalf("ResetAdmin on an as-is volume: %v", err)
	}
}

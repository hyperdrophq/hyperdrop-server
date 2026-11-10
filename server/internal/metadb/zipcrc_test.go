package metadb

import (
	"testing"

	"hyperdrop/server/internal/metadb/prevrelease"
)

func TestAFileRemembersTheCRCOfItsBytes(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 5}}})
	f := commit(t, db, d.ID, "a.txt", 5)
	if _, ok := f.CRC32(); ok {
		t.Fatal("a file no zip has read claims a CRC")
	}
	if err := db.SetFileCRCs(d.ID, []FileCRC{{Path: "a.txt", SHA256: f.SHA256, CRC32: 0xCAFEF00D}}); err != nil {
		t.Fatal(err)
	}
	got, err := db.File(d.ID, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if crc, ok := got.CRC32(); !ok || crc != 0xCAFEF00D {
		t.Fatalf("CRC %x, %v", crc, ok)
	}
}

// A zip reads a file's bytes, then writes their CRC: a replace landing between the
// two must not have the old bytes' CRC recorded against the new bytes.
func TestACRCOfOtherBytesIsNotRecorded(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 5}}})
	commit(t, db, d.ID, "a.txt", 5)
	if err := db.SetFileCRCs(d.ID, []FileCRC{{Path: "a.txt", SHA256: "not-these-bytes", CRC32: 1}}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.File(d.ID, "a.txt")
	if _, ok := got.CRC32(); ok {
		t.Fatal("recorded a CRC for bytes the row does not hold")
	}
}

func TestReplacingAFileForgetsItsCRC(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 5}}})
	f := commit(t, db, d.ID, "a.txt", 5)
	if err := db.SetFileCRCs(d.ID, []FileCRC{{Path: "a.txt", SHA256: f.SHA256, CRC32: 7}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: "a.txt", Size: 5, SHA256: "def", Mime: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.File(d.ID, "a.txt")
	if _, ok := got.CRC32(); ok {
		t.Fatal("the new bytes kept the old bytes' CRC")
	}
}

// A file without a hash has nothing to bind a CRC to, so it never holds one.
func TestAFileWithoutAHashHoldsNoCRC(t *testing.T) {
	db := openTest(t)
	mustUser(t, db, "alice")
	d := mustShare(t, db, CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 5}}})
	if _, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: "a.txt", Size: 5, Mime: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetFileCRCs(d.ID, []FileCRC{{Path: "a.txt", CRC32: 7}}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.File(d.ID, "a.txt")
	if _, ok := got.CRC32(); ok {
		t.Fatal("a file with no hash claims a CRC")
	}
}

// The previous release names no CRC column, so a replace it makes leaves the value
// behind: the value carries the bytes it describes, and reads as absent then.
func TestAReplaceByThePreviousReleaseInvalidatesTheCRC(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("alice", "pw-alice", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	d, err := db.CreateShare(CreateOptions{Name: "x", Owner: "alice", Files: []PendingFile{{Path: "a.txt", Size: 5}}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := db.CommitFile(CommitInput{ShareID: d.ID, Path: "a.txt", Size: 5, SHA256: "0123456789abcdef0123", Mime: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetFileCRCs(d.ID, []FileCRC{{Path: "a.txt", SHA256: f.SHA256, CRC32: 7}}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	prev, err := prevrelease.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prev.CommitFile(prevrelease.CommitInput{ShareID: d.ID, Path: "a.txt", Size: 5,
		SHA256: "fedcba98765432100123", Mime: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	prev.Close()

	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.File(d.ID, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != "fedcba98765432100123" {
		t.Fatalf("hash %q", got.SHA256)
	}
	if _, ok := got.CRC32(); ok {
		t.Fatal("the bytes the previous release wrote kept the old CRC")
	}
}

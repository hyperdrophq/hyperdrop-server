package api

import (
	"fmt"
	"testing"

	"hyperdrop/server/internal/metadb"
)

func commitInputFor(id string, i int) metadb.CommitInput {
	return metadb.CommitInput{ShareID: id, Path: fmt.Sprintf("f%04d", i), SHA256: "x"}
}

func atFileLimit(t *testing.T) *quotaFixture {
	t.Helper()
	f := quotaAccount(t, 1<<20) // 1 MiB: the floor of 1,000 files
	for i := range 1000 {
		if _, err := f.b.DB.CommitFile(commitInputFor(f.id, i)); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// Empty files cost no bytes, so a quota alone never stops them.
func TestAnEmptyFilePastTheFileLimitIsRefused(t *testing.T) {
	f := atFileLimit(t)
	rec := putRange(t, f.h, f.token, f.id, "one-more", "sess-more", 0, 0, 0, nil)
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("= %d %s, want 507 quota", rec.Code, rec.Body)
	}
}

func TestAFilePastTheFileLimitIsRefusedBeforeItsBytes(t *testing.T) {
	f := atFileLimit(t)
	rec := putRange(t, f.h, f.token, f.id, "one-more.bin", "sess-more", 0, 1, 10, []byte{1})
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "quota" {
		t.Fatalf("= %d %s, want 507 quota", rec.Code, rec.Body)
	}
	if n, _ := f.b.FS.PartSize(f.id, "one-more.bin"); n != 0 {
		t.Fatalf("%d bytes staged", n)
	}
}

// Replacing a file and giving a file its tile add no file, so both still work at
// the limit, or an account at its limit could not re-make its own gallery.
func TestAReplaceAndATileStillWorkAtTheFileLimit(t *testing.T) {
	f := atFileLimit(t)
	input := commitInputFor(f.id, 0)
	rec := putRange(t, f.h, f.token, f.id, input.Path, "sess-replace", 0, 1, 1, []byte{1})
	if rec.Code != 201 {
		t.Fatalf("replace = %d %s", rec.Code, rec.Body)
	}
	file, err := f.b.DB.File(f.id, input.Path)
	if err != nil {
		t.Fatal(err)
	}
	if code := doReqBare(t, f.h, "PUT", "/api/shares/"+f.id+"/thumbs/"+file.Slug, f.token, string(paddedJPEG(t, 1024))).Code; code != 204 {
		t.Fatalf("tile = %d", code)
	}
}

// A file freed makes a place.
func TestDeletingAFileGivesItsPlaceBack(t *testing.T) {
	f := atFileLimit(t)
	input := commitInputFor(f.id, 0)
	if rec := doReq(t, f.h, "DELETE", "/api/shares/"+f.id+"/files/"+input.Path, f.token, ""); rec.Code >= 300 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if rec := putRange(t, f.h, f.token, f.id, "one-more", "sess-more", 0, 0, 0, nil); rec.Code != 201 {
		t.Fatalf("= %d %s", rec.Code, rec.Body)
	}
}

// The inode reserve meets an empty file too, which stages no bytes.
func TestAnEmptyFileMeetsTheInodeReserve(t *testing.T) {
	f := quotaAccount(t, 0)
	f.b.FS.InodeSpace = func(string) (int64, int64, error) { return 1, 100, nil }
	rec := putRange(t, f.h, f.token, f.id, "empty", "sess-empty", 0, 0, 0, nil)
	if rec.Code != 507 || errCode(t, rec.Body.String()) != "no-space" {
		t.Fatalf("= %d %s, want 507 no-space", rec.Code, rec.Body)
	}
}

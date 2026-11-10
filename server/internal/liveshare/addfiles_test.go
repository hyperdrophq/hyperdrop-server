package liveshare

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

func addTestRegistry(t *testing.T) *Registry {
	t.Helper()
	n := 0
	return NewRegistry(Config{
		NewID:   func() string { return "aaaaaaaaaa" },
		NewSlug: func() string { n++; return "slug-" + string(rune('a'+n-1)) },
		Now:     func() time.Time { return time.Unix(1700000000, 0) },
	})
}

func addLiveShare(t *testing.T, g *Registry) Record {
	t.Helper()
	rec, err := g.Create(Record{Owner: "alice", Name: "relay", Files: []File{
		{Path: "a.txt", Size: 1, Mime: "text/plain"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// The whole point: a relay that is already serving can be handed more files,
// and each new one gets its own slug so its link works like the first's.
func TestAddFilesMintsSlugsAndKeepsTheOldOnes(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	firstSlug := rec.Files[0].Slug

	got, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "b.txt", Size: 2, Mime: "text/plain"}}}, nil)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if len(got.Files) != 2 {
		t.Fatalf("files = %d, want 2", len(got.Files))
	}
	if got.Files[0].Slug != firstSlug {
		t.Errorf("the existing file's slug changed: %q -> %q", firstSlug, got.Files[0].Slug)
	}
	if got.Files[1].Slug == "" || got.Files[1].Slug == firstSlug {
		t.Errorf("new file's slug = %q", got.Files[1].Slug)
	}
	// The registry, not just the returned copy.
	stored, _ := g.Get(rec.ID)
	if len(stored.Files) != 2 {
		t.Fatalf("registry files = %d, want 2", len(stored.Files))
	}
}

// A path the relay already serves is REPLACED in place and keeps its slug, the
// same rule `add` follows for a stored share: links already handed out keep
// working and point at the new bytes.
func TestAddFilesReplacesAKnownPathInPlace(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	firstSlug := rec.Files[0].Slug

	got, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "a.txt", Size: 99, Mime: "text/plain"}}}, nil)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if len(got.Files) != 1 {
		t.Fatalf("files = %d, want 1", len(got.Files))
	}
	if got.Files[0].Slug != firstSlug {
		t.Errorf("slug changed on replace: %q -> %q", firstSlug, got.Files[0].Slug)
	}
	if got.Files[0].Size != 99 {
		t.Errorf("size = %d, want the new one", got.Files[0].Size)
	}
}

// Owner-scoped like every other registry operation: another account cannot
// push files into someone's relay.
func TestAddFilesRefusesAnotherOwner(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	if _, err := g.Patch(rec.ID, "mallory", Edit{Add: []File{{Path: "b.txt"}}}, nil); err == nil {
		t.Fatal("another owner was allowed to add files")
	}
	if got, _ := g.Get(rec.ID); len(got.Files) != 1 {
		t.Fatalf("files = %d, want the relay untouched", len(got.Files))
	}
}

func TestAddFilesRefusesAnUnknownShare(t *testing.T) {
	g := addTestRegistry(t)
	if _, err := g.Patch("nosuchid00", "alice", Edit{Add: []File{{Path: "b.txt"}}}, nil); err == nil {
		t.Fatal("an unknown id was accepted")
	}
}

// Nothing to add is not an error worth failing a relay over, but it must not
// mint a slug or touch the record either.
func TestAddFilesWithNothingChangesNothing(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	got, err := g.Patch(rec.ID, "alice", Edit{}, nil)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if len(got.Files) != 1 {
		t.Fatalf("files = %d, want 1", len(got.Files))
	}
}

// The archive's declared length is set when the share is made, so a wider file
// list owes a new one or /zip ends short of its own Content-Length.
func TestAddFilesUpdatesTheZipLength(t *testing.T) {
	g := addTestRegistry(t)
	rec, err := g.Create(Record{Owner: "alice", ZipSize: 100, Files: []File{{Path: "a.txt", Size: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "b.txt", Size: 2}}, ZipSize: 250}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.ZipSize != 250 {
		t.Errorf("ZipSize = %d, want 250", got.ZipSize)
	}
	// Zero means "unchanged", for a caller that cannot recompute one.
	again, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "c.txt", Size: 3}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.ZipSize != 250 {
		t.Errorf("ZipSize = %d, want it left alone", again.ZipSize)
	}
}

func TestPatchMetaSetsPasswordAndExpiry(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	hash := "hashed"
	exp := time.Unix(1800000000, 0)
	got, err := g.Patch(rec.ID, "alice", Edit{Meta: Meta{PasswordHash: &hash, SetExpiry: true, ExpiresAt: &exp}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != hash {
		t.Fatalf("PasswordHash = %q", got.PasswordHash)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("ExpiresAt = %v", got.ExpiresAt)
	}
}

func TestReplaceFilesKeepsMatchingSlugs(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	old := rec.Files[0].Slug
	got, err := g.Patch(rec.ID, "alice", Edit{Replace: []File{
		{Path: "a.txt", Size: 9, Mime: "text/plain"},
		{Path: "b.txt", Size: 2, Mime: "text/plain"},
	}, ZipSize: 10}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 2 {
		t.Fatalf("files = %d", len(got.Files))
	}
	if got.Files[0].Slug != old {
		t.Fatalf("slug = %q, want kept %q", got.Files[0].Slug, old)
	}
	if got.Files[1].Slug == "" {
		t.Fatal("new file has no slug")
	}
}

// The cap is on what the share describes, not on one request: a run of
// additions stops at Config.MaxFiles, a refused edit leaves the share as it
// was, and a replace may bring a share back under it.
func TestPatchCapsTheWholeShareAndRefusesWithoutChangingIt(t *testing.T) {
	n := 0
	g := NewRegistry(Config{MaxFiles: 3,
		NewID:   func() string { return "aaaaaaaaaa" },
		NewSlug: func() string { n++; return "slug-" + strconv.Itoa(n) },
	})
	rec := addLiveShare(t, g)
	if _, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "b.txt"}, {Path: "c.txt"}}}, nil); err != nil {
		t.Fatalf("up to the cap: %v", err)
	}
	if _, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "d.txt"}}}, nil); !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("past the cap: %v, want ErrTooManyFiles", err)
	}
	// Replacing a known path adds nothing, so it fits.
	if _, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "a.txt", Size: 5}}}, nil); err != nil {
		t.Fatalf("replace in place at the cap: %v", err)
	}
	stored, _ := g.Get(rec.ID)
	if len(stored.Files) != 3 {
		t.Fatalf("files = %d, want 3", len(stored.Files))
	}
	if _, err := g.Patch(rec.ID, "alice", Edit{Replace: []File{{Path: "z.txt"}}}, nil); err != nil {
		t.Fatalf("a replace under the cap: %v", err)
	}
}

// A check that refuses the result leaves the record untouched, files and
// meta alike, and sees the record as it stood beside the result.
func TestPatchRefusedByItsCheckChangesNothing(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	name := "renamed"
	refused := errors.New("refused")
	_, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "b.txt"}}, Meta: Meta{Name: &name}},
		func(current, next Record) error {
			if len(current.Files) != 1 || len(next.Files) != 2 || next.Name != "renamed" {
				t.Errorf("check saw current=%d next=%d %q", len(current.Files), len(next.Files), next.Name)
			}
			return refused
		})
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v", err)
	}
	stored, _ := g.Get(rec.ID)
	if len(stored.Files) != 1 || stored.Name != "relay" {
		t.Fatalf("a refused edit changed the share: %+v", stored)
	}
}

// A Record handed out before an edit keeps the list it was handed: the
// stored slice is replaced, never written in place, so a reader holding the
// old one cannot see a half-applied edit.
func TestPatchNeverEditsAListAlreadyHandedOut(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	before, _ := g.Get(rec.ID)
	if _, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "a.txt", Size: 77}}}, nil); err != nil {
		t.Fatal(err)
	}
	if before.Files[0].Size != 1 {
		t.Fatalf("the earlier record's file changed to size %d", before.Files[0].Size)
	}
}

// One request naming a new path twice lists it once, the later entry
// winning, rather than appending it twice under two slugs.
func TestPatchAddingOnePathTwiceListsItOnce(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	got, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "b.txt", Size: 1}, {Path: "b.txt", Size: 2}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 2 || got.Files[1].Size != 2 {
		t.Fatalf("files = %+v", got.Files)
	}
}

// The merge is linear: adding to a share far past any real one finishes in
// well under the time a quadratic scan takes on the same lists.
func TestPatchMergesLargeListsInLinearTime(t *testing.T) {
	n := 0
	g := NewRegistry(Config{MaxFiles: 400000,
		NewID:   func() string { return "aaaaaaaaaa" },
		NewSlug: func() string { n++; return "s" },
	})
	files := func(prefix string, count int) []File {
		out := make([]File, count)
		for i := range out {
			out[i] = File{Path: prefix + strconv.Itoa(i)}
		}
		return out
	}
	rec, err := g.Create(Record{Owner: "alice", Files: files("a/", 100000)})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := g.Patch(rec.ID, "alice", Edit{Add: files("b/", 100000)}, nil); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("adding 100k files to 100k took %v", took)
	}
}

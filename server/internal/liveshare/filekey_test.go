package liveshare

import (
	"testing"
	"time"
)

func keyRegistry(now *time.Time) *Registry {
	n := 0
	return NewRegistry(Config{
		NewID:   func() string { n++; return "id" + string(rune('a'+n)) + "aaaaaaaa" },
		NewSlug: func() string { n++; return "slug-" + string(rune('a'+n)) },
		Now:     func() time.Time { return *now },
	})
}

func TestCreateMintsAKeyPerFile(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	g := keyRegistry(&now)
	rec, err := g.Create(Record{Owner: "amy", Files: []File{{Path: "a.txt", Size: 1}, {Path: "b.txt", Size: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Files[0].Key == "" || rec.Files[1].Key == "" || rec.Files[0].Key == rec.Files[1].Key {
		t.Fatalf("keys: %q %q", rec.Files[0].Key, rec.Files[1].Key)
	}
	for _, f := range rec.Files {
		got, slug, ok := g.ByFileKey(f.Key)
		if !ok || got.ID != rec.ID || slug != f.Slug {
			t.Fatalf("ByFileKey(%q) = %v %q %v", f.Key, got.ID, slug, ok)
		}
	}
}

func TestByFileKeyRefusesABadShapeAndAnUnknownKey(t *testing.T) {
	now := time.Now()
	g := keyRegistry(&now)
	if _, _, ok := g.ByFileKey("short"); ok {
		t.Fatal("a key of the wrong shape resolved")
	}
	if _, _, ok := g.ByFileKey("1111111111111111111111"); ok {
		t.Fatal("an unknown key resolved")
	}
}

func TestResumeKeepsKeys(t *testing.T) {
	now := time.Now()
	g := keyRegistry(&now)
	files := []File{{Path: "a.txt", Size: 1, Mime: "text/plain", MTime: now}}
	rec, err := g.Create(Record{Owner: "amy", Files: append([]File(nil), files...)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.Resume(rec.ID, Record{Owner: "amy", Files: files})
	if err != nil {
		t.Fatal(err)
	}
	if got.Files[0].Key != rec.Files[0].Key {
		t.Fatalf("resume changed the key: %q -> %q", rec.Files[0].Key, got.Files[0].Key)
	}
	if _, slug, ok := g.ByFileKey(rec.Files[0].Key); !ok || slug != rec.Files[0].Slug {
		t.Fatalf("key lost after resume: %q %v", slug, ok)
	}
}

func TestByFileKeyForgetsASweptShare(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	g := keyRegistry(&now)
	swept, _ := g.Create(Record{Owner: "amy", Files: []File{{Path: "a.txt"}}})
	stopped, _ := g.Create(Record{Owner: "bob", Files: []File{{Path: "a.txt"}}})
	gone, _ := g.Create(Record{Owner: "cy", Files: []File{{Path: "a.txt"}}})

	if !g.Delete(stopped.ID, "bob") {
		t.Fatal("Delete refused")
	}
	if _, _, ok := g.ByFileKey(stopped.Files[0].Key); ok {
		t.Fatal("a stopped share's key resolves")
	}
	g.DeleteOwner("cy")
	if _, _, ok := g.ByFileKey(gone.Files[0].Key); ok {
		t.Fatal("a deleted owner's key resolves")
	}

	now = now.Add(defaultGrace + time.Second)
	if _, _, ok := g.ByFileKey(swept.Files[0].Key); ok {
		t.Fatal("a swept share's key resolves")
	}
	if len(g.keys) != 0 {
		t.Fatalf("keys left behind: %v", g.keys)
	}
}

func TestAddedFilesGetKeys(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	firstKey := rec.Files[0].Key

	got, err := g.Patch(rec.ID, "alice", Edit{Add: []File{
		{Path: "a.txt", Size: 9, Mime: "text/plain"},
		{Path: "b.txt", Size: 2, Mime: "text/plain"},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Files[0].Key != firstKey {
		t.Fatalf("a known path lost its key: %q -> %q", firstKey, got.Files[0].Key)
	}
	newKey := got.Files[1].Key
	if newKey == "" || newKey == firstKey {
		t.Fatalf("new file key %q", newKey)
	}
	if r, slug, ok := g.ByFileKey(newKey); !ok || r.ID != rec.ID || slug != got.Files[1].Slug {
		t.Fatalf("ByFileKey(new) = %v %q %v", r.ID, slug, ok)
	}
}

func TestReplacingDropsTheKeysOfRemovedFiles(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	got, err := g.Patch(rec.ID, "alice", Edit{Add: []File{{Path: "b.txt", Size: 2}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	aKey, bKey := got.Files[0].Key, got.Files[1].Key

	if _, err := g.Patch(rec.ID, "alice", Edit{Replace: []File{{Path: "b.txt", Size: 2}}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := g.ByFileKey(aKey); ok {
		t.Fatal("a removed file's key still resolves")
	}
	if _, _, ok := g.ByFileKey(bKey); !ok {
		t.Fatal("a kept file's key was lost")
	}
}

func TestARefusedPatchKeepsTheKeys(t *testing.T) {
	g := addTestRegistry(t)
	rec := addLiveShare(t, g)
	_, err := g.Patch(rec.ID, "alice", Edit{Replace: []File{{Path: "z.txt"}}},
		func(_, _ Record) error { return ErrTooManyFiles })
	if err == nil {
		t.Fatal("check did not refuse")
	}
	if _, _, ok := g.ByFileKey(rec.Files[0].Key); !ok {
		t.Fatal("a refused patch dropped a key")
	}
}

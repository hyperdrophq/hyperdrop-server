package linked

import (
	"os"
	"path/filepath"
	"testing"
)

// testRoots writes the given files under a temp volume, keyed by
// volume-relative path, and answers the roots scanned over that volume.
func testRoots(t *testing.T, files map[string]string) *Roots {
	t.Helper()
	vol := t.TempDir()
	for p, body := range files {
		full := filepath.Join(vol, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestARevokedSourceComposesNothingAndCountsForPrefixing(t *testing.T) {
	roots := testRoots(t, map[string]string{
		"photo/2024/a.jpg":        "A",
		"public-share/index.html": "<h1>hi</h1>",
	})
	specs := []SourceSpec{{Path: "photo/2024", Revoked: true}, {Path: "public-share"}}
	l, readable := Compose(roots, specs, MaxWalk)
	if !readable {
		t.Fatal("the live source makes the share readable")
	}
	if len(l.Entries) != 1 || l.Entries[0].Rel != "public-share/index.html" {
		t.Fatalf("entries = %+v, want the live source alone, still prefixed", l.Entries)
	}
	if _, readable := Compose(roots, []SourceSpec{{Path: "photo/2024", Revoked: true}}, MaxWalk); readable {
		t.Fatal("a share whose only source is revoked reads as unavailable")
	}
}

func TestARevokedSourceNeitherCollidesNorOpens(t *testing.T) {
	roots := testRoots(t, map[string]string{"photo/2024/a.jpg": "A"})
	specs := []SourceSpec{{Path: "photo/2024", Revoked: true}}
	if Collides(roots, specs, false, "a.jpg") {
		t.Fatal("an upload may land where a revoked source's entry was")
	}
	if _, _, err := openOne(t, roots, specs, false, "a.jpg"); err == nil {
		t.Fatal("a revoked source's bytes must not open")
	}
}

func TestGrantedReadsTheAllowlistAlone(t *testing.T) {
	if !Granted(true, nil, "anything/at/all") {
		t.Fatal("an admin is granted everything")
	}
	if !Granted(false, []string{"photo"}, "photo/2024") || Granted(false, []string{"photo/2024"}, "photo") {
		t.Fatal("a grant covers what lies below it and nothing above")
	}
	if Granted(false, []string{"../x"}, "../x") {
		t.Fatal("a malformed entry grants nothing")
	}
}

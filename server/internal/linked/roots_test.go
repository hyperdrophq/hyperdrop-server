package linked

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestValidRel(t *testing.T) {
	for rel, want := range map[string]bool{
		"photo": true, "photo/2024/trip": true, "public-share/report.pdf": true,
		"": false, ".": false, "/photo": false, "photo/../homes": false, "photo/./x": false,
		"photo//x": false, "photo\x00": false, "photo\\x": false, "photo/": false,
	} {
		if got := ValidRel(rel); got != want {
			t.Errorf("ValidRel(%q) = %v, want %v", rel, got, want)
		}
	}
}

func TestScanListsReadableTopLevelDirsWithoutSystemNames(t *testing.T) {
	vol := t.TempDir()
	for _, d := range []string{"photo", "public-share", "@appdata", "#recycle", ".hidden"} {
		os.Mkdir(filepath.Join(vol, d), 0o755)
	}
	os.WriteFile(filepath.Join(vol, "vdsm_repo.conf"), []byte("x"), 0o644)
	r, err := NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := r.List()
	if len(got) != 2 || got[0].Name != "photo" || got[1].Name != "public-share" {
		t.Fatalf("List = %+v", got)
	}
	if got[0].Dir != filepath.Join(vol, "photo") {
		t.Errorf("Dir = %q", got[0].Dir)
	}
}

func TestFixedRootsAreNamedByBaseAndDuplicatesRefused(t *testing.T) {
	a := filepath.Join(t.TempDir(), "media")
	b := filepath.Join(t.TempDir(), "media")
	os.Mkdir(a, 0o755)
	os.Mkdir(b, 0o755)
	if _, err := NewRoots([]string{a, b}, nil, nil); err == nil {
		t.Fatal("two roots named media were accepted")
	}
	r, err := NewRoots([]string{a}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l := r.List(); len(l) != 1 || l[0].Name != "media" || l[0].Dir != a {
		t.Fatalf("List = %+v", l)
	}
}

func TestListIsCachedForAMinute(t *testing.T) {
	vol := t.TempDir()
	os.Mkdir(filepath.Join(vol, "a"), 0o755)
	r, _ := NewRoots(nil, []string{vol}, nil)
	now := time.Unix(1000, 0)
	r.Now = func() time.Time { return now }
	if len(r.List()) != 1 {
		t.Fatal("first list")
	}
	os.Mkdir(filepath.Join(vol, "b"), 0o755)
	if len(r.List()) != 1 {
		t.Fatal("cache did not hold")
	}
	now = now.Add(61 * time.Second)
	if len(r.List()) != 2 {
		t.Fatal("cache did not expire")
	}
}

func TestResolveAndOpenStayInsideTheRoot(t *testing.T) {
	vol := t.TempDir()
	os.MkdirAll(filepath.Join(vol, "photo", "2024"), 0o755)
	os.MkdirAll(filepath.Join(vol, "homes", "alice"), 0o755)
	os.WriteFile(filepath.Join(vol, "homes", "alice", "secret"), []byte("s"), 0o644)
	os.Symlink(filepath.Join(vol, "homes"), filepath.Join(vol, "photo", "escape"))
	r, _ := NewRoots(nil, []string{vol}, nil)

	root, sub, err := r.Resolve("photo/2024")
	if err != nil || root.Name != "photo" || sub != "2024" {
		t.Fatalf("Resolve = %+v %q %v", root, sub, err)
	}
	if _, sub, err := r.Resolve("photo"); err != nil || sub != "." {
		t.Fatalf("bare root: %q %v", sub, err)
	}
	if _, _, err := r.Resolve("nope/x"); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("unknown root: %v", err)
	}
	if _, _, err := r.Resolve("photo/../homes"); !errors.Is(err, ErrBadPath) {
		t.Fatalf("dotdot: %v", err)
	}
	or, sub, err := r.Open("photo/escape/alice")
	if err != nil {
		return // The source boundary itself now refuses the directory link.
	}
	defer or.Close()
	if _, err := or.Open(filepath.Join(sub, "secret")); err == nil {
		t.Fatal("symlink escaped the root")
	}
}

func TestNilRootsMeansNoRoots(t *testing.T) {
	var r *Roots
	if r.Enabled() || r.List() != nil {
		t.Fatal("nil roots enabled")
	}
	if _, _, err := r.Resolve("photo"); !errors.Is(err, ErrNoRoot) {
		t.Fatal(err)
	}
}

func TestFromEnvSplitsOnColons(t *testing.T) {
	vol := t.TempDir()
	os.Mkdir(filepath.Join(vol, "a"), 0o755)
	fixed := filepath.Join(t.TempDir(), "srv")
	os.Mkdir(fixed, 0o755)
	env := map[string]string{"HYPERDROP_LINKED_ROOTS": fixed, "HYPERDROP_LINKED_SCAN": vol + ":" + "/nonexistent"}
	r, err := FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	l := r.List()
	if len(l) != 2 || l[0].Name != "a" || l[1].Name != "srv" {
		t.Fatalf("List = %+v", l)
	}
	r2, _ := FromEnv(func(string) string { return "" })
	if r2.Enabled() {
		t.Fatal("empty env enabled")
	}
}

// A hidden path is held to what Walk can list: clean and local, with a
// backslash an ordinary byte.
func TestValidHide(t *testing.T) {
	for rel, want := range map[string]bool{
		"a.jpg": true, `a\b.jpg`: true, "dir/a.jpg": true, `..\x`: true,
		"": false, ".": false, "..": false, "../a": false, "/a": false, "a/": false,
		"a//b": false, "a/./b": false, "a/../b": false, "a\x00b": false,
		strings.Repeat("a", 256): false,
	} {
		if got := ValidHide(rel); got != want {
			t.Errorf("ValidHide(%q) = %v, want %v", rel, got, want)
		}
	}
}

// A configured root the data folder excludes is never listed, and the
// operator is told so once, when the roots are built.
func TestAnExcludedFixedRootIsLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	vol := t.TempDir()
	data := filepath.Join(vol, "HyperDrop")
	photos := filepath.Join(vol, "Photos")
	for _, d := range []string{data, photos} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewRoots([]string{vol, photos}, nil, []string{data})
	if err != nil {
		t.Fatal(err)
	}
	r.List()
	r.List()
	if got := strings.Count(buf.String(), vol); got != 1 || !strings.Contains(buf.String(), "data folder") {
		t.Fatalf("log = %q, want one line naming %s", buf.String(), vol)
	}
	if strings.Contains(buf.String(), photos) {
		t.Fatalf("log names a root that is listed: %q", buf.String())
	}
}

func TestRootsNeverListTheDataFolder(t *testing.T) {
	names := func(r *Roots) []string {
		var out []string
		for _, root := range r.List() {
			out = append(out, root.Name)
		}
		return out
	}
	scan := t.TempDir()
	data := filepath.Join(scan, "HyperDrop")
	photos := filepath.Join(scan, "Photos")
	os.Mkdir(photos, 0o755)
	os.Mkdir(data, 0o755)
	os.WriteFile(filepath.Join(data, "hyperdrop.db"), []byte("x"), 0o600)

	t.Run("scanned", func(t *testing.T) {
		r, err := NewRoots(nil, []string{scan}, []string{data})
		if err != nil {
			t.Fatal(err)
		}
		if got := names(r); len(got) != 1 || got[0] != "Photos" {
			t.Fatalf("roots = %v, want [Photos]", got)
		}
		if _, _, err := r.Resolve("HyperDrop/hyperdrop.db"); !errors.Is(err, ErrNoRoot) {
			t.Fatalf("Resolve into the data folder = %v, want ErrNoRoot", err)
		}
		if _, _, err := r.Open("HyperDrop/hyperdrop.db"); err == nil {
			t.Fatal("Open reached the data folder")
		}
	})
	t.Run("names sharing its prefix", func(t *testing.T) {
		vol := t.TempDir()
		for _, n := range []string{"HyperDrop", "HyperDrop2", "HyperDrop-old"} {
			if err := os.Mkdir(filepath.Join(vol, n), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		excl := filepath.Join(vol, "HyperDrop")
		r, err := NewRoots(nil, []string{vol}, []string{excl})
		if err != nil {
			t.Fatal(err)
		}
		if got := names(r); !slices.Equal(got, []string{"HyperDrop-old", "HyperDrop2"}) {
			t.Fatalf("scanned roots = %v, want [HyperDrop-old HyperDrop2]", got)
		}
		r, _ = NewRoots([]string{excl, filepath.Join(vol, "HyperDrop2"), filepath.Join(vol, "HyperDrop-old")}, nil, []string{excl})
		if got := names(r); !slices.Equal(got, []string{"HyperDrop-old", "HyperDrop2"}) {
			t.Fatalf("fixed roots = %v, want [HyperDrop-old HyperDrop2]", got)
		}
	})
	t.Run("fixed root equal to it", func(t *testing.T) {
		r, _ := NewRoots([]string{data, photos}, nil, []string{data})
		if got := names(r); len(got) != 1 || got[0] != "Photos" {
			t.Fatalf("roots = %v, want [Photos]", got)
		}
	})
	t.Run("symlinked spelling", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(data, link); err != nil {
			t.Skip(err)
		}
		r, _ := NewRoots([]string{link}, nil, []string{data})
		if got := names(r); len(got) != 0 {
			t.Fatalf("symlinked data folder listed: %v", got)
		}
		r, _ = NewRoots([]string{data}, nil, []string{link})
		if got := names(r); len(got) != 0 {
			t.Fatalf("data folder listed through an excluded symlink: %v", got)
		}
		r, _ = NewRoots([]string{photos}, nil, []string{link})
		if got := names(r); len(got) != 1 {
			t.Fatalf("roots = %v, want [Photos]", got)
		}
	})
	t.Run("root containing it", func(t *testing.T) {
		r, _ := NewRoots([]string{scan}, nil, []string{data})
		if got := names(r); len(got) != 0 {
			t.Fatalf("an ancestor of the data folder was listed: %v", got)
		}
	})
	t.Run("root inside it", func(t *testing.T) {
		inner := filepath.Join(data, "shares")
		os.Mkdir(inner, 0o755)
		r, _ := NewRoots([]string{inner}, nil, []string{data})
		if got := names(r); len(got) != 0 {
			t.Fatalf("a folder inside the data folder was listed: %v", got)
		}
	})
	t.Run("FromEnv reads HYPERDROP_DATA", func(t *testing.T) {
		env := map[string]string{"HYPERDROP_LINKED_SCAN": scan, "HYPERDROP_DATA": data}
		r, err := FromEnv(func(k string) string { return env[k] })
		if err != nil {
			t.Fatal(err)
		}
		if got := names(r); len(got) != 1 || got[0] != "Photos" {
			t.Fatalf("roots = %v, want [Photos]", got)
		}
	})
}

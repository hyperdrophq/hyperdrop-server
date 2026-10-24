package linked

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func containmentFixture(t *testing.T) (*Roots, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	for rel, body := range map[string]string{"allowed/real.txt": "PUBLIC", "allowed/sub/own.txt": "OWN", "denied/secret.txt": "PRIVATE"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for rel, target := range map[string]string{"allowed/escape.txt": "../denied/secret.txt", "allowed/alias.txt": "real.txt", "allowed/sub/alias.txt": "../real.txt", "allowed/link": "../denied", "aliasdir": "allowed"} {
		if err := os.Symlink(target, filepath.Join(dir, rel)); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := NewRoots([]string{dir}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return roots, dir
}

func TestSelectedSourceContainsFileSymlinks(t *testing.T) {
	roots, _ := containmentFixture(t)
	specs := []SourceSpec{{Path: "data/allowed"}}
	listing, readable := Compose(roots, specs, MaxWalk)
	if !readable || rels(listing.Entries) != "alias.txt,real.txt,sub/alias.txt,sub/own.txt" {
		t.Errorf("listing readable=%v entries=%s", readable, rels(listing.Entries))
	}
	for _, rel := range []string{"alias.txt", "sub/alias.txt"} {
		f, _, err := openOne(t, roots, specs, false, rel)
		if err != nil {
			t.Errorf("in-source %s: %v", rel, err)
			continue
		}
		body, err := io.ReadAll(f)
		f.Close()
		if err != nil || string(body) != "PUBLIC" {
			t.Errorf("%s: %q %v", rel, body, err)
		}
	}
	for _, rel := range []string{"escape.txt", "link/secret.txt"} {
		if f, _, err := openOne(t, roots, specs, false, rel); err == nil {
			f.Close()
			t.Errorf("opened escaped entry %s", rel)
		}
	}
}

func TestSelectedSourceBoundaryNeverFollowsSymlinks(t *testing.T) {
	roots, _ := containmentFixture(t)
	for _, source := range []string{"data/allowed/link", "data/aliasdir", "data/aliasdir/sub", "data/allowed/alias.txt", "data/allowed/escape.txt"} {
		t.Run(source, func(t *testing.T) {
			if l, readable := Compose(roots, []SourceSpec{{Path: source}}, MaxWalk); readable || len(l.Entries) != 0 {
				t.Fatalf("symlink boundary readable: %s", rels(l.Entries))
			}
		})
	}
}

func TestSourceReplacementCannotBroadenExistingShare(t *testing.T) {
	for _, kind := range []string{"directory", "file"} {
		t.Run(kind, func(t *testing.T) {
			roots, dir := containmentFixture(t)
			source, rel, target := "data/allowed", "real.txt", "denied"
			old := filepath.Join(dir, "allowed")
			if kind == "file" {
				source = "data/allowed/real.txt"
				old = filepath.Join(dir, "allowed", "real.txt")
				target = "../denied/secret.txt"
			}
			specs := []SourceSpec{{Path: source}}
			f, _, err := openOne(t, roots, specs, false, rel)
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
			if err := os.Rename(old, old+"-original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, old); err != nil {
				t.Fatal(err)
			}
			if l, readable := Compose(roots, specs, MaxWalk); readable || len(l.Entries) != 0 {
				t.Errorf("replacement became readable: %s", rels(l.Entries))
			}
			if f, _, err := openOne(t, roots, specs, false, rel); err == nil {
				f.Close()
				t.Fatal("replacement opened")
			}
		})
	}
}

func TestConfiguredRootAliasAndSingleFileNamingRemainSupported(t *testing.T) {
	_, dir := containmentFixture(t)
	configured := filepath.Join(t.TempDir(), "configured")
	if err := os.Symlink(dir, configured); err != nil {
		t.Fatal(err)
	}
	roots, err := NewRoots([]string{configured, filepath.Join(dir, "allowed")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for source, want := range map[string]string{"configured/allowed/real.txt": "real.txt", "allowed/real.txt": "real.txt"} {
		l, readable := Compose(roots, []SourceSpec{{Path: source}}, MaxWalk)
		if !readable || rels(l.Entries) != want {
			t.Errorf("%s: readable=%v entries=%s", source, readable, rels(l.Entries))
		}
	}
}

func TestOpenedSourceHandleStaysAtItsBoundaryAfterReplacement(t *testing.T) {
	roots, dir := containmentFixture(t)
	root, sub, err := roots.Open("data/allowed")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(filepath.Join(dir, "allowed"), filepath.Join(dir, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("denied", filepath.Join(dir, "allowed")); err != nil {
		t.Fatal(err)
	}
	f, err := root.Open(filepath.Join(sub, "real.txt"))
	if err != nil {
		t.Fatalf("opened boundary was lost: %v", err)
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil || string(body) != "PUBLIC" {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if f, err := root.Open(filepath.Join(sub, "secret.txt")); err == nil {
		f.Close()
		t.Fatal("opened handle followed replacement boundary")
	}
}

func TestOpenedFileSourceCannotBecomeADirectoryBoundary(t *testing.T) {
	roots, dir := containmentFixture(t)
	root, sub, err := roots.Open("data/allowed/real.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selected := filepath.Join(dir, "allowed", "real.txt")
	if err := os.Remove(selected); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(selected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "allowed", "private.txt"), []byte("PRIVATE"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../private.txt", filepath.Join(selected, "escape.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selected, "new.txt"), []byte("NEW"), 0600); err != nil {
		t.Fatal(err)
	}
	if entries, _, err := walkSource(root, sub, MaxWalk); err == nil {
		t.Fatalf("file boundary reclassified as directory: %+v", entries)
	}
}

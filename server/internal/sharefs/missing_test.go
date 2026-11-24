package sharefs

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"slices"
	"testing"
)

// putStored writes rel's bytes under files/ the way a commit leaves them.
func putStored(t *testing.T, f *FS, id, rel string) string {
	t.Helper()
	p := filepath.Join(shareDir(f, id), filesDirName, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(rel), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// countListings counts the directory listings MissingAmong makes and the
// exact checks it falls back to, for as long as the test runs.
func countListings(t *testing.T) (listings, exact *int) {
	t.Helper()
	listings, exact = new(int), new(int)
	prevList, prevExact := listDir, exactCheck
	listDir = func(root *os.Root, dir string, fn func(os.DirEntry)) error {
		*listings++
		return prevList(root, dir, fn)
	}
	exactCheck = func(root *os.Root, rel string) (bool, error) {
		*exact++
		return prevExact(root, rel)
	}
	t.Cleanup(func() { listDir, exactCheck = prevList, prevExact })
	return listings, exact
}

// exactVerdicts is what FileMissing answers for each of rels: the missing
// ones, and the ones it could not check.
func exactVerdicts(t *testing.T, f *FS, id string, rels []string) (missing, failed []string) {
	t.Helper()
	for _, rel := range rels {
		gone, err := f.FileMissing(id, rel)
		switch {
		case err != nil:
			failed = append(failed, rel)
		case gone:
			missing = append(missing, rel)
		}
	}
	return missing, failed
}

func TestMissingAmongAnswersWhatFileMissingAnswers(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "elsewhere.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name        string
		damage      func(t *testing.T, f *FS, p string)
		missing     bool
		failed      bool
		exactChecks int
	}{
		{name: "a present file", damage: func(*testing.T, *FS, string) {}},
		{name: "an absent file", missing: true, exactChecks: 1, damage: func(t *testing.T, _ *FS, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a directory where the file is", missing: true, exactChecks: 1, damage: func(t *testing.T, _ *FS, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a symlink to a regular file inside the share", exactChecks: 1, damage: func(t *testing.T, f *FS, p string) {
			if err := os.Rename(p, p+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(p)+".real", p); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a symlink leading outside the share", failed: true, exactChecks: 1, damage: func(t *testing.T, _ *FS, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, p); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := openTest(t)
			const rel = "dir/f.txt"
			c.damage(t, f, putStored(t, f, testID, rel))
			wantMissing, wantFailed := exactVerdicts(t, f, testID, []string{rel})
			if (len(wantMissing) == 1) != c.missing || (len(wantFailed) == 1) != c.failed {
				t.Fatalf("FileMissing: missing %v, failed %v; the case expects missing=%v failed=%v", wantMissing, wantFailed, c.missing, c.failed)
			}
			_, exact := countListings(t)
			got, err := f.MissingAmong(testID, []string{rel})
			if !slices.Equal(got, wantMissing) || (err != nil) != c.failed {
				t.Fatalf("MissingAmong = %v, %v; want %v, an error %v", got, err, wantMissing, c.failed)
			}
			if *exact != c.exactChecks {
				t.Fatalf("%d exact checks, want %d", *exact, c.exactChecks)
			}
		})
	}
}

func TestMissingAmongAnAbsentShareMissesEverything(t *testing.T) {
	f := openTest(t)
	rels := []string{"a.txt", "dir/b.txt"}
	got, err := f.MissingAmong(testID, rels)
	if err != nil || !slices.Equal(got, rels) {
		t.Fatalf("MissingAmong = %v, %v; want every rel missing", got, err)
	}
}

func TestMissingAmongListsEachDirectoryOnce(t *testing.T) {
	f := openTest(t)
	rels := []string{"d/a.txt", "d/e/b.txt", "d/e/c.txt"}
	for _, rel := range rels {
		putStored(t, f, testID, rel)
	}
	listings, exact := countListings(t)
	got, err := f.MissingAmong(testID, rels)
	if err != nil || len(got) != 0 {
		t.Fatalf("MissingAmong = %v, %v; want none missing", got, err)
	}
	if *listings != 2 || *exact != 0 {
		t.Fatalf("%d listings and %d exact checks, want 2 and 0", *listings, *exact)
	}
}

func TestMissingAmongMatchesAnNFCName(t *testing.T) {
	f := openTest(t)
	rel := "caf\u00e9/r\u00e9sum\u00e9.txt" // precomposed, as every relpath is stored
	putStored(t, f, testID, rel)
	listings, exact := countListings(t)
	got, err := f.MissingAmong(testID, []string{rel})
	if err != nil || len(got) != 0 {
		t.Fatalf("MissingAmong = %v, %v; want the file present", got, err)
	}
	if *listings != 1 || *exact != 0 {
		t.Fatalf("%d listings and %d exact checks, want the listing alone to find it", *listings, *exact)
	}
}

// Rows over random directories with random damage: the listing's verdict
// is the exact check's for every row.
func TestTheListingAgreesWithTheExactCheck(t *testing.T) {
	f := openTest(t)
	outside := filepath.Join(t.TempDir(), "elsewhere.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(6, 2026))
	dirs := []string{"", "a", "a/b", "c", "c/d/e", "f"}
	var rels []string
	for i := range 200 {
		rel := path.Join(dirs[r.IntN(len(dirs))], fmt.Sprintf("f%03d.txt", i))
		rels = append(rels, rel)
		p := putStored(t, f, testID, rel)
		switch r.IntN(8) {
		case 0: // deleted
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		case 1: // replaced by a directory
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(p, "inner"), 0o700); err != nil {
				t.Fatal(err)
			}
		case 2: // replaced by a symlink to a file inside the share
			if err := os.Rename(p, p+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(p)+".real", p); err != nil {
				t.Fatal(err)
			}
		case 3: // replaced by a symlink leading outside
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, p); err != nil {
				t.Fatal(err)
			}
		case 4: // replaced by a symlink to nothing
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("nowhere", p); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A whole directory replaced by a file: every row under it is missing.
	under := filepath.Join(shareDir(f, testID), filesDirName, "f")
	if err := os.RemoveAll(under); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(under, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.Shuffle(len(rels), func(i, j int) { rels[i], rels[j] = rels[j], rels[i] })

	wantMissing, wantFailed := exactVerdicts(t, f, testID, rels)
	if len(wantMissing) == 0 || len(wantFailed) == 0 || len(wantMissing)+len(wantFailed) == len(rels) {
		t.Fatalf("the damage left %d missing and %d unreadable of %d: not a mix", len(wantMissing), len(wantFailed), len(rels))
	}
	listings, _ := countListings(t)
	got, err := f.MissingAmong(testID, rels)
	if err == nil {
		t.Fatal("MissingAmong reports no failure for the symlinks leading outside")
	}
	slices.Sort(got)
	slices.Sort(wantMissing)
	if !slices.Equal(got, wantMissing) {
		t.Fatalf("MissingAmong's missing set differs from FileMissing's:\n got %v\nwant %v", got, wantMissing)
	}
	if *listings != len(dirs) {
		t.Fatalf("%d listings, want one per directory (%d)", *listings, len(dirs))
	}
}

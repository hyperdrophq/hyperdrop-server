package sharefs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const copyDstID = "mnpqrstuvw"

// storeFile writes and commits rel in share id, answering its bytes.
func storeFile(t *testing.T, f *FS, id, rel string, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	n, err := f.Write(id, rel, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Write %s: %v", rel, err)
	}
	if _, err := f.Commit(id, rel, n, nil); err != nil {
		t.Fatalf("Commit %s: %v", rel, err)
	}
	return data
}

// storedSum is the SHA-256 of a stored file, read the way it is served.
func storedSum(t *testing.T, f *FS, id, rel string) [32]byte {
	t.Helper()
	fh, _, err := f.Open(id, rel)
	if err != nil {
		t.Fatalf("Open %s/%s: %v", id, rel, err)
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		t.Fatal(err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// partPath is a plain part's path on disk, for assertions.
func partPath(f *FS, id, rel string) string { return filepath.Join(shareDir(f, id), partRel(rel)) }

func TestStageCopyThenCommitServesTheSameBytes(t *testing.T) {
	f := openTest(t)
	const rel = "photos/2026/café.bin"
	// Larger than the copy buffer, so the plain copy runs more than once.
	data := storeFile(t, f, testID, rel, 3<<20+17)
	want := sha256.Sum256(data)

	n, err := f.StageCopy(testID, rel, copyDstID, rel)
	if err != nil {
		t.Fatalf("StageCopy: %v", err)
	}
	if n != int64(len(data)) {
		t.Fatalf("StageCopy wrote %d bytes, want %d", n, len(data))
	}
	if !exists(partPath(f, copyDstID, rel)) {
		t.Fatal("no staged part after StageCopy")
	}
	if exists(filepath.Join(shareDir(f, copyDstID), fileRel(rel))) {
		t.Fatal("StageCopy put bytes under files/ before a commit")
	}
	c, err := f.Commit(copyDstID, rel, n, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if c.Size != n || c.SHA256 != hexSum(want) {
		t.Fatalf("Committed %+v, want size %d sha %s", c, n, hexSum(want))
	}
	if got := storedSum(t, f, copyDstID, rel); got != want {
		t.Fatal("the copy serves different bytes")
	}
	if got := storedSum(t, f, testID, rel); got != want {
		t.Fatal("the source changed")
	}
	if exists(partPath(f, copyDstID, rel)) {
		t.Fatal("the part outlived its commit")
	}
}

func hexSum(sum [32]byte) string { return hex.EncodeToString(sum[:]) }

func TestStageCopyRefusesAnUncleanPath(t *testing.T) {
	f := openTest(t)
	storeFile(t, f, testID, "x", 10)
	for _, tc := range []struct {
		name                         string
		srcID, srcRel, dstID, dstRel string
		want                         error
	}{
		{"source relpath", testID, "../x", copyDstID, "x", ErrBadPath},
		{"destination relpath", testID, "x", copyDstID, "../x", ErrBadPath},
		{"destination dot", testID, "x", copyDstID, ".", ErrBadPath},
		{"unclean destination", testID, "x", copyDstID, "a//x", ErrBadPath},
		{"source id", "../shares", "x", copyDstID, "x", ErrNotFound},
		{"destination id", testID, "x", "../" + copyDstID, "x", ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.StageCopy(tc.srcID, tc.srcRel, tc.dstID, tc.dstRel); !errors.Is(err, tc.want) {
				t.Fatalf("StageCopy = %v, want %v", err, tc.want)
			}
			if exists(shareDir(f, copyDstID)) {
				t.Fatal("a refused copy wrote into the destination")
			}
		})
	}
}

func TestStageCopyOfAMissingSourceWritesNothing(t *testing.T) {
	f := openTest(t)
	storeFile(t, f, testID, "x", 10)
	if _, err := f.StageCopy(testID, "missing", copyDstID, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("StageCopy = %v, want ErrNotFound", err)
	}
	if exists(shareDir(f, copyDstID)) {
		t.Fatal("a copy of nothing wrote into the destination")
	}
}

// A part staged for the path before (an interrupted upload or copy) is
// replaced, never appended to, and its sidecars go with it.
func TestStageCopyReplacesAStalePart(t *testing.T) {
	f := openTest(t)
	data := storeFile(t, f, testID, "doc.txt", 100)
	stale := bytes.Repeat([]byte("s"), 5000)
	if _, err := f.Write(copyDstID, "doc.txt", bytes.NewReader(stale)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partPath(f, copyDstID, "doc.txt")+partRangesExt, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := f.StageCopy(testID, "doc.txt", copyDstID, "doc.txt")
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(data)) {
		t.Fatalf("StageCopy wrote %d, want %d", n, len(data))
	}
	if exists(partPath(f, copyDstID, "doc.txt") + partRangesExt) {
		t.Fatal("the stale part's ranges sidecar survived")
	}
	if _, err := f.Commit(copyDstID, "doc.txt", n, nil); err != nil {
		t.Fatal(err)
	}
	if storedSum(t, f, copyDstID, "doc.txt") != sha256.Sum256(data) {
		t.Fatal("the copy holds the stale part's bytes")
	}
}

// withClone stands clone in for the filesystem's clone for one test.
func withClone(t *testing.T, clone func(dst, src *os.File) error) {
	t.Helper()
	prev := cloneFile
	cloneFile = clone
	t.Cleanup(func() { cloneFile = prev })
}

// A filesystem that cannot clone (or not across these two files) gets a
// plain copy, and so does a system that forbids the clone itself: an
// unprivileged container answers EPERM for it on every filesystem.
func TestStageCopyFallsBackToACopyWhenTheCloneIsRefused(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EOPNOTSUPP, syscall.EXDEV, syscall.EINVAL, syscall.ENOTTY, syscall.ENOSYS, syscall.EPERM, syscall.EACCES} {
		t.Run(errno.Error(), func(t *testing.T) {
			f := openTest(t)
			data := storeFile(t, f, testID, "a.bin", 4096)
			withClone(t, func(dst, src *os.File) error { return errno })
			n, err := f.StageCopy(testID, "a.bin", copyDstID, "a.bin")
			if err != nil {
				t.Fatalf("StageCopy: %v", err)
			}
			if _, err := f.Commit(copyDstID, "a.bin", n, nil); err != nil {
				t.Fatal(err)
			}
			if storedSum(t, f, copyDstID, "a.bin") != sha256.Sum256(data) {
				t.Fatal("the fallback copy serves different bytes")
			}
		})
	}
}

// Any other failure after the part was created removes the part.
func TestAFailedStageCopyLeavesNoPart(t *testing.T) {
	f := openTest(t)
	storeFile(t, f, testID, "a.bin", 4096)
	withClone(t, func(dst, src *os.File) error {
		dst.Write([]byte("half"))
		return syscall.EIO
	})
	if _, err := f.StageCopy(testID, "a.bin", copyDstID, "a.bin"); !errors.Is(err, syscall.EIO) {
		t.Fatalf("StageCopy = %v, want EIO", err)
	}
	if exists(partPath(f, copyDstID, "a.bin")) {
		t.Fatal("a failed copy left its part")
	}
	withClone(t, func(dst, src *os.File) error { return syscall.ENOSPC })
	if _, err := f.StageCopy(testID, "a.bin", copyDstID, "a.bin"); !errors.Is(err, ErrDiskFull) {
		t.Fatalf("StageCopy on a full disk = %v, want ErrDiskFull", err)
	}
	if exists(partPath(f, copyDstID, "a.bin")) {
		t.Fatal("a copy onto a full disk left its part")
	}
}

const slugC = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e"
const slugD = "3c4d5e6f-7a8b-4c9d-8e0f-2a3b4c5d6e7f"

// copySidecars is the copy line's sidecar pass over one map: the tiles, the
// poster through the same map, and the recount.
func copySidecars(f *FS, srcID, dstID string, slugMap map[string]string, owner string) error {
	if err := f.CopyThumbs(srcID, dstID, slugMap, owner); err != nil {
		return err
	}
	err := f.CopyPoster(srcID, dstID, owner, func(old string) (string, bool, error) {
		slug, ok := slugMap[old]
		return slug, ok, nil
	})
	if err != nil {
		return err
	}
	f.RecountSidecars(dstID, owner)
	return nil
}

// Tiles copied a page at a time land as one copy: each page's map alone,
// then the poster through a lookup that names a slug no page held.
func TestCopyThumbsInPagesThenThePoster(t *testing.T) {
	f := openTest(t)
	tile := jpegBytes(t)
	for _, s := range []string{slugA, slugB} {
		if err := f.SetThumb(testID, "alice", s, tile, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.SetPoster(testID, "alice", slugB, jpegBytes(t)); err != nil {
		t.Fatal(err)
	}
	for _, page := range []map[string]string{{slugA: slugC}, {slugB: slugD}} {
		if err := f.CopyThumbs(testID, copyDstID, page, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	asked := ""
	if err := f.CopyPoster(testID, copyDstID, "alice", func(old string) (string, bool, error) {
		asked = old
		return slugD, true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if asked != slugB {
		t.Fatalf("the poster asked for %q, want %s", asked, slugB)
	}
	for _, s := range []string{slugC, slugD} {
		if _, err := f.Thumb(copyDstID, s); err != nil {
			t.Fatalf("tile %s: %v", s, err)
		}
	}
	if src, err := f.PosterSource(copyDstID); err != nil || src != slugD {
		t.Fatalf("the copy's poster names %q, %v", src, err)
	}
	// A lookup that fails fails the poster; one that answers a bad slug is
	// refused before anything is written.
	other := "zxcvbnmasd"
	if err := f.CopyPoster(testID, other, "alice", func(string) (string, bool, error) {
		return "", false, errors.New("the database is gone")
	}); err == nil {
		t.Fatal("a failed lookup copied the poster")
	}
	if err := f.CopyPoster(testID, other, "alice", func(string) (string, bool, error) {
		return "../x", true, nil
	}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a bad slug from the lookup: %v", err)
	}
}

func TestCopySidecarsRekeysThumbs(t *testing.T) {
	f := openTest(t)
	tileA, tileB, poster := jpegBytes(t), jpegBytes(t), jpegBytes(t)
	tileB = append(tileB, 0) // a different file than tileA
	if err := f.SetThumb(testID, "alice", slugA, tileA, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.SetThumb(testID, "alice", slugB, tileB, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.SetPoster(testID, "alice", slugA, poster); err != nil {
		t.Fatal(err)
	}
	const untiled = "4d5e6f7a-8b9c-4d0e-9f1a-3b4c5d6e7f80"
	const untiledNew = "5e6f7a8b-9c0d-4e1f-8a2b-4c5d6e7f8091"
	slugMap := map[string]string{slugA: slugC, slugB: slugD, untiled: untiledNew}
	if err := copySidecars(f, testID, copyDstID, slugMap, "alice"); err != nil {
		t.Fatalf("copySidecars: %v", err)
	}
	for old, tile := range map[string][]byte{slugC: tileA, slugD: tileB} {
		got, err := f.Thumb(copyDstID, old)
		if err != nil || !bytes.Equal(got, tile) {
			t.Fatalf("the copy's tile %s: %d bytes, %v", old, len(got), err)
		}
	}
	for _, old := range []string{slugA, slugB, untiledNew} {
		if _, err := f.Thumb(copyDstID, old); !errors.Is(err, ErrNoThumb) {
			t.Fatalf("the copy holds a tile under %s: %v", old, err)
		}
	}
	got, err := f.Poster(copyDstID)
	if err != nil || !bytes.Equal(got, poster) {
		t.Fatalf("the copy's poster: %d bytes, %v", len(got), err)
	}
	if src, err := f.PosterSource(copyDstID); err != nil || src != slugC {
		t.Fatalf("the copy's poster names %q (%v), want %s", src, err, slugC)
	}
	if src, err := f.PosterSource(testID); err != nil || src != slugA {
		t.Fatalf("the source's poster now names %q (%v)", src, err)
	}
	want := 2 * int64(len(tileA)+len(tileB)+len(poster))
	if got := f.SidecarBytes("alice"); got != want {
		t.Fatalf("SidecarBytes = %d, want %d (both shares' tiles and posters)", got, want)
	}
}

// A poster naming no entry is copied naming none; a poster naming an entry
// the copy does not hold, or a note that cannot be read, is not copied: the
// original withholds it from the card, so a copy must not show it.
func TestCopySidecarsCopiesThePosterOnlyWhenItsEntryCame(t *testing.T) {
	cases := []struct {
		name     string
		set      func(f *FS) error
		wantCopy bool
	}{
		{"names no entry", func(f *FS) error { return f.SetPoster(testID, "alice", "", jpegBytes(t)) }, true},
		{"names an entry not copied", func(f *FS) error { return f.SetPoster(testID, "alice", slugB, jpegBytes(t)) }, false},
		{"a garbled note", func(f *FS) error {
			if err := f.SetPoster(testID, "alice", slugA, jpegBytes(t)); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(shareDir(f, testID), posterSourceFileName), []byte("nope"), 0o600)
		}, false},
		{"no poster", func(f *FS) error { return f.SetThumb(testID, "alice", slugA, jpegBytes(t), nil) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := openTest(t)
			if err := tc.set(f); err != nil {
				t.Fatal(err)
			}
			if err := copySidecars(f, testID, copyDstID, map[string]string{slugA: slugC}, "alice"); err != nil {
				t.Fatalf("copySidecars: %v", err)
			}
			if got := f.HasPoster(copyDstID); got != tc.wantCopy {
				t.Fatalf("the copy has a poster: %v, want %v", got, tc.wantCopy)
			}
			if src, err := f.PosterSource(copyDstID); err != nil || src != "" {
				t.Fatalf("the copy's poster note: %q, %v", src, err)
			}
		})
	}
}

func TestCopySidecarsRefusesBadIDsAndSlugs(t *testing.T) {
	f := openTest(t)
	if err := f.SetThumb(testID, "alice", slugA, jpegBytes(t), nil); err != nil {
		t.Fatal(err)
	}
	if err := copySidecars(f, "../x", copyDstID, nil, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad source id: %v", err)
	}
	if err := copySidecars(f, testID, "../x", nil, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad destination id: %v", err)
	}
	for _, m := range []map[string]string{{slugA: "../../x"}, {"../x": slugC}} {
		if err := copySidecars(f, testID, copyDstID, m, "alice"); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("copySidecars(%v) = %v, want ErrBadRequest", m, err)
		}
	}
	if exists(shareDir(f, copyDstID)) {
		t.Fatal("a refused copy wrote into the destination")
	}
}

// A source with no directory at all (every file linked, nothing tiled) has
// nothing to copy.
func TestCopySidecarsOfAShareWithNoDirectory(t *testing.T) {
	f := openTest(t)
	if err := copySidecars(f, testID, copyDstID, map[string]string{slugA: slugC}, "alice"); err != nil {
		t.Fatal(err)
	}
	if f.HasPoster(copyDstID) || f.SidecarBytes("alice") != 0 {
		t.Fatal("a copy of nothing holds something")
	}
}

package sharefs

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const slugA = "0f2b7c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e"
const slugB = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"

func jpegBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, image.NewGray(image.Rect(0, 0, 4, 4)), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestValidSlugAcceptsOnlyTheUUIDShape(t *testing.T) {
	for _, ok := range []string{slugA, slugB} {
		if !ValidSlug(ok) {
			t.Errorf("ValidSlug(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "..", "a/b", "0F2B7C1E-4D5A-4B6C-8D7E-9F0A1B2C3D4E", "0f2b7c1e4d5a4b6c8d7e9f0a1b2c3d4e0000", slugA[:35]} {
		if ValidSlug(bad) {
			t.Errorf("ValidSlug(%q) = true", bad)
		}
	}
}

func TestThumbsRoundTripAndAreValidated(t *testing.T) {
	f := openTest(t)
	pic := jpegBytes(t)
	if err := f.SetThumb(testID, slugA, pic, nil); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(filepath.Join(shareDir(f, testID), thumbsDirName)); err != nil {
		t.Fatal(err)
	} else {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Fatalf("leftover tmp file: %s", e.Name())
			}
		}
	}
	got, err := f.Thumb(testID, slugA)
	if err != nil || !bytes.Equal(got, pic) {
		t.Fatalf("Thumb: %d bytes, %v", len(got), err)
	}
	if _, err := f.Thumb(testID, slugB); !errors.Is(err, ErrNoThumb) {
		t.Fatalf("missing tile: %v", err)
	}
	if _, err := f.Thumb("abcdefghjm", slugA); !errors.Is(err, ErrNoThumb) {
		t.Fatalf("missing share: %v", err)
	}
	if err := f.SetThumb(testID, "not-a-slug", pic, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad slug: %v", err)
	}
	if err := f.SetThumb(testID, slugB, []byte("not a jpeg"), nil); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("not a JPEG: %v", err)
	}
	if err := f.SetThumb(testID, slugB, nil, nil); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("empty: %v", err)
	}
	if err := f.SetThumb(testID, slugB, make([]byte, SidecarMaxBytes+1), nil); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("oversize: %v", err)
	}
	if err := f.SetThumb(testID, slugB, pic, nil); err != nil {
		t.Fatal(err)
	}
	slugs, err := f.ThumbSlugs(testID)
	if err != nil || len(slugs) != 2 || !slugs[slugA] || !slugs[slugB] {
		t.Fatalf("ThumbSlugs = %v, %v", slugs, err)
	}
	times, err := f.ThumbTimes(testID)
	if err != nil || len(times) != 2 || time.Since(times[slugA]) > time.Minute {
		t.Fatalf("ThumbTimes = %v, %v", times, err)
	}
	f.RemoveThumb(testID, slugA)
	if slugs, _ := f.ThumbSlugs(testID); len(slugs) != 1 || slugs[slugA] {
		t.Fatalf("after remove: %v", slugs)
	}
	f.RemoveThumb(testID, slugA) // absent is fine
	if slugs, err := f.ThumbSlugs("abcdefghjm"); err != nil || len(slugs) != 0 {
		t.Fatalf("a share with no directory has no tiles: %v, %v", slugs, err)
	}
	if _, err := f.ThumbSlugs("bad"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
}

// One sidecar written twice at once lands as one of the two bodies whole:
// the path lock keeps replaceFile's temporary name from being shared.
func TestConcurrentSidecarWritesNeverInterleave(t *testing.T) {
	f := openTest(t)
	small := jpegBytes(t)
	var big bytes.Buffer
	if err := jpeg.Encode(&big, image.NewGray(image.Rect(0, 0, 64, 64)), nil); err != nil {
		t.Fatal(err)
	}
	large := big.Bytes()
	if len(large) <= len(small) {
		t.Fatal("the two bodies must differ in length for this to prove anything")
	}
	for _, tc := range []struct {
		name  string
		write func(data []byte) error
		read  func() ([]byte, error)
	}{
		{"thumb",
			func(data []byte) error { return f.SetThumb(testID, slugA, data, nil) },
			func() ([]byte, error) { return f.Thumb(testID, slugA) }},
		{"poster",
			func(data []byte) error { return f.SetPoster(testID, "", data) },
			func() ([]byte, error) { return f.Poster(testID) }},
	} {
		var wg sync.WaitGroup
		for _, data := range [][]byte{small, large} {
			wg.Add(1)
			go func(data []byte) {
				defer wg.Done()
				if err := tc.write(data); err != nil {
					t.Errorf("%s: %v", tc.name, err)
				}
			}(data)
		}
		wg.Wait()
		got, err := tc.read()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !bytes.Equal(got, small) && !bytes.Equal(got, large) {
			t.Fatalf("%s stored %d bytes, neither body whole", tc.name, len(got))
		}
	}
}

// The caller's check that the slug names a live file is asked under the
// tile's lock, the one RemoveThumb takes after a delete removed the rows, so
// a tile for a file deleted meanwhile is refused rather than left public.
func TestSetThumbAsksItsCheckUnderTheTileLock(t *testing.T) {
	f := openTest(t)
	pic := jpegBytes(t)
	if err := f.SetThumb(testID, slugA, pic, func() bool { return false }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a tile for a slug the share does not hold = %v", err)
	}
	if _, err := f.Thumb(testID, slugA); !errors.Is(err, ErrNoThumb) {
		t.Fatalf("the refused tile was stored: %v", err)
	}
	if err := f.SetThumb(testID, slugA, pic, func() bool {
		l, done := f.pathLockFor(testID, thumbRel(slugA))
		defer done()
		if l.mu.TryLock() {
			l.mu.Unlock()
			t.Error("the check ran outside the tile lock")
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
}

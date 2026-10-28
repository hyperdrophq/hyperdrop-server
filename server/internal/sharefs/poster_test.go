package sharefs

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestPosterRoundTrip(t *testing.T) {
	f := openTest(t)
	if f.HasPoster(testID) {
		t.Fatal("no poster yet")
	}
	if _, err := f.Poster(testID); !errors.Is(err, ErrNoPoster) {
		t.Fatalf("missing: %v", err)
	}
	pic := jpegBytes(t)
	if err := f.SetPoster(testID, "", pic); err != nil {
		t.Fatal(err)
	}
	if !f.HasPoster(testID) {
		t.Fatal("HasPoster after set")
	}
	got, err := f.Poster(testID)
	if err != nil || !bytes.Equal(got, pic) {
		t.Fatalf("Poster: %d bytes, %v", len(got), err)
	}
	if err := f.SetPoster(testID, "", nil); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("empty: %v", err)
	}
	if err := f.SetPoster(testID, "", make([]byte, SidecarMaxBytes+1)); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("oversize: %v", err)
	}
	if err := f.SetPoster(testID, "", []byte("\xff\xd8 not a picture")); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("not a JPEG: %v", err)
	}
	if got, _ := f.Poster(testID); !bytes.Equal(got, pic) {
		t.Fatal("a refused poster replaced the stored one")
	}
	if err := f.SetPoster("bad", "", pic); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
	if f.HasPoster("abcdefghjm") {
		t.Fatal("a share with no directory has no poster")
	}
}

func TestRemovePosterDeletesTheFileAndItsNote(t *testing.T) {
	f := openTest(t)
	if err := f.SetPoster(testID, "6f1c3b0e-2d4a-4b8e-9c3f-0a1b2c3d4e5f", jpegBytes(t)); err != nil {
		t.Fatal(err)
	}
	if err := f.RemovePoster(testID); err != nil {
		t.Fatal(err)
	}
	if f.HasPoster(testID) {
		t.Fatal("HasPoster after remove")
	}
	if slug, err := f.PosterSource(testID); err != nil || slug != "" {
		t.Fatalf("PosterSource = %q, %v", slug, err)
	}
	if err := f.RemovePoster(testID); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

// The image and its note are one poster: while the poster lock is held,
// neither a set nor a removal touches either file, and each runs whole once
// it is released.
func TestSetAndRemovePosterHoldTheOnePosterLock(t *testing.T) {
	f := openTest(t)
	const slug = "6f1c3b0e-2d4a-4b8e-9c3f-0a1b2c3d4e5f"
	pic := jpegBytes(t)
	for _, tc := range []struct {
		name  string
		op    func() error
		after func() bool
	}{
		{"set", func() error { return f.SetPoster(testID, slug, pic) }, func() bool {
			got, err := f.PosterSource(testID)
			return f.HasPoster(testID) && got == slug && err == nil
		}},
		{"remove", func() error { return f.RemovePoster(testID) }, func() bool {
			got, err := f.PosterSource(testID)
			return !f.HasPoster(testID) && got == "" && err == nil
		}},
	} {
		before, _ := f.PosterSource(testID)
		had := f.HasPoster(testID)
		unlock := f.lockPoster(testID)
		done := make(chan error, 1)
		go func() { done <- tc.op() }()
		select {
		case err := <-done:
			unlock()
			t.Fatalf("%s ran while the poster lock was held: %v", tc.name, err)
		case <-time.After(50 * time.Millisecond):
		}
		if got, _ := f.PosterSource(testID); got != before || f.HasPoster(testID) != had {
			unlock()
			t.Fatalf("%s changed the poster under the lock", tc.name)
		}
		unlock()
		if err := <-done; err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !tc.after() {
			t.Fatalf("%s left the image and its note apart", tc.name)
		}
	}
}

// A refused image changes neither file: the stored poster keeps its note.
func TestARefusedPosterKeepsTheStoredNote(t *testing.T) {
	f := openTest(t)
	const slug = "6f1c3b0e-2d4a-4b8e-9c3f-0a1b2c3d4e5f"
	if err := f.SetPoster(testID, slug, jpegBytes(t)); err != nil {
		t.Fatal(err)
	}
	if err := f.SetPoster(testID, "", []byte("not a picture")); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("not a JPEG: %v", err)
	}
	if err := f.SetPoster(testID, "../files/x", jpegBytes(t)); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a non-slug note: %v", err)
	}
	if got, err := f.PosterSource(testID); got != slug || err != nil {
		t.Fatalf("PosterSource = %q, %v; want %q", got, err, slug)
	}
}

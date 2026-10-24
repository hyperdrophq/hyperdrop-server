package sharefs

import (
	"bytes"
	"errors"
	"testing"
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
	if err := f.SetPoster(testID, pic); err != nil {
		t.Fatal(err)
	}
	if !f.HasPoster(testID) {
		t.Fatal("HasPoster after set")
	}
	got, err := f.Poster(testID)
	if err != nil || !bytes.Equal(got, pic) {
		t.Fatalf("Poster: %d bytes, %v", len(got), err)
	}
	if err := f.SetPoster(testID, nil); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("empty: %v", err)
	}
	if err := f.SetPoster(testID, make([]byte, SidecarMaxBytes+1)); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("oversize: %v", err)
	}
	if err := f.SetPoster(testID, []byte("\xff\xd8 not a picture")); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("not a JPEG: %v", err)
	}
	if got, _ := f.Poster(testID); !bytes.Equal(got, pic) {
		t.Fatal("a refused poster replaced the stored one")
	}
	if err := f.SetPoster("bad", pic); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
	if f.HasPoster("abcdefghjm") {
		t.Fatal("a share with no directory has no poster")
	}
}

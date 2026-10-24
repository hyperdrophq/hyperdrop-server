package sharefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPosterSourceRoundTrip(t *testing.T) {
	f := openTest(t)
	if got, err := f.PosterSource(testID); got != "" || err != nil {
		t.Fatalf("no note yet: %q, %v", got, err)
	}
	const slug = "6f1c3b0e-2d4a-4b8e-9c3f-0a1b2c3d4e5f"
	if err := f.SetPosterSource(testID, slug); err != nil {
		t.Fatal(err)
	}
	if got, err := f.PosterSource(testID); got != slug || err != nil {
		t.Fatalf("PosterSource = %q, %v; want %q", got, err, slug)
	}
	if err := f.SetPosterSource(testID, "../files/x"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("a non-slug: %v, want ErrBadRequest", err)
	}
	if got, _ := f.PosterSource(testID); got != slug {
		t.Fatalf("a refused note replaced the stored one: %q", got)
	}
	if err := f.SetPosterSource(testID, ""); err != nil {
		t.Fatal(err)
	}
	if got, err := f.PosterSource(testID); got != "" || err != nil {
		t.Fatalf("after removal: %q, %v", got, err)
	}
	if err := f.SetPosterSource(testID, ""); err != nil {
		t.Fatalf("removing an absent note: %v", err)
	}
	if err := f.SetPosterSource("bad", slug); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
}

// A note that does not hold a slug is reported, never read as "no entry",
// so a card withholds the poster rather than shows it.
func TestAGarbledPosterSourceIsAnError(t *testing.T) {
	f := openTest(t)
	if err := f.SetPosterSource(testID, "6f1c3b0e-2d4a-4b8e-9c3f-0a1b2c3d4e5f"); err != nil {
		t.Fatal(err)
	}
	dir, err := f.ShareDir(testID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, posterSourceFileName), []byte("not a slug"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.PosterSource(testID); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("garbled note: %v, want ErrBadRequest", err)
	}
}

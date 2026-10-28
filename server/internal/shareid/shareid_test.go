package shareid

import (
	"strings"
	"testing"
)

func TestValidIDAcceptsOnlyTenBase58Characters(t *testing.T) {
	for _, ok := range []string{"abcdefghjk", "1234567891", NewID()} {
		if !ValidID(ok) {
			t.Errorf("ValidID(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "short", "abcdefghjkl", "abcdefghj0", "abcdefghjO", "abcdefghjI", "abcd/fghjk", "abcd.fghjk"} {
		if ValidID(bad) {
			t.Errorf("ValidID(%q) = true, want false", bad)
		}
	}
}

func TestNewIDIsFreshEachCall(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if len(id) != 10 || seen[id] {
			t.Fatalf("NewID produced %q (len %d, seen %v)", id, len(id), seen[id])
		}
		seen[id] = true
	}
}

func TestValidRelPathRejectsEscapesAndUncleanForms(t *testing.T) {
	for _, ok := range []string{"a.txt", "dir/a.txt", "dir/sub/a", "café.txt"} {
		if !ValidRelPath(ok) {
			t.Errorf("ValidRelPath(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "../a", "/a", "a/../b", "a//b", "a/", "./a", "a\\b", "a\x00b"} {
		if ValidRelPath(bad) {
			t.Errorf("ValidRelPath(%q) = true, want false", bad)
		}
	}
}

// A segment longer than NAME_MAX can never be renamed into files/, so it is
// refused where every route validates, before any byte is staged; a long
// path of short segments is fine up to MaxRelPathBytes.
func TestValidRelPathBoundsNameAndPathLength(t *testing.T) {
	name := strings.Repeat("a", MaxNameBytes)
	deep := strings.TrimSuffix(strings.Repeat("abcdefg/", MaxRelPathBytes/8), "/")
	for _, ok := range []string{name, "dir/" + name, deep, strings.Repeat("é", MaxNameBytes/2)} {
		if !ValidRelPath(ok) {
			t.Errorf("ValidRelPath(len %d) = false, want true", len(ok))
		}
	}
	for _, bad := range []string{name + "a", "dir/" + name + "a/b", deep + "/x", strings.Repeat("é", MaxNameBytes/2+1)} {
		if ValidRelPath(bad) {
			t.Errorf("ValidRelPath(len %d) = true, want false", len(bad))
		}
	}
}

func TestNewSlugIsAUUIDv4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		s := NewSlug()
		if len(s) != 36 || seen[s] {
			t.Fatalf("NewSlug produced %q (len %d, seen %v)", s, len(s), seen[s])
		}
		seen[s] = true
		if s[14] != '4' {
			t.Fatalf("version nibble of %q", s)
		}
		if !strings.ContainsRune("89ab", rune(s[19])) {
			t.Fatalf("variant nibble of %q", s)
		}
		if !ValidSlug(s) {
			t.Fatalf("ValidSlug(%q) = false", s)
		}
	}
	for _, bad := range []string{"", "..", "a/b", "0F2B7C1E-4D5A-4B6C-8D7E-9F0A1B2C3D4E",
		"0f2b7c1e4d5a4b6c8d7e9f0a1b2c3d4e0000", NewSlug()[:35]} {
		if ValidSlug(bad) {
			t.Errorf("ValidSlug(%q) = true", bad)
		}
	}
}

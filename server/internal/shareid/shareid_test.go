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

func TestNewPublishIDIsValid(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewPublishID()
		if len(id) != PublishIDLen || !ValidPublishID(id) {
			t.Fatalf("NewPublishID() = %q, not a valid publish id", id)
		}
		if seen[id] {
			t.Fatalf("duplicate publish id %q", id)
		}
		seen[id] = true
	}
}

func TestValidPublishIDRefuses(t *testing.T) {
	for _, s := range []string{
		"",
		NewID(),
		NewSlug(),
		RandomBase58(PublishIDLen - 1),
		RandomBase58(PublishIDLen + 1),
		"/",
		".",
		"..",
		"%2F",
		RandomBase58(PublishIDLen-1) + "/",
		RandomBase58(PublishIDLen-2) + "..",
		"0" + RandomBase58(PublishIDLen-1),
	} {
		if ValidPublishID(s) {
			t.Errorf("ValidPublishID(%q) = true", s)
		}
	}
}

func TestNewFileKeyIsValid(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		k := NewFileKey()
		if len(k) != 22 || FileKeyLen != 22 {
			t.Fatalf("key %q has length %d", k, len(k))
		}
		if !ValidFileKey(k) {
			t.Fatalf("NewFileKey minted %q, which ValidFileKey refuses", k)
		}
		if seen[k] {
			t.Fatalf("duplicate key %q", k)
		}
		seen[k] = true
	}
}

func TestValidFileKeyRefuses(t *testing.T) {
	a21 := strings.Repeat("A", 21)
	if !ValidFileKey(a21 + "A") {
		t.Fatal("a 22-character base58 key is refused")
	}
	for name, k := range map[string]string{
		"empty":      "",
		"a share id": NewID(),
		"a slug":     NewSlug(),
		"21 chars":   a21,
		"23 chars":   a21 + "AA",
		"zero":       a21 + "0",
		"capital O":  a21 + "O",
		"capital I":  a21 + "I",
		"lower l":    a21 + "l",
		"slash":      a21 + "/",
		"dot":        a21 + ".",
		"percent":    strings.Repeat("A", 19) + "%2F",
		"multibyte":  strings.Repeat("A", 20) + "é",
		"NUL":        a21 + "\x00",
	} {
		if ValidFileKey(k) {
			t.Errorf("%s: %q accepted", name, k)
		}
	}
}

func TestValidNewRelPathCapsTheDepth(t *testing.T) {
	deep := func(n int) string { return strings.TrimSuffix(strings.Repeat("d/", n), "/") }
	if !ValidNewRelPath(deep(MaxRelPathDepth)) {
		t.Errorf("%d segments refused, want accepted", MaxRelPathDepth)
	}
	if ValidNewRelPath(deep(MaxRelPathDepth + 1)) {
		t.Errorf("%d segments accepted, want refused", MaxRelPathDepth+1)
	}
	if !ValidRelPath(deep(MaxRelPathDepth + 1)) {
		t.Errorf("ValidRelPath of %d segments refused: reads and deletes must still reach it", MaxRelPathDepth+1)
	}
	if ValidNewRelPath("../x") || ValidNewRelPath("") {
		t.Error("ValidNewRelPath accepted an unclean path")
	}
}

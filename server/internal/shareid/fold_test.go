package shareid

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The key is broad: every pair some folding volume merges shares it, the
// full folds APFS and casefold ext4 make and the upcase pairs exFAT makes.
func TestFoldPathKeysEveryPairAFoldingVolumeMerges(t *testing.T) {
	same := [][2]string{
		{"report.pdf", "Report.PDF"},
		{"Docs/A.txt", "docs/a.txt"},
		{"ÉTÉ.txt", "été.txt"},
		{"été.txt", "ÉTÉ.txt"}, // decomposed against composed
		{"ΣΟΦΟΣ", "σοφος"},
		{"ς", "σ"},
		{"straße", "STRASSE"}, // APFS, ext4: full folding
		{"ß", "ẞ"},
		{"ﬁle", "file"},
		{"İ", "i̇"},
		{"ı", "i"}, // exFAT: ı upcases to I
		{"ǅ", "ǆ"},
		{"K", "k"}, // Kelvin sign
		{"ſ", "s"},
	}
	for _, p := range same {
		if FoldPath(p[0]) != FoldPath(p[1]) {
			t.Errorf("FoldPath(%q) = %q, FoldPath(%q) = %q", p[0], FoldPath(p[0]), p[1], FoldPath(p[1]))
		}
	}
	for _, p := range [][2]string{{"a.txt", "b.txt"}, {"docs/a", "docs a"}, {"e.txt", "é.txt"}, {"İ", "i"}} {
		if FoldPath(p[0]) == FoldPath(p[1]) {
			t.Errorf("FoldPath(%q) = FoldPath(%q)", p[0], p[1])
		}
	}
}

// A key keeps its path's segments: only "/" keys to a "/", and no rune keys
// to nothing, so a key's first n segments are the key of the path's first n
// segments, which is how the store reads a folder's spelling off a row
// beneath it.
func TestAKeyKeepsItsPathsSegments(t *testing.T) {
	foldOnce.Do(buildFold)
	for r, k := range foldKeys {
		if strings.Contains(k, "/") || k == "" || !utf8.ValidString(k) {
			t.Fatalf("%q keys to %q", r, k)
		}
	}
}

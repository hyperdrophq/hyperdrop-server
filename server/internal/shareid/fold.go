package shareid

import (
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// FoldPath is the key under which a data volume that matches names
// case-insensitively may take two relpaths for one file. Volumes do not fold
// alike: APFS and a casefold ext4 directory fold fully (straße is strasse,
// ﬁ is fi), exFAT compares through a one-to-one upcase table (ı is I), and
// each keeps apart pairs another merges. The key is therefore BROAD, a
// superset of what any of them merges: each rune of the NFC spelling is
// upper-cased (unicode.ToUpper, which catches exFAT's upcase pairs) and then
// fully case-folded (golang.org/x/text/cases.Fold, CaseFolding.txt's C and F
// mappings), and the keys are concatenated. Two names with different keys
// are two files on every such volume. Two names with one key may still be
// two files on a given volume, so the key only finds candidates: what writes
// a path under another name's spelling asks the volume itself first
// (sharefs.FS.SameName), and only a decision where holding names apart costs
// nothing but a number or a shared lock (an inbox's numbering, the path
// locks) uses the key alone.
func FoldPath(rel string) string {
	rel = norm.NFC.String(rel)
	var b strings.Builder
	b.Grow(len(rel))
	for _, r := range rel {
		b.WriteString(runeKey(r))
	}
	return b.String()
}

// PrepareFold builds the rune table FoldPath reads (about 80 ms), so a
// server pays it at startup rather than in the first write or request that
// folds a name outside ASCII, which may hold a lock.
func PrepareFold() { foldOnce.Do(buildFold) }

var (
	foldOnce sync.Once
	// foldKeys is every rune whose key is not the rune itself.
	foldKeys map[rune]string
)

func buildFold() {
	foldKeys = map[rune]string{}
	c := cases.Fold()
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		k := norm.NFC.String(c.String(string(unicode.ToUpper(r))))
		if k == string(r) || !utf8.ValidString(k) {
			continue
		}
		foldKeys[r] = k
	}
}

// runeKey is one rune's part of FoldPath.
func runeKey(r rune) string {
	if r < utf8.RuneSelf {
		if 'A' <= r && r <= 'Z' {
			r += 'a' - 'A'
		}
		return string(r)
	}
	foldOnce.Do(buildFold)
	if k, ok := foldKeys[r]; ok {
		return k
	}
	return string(r)
}

// Package uniquename is the one collision scheme HyperDrop numbers a taken
// name with, everywhere: a share's uploads and media plan
// (judge.UniqueName), a Receive Inbox's anonymous uploads (the server's
// auto-rename), an inbox's local copies (core/inboxsync) and the Files
// app's tree on the iPhone (a Swift mirror). It answers "name 2.ext", then
// "name 3.ext": the number goes before the last extension of the last path
// segment, so a renamed file keeps the type its opener needs.
//
// The package is pure (strings and strconv, no I/O), so the server may
// import it (server/pureimports_test.go). What counts as taken is the
// caller's: NFC spellings, case folding and the disk are its to decide.
package uniquename

import (
	"strconv"
	"strings"
)

// Numbered is name with " n" before the last segment's extension:
// "d/IMG 2.HEIC", "a.tar 2.gz". A segment that is all extension or has none
// numbers after itself (".env 2", "README 2"); the extension is Go's
// path.Ext of the segment, so a dot in a folder is no extension of the file.
func Numbered(name string, n int) string {
	dir, base := "", name
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		dir, base = name[:i+1], name[i+1:]
	}
	stem, ext := base, ""
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		stem, ext = base[:i], base[i:]
	}
	return dir + stem + " " + strconv.Itoa(n) + ext
}

// First is the first of name, Numbered(name, 2), Numbered(name, 3)… that
// taken does not hold. There is no try limit: a caller whose taken answers
// from a finite set always gets a name; one that asks the disk bounds its
// own tries with Numbered.
func First(name string, taken func(string) bool) string {
	c := name
	for n := 2; taken(c); n++ {
		c = Numbered(name, n)
	}
	return c
}

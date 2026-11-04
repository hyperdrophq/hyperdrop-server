// Package shareid holds the identifier rules shared by the metadata database
// and the file layer: a share id is also a directory name, and a relpath is
// also a file name, so both are validated before they reach either.
package shareid

import (
	"crypto/rand"
	"encoding/hex"
	"path"
	"path/filepath"
	"strings"
)

// alphabet is base58: no 0, O, I or l, so an id survives being read aloud.
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// IDLen is the length of every share id.
const IDLen = 10

// NewID mints a random share id.
func NewID() string { return RandomBase58(IDLen) }

// RandomBase58 returns n random characters of the base58 alphabet share ids
// use.
func RandomBase58(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// ValidID accepts only what NewID mints. A caller-supplied id becomes a
// directory name, so anything looser is a path traversal waiting to happen.
func ValidID(id string) bool {
	if len(id) != IDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !strings.ContainsRune(alphabet, rune(id[i])) {
			return false
		}
	}
	return true
}

// PublishIDLen is the length of every publish id.
const PublishIDLen = 22

// NewPublishID mints a random publish id: the name of one publish's staging
// directory under its share.
func NewPublishID() string { return RandomBase58(PublishIDLen) }

// ValidPublishID accepts only what NewPublishID mints. A caller-supplied
// publish id becomes a directory name, so anything looser is a path
// traversal waiting to happen.
func ValidPublishID(id string) bool {
	if len(id) != PublishIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !strings.ContainsRune(alphabet, rune(id[i])) {
			return false
		}
	}
	return true
}

// FileKeyLen is the length of every file key: about 129 bits, and a length no
// share id (IDLen) or slug (36) shares.
const FileKeyLen = 22

// NewFileKey mints the random key of one file's direct link.
func NewFileKey() string { return RandomBase58(FileKeyLen) }

// ValidFileKey accepts only what NewFileKey mints. A key arrives from a URL
// path, so it is checked before any query that takes one.
func ValidFileKey(k string) bool {
	if len(k) != FileKeyLen {
		return false
	}
	for i := 0; i < len(k); i++ {
		if !strings.ContainsRune(alphabet, rune(k[i])) {
			return false
		}
	}
	return true
}

// NewSlug mints a UUIDv4, the public token of one file.
func NewSlug() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ValidSlug accepts only the UUIDv4 shape NewSlug mints: 36 characters of
// lowercase hex and hyphens as 8-4-4-4-12. A slug reaches the file layer
// from a URL path and becomes a FILENAME, so the check is the same kind of
// boundary ValidID is.
func ValidSlug(slug string) bool {
	if len(slug) != 36 {
		return false
	}
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", rune(c)) {
			return false
		}
	}
	return true
}

// MaxNameBytes bounds one segment of a relpath: NAME_MAX on every
// filesystem a server stores on, so a longer name could never be renamed
// into files/ and is refused before a byte of it is staged.
const MaxNameBytes = 255

// MaxRelPathBytes bounds a whole relpath: PATH_MAX on Linux, the longest
// path a client's own filesystem can name.
const MaxRelPathBytes = 4096

// ValidRelPath accepts clean, local, slash-separated relative paths only,
// within MaxRelPathBytes and with no segment over MaxNameBytes.
// "." is rejected explicitly: filepath.IsLocal(".") is true.
func ValidRelPath(p string) bool {
	if p == "" || p == "." || len(p) > MaxRelPathBytes || strings.ContainsAny(p, "\x00") || strings.Contains(p, "\\") {
		return false
	}
	if !filepath.IsLocal(p) || path.Clean(p) != p {
		return false
	}
	for seg := range strings.SplitSeq(p, "/") {
		if len(seg) > MaxNameBytes {
			return false
		}
	}
	return true
}

// MaxRelPathDepth bounds the segments of a path a request CREATES: far
// deeper than any real tree, shallow enough that a share cannot be made of a
// directory chain whose every walk costs a syscall per level.
const MaxRelPathDepth = 128

// ValidNewRelPath is ValidRelPath for a path about to be created (an upload,
// a folder, a move's destination): it also holds at most MaxRelPathDepth
// segments. Reads, listings, deletes and a move's source keep ValidRelPath,
// so a file stored deeper stays reachable.
func ValidNewRelPath(p string) bool {
	return ValidRelPath(p) && strings.Count(p, "/") < MaxRelPathDepth
}

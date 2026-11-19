// Package commonpw holds the most common passwords of 8 to 72 bytes, which the
// server refuses when a person chooses one. The list is gen.sh's output from
// the SecLists file SOURCE names. It lives in its own package so that the copy
// of metadb that freeze.sh makes needs only Go files.
package commonpw

import (
	_ "embed"
	"slices"
	"strings"
	"sync"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

//go:embed commonpw.txt
var listText string

// maxInput is the longest input Common folds; a password beyond it is already
// refused by the length rules.
const maxInput = 1024

// list is the embedded file split into its lines, sorted in byte order.
var list = sync.OnceValue(func() []string {
	return strings.Split(strings.TrimSuffix(listText, "\n"), "\n")
})

// Common reports whether pw, NFC-normalised and case-folded, is in the list.
// Whitespace is not trimmed: " password1" is another password.
func Common(pw string) bool {
	if len(pw) > maxInput {
		return false
	}
	key := cases.Fold().String(norm.NFC.String(pw))
	_, found := slices.BinarySearch(list(), key)
	return found
}

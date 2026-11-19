// Package sharenamerule is the one rule for what a share name may be. It is
// pure (no I/O, no clock, no platform), so the server applies the same rule
// every client applies before it sends a name (TestServerImportsOnlyPureCore
// in server/ keeps it that way); core/sharename, which also names a share from
// a selection and walks paths to do it, answers through it.
package sharenamerule

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxLen caps a share name. The name becomes a title on the public /share
// page and the name of a zip or text file, so it is bounded rather than free.
// The app's Swift port (ShareName.maxLen) carries the same number: a name one
// accepts must never be one another refuses.
const MaxLen = 120

// Clean trims a name and reports why it cannot be used, or returns the
// trimmed form. Callers store what this returns, never the raw input.
func Clean(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fmt.Errorf("a share name cannot be empty")
	}
	if utf8.RuneCountInString(trimmed) > MaxLen {
		return "", fmt.Errorf("a share name is at most %d characters", MaxLen)
	}
	if strings.ContainsRune(trimmed, '/') {
		return "", fmt.Errorf("a share name cannot contain /")
	}
	for _, r := range trimmed {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("a share name cannot contain control characters")
		}
	}
	return trimmed, nil
}

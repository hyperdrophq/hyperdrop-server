package sharenamerule

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A share name is typed, pasted or sent by a client. A name Clean accepts is
// trimmed, at most MaxLen characters, holds no slash and no control
// character, and is accepted again unchanged.
func FuzzClean(f *testing.F) {
	for _, s := range []string{"Holiday photos", "  padded  ", "a/b", "tab\there", "\x7f", "", "   ", strings.Repeat("é", MaxLen), strings.Repeat("é", MaxLen+1), " name ", "\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		out, err := Clean(name)
		if err != nil {
			if out != "" {
				t.Fatalf("Clean(%q) refuses and answers %q", name, out)
			}
			return
		}
		if out == "" || out != strings.TrimSpace(out) || utf8.RuneCountInString(out) > MaxLen || strings.Contains(out, "/") {
			t.Fatalf("Clean(%q) = %q", name, out)
		}
		for _, r := range out {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("Clean(%q) = %q, which holds a control character", name, out)
			}
		}
		if again, err := Clean(out); err != nil || again != out {
			t.Fatalf("Clean(%q) = %q, cleaned again %q, %v", name, out, again, err)
		}
	})
}

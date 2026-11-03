package sharenamerule

import (
	"strings"
	"testing"
)

func TestCleanAcceptsAnOrdinaryName(t *testing.T) {
	got, err := Clean("  Q3 Financials  ")
	if err != nil || got != "Q3 Financials" {
		t.Errorf("Clean = %q, %v; want %q, nil", got, err, "Q3 Financials")
	}
}

func TestCleanRefusesWhatWouldBreakAMountFolderOrAPage(t *testing.T) {
	for _, bad := range []string{
		"",                            // nothing
		"   ",                         // nothing after trimming
		"a/b",                         // a mount folder name cannot hold a separator
		"a\nb",                        // control character
		"a\tb",                        // control character
		"a\x7fb",                      // DEL
		strings.Repeat("x", MaxLen+1), // over the cap
	} {
		if _, err := Clean(bad); err == nil {
			t.Errorf("Clean(%q) = nil error, want a refusal", bad)
		}
	}
}

// The app's Swift port, ShareName.maxLen, carries the same number. A name the
// panel accepts must never be one the server refuses.
func TestTheLengthCapIsTheOneTheAppUses(t *testing.T) {
	if MaxLen != 120 {
		t.Errorf("MaxLen = %d, want 120 (ShareName.maxLen)", MaxLen)
	}
	if got, err := Clean(strings.Repeat("é", MaxLen)); err != nil || got == "" {
		t.Errorf("a name of exactly MaxLen runes was refused: %v", err)
	}
}

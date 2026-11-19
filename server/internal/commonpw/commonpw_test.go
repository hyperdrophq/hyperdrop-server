package commonpw

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTheListIsWellFormed(t *testing.T) {
	if len(listText) > 131072 {
		t.Fatalf("the list is %d bytes, over 131072", len(listText))
	}
	lines := strings.Split(strings.TrimSuffix(listText, "\n"), "\n")
	if len(lines) != 10000 {
		t.Fatalf("the list has %d lines, want 10000", len(lines))
	}
	shape := regexp.MustCompile(`^[ -~]{8,72}$`)
	for i, l := range lines {
		if !shape.MatchString(l) {
			t.Fatalf("line %d %q is not 8 to 72 printable ASCII bytes", i+1, l)
		}
		if strings.ContainsAny(l, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Fatalf("line %d %q holds an upper-case letter", i+1, l)
		}
		if i > 0 && lines[i-1] >= l {
			t.Fatalf("line %d %q does not sort after %q", i+1, l, lines[i-1])
		}
	}
}

func TestTheListMatchesItsGenerator(t *testing.T) {
	src := os.Getenv("HYPERDROP_COMMONPW_SOURCE")
	if src == "" {
		t.Skip("HYPERDROP_COMMONPW_SOURCE names no SecLists file")
	}
	out := filepath.Join(t.TempDir(), "commonpw.txt")
	if b, err := exec.Command("sh", "gen.sh", src, out).CombinedOutput(); err != nil {
		t.Fatalf("gen.sh: %v\n%s", err, b)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != listText {
		t.Fatal("commonpw.txt differs from what gen.sh writes from the source")
	}
}

func TestCommonFoldsCaseAndNFC(t *testing.T) {
	// blink182 with U+212A KELVIN SIGN for its k, and "password" with U+017F LONG S.
	for _, pw := range []string{"password", "PASSWORD", "Password", "12345678", "paſſword", "blinK182"} {
		if !Common(pw) {
			t.Errorf("Common(%q) = false, want true", pw)
		}
	}
	for _, pw := range []string{" password", "password ", "correct horse battery staple"} {
		if Common(pw) {
			t.Errorf("Common(%q) = true, want false", pw)
		}
	}
}

func TestCommonIsFalseForShortAndOverlongInput(t *testing.T) {
	for _, pw := range []string{"", "1234567", strings.Repeat("a", 73)} {
		if Common(pw) {
			t.Errorf("Common(%q) = true, want false", pw)
		}
	}
}

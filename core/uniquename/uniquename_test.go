package uniquename

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// The one collision scheme: "name 2.ext", then 3, the number before the last
// extension of the last segment.
func TestNumbered(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		want string
	}{
		{"a.jpg", 2, "a 2.jpg"},
		{"a.jpg", 3, "a 3.jpg"},
		{"README", 2, "README 2"},
		// A segment that is all extension numbers after itself.
		{".env", 2, ".env 2"},
		{".env.local", 2, ".env 2.local"},
		// Only the last extension.
		{"a.tar.gz", 2, "a.tar 2.gz"},
		{"a.", 2, "a 2."},
		{"d/IMG_0001.HEIC", 2, "d/IMG_0001 2.HEIC"},
		// A dot in a folder is no extension of the file.
		{"d.v2/notes", 2, "d.v2/notes 2"},
		{"café.jpg", 2, "café 2.jpg"},
	} {
		if got := Numbered(tc.name, tc.n); got != tc.want {
			t.Errorf("Numbered(%q, %d) = %q, want %q", tc.name, tc.n, got, tc.want)
		}
	}
}

func TestFirstAnswersTheFirstFreeName(t *testing.T) {
	taken := map[string]bool{"a.jpg": true, "a 2.jpg": true, "b.jpg": false}
	has := func(c string) bool { return taken[c] }
	for name, want := range map[string]string{"a.jpg": "a 3.jpg", "b.jpg": "b.jpg", "c": "c"} {
		if got := First(name, has); got != want {
			t.Errorf("First(%q) = %q, want %q", name, got, want)
		}
	}
	// The predicate is the caller's: a case-folding one numbers a case twin.
	folded := func(c string) bool { return strings.EqualFold(c, "A.JPG") }
	if got := First("a.jpg", folded); got != "a 2.jpg" {
		t.Errorf("folded: %q", got)
	}
}

// The server imports this package (the Receive Inbox's rename), so it is
// pure: standard packages the server's pure list holds, and nothing else.
func TestImportsOnlyPureStd(t *testing.T) {
	out, err := exec.Command("go", "list", "-json", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	var p struct{ Imports []string }
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatal(err)
	}
	for _, imp := range p.Imports {
		if imp != "strconv" && imp != "strings" {
			t.Errorf("core/uniquename imports %s", imp)
		}
	}
}

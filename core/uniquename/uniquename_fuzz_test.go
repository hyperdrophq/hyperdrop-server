package uniquename

import (
	"strconv"
	"strings"
	"testing"
)

// A taken name is a file name someone uploaded. Its numbered form stays in
// the same folder, keeps the last segment's extension, differs from the name
// and from every other number's form, and First answers a name that is free.
func FuzzNumbered(f *testing.F) {
	f.Add("d/IMG.HEIC", 2, 3)
	f.Add("a.tar.gz", 2, 10)
	f.Add(".env", 3, 2)
	f.Add("README", 2, 2)
	f.Add("dir.d/file", 7, 4)
	f.Add("a/", 2, 1)
	f.Add("", 0, 0)
	f.Fuzz(func(t *testing.T, name string, n, taken int) {
		got := Numbered(name, n)
		dir := name[:strings.LastIndexByte(name, '/')+1]
		base := name[len(dir):]
		if !strings.HasPrefix(got, dir) || strings.Contains(got[len(dir):], "/") {
			t.Fatalf("Numbered(%q, %d) = %q leaves its folder", name, n, got)
		}
		if got == name || !strings.Contains(got[len(dir):], " "+strconv.Itoa(n)) {
			t.Fatalf("Numbered(%q, %d) = %q", name, n, got)
		}
		if i := strings.LastIndexByte(base, '.'); i > 0 && !strings.HasSuffix(got, base[i:]) {
			t.Fatalf("Numbered(%q, %d) = %q loses the extension %q", name, n, got, base[i:])
		}
		if n != n+1 && Numbered(name, n+1) == got {
			t.Fatalf("Numbered(%q) answers %q for %d and %d", name, got, n, n+1)
		}
		taken = min(max(taken, 0), 64)
		set := map[string]bool{name: taken > 0}
		for i := 2; i <= taken; i++ {
			set[Numbered(name, i)] = true
		}
		first := First(name, func(s string) bool { return set[s] })
		if set[first] {
			t.Fatalf("First(%q) = %q, which is taken", name, first)
		}
		if want := name; taken > 0 {
			want = Numbered(name, max(taken, 1)+1)
			if first != want {
				t.Fatalf("First(%q) with %d taken = %q, want %q", name, taken, first, want)
			}
		} else if first != want {
			t.Fatalf("First(%q) with none taken = %q", name, first)
		}
	})
}

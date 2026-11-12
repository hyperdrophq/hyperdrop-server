package api

import (
	"strings"
	"testing"
	"unicode/utf8"

	"hyperdrop/server/internal/shareid"
)

// heldBy answers claim's question from a predicate on one path.
func heldBy(pred func(string) bool) func([]string) map[string]bool {
	return func(candidates []string) map[string]bool {
		taken := map[string]bool{}
		for _, c := range candidates {
			taken[c] = pred(c)
		}
		return taken
	}
}

func TestClaimRenamesCollisionsAndReleases(t *testing.T) {
	c := newInboxClaims()
	taken := heldBy(func(p string) bool { return p == "a.jpg" })
	first, _ := c.claim("share1", "alice", "a.jpg", taken, 10, "sender-one")
	if first.Name != "a 2.jpg" {
		t.Fatalf("first claim = %q, want a 2.jpg", first.Name)
	}
	second, _ := c.claim("share1", "alice", "a.jpg", taken, 20, "sender-two")
	if second.Name != "a 3.jpg" {
		t.Fatalf("second claim = %q, want a 3.jpg", second.Name)
	}
	in := c.incoming("share1")
	if len(in) != 2 || in[0].Name != "a 2.jpg" || in[0].Total != 10 || in[0].By != "sender-one" {
		t.Fatalf("incoming = %+v", in)
	}
	if in[1].Name != "a 3.jpg" || in[1].Total != 20 || in[1].By != "sender-two" {
		t.Fatalf("incoming = %+v", in)
	}
	first.Release()
	again, _ := c.claim("share1", "alice", "a.jpg", taken, 30, "")
	if again.Name != "a 2.jpg" {
		t.Fatalf("claim after release = %q, want a 2.jpg", again.Name)
	}
	// A share nobody is uploading into has no entry at all.
	if in := c.incoming("share2"); len(in) != 0 {
		t.Fatalf("incoming for an idle share = %+v", in)
	}
}

// The rename is the one collision scheme (core/uniquename), the number
// before the extension so a renamed file keeps the type its opener needs.
func TestClaimNumbersBeforeTheExtension(t *testing.T) {
	c := newInboxClaims()
	for _, tc := range []struct{ name, want string }{
		{"photo.jpg", "photo 2.jpg"},
		{"notes", "notes 2"},
		{"archive.tar.gz", "archive.tar 2.gz"},
		{".hidden", ".hidden 2"},
	} {
		up, _ := c.claim("share1", "alice", tc.name, heldBy(func(p string) bool { return p == tc.name }), 1, "")
		up.Release()
		if up.Name != tc.want {
			t.Errorf("claim(%q) over itself = %q, want %q", tc.name, up.Name, tc.want)
		}
	}
}

// A name taken past the walk's bound is refused rather than walked further,
// and the walk reads the rows twice at most, the name alone and then every
// numbered candidate at once: a link flooded with one name costs each later
// upload two reads under the claims' lock, not one per candidate.
func TestClaimGivesUpPastTheNameWalk(t *testing.T) {
	c := newInboxClaims()
	reads, asked := 0, 0
	all := func(candidates []string) map[string]bool {
		reads++
		asked += len(candidates)
		return heldBy(func(string) bool { return true })(candidates)
	}
	if _, ok := c.claim("share1", "alice", "a.jpg", all, 1, ""); ok {
		t.Fatal("a claim with every candidate taken succeeded")
	}
	if reads != 2 || asked != inboxNameWalk {
		t.Fatalf("%d reads asking about %d candidates, want 2 asking about %d", reads, asked, inboxNameWalk)
	}
	if in := c.incoming("share1"); len(in) != 0 {
		t.Fatalf("a refused claim left %+v", in)
	}
}

// A name at the byte limit is still numbered when it collides: its stem is
// cut back on a character boundary to make room for the number, and the
// extension stays.
func TestClaimNumbersANameAtTheByteLimit(t *testing.T) {
	c := newInboxClaims()
	for _, name := range []string{
		strings.Repeat("a", shareid.MaxNameBytes-4) + ".pdf",
		strings.Repeat("é", (shareid.MaxNameBytes-4)/2) + "x.pdf",
		strings.Repeat("b", shareid.MaxNameBytes),
	} {
		up, ok := c.claim("share1", "alice", name, heldBy(func(p string) bool { return p == name }), 1, "")
		if !ok {
			t.Fatalf("claim over a %d-byte name refused", len(name))
		}
		up.Release()
		got := up.Name
		if !shareid.ValidRelPath(got) || !utf8.ValidString(got) || !strings.Contains(got, " 2") ||
			strings.HasSuffix(name, ".pdf") != strings.HasSuffix(got, " 2.pdf") {
			t.Errorf("claim over a %d-byte name = %q (%d bytes)", len(name), got, len(got))
		}
	}
	if got := numberedName("c."+strings.Repeat("x", shareid.MaxNameBytes-2), 2); got != "" {
		t.Errorf("a name whose extension leaves no room = %q, want none", got)
	}
}

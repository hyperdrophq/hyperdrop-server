package linked

import "testing"

func TestAllowed(t *testing.T) {
	roots := []Root{{Name: "photo"}, {Name: "public-share"}}
	cases := []struct {
		admin bool
		allow []string
		rel   string
		want  bool
		why   string
	}{
		{true, nil, "photo/2024", true, "admin sees every root"},
		{true, nil, "homes/x", false, "even an admin needs a listed root"},
		{false, nil, "photo", false, "a user with no allowlist shares nothing"},
		{false, []string{"photo"}, "photo", true, "the root itself"},
		{false, []string{"photo"}, "photo/2024/trip", true, "below the root"},
		{false, []string{"photo/2024"}, "photo/2023", false, "a sibling of the allowed sub-path"},
		{false, []string{"photo/2024"}, "photo/20245", false, "prefix is not containment"},
		{false, []string{"homes"}, "homes/x", false, "an allow entry whose root is not listed"},
	}
	for _, c := range cases {
		if got := Allowed(c.admin, c.allow, roots, c.rel); got != c.want {
			t.Errorf("%s: Allowed=%v", c.why, got)
		}
	}
}

func TestVisibleRoots(t *testing.T) {
	roots := []Root{{Name: "photo"}, {Name: "public-share"}}
	if got := VisibleRoots(true, nil, roots); len(got) != 2 || got[0] != "photo" {
		t.Fatalf("admin: %v", got)
	}
	got := VisibleRoots(false, []string{"photo/2024", "homes", "public-share"}, roots)
	if len(got) != 2 || got[0] != "photo/2024" || got[1] != "public-share" {
		t.Fatalf("user: %v", got)
	}
}

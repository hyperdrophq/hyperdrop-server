package signinannounce

import "testing"

func TestLabelOfStripsTheServersPrefixOnce(t *testing.T) {
	for in, want := range map[string]string{
		"Phone sign-in: Studio iMac":        "Studio iMac",
		"Phone sign-in: Phone sign-in: odd": "Phone sign-in: odd",
		"Studio iMac":                       "Studio iMac",
		"Phone sign-in: ":                   "",
	} {
		if got := LabelOf(in); got != want {
			t.Errorf("LabelOf(%q) = %q, want %q", in, got, want)
		}
	}
}

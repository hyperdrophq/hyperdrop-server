package compatwindow

import (
	"strconv"
	"testing"
)

// A version arrives in a header or a manifest. An unreadable one is no
// verdict; between two sides at or above OldestServer the verdict mirrors
// when the sides swap; a patch never changes it; and Reach names exactly the
// minors Compatible accepts.
func FuzzCompatible(f *testing.F) {
	f.Add("1.8.1", "1.6.0")
	f.Add("1.5", "1.7")
	f.Add("1.6", "1.4")
	f.Add("2.0", "1.9")
	f.Add("0.9", "1.0")
	f.Add("1.1048576", "1.1048577")
	f.Add(" 1.8 ", "1.-1")
	f.Add("1", "x.y")
	f.Add("9223372036854775807.1", "1.9223372036854775807")
	f.Fuzz(func(t *testing.T, client, server string) {
		v := Compatible(client, server)
		cMaj, cMin, cok := majorMinor(client)
		sMaj, sMin, sok := majorMinor(server)
		if (v == Unknown) != (!cok || !sok) {
			t.Fatalf("Compatible(%q, %q) = %s, readable %v and %v", client, server, v, cok, sok)
		}
		if w := WidthOf(client); w != LegacyWindowMinors && w != WindowMinors {
			t.Fatalf("WidthOf(%q) = %d", client, w)
		}
		if !cok || !sok {
			if _, _, _, ok := Reach(client); ok && !cok {
				t.Fatalf("Reach(%q) answers for a version that does not read", client)
			}
			return
		}
		cv := strconv.Itoa(cMaj) + "." + strconv.Itoa(cMin)
		sv := strconv.Itoa(sMaj) + "." + strconv.Itoa(sMin)
		if got := Compatible(cv+".7", sv+".0"); got != v {
			t.Fatalf("Compatible(%q, %q) = %s, with patches %s", client, server, v, got)
		}
		if atLeast(cMaj, cMin, OldestServer) && atLeast(sMaj, sMin, OldestServer) {
			mirror := map[Verdict]Verdict{OK: OK, ClientOutdated: ServerOutdated, ServerOutdated: ClientOutdated}
			if got := Compatible(server, client); got != mirror[v] {
				t.Fatalf("Compatible(%q, %q) = %s, swapped %s", client, server, v, got)
			}
		}
		major, lowest, highest, ok := Reach(client)
		inReach := ok && sMaj == major && sMin >= lowest && sMin <= highest
		if inReach != (v == OK) {
			t.Fatalf("Compatible(%q, %q) = %s, Reach = %d.%d to %d.%d (%v)", client, server, v, major, lowest, major, highest, ok)
		}
		if ok && (lowest < 0 || lowest > highest || highest-lowest > 2*WindowMinors) {
			t.Fatalf("Reach(%q) = %d to %d", client, lowest, highest)
		}
	})
}

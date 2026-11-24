package compatwindow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fixtureRow struct {
	Client  string  `json:"client"`
	Server  string  `json:"server"`
	Verdict Verdict `json:"verdict"`
}

func readFixture(t *testing.T) []fixtureRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "compatible.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []fixtureRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("the fixture holds no rows")
	}
	return rows
}

// testdata/compatible.json is the rule every reader of it (the server, the
// browser's core, the release scripts, the apps) checks itself against.
func TestCompatibleMatchesTheFixture(t *testing.T) {
	for _, row := range readFixture(t) {
		if got := Compatible(row.Client, row.Server); got != row.Verdict {
			t.Errorf("Compatible(%q, %q) = %q, the fixture says %q", row.Client, row.Server, got, row.Verdict)
		}
	}
}

// Reach is exactly the servers Compatible accepts: every fixture row of a
// readable pair sits inside its client's reach when it is ok, and outside it
// otherwise.
func TestReachIsWhatCompatibleAccepts(t *testing.T) {
	for _, row := range readFixture(t) {
		if row.Verdict == Unknown {
			continue
		}
		major, lowest, highest, ok := Reach(row.Client)
		sMaj, sMin, _ := majorMinor(row.Server)
		inside := ok && sMaj == major && sMin >= lowest && sMin <= highest
		if inside != (row.Verdict == OK) {
			t.Errorf("Reach(%q) = %d.%d..%d.%d (%v), but the fixture says %s for server %s", row.Client, major, lowest, major, highest, ok, row.Verdict, row.Server)
		}
	}
}

func TestReachOfOneSixIsOneFiveToOneEight(t *testing.T) {
	major, lowest, highest, ok := Reach("1.6.0")
	if !ok || major != 1 || lowest != 5 || highest != 8 {
		t.Fatalf("Reach(1.6.0) = %d.%d..%d.%d (%v), want 1.5..1.8", major, lowest, major, highest, ok)
	}
}

func TestReachOfOneEightIsOneSixToOneTen(t *testing.T) {
	major, lowest, highest, ok := Reach("1.8.0")
	if !ok || major != 1 || lowest != 6 || highest != 10 {
		t.Fatalf("Reach(1.8.0) = %d.%d..%d.%d (%v), want 1.6..1.10", major, lowest, major, highest, ok)
	}
}

func TestReachOfAnUnreadableContractIsNone(t *testing.T) {
	if _, _, _, ok := Reach("dev"); ok {
		t.Fatal("an unreadable contract reaches no server")
	}
}

// A build of a contract up to 1.5 reaches one minor either side; from 1.6
// on, two. A version that does not read is given the narrow width.
func TestWidthOf(t *testing.T) {
	for v, want := range map[string]int{
		"1.0.0": 1, "1.4.2": 1, "1.5.0": 1, "1.5.9": 1,
		"1.6.0": 2, "1.7": 2, "1.10.0": 2, "2.0.0": 2, "3.4.1": 2,
		"0.9.0": 1, "x": 1, "": 1, "1.9223372036854775805": 1,
	} {
		if got := WidthOf(v); got != want {
			t.Errorf("WidthOf(%q) = %d, want %d", v, got, want)
		}
	}
}

// The constants agree with themselves: the widened width is the wider one,
// and the contract this client ships carries it.
func TestTheWidthConstantsAgree(t *testing.T) {
	if WindowMinors <= LegacyWindowMinors {
		t.Fatalf("WindowMinors %d is not wider than LegacyWindowMinors %d", WindowMinors, LegacyWindowMinors)
	}
	if WidthOf(WidenedAt) != WindowMinors {
		t.Fatalf("WidthOf(WidenedAt %q) = %d, want %d", WidenedAt, WidthOf(WidenedAt), WindowMinors)
	}
	if WidthOf(Contract) != WindowMinors {
		t.Fatalf("this client's contract %s has width %d, want %d", Contract, WidthOf(Contract), WindowMinors)
	}
}

// A part above MaxVersionNumber does not read: Compatible answers unknown
// and Reach reaches nothing, both at once, so no sum of a minor and a width
// can overflow.
func TestAHugeVersionDoesNotRead(t *testing.T) {
	for _, v := range []string{"1.9223372036854775805", "1.1048577", "1048577.0", "9223372036854775807.6"} {
		if got := Compatible(v, "1.6.0"); got != Unknown {
			t.Errorf("Compatible(%q, 1.6.0) = %q, want unknown", v, got)
		}
		if got := Compatible("1.6.0", v); got != Unknown {
			t.Errorf("Compatible(1.6.0, %q) = %q, want unknown", v, got)
		}
		if _, _, _, ok := Reach(v); ok {
			t.Errorf("Reach(%q) reaches a server", v)
		}
	}
	if _, _, _, ok := Reach("1.1048576"); !ok {
		t.Error("a minor of exactly MaxVersionNumber reads")
	}
}

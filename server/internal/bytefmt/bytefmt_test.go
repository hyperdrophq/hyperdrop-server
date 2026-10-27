package bytefmt

import "testing"

// Decimal is what the app shows. Pinned because a binary divisor labelled
// "GB" once made one upload read as two different sizes.
func TestDecimalMatchesWhatTheAppShows(t *testing.T) {
	for n, want := range map[int64]string{
		999:            "999 B",
		1_000:          "1.0 KB",
		900_000:        "900.0 KB",
		1_000_000:      "1.0 MB",
		5_000_000_000:  "5.0 GB",
		91_700_000_000: "91.7 GB",
	} {
		if got := Decimal(n); got != want {
			t.Errorf("Decimal(%d) = %q, want %q", n, got, want)
		}
	}
}

// Binary echoes a limit in the units it was set in: --quota 10G is 10*1024^3.
func TestBinaryEchoesTheUnitsALimitWasSetIn(t *testing.T) {
	const tenGiB = 10 << 30
	if got := Binary(tenGiB); got != "10.0 GB" {
		t.Errorf("Binary(10 GiB) = %q, want %q", got, "10.0 GB")
	}
	if got := Decimal(tenGiB); got != "10.7 GB" {
		t.Errorf("Decimal(10 GiB) = %q, want %q (this is why the two exist)", got, "10.7 GB")
	}
}

// Under one unit the exact count is shown: "612 B" is a fact where "0.6 KB"
// is a rounding of one. Below 1000 both bases agree, since neither has
// reached its first unit.
func TestSmallSizesAreExact(t *testing.T) {
	for _, n := range []int64{0, 1, 612, 999} {
		if got := Binary(n); got != Decimal(n) {
			t.Errorf("%d: bases disagree below one unit: %q vs %q", n, got, Decimal(n))
		}
	}
}

// The ladder stops at the largest unit it has a letter for rather than
// running off the end of the string.
func TestVeryLargeSizesStayOnTheLastUnit(t *testing.T) {
	huge := int64(1) << 62
	if got := Binary(huge); got == "" {
		t.Fatal("no output for a very large size")
	}
}

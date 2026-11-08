package shareid

import (
	"strings"
	"testing"
)

func TestANewIDIsSixteenCharacters(t *testing.T) {
	for range 100 {
		id := NewID()
		if len(id) != 16 || !ValidID(id) {
			t.Fatalf("NewID = %q", id)
		}
	}
}

// Links already sent carry ten characters and keep working.
func TestAnIDOfEitherLengthIsValid(t *testing.T) {
	for id, want := range map[string]bool{
		"abcdefghjk":             true,
		"abcdefghjkmnpqrs":       true,
		"abcdefghj":              false,
		"abcdefghjkm":            false,
		"abcdefghjkmnpqr":        false,
		"abcdefghjkmnpqrst":      false,
		"abcdefghj0":             false,
		"abcdefghjkmnpqr/":       false,
		"":                       false,
		"../../../../etc/passwd": false,
	} {
		if got := ValidID(id); got != want {
			t.Errorf("ValidID(%q) = %v, want %v", id, got, want)
		}
	}
}

// Every symbol of the alphabet comes up equally often. Taking a random byte
// modulo 58 favours the first 24 symbols by a quarter, which this catches.
func TestRandomBase58HasNoBias(t *testing.T) {
	const samples = 2_000_000
	counts := map[byte]int{}
	for _, c := range []byte(RandomBase58(samples)) {
		counts[c]++
	}
	expected := float64(samples) / float64(len(alphabet))
	for i := range len(alphabet) {
		got := float64(counts[alphabet[i]])
		if got < expected*0.97 || got > expected*1.03 {
			t.Errorf("%q came up %.0f times, want about %.0f", alphabet[i], got, expected)
		}
	}
	if strings.ContainsAny(RandomBase58(1000), "0OIl") {
		t.Error("a symbol outside the alphabet")
	}
}

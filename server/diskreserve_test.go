package main

import (
	"testing"

	"hyperdrop/server/internal/sharefs"
)

// Unset, the reserve is the flat 1 GiB; a set value is a percentage, 0
// turning the reserve off, as documented since 1.0.0.
func TestDiskReserveFromTheEnvironment(t *testing.T) {
	for v, want := range map[string]int{"": sharefs.FlatReserve, "0": 0, "10": 10, "90": 90} {
		if got, err := diskReservePercent(v); err != nil || got != want {
			t.Errorf("%q: %d, %v; want %d", v, got, err, want)
		}
	}
	for _, v := range []string{"-1", "91", "ten", "5%"} {
		if _, err := diskReservePercent(v); err == nil {
			t.Errorf("%q was accepted", v)
		}
	}
}

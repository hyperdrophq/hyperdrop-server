//go:build !(darwin || linux)

package volume

// fsState cannot tell on this system.
func fsState(string) (freeBytes, usedInodes int64, ok bool) { return 0, 0, false }

// syncAll has nothing to ask for on this system; the generator syncs the
// database file itself.
func syncAll() {}

package compatwindow

import (
	"strconv"
	"strings"
)

// Verdict is Compatible's answer, in the client's view of the server.
type Verdict string

const (
	// OK: the two work together.
	OK Verdict = "ok"
	// ClientOutdated: the server is too new for this client (above its
	// reach, or on a newer major).
	ClientOutdated Verdict = "client-outdated"
	// ServerOutdated: the server is too old for this client (below its
	// reach, on an older major, or below OldestServer).
	ServerOutdated Verdict = "server-outdated"
	// Unknown: either version does not read, which is no verdict.
	Unknown Verdict = "unknown"
)

// MaxVersionNumber is the largest major or minor a version may carry and
// still read. Above it the version is unreadable (Unknown, no reach), which
// keeps every minor-plus-width sum far from overflowing.
const MaxVersionNumber = 1048576

// majorMinor reads MAJOR.MINOR from "MAJOR.MINOR[.PATCH]", ignoring
// whatever follows the second dot. ok is false for anything else: a
// negative number, or one above MaxVersionNumber.
func majorMinor(v string) (major, minor int, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(v), ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || ma < 0 || mi < 0 || ma > MaxVersionNumber || mi > MaxVersionNumber {
		return 0, 0, false
	}
	return ma, mi, true
}

// atLeast says whether major.minor is at or above the MAJOR.MINOR floor.
func atLeast(major, minor int, floor string) bool {
	fMaj, fMin, ok := majorMinor(floor)
	if !ok {
		return true
	}
	return major > fMaj || (major == fMaj && minor >= fMin)
}

// WidthOf is how many minors either side of its own a build of contract
// works with: LegacyWindowMinors below WidenedAt, WindowMinors from it on.
// A contract that does not read is given LegacyWindowMinors.
func WidthOf(contract string) int {
	major, minor, ok := majorMinor(contract)
	if !ok || !atLeast(major, minor, WidenedAt) {
		return LegacyWindowMinors
	}
	return WindowMinors
}

// Compatible says whether a client of contract client and a server of
// contract server work together: they share a major, their minors stand at
// most min(WidthOf(client), WidthOf(server)) apart, and the server is not
// below OldestServer. Each side refuses the other by its own width, so the
// narrower one decides. Only MAJOR.MINOR counts; patches never matter.
func Compatible(client, server string) Verdict {
	cMaj, cMin, cok := majorMinor(client)
	sMaj, sMin, sok := majorMinor(server)
	if !cok || !sok {
		return Unknown
	}
	switch {
	case sMaj < cMaj:
		return ServerOutdated
	case sMaj > cMaj:
		return ClientOutdated
	case !atLeast(sMaj, sMin, OldestServer):
		return ServerOutdated
	}
	width := min(WidthOf(client), WidthOf(server))
	switch {
	case sMin < cMin-width:
		return ServerOutdated
	case sMin > cMin+width:
		return ClientOutdated
	}
	return OK
}

// Reach is the servers Compatible accepts for a client of contract client:
// major, and the lowest and highest minor, every minor between them
// included. ok is false when the contract does not read or no server is
// compatible with it.
func Reach(client string) (major, lowest, highest int, ok bool) {
	major, minor, ok := majorMinor(client)
	if !ok {
		return 0, 0, 0, false
	}
	width := WidthOf(client)
	lowest, highest = -1, -1
	for s := max(minor-width, 0); s <= minor+width; s++ {
		if Compatible(client, strconv.Itoa(major)+"."+strconv.Itoa(s)) != OK {
			continue
		}
		if lowest < 0 {
			lowest = s
		}
		highest = s
	}
	if lowest < 0 {
		return 0, 0, 0, false
	}
	return major, lowest, highest, true
}

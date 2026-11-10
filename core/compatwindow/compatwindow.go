// Package compatwindow is the contract, its window and the compatibility
// rule; pure. It serves the code that cannot link core/api: the rule table
// the browser runs (core/judgerules, compiled to WebAssembly), the server's
// check of a client, and anything else that must stay free of network and
// file I/O. It imports the standard library alone.
//
// core/api keeps its own literals (ExpectedServerVersion, OldestServer,
// WindowMinors), which the release scripts and the Swift mirror read from
// its source; TestCompatWindowMatchesThisPackage in core/api pins these to
// them, so a bump moves both. testdata/compatible.json is the rule as
// examples, which every other implementation of it checks itself against.
package compatwindow

// Contract is core/api.ExpectedServerVersion: the server contract this
// client ships.
const Contract = "1.7.4"

// OldestServer is core/api.OldestServer: the lowest server MAJOR.MINOR any
// client accepts.
const OldestServer = "1.0"

// WindowMinors is core/api.WindowMinors: the width of a build of contract
// WidenedAt or newer, the minors either side of its own it works with
// inside its major.
const WindowMinors = 2

// LegacyWindowMinors is the width of a build of a contract below WidenedAt.
// Those builds are released and judge by it, which is why Compatible takes
// the smaller of the two sides' widths.
const LegacyWindowMinors = 1

// WidenedAt is the first contract whose builds have width WindowMinors.
const WidenedAt = "1.6"

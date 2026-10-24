// Package metadb is the server's metadata store.
//
// One SQLite file, <data>/hyperdrop.db, holds shares, files, accounts, tokens,
// second-factor state, scheduled changes, linked-share sources and filters,
// gallery metadata and the change journal. This is the only package that
// contains SQL or imports the driver.
//
// Every exported method is one transaction unless its comment names the
// split (a read before the write it may need, as AssignSlugs and ApplyDue
// make). Writes go through a single connection that takes the write lock at
// BEGIN; reads use a pool and see one snapshot per transaction. A method that changes what a client can
// observe inserts its own row in `changes` and wakes Subscribe channels
// after the commit. Counters (shares.bytes, shares.committed, shares.files,
// owner_stats) are kept by triggers, never by Go code.
//
// The package does no disk I/O beyond the database. Bytes live under the
// share's directory and are the file layer's business; the ordering between
// a row and its file is the caller's contract, chosen so that a crash leaves
// at worst a stray file and never a row naming bytes that are not there: the
// row first on create, the staged part renamed then the row written on
// commit (a crash between leaves a pending row the stalled sweep resolves),
// the rows then the directory on delete (a crash between leaves an orphan
// directory the boot pass removes).
package metadb

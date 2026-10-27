// Package sharefs is the server's file layer: the one package that reads
// and writes the data directory apart from the database file.
//
// It knows paths, staging, renames, thumbnails, posters, incoming
// transfers, free space and the boot orphan pass, and nothing about owners,
// quotas, slugs, expiry or listings: those are rows in the metadata
// database, and the ordering between a row and its file (row first on
// create, rename then row on commit, rows then directory on delete) is the
// caller's contract. Rows are the truth, so a crash between the two steps
// leaves at worst a pending row the stalled sweep resolves or an orphan
// directory the boot pass removes.
//
// Every byte of a share is reached through an os.Root opened on the share's
// directory, so a symlink planted inside a share cannot lead outside it.
// Every id, relpath, slug, hash and owner segment is validated before a
// path is composed from it.
package sharefs

package volume

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"hyperdrop/server/internal/metadb"
)

// verify holds the finished database to what was written, so a volume
// that came out short is never marked complete: every planned share and
// file has its row, every file committed, the counters the triggers keep
// agree with the rows, each account has its token, and the database is
// left in WAL mode at the schema's stamp. It answers the shares and files
// the database holds.
func verify(dir string, want written, accounts int) (shares, files int64, err error) {
	db, err := sql.Open("sqlite", fileURI(filepath.Join(dir, metadb.FileName))+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return 0, 0, err
	}
	defer db.Close()
	var committed, shareFiles, shareCommitted, statShares, statCommitted, users, tokens, stamp int64
	var mode string
	for _, q := range []struct {
		query string
		into  []any
	}{
		{`SELECT count(*) FROM shares`, []any{&shares}},
		{`SELECT count(*), coalesce(sum(pending = 0), 0) FROM files`, []any{&files, &committed}},
		{`SELECT coalesce(sum(files), 0), coalesce(sum(committed), 0) FROM shares`, []any{&shareFiles, &shareCommitted}},
		{`SELECT coalesce(sum(shares), 0), coalesce(sum(committed), 0) FROM owner_stats`, []any{&statShares, &statCommitted}},
		{`SELECT count(*) FROM users`, []any{&users}},
		{`SELECT count(DISTINCT username) FROM tokens`, []any{&tokens}},
		{`PRAGMA journal_mode`, []any{&mode}},
		{`PRAGMA user_version`, []any{&stamp}},
	} {
		if err := db.QueryRow(q.query).Scan(q.into...); err != nil {
			return 0, 0, fmt.Errorf("verify: %s: %w", q.query, err)
		}
	}
	var bad []string
	check := func(what string, got, wanted int64) {
		if got != wanted {
			bad = append(bad, fmt.Sprintf("%s %d, want %d", what, got, wanted))
		}
	}
	check("shares", shares, want.shares)
	check("file rows", files, want.files)
	check("committed file rows", committed, want.files)
	check("share file counters", shareFiles, want.files)
	check("share committed counters", shareCommitted, want.files)
	check("owner share counters", statShares, want.shares)
	check("owner committed counters", statCommitted, want.files)
	check("accounts", users, int64(accounts))
	check("accounts with a token", tokens, int64(accounts))
	check("schema stamp", stamp, metadb.SchemaVersion)
	if !strings.EqualFold(mode, "wal") {
		bad = append(bad, "journal mode "+mode+", want wal")
	}
	if len(bad) > 0 {
		return shares, files, fmt.Errorf("verify: the volume does not hold what was written: %s", strings.Join(bad, "; "))
	}
	return shares, files, nil
}

// Projection is what a volume of Shares shares is expected to cost.
type Projection struct {
	Shares    int
	Files     int64
	DiskBytes int64
	Inodes    int64
	Took      time.Duration
}

// Project extrapolates two generated volumes of one seed to a volume of
// target shares. Disk, inodes and time all grow with the files a volume
// holds far more than with anything else, so each is taken as a straight
// line through the two volumes in their file counts and read at the
// target's file count, which the target's plan (the larger volume's seed and
// epoch) gives exactly. Two volumes
// of one file count scale the larger in proportion instead.
func Project(small, large Manifest, target int) Projection {
	if small.Files > large.Files {
		small, large = large, small
	}
	files, _ := NewPlanAt(target, large.Plan.Seed, large.Plan.Epoch).Totals()
	at := func(s, l int64) int64 {
		if large.Files == small.Files {
			if large.Files == 0 {
				return 0
			}
			return int64(float64(l) * float64(files) / float64(large.Files))
		}
		slope := float64(l-s) / float64(large.Files-small.Files)
		return l + int64(slope*float64(files-large.Files))
	}
	return Projection{
		Shares:    target,
		Files:     files,
		DiskBytes: at(small.DiskBytes, large.DiskBytes),
		Inodes:    at(small.Inodes, large.Inodes),
		Took:      time.Duration(at(int64(small.Took), int64(large.Took))),
	}
}

package metadb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/shareid"
)

// A lookup costs the same statements whatever the share holds beside the
// name: no decoys, sixty or three hundred, and twenty thousand other rows or
// none.
func TestAFoldLookupCostsTheSameWhateverTheShareHolds(t *testing.T) {
	type cost struct{ spell, one, many int64 }
	costs := map[string]cost{}
	for _, v := range []struct {
		decoys, others int
	}{{0, 0}, {60, 0}, {300, 0}, {60, 20000}} {
		db := openTest(t)
		id, victim, attacker := decoyShare(t, db, v.decoys, true)
		if err := db.commit(func(tx *sql.Tx) error {
			for i := range v.others {
				if err := insertPending(tx, id, fmt.Sprintf("Θ other %d.txt", i), 1, time.Now()); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		var candidates []string
		for n := 2; n <= 1000; n++ {
			candidates = append(candidates, numbered(attacker, n))
		}
		var c cost
		start := time.Now()
		before := foldSeeks.Load()
		if got, err := db.Spelling(id, attacker, ""); err != nil || got != victim {
			t.Fatalf("Spelling = %v, %v", got == victim, err)
		}
		c.spell = foldSeeks.Load() - before
		before = foldSeeks.Load()
		if held, err := db.PathsHeld(id, []string{attacker}); err != nil || !held[attacker] {
			t.Fatalf("PathsHeld = %v, %v", held, err)
		}
		c.one = foldSeeks.Load() - before
		before = foldSeeks.Load()
		if held, err := db.PathsHeld(id, candidates); err != nil || held[candidates[0]] {
			t.Fatalf("PathsHeld(numbered) = %v, %v", held[candidates[0]], err)
		}
		c.many = foldSeeks.Load() - before
		label := fmt.Sprintf("decoys=%d others=%d", v.decoys, v.others)
		t.Logf("%s: %+v statements, %v", label, c, time.Since(start))
		costs[label] = c
	}
	want := costs["decoys=0 others=0"]
	for label, c := range costs {
		if c != want {
			t.Fatalf("%s costs %+v, an empty share %+v", label, c, want)
		}
	}
}

// A folder's spelling is read off a row beneath it: one seek whatever the
// folder holds, and on a volume that keeps apart two spellings of one key
// (exFAT's straße and strasse) the lookup steps past the one it keeps
// apart to the one it takes.
func TestAFolderSpellingIsReadOffARowBeneathIt(t *testing.T) {
	db := openTest(t)
	db.SetFoldCase(bySegment(upcaseFold))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	if err := db.commit(func(tx *sql.Tx) error {
		for i := range 20000 {
			if err := insertPending(tx, sh.ID, fmt.Sprintf("straße/%05d.jpg", i), 1, time.Now()); err != nil {
				return err
			}
		}
		return insertPending(tx, sh.ID, "Strasse/b.jpg", 1, time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{
		"STRASSE/c.jpg":       "Strasse/c.jpg",
		"STRAßE/00007.JPG":    "straße/00007.jpg",
		"strasse/sub/new.jpg": "Strasse/sub/new.jpg",
		"STRASSE":             "Strasse",
	} {
		before := foldSeeks.Load()
		got, err := db.Spelling(sh.ID, rel, "")
		if err != nil || got != want {
			t.Errorf("Spelling(%q) = %q, %v, want %q", rel, got, err, want)
		}
		if n := foldSeeks.Load() - before; n > 24 {
			t.Errorf("Spelling(%q) ran %d statements", rel, n)
		}
	}
}

// Past maxSpellings stored spellings of one name the volume keeps apart,
// a lookup fails closed: the owner's write is refused with ErrConflict and
// the inbox is told every candidate is held.
func TestTooManySpellingsOfOneNameFailClosed(t *testing.T) {
	db := openTest(t)
	db.SetFoldCase(bySegment(func(a, b string) bool { return a == b }))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice"})
	spellings := caseSpellings("abcdefg.txt", maxSpellings+2)
	for _, p := range spellings[:maxSpellings+1] {
		if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: p, Size: 1}); err != nil {
			t.Fatal(err)
		}
	}
	last := spellings[maxSpellings+1]
	if _, err := db.Spelling(sh.ID, last, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("Spelling past the bound = %v, want ErrConflict", err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: last, Size: 1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("a commit past the bound = %v, want ErrConflict", err)
	}
	if got, err := db.Spelling(sh.ID, spellings[3], ""); err != nil || got != spellings[3] {
		t.Fatalf("an exact stored spelling = %q, %v", got, err)
	}
}

// caseSpellings answers n spellings of name differing only in the case of
// its letters.
func caseSpellings(name string, n int) []string {
	var out []string
	for mask := 0; len(out) < n; mask++ {
		b := []byte(name)
		for i := range b {
			if mask&(1<<i) != 0 && b[i] >= 'a' && b[i] <= 'z' {
				b[i] -= 'a' - 'A'
			}
		}
		if s := string(b); !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// The key rekeyFolds writes inside SQLite is the key a write gives the row:
// hd_fold_key is shareid.FoldPath byte for byte, on every ASCII character,
// on names outside ASCII and on a path that is not valid UTF-8, and NULL
// stays NULL.
func TestTheSQLFoldKeyIsFoldPath(t *testing.T) {
	db := openTest(t)
	var all []byte
	for c := byte(1); c < 0x80; c++ {
		all = append(all, c)
	}
	cases := append([]string{string(all), "Straße/ÄRGER.txt", "İ/ı/ǅ/ﬁ/Ω/K", "é.txt", "\xc3.txt", "a\xffb"},
		strings.Split(string(all), "")...)
	for _, s := range cases {
		var got []byte
		if err := db.r.QueryRow(`SELECT CAST(hd_fold_key(?) AS BLOB)`, s).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if string(got) != shareid.FoldPath(s) {
			t.Errorf("%q: hd_fold_key %q, FoldPath %q", s, got, shareid.FoldPath(s))
		}
	}
	var null sql.NullString
	if err := db.r.QueryRow(`SELECT hd_fold_key(NULL)`).Scan(&null); err != nil || null.Valid {
		t.Fatalf("hd_fold_key(NULL) = %v, %v", null, err)
	}
}

// A release without fold_key inserts rows with no key and renames rows
// without touching it. The serving open after it recomputes every such
// key, so the lookups find those rows by fold and nothing by a key a row
// no longer has.
func TestTheServingOpenRekeysRowsAReleaseWithoutTheColumnWrote(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice",
		Files: []PendingFile{{Path: "Docs/Report.pdf", Size: 1}, {Path: "Ärger/Brief.txt", Size: 1}}})
	if _, err := db.AddFolder(sh.ID, "Plans"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	raw := rawDB(t, dir)
	for _, q := range []string{
		`INSERT INTO files(share_id, path, slug, size, pending, declared_at) VALUES(?1, 'Notes.TXT', 'slug-a', 1, 1, 0)`,
		`INSERT INTO files(share_id, path, slug, size, pending, declared_at) VALUES(?1, 'Été/Ünï.txt', 'slug-b', 1, 1, 0)`,
		`INSERT INTO files(share_id, path, slug, size, pending, declared_at) VALUES(?1, CAST(x'4261c32e747874' AS TEXT), 'slug-c', 1, 1, 0)`,
		`INSERT INTO folders(share_id, path) VALUES(?1, 'Empty')`,
		`UPDATE files SET path = 'Moved/Report.pdf' WHERE share_id = ?1 AND path = 'Docs/Report.pdf'`,
		`UPDATE files SET path = 'Ölung/Brief.txt' WHERE share_id = ?1 AND path = 'Ärger/Brief.txt'`,
		`UPDATE folders SET path = 'Pläne' WHERE share_id = ?1 AND path = 'Plans'`,
	} {
		if _, err := raw.Exec(q, sh.ID); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	raw.Close()

	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetFoldCase(bySegment(fullFold))
	for rel, want := range map[string]string{
		"moved/REPORT.pdf": "Moved/Report.pdf",
		"docs/report.pdf":  "docs/report.pdf",
		"ÉTÉ/ünÏ.TXT":      "Été/Ünï.txt",
		"ölung/BRIEF.txt":  "Ölung/Brief.txt",
		"ärger/brief.txt":  "ärger/brief.txt",
		"PLÄNE/a.txt":      "Pläne/a.txt",
		"plans/a.txt":      "plans/a.txt",
		"EMPTY/a.txt":      "Empty/a.txt",
	} {
		if got, err := db.Spelling(sh.ID, rel, ""); err != nil || got != want {
			t.Errorf("Spelling(%q) = %q, %v, want %q", rel, got, err, want)
		}
	}
	held, err := db.PathsHeld(sh.ID, []string{"notes.txt", "notes 2.txt"})
	if err != nil || !held["notes.txt"] || held["notes 2.txt"] {
		t.Fatalf("PathsHeld = %v, %v", held, err)
	}
	if _, err := db.AddFolder(sh.ID, "EMPTY"); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("AddFolder(EMPTY) = %v, want ErrPathTaken", err)
	}
	for _, table := range []string{"files", "folders"} {
		rows, err := db.r.Query(`SELECT path, fold_key FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var p string
			var k sql.NullString
			if err := rows.Scan(&p, &k); err != nil {
				t.Fatal(err)
			}
			if k.String != shareid.FoldPath(p) {
				t.Errorf("%s %q keyed %v", table, p, k)
			}
		}
		rows.Close()
	}
}

// A row with no fold_key while the server serves (a writer outside this
// store) makes every folded lookup of its share fail closed: an owner's
// write is refused with ErrConflict and the inbox's held answers an error,
// which it reads as every candidate held. A volume that does not fold never
// reads the key.
func TestARowWithNoKeyWhileServingFailsClosed(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetFoldCase(bySegment(fullFold))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "in", Owner: "alice", Inbox: true})
	if _, err := rawDB(t, dir).Exec(`INSERT INTO files(share_id, path, slug, size, pending, declared_at)
		VALUES(?, 'Report.pdf', 'slug-a', 1, 1, 0)`, sh.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Spelling(sh.ID, "report.pdf", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("Spelling = %v, want ErrConflict", err)
	}
	if _, err := db.PathsHeld(sh.ID, []string{"report.pdf"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("PathsHeld = %v, want ErrConflict", err)
	}
	if _, err := db.DeclareFile(sh.ID, "other.pdf", 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("DeclareFile = %v, want ErrConflict", err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: "report.pdf", Size: 1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("CommitFile = %v, want ErrConflict", err)
	}
	if _, err := db.AddFolder(sh.ID, "REPORT.pdf"); !errors.Is(err, ErrConflict) {
		t.Fatalf("AddFolder = %v, want ErrConflict", err)
	}
	db.SetFoldCase(nil)
	if held, err := db.PathsHeld(sh.ID, []string{"report.pdf"}); err != nil || held["report.pdf"] {
		t.Fatalf("PathsHeld on a volume that does not fold = %v, %v", held, err)
	}
}

// foldBenchRows fills a fresh volume in dir with n file rows of one share,
// half of them named in printable ASCII and half not, and answers the share.
func foldBenchRows(b *testing.B, dir string, n int) string {
	b.Helper()
	db, err := Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if _, err := db.CreateUser("alice", "pw-alice", RoleUser, Settings{}); err != nil {
		b.Fatal(err)
	}
	d, err := db.CreateShare(CreateOptions{Name: "s", Owner: "alice"})
	if err != nil {
		b.Fatal(err)
	}
	if err := db.commit(func(tx *sql.Tx) error {
		for i := range n {
			p := fmt.Sprintf("Folder %d/Report %d.pdf", i%100, i)
			if i%2 == 1 {
				p = fmt.Sprintf("Été %d/Ärger %d.pdf", i%100, i)
			}
			if err := insertPending(tx, d.ID, p, 1, time.Now()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	return d.ID
}

// rekeyFolds on 200,000 file rows, half of them outside ASCII: with every
// key current (every boot), with every key missing (the first boot after a
// release without the column wrote them all), and the whole serving open
// with every key current, for scale.
func BenchmarkServingOpenRekeysFolds(b *testing.B) {
	dir := b.TempDir()
	foldBenchRows(b, dir, 200000)
	b.Run("open", func(b *testing.B) {
		for b.Loop() {
			db, err := Open(dir)
			if err != nil {
				b.Fatal(err)
			}
			db.Close()
		}
	})
	db, err := Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	for _, v := range []struct {
		name  string
		reset string
	}{
		{"current", ``},
		{"missing", `UPDATE files SET fold_key = NULL`},
	} {
		b.Run(v.name, func(b *testing.B) {
			for b.Loop() {
				if v.reset != "" {
					b.StopTimer()
					if _, err := db.w.Exec(v.reset); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
				}
				if err := db.write(rekeyFolds); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// What the key costs a write: a pending row inserted with its key, against
// the same insert without the column or its index, half the names ASCII.
func BenchmarkFoldKeyWriteCost(b *testing.B) {
	for _, keyed := range []bool{true, false} {
		b.Run(fmt.Sprintf("keyed=%v", keyed), func(b *testing.B) {
			dir := b.TempDir()
			id := foldBenchRows(b, dir, 0)
			db, err := Open(dir)
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			if !keyed {
				if _, err := db.w.Exec(`DROP INDEX files_fold`); err != nil {
					b.Fatal(err)
				}
			}
			i := 0
			for b.Loop() {
				err := db.commit(func(tx *sql.Tx) error {
					for range 100 {
						i++
						p := fmt.Sprintf("Folder %d/Report %d.pdf", i%100, i)
						if i%2 == 1 {
							p = fmt.Sprintf("Été %d/Ärger %d.pdf", i%100, i)
						}
						if keyed {
							if err := insertPending(tx, id, p, 1, time.Now()); err != nil {
								return err
							}
						} else if _, err := tx.Exec(`INSERT INTO files(share_id, path, slug, size, pending, declared_at) VALUES(?, ?, ?, ?, 1, ?)`,
							id, p, newSlug(), 1, toNS(time.Now())); err != nil {
							return err
						}
					}
					return nil
				})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// decoyShare is a share on a fully folding volume holding the victim
// θ×100.txt and n decoys, each θ^d, then one of Θ ϑ ϴ (whose key is θ's),
// then θ^(99-d) and a suffix of its own: names sharing every prefix of the
// victim's key but never the key itself.
func decoyShare(t *testing.T, db *DB, n int, inbox bool) (id, victim, attacker string) {
	t.Helper()
	db.SetFoldCase(bySegment(fullFold))
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice", Inbox: inbox})
	const l = 100
	victim = strings.Repeat("θ", l) + ".txt"
	if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: victim, Size: 1}); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		d, x := i/3%l, []string{"Θ", "ϑ", "ϴ"}[i%3]
		p := strings.Repeat("θ", d) + x + strings.Repeat("θ", l-1-d) + "-" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676))
		if _, err := db.CommitFile(CommitInput{ShareID: sh.ID, Path: p, Size: 1}); err != nil {
			t.Fatal(err)
		}
	}
	return sh.ID, victim, "Θ" + strings.Repeat("θ", l-1) + ".txt"
}

// Decoys sharing every prefix of a stored name's key cannot hide it: the
// inbox numbers the other spelling, an anonymous commit of it is refused,
// and an owner's commit lands on the stored row, never beside it.
func TestDecoysCannotHideAStoredName(t *testing.T) {
	db := openTest(t)
	id, victim, attacker := decoyShare(t, db, 60, true)
	held, err := db.PathsHeld(id, []string{attacker})
	if err != nil || !held[attacker] {
		t.Fatalf("PathsHeld(attacker) = %v, %v; the inbox must number it", held, err)
	}
	if got, err := db.Spelling(id, attacker, ""); err != nil || got != victim {
		t.Fatalf("Spelling(attacker) is the victim: %v, %v", got == victim, err)
	}
	if _, err := db.CommitFile(CommitInput{ShareID: id, Path: attacker, Size: 1, Anonymous: true}); !errors.Is(err, ErrPathTaken) {
		t.Fatalf("an anonymous commit of the attacker's spelling = %v, want ErrPathTaken", err)
	}
	f, err := db.CommitFile(CommitInput{ShareID: id, Path: attacker, Size: 2})
	if err != nil || f.Path != victim {
		t.Fatalf("the owner's commit = %q, %v, want the victim's row", f.Path, err)
	}
	d, err := db.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.Files {
		if f.Path == attacker {
			t.Fatal("a second row stands for the victim's file")
		}
	}
	if len(d.Files) != 61 {
		t.Fatalf("%d rows, want 61", len(d.Files))
	}
}

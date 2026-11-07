package metadb

import (
	"database/sql"
	"strings"
	"testing"
)

func seedUser(t *testing.T, db *DB, name string) {
	t.Helper()
	err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)`, name, "x", RoleUser, toNS(at))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func seedShare(t *testing.T, db *DB, id, owner string) {
	t.Helper()
	err := db.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO shares(id,owner,name,name_lower,created_at) VALUES(?,?,?,?,?)`, id, owner, "N", "n", toNS(at))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func counters(t *testing.T, db *DB, id string) (files, committed int, bytes int64) {
	t.Helper()
	err := db.read(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT files, committed, bytes FROM shares WHERE id=?`, id).Scan(&files, &committed, &bytes)
	})
	if err != nil {
		t.Fatal(err)
	}
	return
}

func ownerStats(t *testing.T, db *DB, owner string) (shares int, bytes int64) {
	t.Helper()
	err := db.read(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT shares, bytes FROM owner_stats WHERE owner=?`, owner).Scan(&shares, &bytes)
	})
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestFileTriggersKeepShareCounters(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	seedShare(t, db, "abcdefghjk", "alice")
	exec := func(q string, args ...any) {
		t.Helper()
		if err := db.write(func(tx *sql.Tx) error { _, err := tx.Exec(q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO files(share_id,path,slug,size,pending) VALUES('abcdefghjk','a',    'sa', 10, 1)`)
	exec(`INSERT INTO files(share_id,path,slug,size,pending) VALUES('abcdefghjk','b',    'sb', 20, 0)`)
	if f, c, b := counters(t, db, "abcdefghjk"); f != 2 || c != 1 || b != 20 {
		t.Fatalf("after inserts: files=%d committed=%d bytes=%d, want 2 1 20", f, c, b)
	}
	exec(`UPDATE files SET pending=0, size=15 WHERE share_id='abcdefghjk' AND path='a'`)
	if f, c, b := counters(t, db, "abcdefghjk"); f != 2 || c != 2 || b != 35 {
		t.Fatalf("after commit: files=%d committed=%d bytes=%d, want 2 2 35", f, c, b)
	}
	exec(`DELETE FROM files WHERE share_id='abcdefghjk' AND path='b'`)
	if f, c, b := counters(t, db, "abcdefghjk"); f != 1 || c != 1 || b != 15 {
		t.Fatalf("after delete: files=%d committed=%d bytes=%d, want 1 1 15", f, c, b)
	}
	if d, b := ownerStats(t, db, "alice"); d != 1 || b != 15 {
		t.Fatalf("owner_stats: shares=%d bytes=%d, want 1 15", d, b)
	}
}

func TestDeletingAShareCascadesAndSettlesOwnerStats(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	seedShare(t, db, "abcdefghjk", "alice")
	seedShare(t, db, "abcdefghjm", "alice")
	err := db.write(func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO files(share_id,path,slug,size) VALUES('abcdefghjk','a','sa',10)`,
			`INSERT INTO folders(share_id,path) VALUES('abcdefghjk','d')`,
			`INSERT INTO scheduled(share_id,kind,apply_at) VALUES('abcdefghjk','expiry',1)`,
			`INSERT INTO share_sources(share_id,source,position) VALUES('abcdefghjk','photos',0)`,
			`INSERT INTO source_paths(share_id,source,kind,rel) VALUES('abcdefghjk','photos','hidden','x')`,
			`INSERT INTO linked_slugs(share_id,rel,slug) VALUES('abcdefghjk','x','sx')`,
			`INSERT INTO gallery(share_id,slug) VALUES('abcdefghjk','sa')`,
			`DELETE FROM shares WHERE id='abcdefghjk'`,
		} {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"files", "folders", "scheduled", "share_sources", "source_paths", "linked_slugs", "gallery"} {
		var n int
		db.read(func(tx *sql.Tx) error { return tx.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n) })
		if n != 0 {
			t.Errorf("%s still holds %d rows after the share was deleted", table, n)
		}
	}
	if d, b := ownerStats(t, db, "alice"); d != 1 || b != 0 {
		t.Fatalf("owner_stats: shares=%d bytes=%d, want 1 0", d, b)
	}
}

func TestAShareCannotClaimTwoViewAnswers(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	for _, cols := range []string{"entry='index.html', media=1", "media=1, listing=1", "entry='a', listing=1"} {
		err := db.write(func(tx *sql.Tx) error {
			_, err := tx.Exec(`INSERT INTO shares(id,owner,name,name_lower,created_at) VALUES('abcdefghjk','alice','N','n',1)`)
			if err != nil {
				return err
			}
			_, err = tx.Exec(`UPDATE shares SET ` + cols + ` WHERE id='abcdefghjk'`)
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Errorf("%s: err = %v, want a CHECK failure", cols, err)
		}
	}
}

func TestDeletingAUserWithSharesIsRefused(t *testing.T) {
	db := openTest(t)
	seedUser(t, db, "alice")
	seedShare(t, db, "abcdefghjk", "alice")
	err := db.write(func(tx *sql.Tx) error { _, err := tx.Exec(`DELETE FROM users WHERE username='alice'`); return err })
	if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Fatalf("err = %v, want a foreign key failure", err)
	}
}

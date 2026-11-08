package metadb

import (
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"
)

// scaleID mints a ten-character id from the base58 alphabet for an insert
// loop index. An id is ten base58 characters, and "0" is not one of them, so
// the digits run "1" to "9" and every id ValidID accepts.
func scaleID(i int) string {
	const digits = "123456789"
	b := []byte("aaaaaaaaaa")
	for k := 9; k >= 1 && i > 0; k-- {
		b[k] = digits[i%9]
		i /= 9
	}
	return string(b)
}

// TestScaleLatencies inserts 300k shares and 500k files straight through SQL
// and pins the latencies the 2026-09-19 spike measured, with headroom. Run
// with HYPERDROP_SCALE_TEST=1.
func TestScaleLatencies(t *testing.T) {
	if os.Getenv("HYPERDROP_SCALE_TEST") == "" {
		t.Skip("set HYPERDROP_SCALE_TEST=1 to run the 300k-row scale test")
	}
	db := openTest(t)
	mustUser(t, db, "admin")
	mustUser(t, db, "alice")
	r := rand.New(rand.NewSource(1))
	nouns := []string{"river", "harbor", "invoice", "photo", "budget", "design", "trip"}
	err := db.write(func(tx *sql.Tx) error {
		ins, err := tx.Prepare(`INSERT INTO shares(id, owner, name, name_lower, created_at, expires_at) VALUES(?, ?, ?, lower(?), ?, ?)`)
		if err != nil {
			return err
		}
		insF, err := tx.Prepare(`INSERT INTO files(share_id, path, slug, size, sha256, mime, committed_at, added_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		base := at.UnixNano()
		for i := 0; i < 300000; i++ {
			id := scaleID(i)
			owner := "admin"
			if i%10 == 0 {
				owner = "alice"
			}
			name := fmt.Sprintf("quiet %s %d", nouns[i%len(nouns)], i)
			var exp any
			if i%20 == 0 {
				exp = base + int64(400*24)*int64(time.Hour)
			}
			if _, err := ins.Exec(id, owner, name, name, base+int64(i)*int64(time.Second), exp); err != nil {
				return err
			}
			files := 1
			if i%5 == 0 {
				files = 3
			}
			for f := 0; f < files; f++ {
				if _, err := insF.Exec(id, fmt.Sprintf("f%d.jpg", f), newSlug(), int64(1000+r.Intn(50000)), fmt.Sprintf("%064d", r.Intn(2000)), "image/jpeg", base, base); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Optimize(); err != nil {
		t.Fatal(err)
	}
	median := func(name string, budget time.Duration, fn func()) {
		t.Helper()
		var ds []time.Duration
		for i := 0; i < 15; i++ {
			s := time.Now()
			fn()
			ds = append(ds, time.Since(s))
		}
		for i := 1; i < len(ds); i++ {
			for j := i; j > 0 && ds[j] < ds[j-1]; j-- {
				ds[j], ds[j-1] = ds[j-1], ds[j]
			}
		}
		m := ds[len(ds)/2]
		t.Logf("%-40s median %v (budget %v)", name, m.Round(time.Microsecond), budget)
		if m > budget {
			t.Errorf("%s: median %v exceeds %v", name, m, budget)
		}
	}
	median("list newest 500 + files", 50*time.Millisecond, func() { db.List(ListQuery{Owner: "admin"}) })
	median("list at offset 100000", 50*time.Millisecond, func() { db.List(ListQuery{Owner: "admin", Offset: 100000}) })
	median("search substring", 500*time.Millisecond, func() { db.List(ListQuery{Owner: "admin", Name: "river"}) })
	median("usage", 5*time.Millisecond, func() { db.Usage("admin") })
	median("expired", 5*time.Millisecond, func() { db.Expired(at) })
	median("empty shares", 5*time.Millisecond, func() { db.EmptyShares(at) })
	median("get one share", 5*time.Millisecond, func() { db.Share(scaleID(150000)) })
	median("resolve slug", 5*time.Millisecond, func() {
		d, _ := db.Share(scaleID(150001))
		db.ResolveSlug(d.ID, d.Files[0].Slug)
	})
	median("commit one file", 20*time.Millisecond, func() {
		db.CommitFile(CommitInput{ShareID: scaleID(1), Path: fmt.Sprintf("new%d", r.Int()), Size: 1, SHA256: "x", Mime: "text/plain"})
	})
	median("pending files", 5*time.Millisecond, func() { db.PendingFiles(at) })
	median("share ids", 500*time.Millisecond, func() { db.ShareIDs() })
	walk := time.Now()
	cursor := ""
	pages := 0
	for {
		p, err := db.List(ListQuery{Owner: "admin", After: cursor, Limit: 2000, MaxFiles: 1})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	t.Logf("cursor walk of 270k shares: %d pages in %v", pages, time.Since(walk).Round(time.Millisecond))
	if time.Since(walk) > 15*time.Second {
		t.Errorf("cursor walk took %v", time.Since(walk))
	}
}

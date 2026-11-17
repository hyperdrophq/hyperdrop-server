package metadb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/shareid"
)

// cleanVolume is a volume a serving open filled and CloseClean closed: an
// account, a share of 200 more beside it so the file has pages to damage,
// and one file row whose fold_key a writer outside the store left stale,
// which only rekeyFolds puts right.
type cleanVolume struct {
	dir, shareID, path string
}

func writeCleanVolume(t *testing.T) cleanVolume {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	mustUser(t, db, "alice")
	sh := mustShare(t, db, CreateOptions{Name: "s", Owner: "alice", Files: []PendingFile{{Path: "Docs/Report.pdf", Size: 1}}})
	for i := range 200 {
		seedShare(t, db, fmt.Sprintf("s%05d", i), "alice")
	}
	if _, err := db.w.Exec(`UPDATE files SET fold_key = 'stale' WHERE share_id = ? AND path = ?`, sh.ID, "Docs/Report.pdf"); err != nil {
		t.Fatal(err)
	}
	recorded, err := db.CloseClean()
	if err != nil || !recorded {
		t.Fatalf("CloseClean = %v, %v, want a record", recorded, err)
	}
	return cleanVolume{dir: dir, shareID: sh.ID, path: "Docs/Report.pdf"}
}

// foldKeyOf answers the fold_key the row of v's file holds.
func (v cleanVolume) foldKeyOf(t *testing.T, db *DB) string {
	t.Helper()
	var k string
	if err := db.r.QueryRow(`SELECT fold_key FROM files WHERE share_id = ? AND path = ?`, v.shareID, v.path).Scan(&k); err != nil {
		t.Fatal(err)
	}
	return k
}

func (v cleanVolume) file() string   { return filepath.Join(v.dir, FileName) }
func (v cleanVolume) record() string { return filepath.Join(v.dir, CleanCloseFile) }

// keepMtime runs damage on the database file and puts its modification
// time back, the shape bit rot or a tamperer that preserves it leaves.
func (v cleanVolume) keepMtime(t *testing.T, damage func()) {
	t.Helper()
	fi, err := os.Stat(v.file())
	if err != nil {
		t.Fatal(err)
	}
	damage()
	if err := os.Chtimes(v.file(), fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
}

func TestACleanCloseSkipsTheCheckAndTheRepairs(t *testing.T) {
	v := writeCleanVolume(t)
	var rec struct {
		Generation int    `json:"generation"`
		KeyTables  string `json:"keyTables"`
		Size       int64  `json:"size"`
		MtimeNs    int64  `json:"mtimeNs"`
		Inode      uint64 `json:"inode"`
	}
	data, err := os.ReadFile(v.record())
	if err != nil || json.Unmarshal(data, &rec) != nil {
		t.Fatalf("record %s: %v", data, err)
	}
	fi, _ := os.Stat(v.file())
	if rec.Generation != RepairGeneration || rec.KeyTables == "" || rec.KeyTables != keyTables() || rec.Size != fi.Size() || rec.MtimeNs != fi.ModTime().UnixNano() || rec.Inode == 0 {
		t.Fatalf("record %s, file %d bytes at %d", data, fi.Size(), fi.ModTime().UnixNano())
	}

	db, err := Open(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := db.OpenStats()
	if !st.Trusted || st.Checked || st.Distrust != "" || st.Size != fi.Size() {
		t.Fatalf("OpenStats = %+v, want trusted and not checked", st)
	}
	if st.Names != 0 || st.Folds != 0 || st.Seal != 0 {
		t.Fatalf("OpenStats = %+v, want no repair run", st)
	}
	if got := v.foldKeyOf(t, db); got != "stale" {
		t.Fatalf("fold_key = %q, want the stale key a skipped rekeyFolds leaves", got)
	}
	if _, err := os.Stat(v.record()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the record survived the open: %v", err)
	}
}

func TestEachInvalidatorForcesTheFullOpen(t *testing.T) {
	rewrite := func(t *testing.T, v cleanVolume, edit func(map[string]any)) {
		data, err := os.ReadFile(v.record())
		if err != nil {
			t.Fatal(err)
		}
		// Numbers stay json.Number, so the size and nanosecond time come
		// back exactly and only the edited field differs.
		var rec map[string]any
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
		edit(rec)
		data, _ = json.Marshal(rec)
		if err := os.WriteFile(v.record(), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name, distrust string
		change         func(t *testing.T, v cleanVolume)
	}{
		{"size", "size differs", func(t *testing.T, v cleanVolume) {
			v.keepMtime(t, func() {
				fi, _ := os.Stat(v.file())
				if err := os.Truncate(v.file(), fi.Size()+4096); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"mtime", "modification time differs", func(t *testing.T, v cleanVolume) {
			fi, _ := os.Stat(v.file())
			moved := fi.ModTime().Add(time.Nanosecond)
			if err := os.Chtimes(v.file(), moved, moved); err != nil {
				t.Fatal(err)
			}
		}},
		{"wal", "-wal present", func(t *testing.T, v cleanVolume) {
			if err := os.WriteFile(v.file()+"-wal", nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"check owed", "a check is owed", func(t *testing.T, v cleanVolume) {
			if err := os.WriteFile(filepath.Join(v.dir, CheckOwedFile), []byte(`{"at":"2026-09-19T12:00:00Z","reason":"test"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"generation", fmt.Sprintf("generation 0, this build repairs to %d", RepairGeneration), func(t *testing.T, v cleanVolume) {
			rewrite(t, v, func(rec map[string]any) { rec["generation"] = 0 })
		}},
		{"key tables", "key tables differ", func(t *testing.T, v cleanVolume) {
			rewrite(t, v, func(rec map[string]any) { rec["keyTables"] = "unicode 15.0.0, golang.org/x/text v0.21.0" })
		}},
		{"no key tables", "key tables differ", func(t *testing.T, v cleanVolume) {
			rewrite(t, v, func(rec map[string]any) { delete(rec, "keyTables") })
		}},
		{"missing", "no record", func(t *testing.T, v cleanVolume) {
			if err := os.Remove(v.record()); err != nil {
				t.Fatal(err)
			}
		}},
		{"garbage", "record unreadable", func(t *testing.T, v cleanVolume) {
			if err := os.WriteFile(v.record(), []byte("not a record"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"inode", "inode differs", func(t *testing.T, v cleanVolume) {
			v.keepMtime(t, func() {
				in, err := os.Open(v.file())
				if err != nil {
					t.Fatal(err)
				}
				defer in.Close()
				out, err := os.OpenFile(v.file()+".copy", os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.Copy(out, in); err != nil {
					t.Fatal(err)
				}
				if err := out.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(v.file()+".copy", v.file()); err != nil {
					t.Fatal(err)
				}
			})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := writeCleanVolume(t)
			c.change(t, v)
			db, err := Open(v.dir)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			st := db.OpenStats()
			if st.Trusted || !st.Checked || st.Distrust != c.distrust {
				t.Fatalf("OpenStats = %+v, want checked for %q", st, c.distrust)
			}
			if got := v.foldKeyOf(t, db); got != shareid.FoldPath(v.path) {
				t.Fatalf("fold_key = %q, want rekeyFolds' %q", got, shareid.FoldPath(v.path))
			}
			if _, err := os.Stat(v.record()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the record survived the open: %v", err)
			}
			if _, err := os.Stat(filepath.Join(v.dir, CheckOwedFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the passing check left %s: %v", CheckOwedFile, err)
			}
		})
	}
}

// A build that cannot name its key tables (no build info, or no version for
// golang.org/x/text) records none and trusts no record, its own included.
func TestUnknownKeyTablesAreNeverTrusted(t *testing.T) {
	known := keyTables
	t.Cleanup(func() { keyTables = known })
	keyTables = func() string { return "" }
	v := writeCleanVolume(t)
	db, err := Open(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if st := db.OpenStats(); st.Trusted || !st.Checked || st.Distrust != distrustKeyTables {
		t.Fatalf("OpenStats = %+v, want checked for %q", st, distrustKeyTables)
	}
	if got := v.foldKeyOf(t, db); got != shareid.FoldPath(v.path) {
		t.Fatalf("fold_key = %q, want rekeyFolds' %q", got, shareid.FoldPath(v.path))
	}
}

// A process that ends without closing (a crash, SIGKILL) leaves no record:
// the open removed it, and only a clean close writes another.
func TestACrashLeavesNoRecord(t *testing.T) {
	v := writeCleanVolume(t)
	abandoned, err := Open(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer abandoned.Close()
	if !abandoned.OpenStats().Trusted {
		t.Fatalf("OpenStats = %+v, want trusted", abandoned.OpenStats())
	}
	seedShare(t, abandoned, "crashed", "alice")
	if _, err := os.Stat(v.record()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a record stands while the database is open: %v", err)
	}

	db, err := Open(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if st := db.OpenStats(); st.Trusted || !st.Checked || st.Distrust != "no record" {
		t.Fatalf("OpenStats = %+v, want checked for no record", st)
	}
}

// Damage that reaches the file while the server is stopped, with the
// modification time kept, passes the record: the daily copy's check finds
// it, and the start after that checks and restores the older good copy.
func TestDamageWhileStoppedIsCaughtByTheDailyCheck(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	for i := range 200 {
		seedShare(t, db, fmt.Sprintf("s%05d", i), "admin")
	}
	bdir := filepath.Join(dir, "backups")
	good, err := Backup(context.Background(), db, bdir, at)
	if err != nil {
		t.Fatal(err)
	}
	if recorded, err := db.CloseClean(); err != nil || !recorded {
		t.Fatalf("CloseClean = %v, %v", recorded, err)
	}
	v := cleanVolume{dir: dir}
	v.keepMtime(t, func() { corruptLastPage(t, v.file()) })

	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st := db.OpenStats(); !st.Trusted || st.Checked {
		t.Fatalf("OpenStats = %+v, want the damaged file trusted", st)
	}
	if _, err := Backup(context.Background(), db, bdir, at.Add(48*time.Hour)); !errors.Is(err, ErrCopyDamaged) {
		t.Fatalf("Backup = %v, want ErrCopyDamaged", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := db.OpenStats()
	if st.Trusted || !st.Checked || st.Recovered != good {
		t.Fatalf("OpenStats = %+v, want checked and restored from %s", st, good)
	}
	if rec, ok := ReadRecovered(dir); !ok || rec.Backup != good {
		t.Fatalf("%s = %+v, %v, want the restore from %s", RecoveredMarker, rec, ok, good)
	}
}

// Damage the trusted open itself meets is checked in the same open: the
// file is checked after all and the newest good copy restored.
func TestATrustedOpenThatMeetsCorruptionChecksAfterAll(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	seedShare(t, db, "s1s1", "admin")
	good, err := Backup(context.Background(), db, filepath.Join(dir, "backups"), at)
	if err != nil {
		t.Fatal(err)
	}
	if recorded, err := db.CloseClean(); err != nil || !recorded {
		t.Fatalf("CloseClean = %v, %v", recorded, err)
	}
	v := cleanVolume{dir: dir}
	v.keepMtime(t, func() { corruptSchemaTree(t, v.file()) })

	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := db.OpenStats()
	if st.Trusted || !st.Checked || st.Recovered != good || st.Distrust != distrustDamaged {
		t.Fatalf("OpenStats = %+v, want checked after all and restored from %s", st, good)
	}
	if !hasShare(t, db, "s1s1") {
		t.Fatal("the restored copy lacks the share")
	}
}

// A close that leaves the write-ahead log (a connection still open) writes
// no record.
func TestACloseUnderAnOpenConnectionWritesNoRecord(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "admin")
	other, err := OpenAsIs(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if recorded, err := db.CloseClean(); err != nil || recorded {
		t.Fatalf("CloseClean = %v, %v, want no record", recorded, err)
	}
	if _, err := os.Stat(filepath.Join(dir, CleanCloseFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a record was written beside an open connection: %v", err)
	}
}

// RepairGeneration's list names every call ensureSchema's serving branch
// for a database at SchemaVersion makes, besides ensureAdditive (which a
// trusted open runs too) and the steps' timing (lap, time.Now): a repair
// added there owes the generation a raise, or a record an earlier build's
// close left would let the open skip it. The steps outside this package that
// a trusted boot skips (trustedBootSkips) are still called from the file the
// list names.
func TestTheRepairGenerationNamesEveryBootRepair(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "db.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var branch *ast.CaseClause
	ast.Inspect(f, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Name.Name == "ensureSchema" {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				cc, ok := n.(*ast.CaseClause)
				if !ok || len(cc.List) != 1 {
					return true
				}
				if b, ok := cc.List[0].(*ast.BinaryExpr); ok && b.Op == token.EQL {
					if x, ok := b.X.(*ast.Ident); ok && x.Name == "v" {
						if y, ok := b.Y.(*ast.Ident); ok && y.Name == "SchemaVersion" {
							branch = cc
						}
					}
				}
				return true
			})
			return false
		}
		return true
	})
	if branch == nil {
		t.Fatal("ensureSchema has no case v == SchemaVersion")
	}
	var calls []string
	for _, stmt := range branch.Body {
		ast.Inspect(stmt, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false // lap's own clock reads
			case *ast.CallExpr:
				var name string
				switch fun := n.Fun.(type) {
				case *ast.Ident:
					name = fun.Name
				case *ast.SelectorExpr:
					if x, ok := fun.X.(*ast.Ident); ok {
						name = x.Name + "." + fun.Sel.Name
					}
				}
				if !slices.Contains([]string{"ensureAdditive", "lap", "time.Now"}, name) && !slices.Contains(calls, name) {
					calls = append(calls, name)
				}
			}
			return true
		})
	}
	var skips []string
	for _, s := range trustedBootSkips {
		skips = append(skips, s.call+" ("+s.file+")")
	}
	if !slices.Equal(calls, bootRepairs[:]) {
		t.Fatalf("ensureSchema's serving branch calls %s, RepairGeneration %d lists %s: raise RepairGeneration and list it "+
			"(a trusted boot also skips %s, so a change to what it judges, the sealed-password scheme, raises it too)",
			strings.Join(calls, ", "), RepairGeneration, strings.Join(bootRepairs[:], ", "), strings.Join(skips, ", "))
	}
	// Each step outside this package that a trusted boot skips is still
	// called where the list says.
	for _, s := range trustedBootSkips {
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", s.file), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		pkg, fn, _ := strings.Cut(s.call, ".")
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == fn {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == pkg {
						found = true
					}
				}
			}
			return !found
		})
		if !found {
			t.Fatalf("%s no longer calls %s, which RepairGeneration %d names as a step a trusted boot skips: "+
				"update trustedBootSkips, and raise RepairGeneration when the boot gains or changes a repair",
				s.file, s.call, RepairGeneration)
		}
	}
}

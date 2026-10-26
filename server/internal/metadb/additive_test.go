package metadb

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// These tests pin the serving open's additive step (additive.go): a stamp-1
// volume an earlier build made without some additive column or object gains
// it when served, ends in the shape a fresh volume has, and a volume this
// tree made reopens unchanged. No frozen previous release is checked in
// until a public release has a successor (prevrelease/freeze.sh).

// rawDB opens dir's database file directly, beside whatever else has it open.
func rawDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	return raw
}

func userVersion(t *testing.T, dir string) (v int) {
	t.Helper()
	if err := rawDB(t, dir).QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// columns lists a table's columns as (name, type, notnull, default, pk), in
// column order.
func columns(t *testing.T, raw *sql.DB, table string) []string {
	t.Helper()
	rows, err := raw.Query(`SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_xinfo(?) ORDER BY cid`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s %s notnull=%d default=%v pk=%d", name, typ, notnull, dflt, pk))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func hasColumn(t *testing.T, dir, table, column string) bool {
	t.Helper()
	var n int
	if err := rawDB(t, dir).QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// olderVolume makes a volume as an earlier build of stamp 1 left it: this
// tree's volume with every additive column and object taken away, holding an
// admin, alice, and one share of alice's with the password hash h1.
func olderVolume(t *testing.T) (dir, id string) {
	t.Helper()
	dir = t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAdmin("root", "pw-root"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("alice", "pw-alice", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	d, err := db.CreateShare(CreateOptions{Name: "x", Owner: "alice", PasswordHash: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	raw, err := sql.Open("sqlite", filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for i := len(addedObjects) - 1; i >= 0; i-- {
		o := addedObjects[i]
		if _, err := raw.Exec(`DROP ` + strings.ToUpper(o[0]) + ` ` + o[1]); err != nil {
			t.Fatalf("drop %s %s: %v", o[0], o[1], err)
		}
	}
	for _, c := range additiveColumns {
		if slices.Contains(addedObjects, [2]string{"table", c.table}) {
			continue // dropped with its table
		}
		if _, err := raw.Exec(`ALTER TABLE ` + c.table + ` DROP COLUMN ` + c.column); err != nil {
			t.Fatalf("drop %s.%s: %v", c.table, c.column, err)
		}
	}
	if have, _ := added(t, dir); len(have) != 0 {
		t.Fatalf("the older volume still holds %v", have)
	}
	return dir, d.ID
}

// addedObjects are the additiveObjects by type and name, as sqlite_master
// lists them.
var addedObjects = [][2]string{{"index", "tokens_push"}, {"index", "tokens_user"}, {"index", "files_committed"}, {"table", "push_state"},
	{"table", "device_links"}, {"index", "device_links_user"}, {"index", "files_fold"}, {"index", "folders_fold"}}

func hasObject(t *testing.T, dir, typ, name string) bool {
	t.Helper()
	var n int
	if err := rawDB(t, dir).QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = ? AND name = ?`, typ, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// added reports which additive columns and objects dir holds.
func added(t *testing.T, dir string) (have, lack []string) {
	t.Helper()
	for _, c := range additiveColumns {
		if hasColumn(t, dir, c.table, c.column) {
			have = append(have, c.table+"."+c.column)
		} else {
			lack = append(lack, c.table+"."+c.column)
		}
	}
	for _, o := range addedObjects {
		if hasObject(t, dir, o[0], o[1]) {
			have = append(have, o[0]+" "+o[1])
		} else {
			lack = append(lack, o[0]+" "+o[1])
		}
	}
	return have, lack
}

func TestAnOlderVolumeGainsTheAdditiveColumnsWhenServed(t *testing.T) {
	if len(addedObjects) != len(additiveObjects) {
		t.Fatalf("addedObjects names %d objects, additiveObjects creates %d", len(addedObjects), len(additiveObjects))
	}
	dir, id := olderVolume(t)
	have, _ := added(t, dir)

	op, err := OpenAsIs(dir)
	if err != nil {
		t.Fatalf("OpenAsIs: %v", err)
	}
	op.Close()
	if now, _ := added(t, dir); !slices.Equal(now, have) {
		t.Fatalf("OpenAsIs added %v", slices.DeleteFunc(now, func(s string) bool { return slices.Contains(have, s) }))
	}
	if v := userVersion(t, dir); v != 1 {
		t.Fatalf("user_version = %d after OpenAsIs", v)
	}

	for round := 1; round <= 2; round++ { // the second serving open is a no-op
		db, err := Open(dir)
		if err != nil {
			t.Fatalf("Open round %d: %v", round, err)
		}
		if _, lack := added(t, dir); len(lack) != 0 {
			t.Fatalf("round %d: the serving open left the volume without %v", round, lack)
		}
		if v := userVersion(t, dir); v != SchemaVersion || SchemaVersion != 1 {
			t.Fatalf("round %d: user_version = %d, SchemaVersion %d; an additive column keeps stamp 1", round, v, SchemaVersion)
		}
		d, err := db.Share(id)
		if err != nil {
			t.Fatal(err)
		}
		if d.PasswordHash != "h1" || d.PasswordSealed != nil {
			t.Fatalf("round %d: a password set without a sealed copy: hash %q sealed %q", round, d.PasswordHash, d.PasswordSealed)
		}
		raw, err := db.MintToken("alice", "x")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok, err := db.PushOf(TokenHash(raw)); ok || err != nil {
			t.Fatalf("round %d: PushOf on a fresh token: %v %v", round, ok, err)
		}
		if users, err := db.PushUsers(); err != nil || len(users) != 0 {
			t.Fatalf("round %d: PushUsers = %v %v", round, users, err)
		}
		db.Close()
	}
}

// columnDecl answers table.column's declared type, or "" when it is absent.
func columnDecl(t *testing.T, dir, table, column string) string {
	t.Helper()
	var decl string
	err := rawDB(t, dir).QueryRow(`SELECT type FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&decl)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return decl
}

// The add path of ensureAdditive, one item at a time: a volume this tree
// made, with one additive column or object taken away, keeps lacking it
// under OpenAsIs and has it back, with the type a fresh volume gives it,
// after the serving open.
func TestTheServingOpenRestoresEveryAdditiveColumnAndObject(t *testing.T) {
	fresh := t.TempDir()
	db, err := Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	freshObjects := shape(t, fresh)["objects"]

	check := func(label string, remove func(raw *sql.DB) error, present func(dir string) bool) {
		t.Helper()
		dir := t.TempDir()
		db, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
		raw, err := sql.Open("sqlite", filepath.Join(dir, FileName))
		if err != nil {
			t.Fatal(err)
		}
		err = remove(raw)
		raw.Close()
		if err != nil {
			t.Fatalf("%s: take it away: %v", label, err)
		}
		if present(dir) {
			t.Fatalf("%s: still there after it was taken away", label)
		}
		op, err := OpenAsIs(dir)
		if err != nil {
			t.Fatalf("%s: OpenAsIs: %v", label, err)
		}
		op.Close()
		if present(dir) {
			t.Fatalf("%s: OpenAsIs put it back; only the serving open may", label)
		}
		db, err = Open(dir)
		if err != nil {
			t.Fatalf("%s: Open: %v", label, err)
		}
		db.Close()
		if !present(dir) {
			t.Fatalf("%s: the serving open did not put it back", label)
		}
		if _, lack := added(t, dir); len(lack) != 0 {
			t.Fatalf("%s: after the serving open the volume lacks %v", label, lack)
		}
		if got := shape(t, dir)["objects"]; !reflect.DeepEqual(got, freshObjects) {
			t.Fatalf("%s: objects after the serving open differ from a fresh volume:\n fresh %q\n got   %q", label, freshObjects, got)
		}
		if v := userVersion(t, dir); v != SchemaVersion {
			t.Fatalf("%s: user_version = %d", label, v)
		}
	}

	for _, c := range additiveColumns {
		check(c.table+"."+c.column, func(raw *sql.DB) error {
			// An index that names the column blocks DROP COLUMN: take it
			// away too; the serving open's objects put it back.
			rows, err := raw.Query(`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND sql LIKE '%' || ? || '%'`, c.table, c.column)
			if err != nil {
				return err
			}
			var indexes []string
			for rows.Next() {
				var name string
				if err := rows.Scan(&name); err != nil {
					rows.Close()
					return err
				}
				indexes = append(indexes, name)
			}
			rows.Close()
			for _, name := range indexes {
				if _, err := raw.Exec(`DROP INDEX ` + name); err != nil {
					return err
				}
			}
			_, err = raw.Exec(`ALTER TABLE ` + c.table + ` DROP COLUMN ` + c.column)
			return err
		}, func(dir string) bool {
			// The type ADD COLUMN gives it must be the one a fresh volume's
			// schema gives it, or an added volume and a fresh one differ.
			decl, want := columnDecl(t, dir, c.table, c.column), columnDecl(t, fresh, c.table, c.column)
			if decl != "" && decl != want {
				t.Fatalf("%s.%s is %q after the serving open, %q in a fresh volume", c.table, c.column, decl, want)
			}
			return decl != ""
		})
	}
	for _, o := range addedObjects {
		check(o[0]+" "+o[1], func(raw *sql.DB) error {
			_, err := raw.Exec(`DROP ` + strings.ToUpper(o[0]) + ` ` + o[1])
			return err
		}, func(dir string) bool { return hasObject(t, dir, o[0], o[1]) })
	}
}

// shape is every table's columns plus the schema's objects.
func shape(t *testing.T, dir string) map[string][]string {
	t.Helper()
	raw := rawDB(t, dir)
	rows, err := raw.Query(`SELECT type, name, tbl_name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	var tables []string
	for rows.Next() {
		var typ, name, tbl string
		if err := rows.Scan(&typ, &name, &tbl); err != nil {
			t.Fatal(err)
		}
		out["objects"] = append(out["objects"], typ+" "+name+" on "+tbl)
		if typ == "table" {
			tables = append(tables, name)
		}
	}
	rows.Close()
	for _, table := range tables {
		out["table "+table] = columns(t, raw, table)
	}
	return out
}

func TestAnAddedVolumeHasTheFreshShape(t *testing.T) {
	fresh := t.TempDir()
	db, err := Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	added, _ := olderVolume(t)
	db, err = Open(added)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	want, got := shape(t, fresh), shape(t, added)
	if !reflect.DeepEqual(want, got) {
		for k := range want {
			if !reflect.DeepEqual(want[k], got[k]) {
				t.Errorf("%s:\n fresh %q\n added %q", k, want[k], got[k])
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Errorf("%s only in the added volume", k)
			}
		}
	}
}

// schemaText is every object's CREATE statement, as sqlite_master stores it.
func schemaText(t *testing.T, dir string) []string {
	t.Helper()
	rows, err := rawDB(t, dir).Query(`SELECT type || ' ' || name || ': ' || coalesce(sql, '') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// A volume this tree made, already holding every additive column and
// object, reopens with its schema text, stamp and rows untouched: the
// serving open's additive step finds nothing to add.
func TestAVolumeThisTreeMadeReopensUnchanged(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureAdmin("root", "pw-root"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("alice", "pw-alice", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	d, err := db.CreateShare(CreateOptions{Name: "x", Owner: "alice", PasswordHash: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, lack := added(t, dir); len(lack) != 0 {
		t.Fatalf("a fresh volume lacks %v", lack)
	}
	before, beforeText := shape(t, dir), schemaText(t, dir)

	for round := 1; round <= 2; round++ {
		db, err := Open(dir)
		if err != nil {
			t.Fatalf("Open round %d: %v", round, err)
		}
		got, err := db.Share(d.ID)
		if err != nil || got.PasswordHash != "h1" || got.Owner != "alice" {
			t.Fatalf("round %d: Share = %+v, %v", round, got, err)
		}
		db.Close()
		if after := shape(t, dir); !reflect.DeepEqual(before, after) {
			t.Fatalf("round %d: the shape changed:\n before %q\n after  %q", round, before, after)
		}
		if after := schemaText(t, dir); !slices.Equal(beforeText, after) {
			t.Fatalf("round %d: the schema text changed:\n before %q\n after  %q", round, beforeText, after)
		}
		if v := userVersion(t, dir); v != SchemaVersion {
			t.Fatalf("round %d: user_version = %d", round, v)
		}
	}
}

// The operator subcommands (checkschema, checkdb, admins, resetadmin,
// reset2fa) open through OpenAsIs while another binary may still be serving
// the volume: none of them may alter its shape or its stamp.
func TestOperatorOpensNeverAlterAVolume(t *testing.T) {
	dir, _ := olderVolume(t)
	before := shape(t, dir)

	db, err := OpenAsIs(dir)
	if err != nil {
		t.Fatalf("OpenAsIs: %v", err)
	}
	if err := db.Check(); err != nil {
		t.Fatal(err)
	}
	if names, err := db.AdminNames(); err != nil || len(names) != 1 {
		t.Fatalf("AdminNames: %v %v", names, err)
	}
	if _, err := db.ResetAdmin("root", "pw-new"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.User("alice"); err != nil {
		t.Fatal(err)
	}
	if err := db.DisableTOTP("alice"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if after := shape(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("an operator open altered the volume:\n before %q\n after  %q", before, after)
	}
	if v := userVersion(t, dir); v != 1 {
		t.Fatalf("user_version = %d", v)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
}

// A volume of a release that already had device_links but not its
// stepped_up column gains the column on the serving open, and its links
// read as not stepped up.
func TestDeviceLinksGainSteppedUpWhenServed(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := rawDB(t, dir).Exec(`ALTER TABLE device_links DROP COLUMN stepped_up`); err != nil {
		t.Fatal(err)
	}
	if hasColumn(t, dir, "device_links", "stepped_up") {
		t.Fatal("the column survived its drop")
	}
	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if !hasColumn(t, dir, "device_links", "stepped_up") {
		t.Fatal("the serving open did not add device_links.stepped_up")
	}
}

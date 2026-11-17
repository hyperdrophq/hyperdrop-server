package volume

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sealpw"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// honestSpecs are the plan's newest share of every kind and its newest
// share at the file cap, their files cut to a few dozen so building them
// the API's way stays quick. The cap share is moved to two days before the
// Epoch, inside the journal's retention, so its journal row is kept.
func honestSpecs(t *testing.T, p Plan) []ShareSpec {
	t.Helper()
	var out []ShareSpec
	seen := map[Kind]bool{}
	capped := false
	for i := p.Shares - 1; i >= 0; i-- {
		s := p.Share(i)
		switch {
		case s.Files == p.FileCap && !capped:
			capped = true
			s.CreatedAt = p.Epoch.Add(-48 * time.Hour)
		case !seen[s.Kind] && s.Files != p.FileCap:
			seen[s.Kind] = true
		default:
			continue
		}
		s.Files = min(s.Files, 60)
		out = append(out, s)
	}
	for k := Plain; k <= Inbox; k++ {
		if !seen[k] {
			t.Fatalf("the plan holds no %v share", k)
		}
	}
	if !capped {
		t.Fatal("the plan holds no share at the file cap")
	}
	return out
}

// createLikeTheAPI makes s through the calls the API's handlers make: the
// create route's CreateShare with the manifest a client sends, the folder
// route's AddFolder, and per file the batch route's staged write and
// commit, or for an inbox the public upload's declare, write and anonymous
// commit.
func createLikeTheAPI(t *testing.T, db *metadb.DB, store *sharefs.FS, p Plan, s ShareSpec) {
	t.Helper()
	o := metadb.CreateOptions{ID: s.ID, Name: s.Name, Owner: s.Owner, Folder: folderFlag(s), CreatedAt: s.CreatedAt,
		Media: s.Kind == Gallery, Text: s.Kind == Text, Inbox: s.Kind == Inbox}
	if !s.ExpiresAt.IsZero() {
		e := s.ExpiresAt
		o.ExpiresAt = &e
	}
	if s.Kind == Protected {
		hash, err := bcrypt.GenerateFromPassword([]byte(SharePassword), metadb.BcryptCost)
		if err != nil {
			t.Fatal(err)
		}
		o.PasswordHash = string(hash)
		o.SealPassword = func(id string) ([]byte, error) {
			return sealpw.Seal(store.Secret(), id, string(hash), SharePassword)
		}
	}
	if s.Kind != Inbox {
		for f := 0; f < s.Files; f++ {
			name := p.FileName(s, f)
			o.Files = append(o.Files, metadb.PendingFile{Path: name, Size: int64(blobSize(pickBlob(p.Seed, s.Index, f, name)))})
		}
	}
	if _, err := db.CreateShare(o); err != nil {
		t.Fatalf("create %v share: %v", s.Kind, err)
	}
	for _, dir := range emptyFolders(s) {
		if _, err := db.AddFolder(s.ID, dir); err != nil {
			t.Fatalf("folder %s: %v", dir, err)
		}
	}
	for f := 0; f < s.Files; f++ {
		name := p.FileName(s, f)
		content := blobContent(p.Seed, pickBlob(p.Seed, s.Index, f, name))
		in := metadb.CommitInput{ShareID: s.ID, Path: name}
		if s.Kind == Inbox {
			if _, err := db.DeclareFile(s.ID, name, int64(len(content))); err != nil {
				t.Fatal(err)
			}
			in.UploadSession, in.Anonymous = sender(p.Seed, s.Index, f), true
		}
		if _, err := store.Write(s.ID, name, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
		_, err := store.Commit(s.ID, name, int64(len(content)), func(c sharefs.Committed) error {
			in.Size, in.SHA256, in.Mime = c.Size, c.SHA256, c.Mime
			_, err := db.CommitFile(in)
			return err
		})
		if err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}
}

// volumeDB is one finished data directory opened for comparison.
type volumeDB struct {
	db     *sql.DB
	secret []byte
}

// normaliser maps a column's value to what is compared in its place.
type normaliser func(v volumeDB, row map[string]any) any

// tableRule says how a table that references shares is compared: columns
// compared as they are, columns normalised, or no row at all on either side
// (a table only another kind of share, or later use, writes).
type tableRule struct {
	exact []string
	norm  map[string]normaliser
	empty bool
}

func present(col string) normaliser {
	return func(_ volumeDB, row map[string]any) any {
		if row[col] == nil {
			return nil
		}
		return "set"
	}
}

// shareTables names every table holding a share's rows. A table the schema
// gains that references shares, or a column one of these gains, fails the
// test until it is named here.
var shareTables = map[string]tableRule{
	"shares": {
		exact: []string{"id", "owner", "name", "name_lower", "folder", "entry", "media", "listing", "inbox", "text",
			"note", "closed", "max_bytes", "max_files", "notify_off", "seen_at", "pinned_at", "password_gen",
			"created_at", "expires_at", "bytes", "committed", "files", "visitors", "links_off_at", "copying_from"},
		norm: map[string]normaliser{
			"modified_at": func(_ volumeDB, row map[string]any) any {
				m, ok := row["modified_at"].(int64)
				if !ok {
					return row["modified_at"]
				}
				return m > row["created_at"].(int64)
			},
			"password_hash": func(_ volumeDB, row map[string]any) any {
				h, ok := row["password_hash"].(string)
				if !ok {
					return row["password_hash"]
				}
				return bcrypt.CompareHashAndPassword([]byte(h), []byte(SharePassword)) == nil
			},
			"password_sealed": func(v volumeDB, row map[string]any) any {
				b, ok := row["password_sealed"].([]byte)
				if !ok {
					return row["password_sealed"]
				}
				h, _ := row["password_hash"].(string)
				pw, err := sealpw.Open(v.secret, row["id"].(string), h, b)
				return err == nil && pw == SharePassword
			},
		},
	},
	"files": {
		exact: []string{"share_id", "path", "size", "sha256", "mime", "pending", "upload_session", "fold_key", "zip_crc"},
		norm: map[string]normaliser{
			"slug": func(_ volumeDB, row map[string]any) any {
				s, _ := row["slug"].(string)
				return shareid.ValidSlug(s) && s[14] == '4'
			},
			"committed_at": present("committed_at"),
			"added_at":     present("added_at"),
			"declared_at":  present("declared_at"),
		},
	},
	"folders": {exact: []string{"share_id", "path", "fold_key"}},
	// changes holds one row per run of consecutive writes to a share, so how
	// many rows a share has depends on what else the volume did between its
	// writes; TestTheJournalCoalescesAsTheServerDoes pins that. Here each
	// share's newest row is compared.
	"changes": {
		exact: []string{"owner", "share_id", "deleted"},
		norm:  map[string]normaliser{"seq": present("seq"), "at": present("at")},
	},
	"scheduled":     {empty: true},
	"share_sources": {empty: true},
	"source_paths":  {empty: true},
	"linked_slugs":  {empty: true},
	"gallery":       {empty: true},
	"visitors":      {empty: true},
	"file_links":    {empty: true},
}

// ownerStats is how an owner's owner_stats row is compared, under the same
// rule as the share tables: every column named.
var ownerStats = tableRule{exact: []string{"owner", "shares", "bytes", "committed"}}

// checkRuleColumns fails on a column of table the rule neither compares nor
// normalises, and on a name in the rule the table does not have, so a new or
// misspelled column cannot pass unseen.
func checkRuleColumns(t *testing.T, table string, rule tableRule, cols []string) {
	t.Helper()
	for _, c := range cols {
		if _, normalised := rule.norm[c]; !normalised && !slices.Contains(rule.exact, c) {
			t.Errorf("column %s.%s is neither compared nor normalised", table, c)
		}
	}
	named := slices.Clone(rule.exact)
	for c := range rule.norm {
		named = append(named, c)
	}
	for _, c := range named {
		if !slices.Contains(cols, c) {
			t.Errorf("the rule for %s names %s, which the table does not have", table, c)
		}
	}
}

// shareTableNames lists the schema's tables that hold a share's rows:
// shares itself and every table with a share_id column.
func shareTableNames(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT m.name FROM sqlite_master m WHERE m.type = 'table'
		AND (m.name = 'shares' OR EXISTS (SELECT 1 FROM pragma_table_info(m.name) c WHERE c.name = 'share_id'))
		ORDER BY m.name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func columnsOf(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// rowsOf reads a table's rows of one share, each as column to value.
func rowsOf(t *testing.T, db *sql.DB, table, id string) []map[string]any {
	t.Helper()
	key := "share_id"
	if table == "shares" {
		key = "id"
	}
	return rowsWhere(t, db, table, key, id)
}

// rowsWhere reads a table's rows whose column key holds val, each as column
// to value; a changes table's rows are cut to the newest.
func rowsWhere(t *testing.T, db *sql.DB, table, key, val string) []map[string]any {
	t.Helper()
	rows, err := db.Query(`SELECT * FROM `+table+` WHERE `+key+` = ?`, val)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		row := map[string]any{}
		for i, c := range cols {
			row[c] = vals[i]
		}
		out = append(out, row)
	}
	if table == "changes" && len(out) > 0 {
		newest := out[0]
		for _, r := range out {
			if r["seq"].(int64) > newest["seq"].(int64) {
				newest = r
			}
		}
		out = []map[string]any{newest}
	}
	return out
}

// compared renders a share's rows of one table as the rule compares them,
// sorted, one line per row.
func compared(v volumeDB, rule tableRule, rows []map[string]any) []string {
	var out []string
	for _, row := range rows {
		var parts []string
		for _, c := range rule.exact {
			parts = append(parts, fmt.Sprintf("%s=%v", c, row[c]))
		}
		for c, n := range rule.norm {
			parts = append(parts, fmt.Sprintf("%s~%v", c, n(v, row)))
		}
		sort.Strings(parts)
		out = append(out, strings.Join(parts, " "))
	}
	sort.Strings(out)
	return out
}

// tree lists a share's directory as names, types, permissions and sizes.
func tree(t *testing.T, dir, id string) []string {
	t.Helper()
	root := filepath.Join(dir, "shares", id)
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		size := int64(0)
		if fi.Mode().IsRegular() {
			size = fi.Size()
		}
		out = append(out, fmt.Sprintf("%s %v %d", filepath.ToSlash(rel), fi.Mode(), size))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func openCompared(t *testing.T, dir string) volumeDB {
	t.Helper()
	db, err := sql.Open("sqlite", fileURI(filepath.Join(dir, metadb.FileName))+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	secret, err := os.ReadFile(filepath.Join(dir, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	return volumeDB{db: db, secret: secret}
}

// TestGeneratedSharesMatchAPICreatedOnes builds one share of every kind the
// way the API's handlers build it and the same share through the
// generator, and holds the two volumes to the same rows, the same owner
// counters and the same directory trees.
func TestGeneratedSharesMatchAPICreatedOnes(t *testing.T) {
	p := NewPlan(3000, 11)
	specs := honestSpecs(t, p)
	owners := map[string]bool{}
	for _, s := range specs {
		owners[s.Owner] = true
	}

	ref := filepath.Join(t.TempDir(), "api")
	db, err := metadb.Open(ref)
	if err != nil {
		t.Fatal(err)
	}
	store, err := sharefs.Open(ref)
	if err != nil {
		t.Fatal(err)
	}
	if store.FoldsCase() {
		db.SetFoldCase(store.SamePath)
	}
	for o := range owners {
		if _, err := db.CreateUser(o, Password, metadb.RoleUser, metadb.Settings{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range specs {
		createLikeTheAPI(t, db, store, p, s)
	}
	db.Close()

	gen := filepath.Join(t.TempDir(), "gen")
	if err := os.Mkdir(gen, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := openWriter(gen, p, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if _, err := w.accounts(); err != nil {
		t.Fatal(err)
	}
	res, err := w.shares(context.Background(), len(specs), func(k int) ShareSpec { return specs[k] }, func(int) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.journal(context.Background(), res.events); err != nil {
		t.Fatal(err)
	}
	if err := w.finish(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verify(gen, res, p.Accounts); err != nil {
		t.Fatal(err)
	}

	a, b := openCompared(t, ref), openCompared(t, gen)
	tables := shareTableNames(t, a.db)
	if got := shareTableNames(t, b.db); !slices.Equal(tables, got) {
		t.Fatalf("the two volumes' schemas differ: %v and %v", tables, got)
	}
	for _, table := range tables {
		rule, ok := shareTables[table]
		if !ok {
			t.Errorf("table %s holds share rows and is not compared: name it in shareTables", table)
			continue
		}
		if rule.empty {
			continue
		}
		checkRuleColumns(t, table, rule, columnsOf(t, a.db, table))
	}
	for name := range shareTables {
		if !slices.Contains(tables, name) {
			t.Errorf("shareTables names %s, which the schema does not hold", name)
		}
	}
	for _, s := range specs {
		for _, table := range tables {
			rule := shareTables[table]
			ra, rb := rowsOf(t, a.db, table, s.ID), rowsOf(t, b.db, table, s.ID)
			if rule.empty {
				if len(ra)+len(rb) > 0 {
					t.Errorf("%v share: %s holds %d API rows and %d generated ones, want none", s.Kind, table, len(ra), len(rb))
				}
				continue
			}
			if len(ra) == 0 && table != "folders" {
				t.Errorf("%v share: the API left no %s row", s.Kind, table)
			}
			ca, cb := compared(a, rule, ra), compared(b, rule, rb)
			if !slices.Equal(ca, cb) {
				t.Errorf("%v share %s: %s rows differ\n api: %v\n gen: %v", s.Kind, s.ID, table, ca, cb)
			}
		}
		if ta, tb := tree(t, ref, s.ID), tree(t, gen, s.ID); !slices.Equal(ta, tb) {
			t.Errorf("%v share %s: directories differ\n api: %v\n gen: %v", s.Kind, s.ID, ta, tb)
		}
	}
	checkRuleColumns(t, "owner_stats", ownerStats, columnsOf(t, a.db, "owner_stats"))
	for o := range owners {
		ra, rb := rowsWhere(t, a.db, "owner_stats", "owner", o), rowsWhere(t, b.db, "owner_stats", "owner", o)
		if len(ra) != 1 {
			t.Errorf("owner_stats holds %d API rows of %s, want one", len(ra), o)
		}
		if ca, cb := compared(a, ownerStats, ra), compared(b, ownerStats, rb); !slices.Equal(ca, cb) {
			t.Errorf("owner_stats of %s differ\n api: %v\n gen: %v", o, ca, cb)
		}
	}
}

// TestTheJournalCoalescesAsTheServerDoes replays one order of writes to two
// shares through metadb and through the generator's journal, and holds
// both to the same rows, in the same order; then holds the generator's
// prune to the server's answer for a cursor older than what it kept.
func TestTheJournalCoalescesAsTheServerDoes(t *testing.T) {
	p := NewPlan(300, 5)
	x, y := p.Share(0), p.Share(1)
	writes := []ShareSpec{x, y, x, x, y, x, y, y, x}

	ref := t.TempDir()
	db, err := metadb.Open(ref)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, o := range slices.Compact([]string{x.Owner, y.Owner}) {
		if _, err := db.CreateUser(o, Password, metadb.RoleUser, metadb.Settings{}); err != nil {
			t.Fatal(err)
		}
	}
	// events answers the writes as the generator records them, an hour
	// apart with the newest ago plus an hour before the Epoch, listed newest
	// first so the journal has to put them in order itself.
	events := func(ago time.Duration) []event {
		var out []event
		for k, s := range writes {
			out = append(out, event{at: ns(p.Epoch.Add(-ago + time.Duration(k-len(writes))*time.Hour)), idx: int32(s.Index)})
		}
		slices.Reverse(out)
		return out
	}
	created := map[string]bool{}
	for k, s := range writes {
		if !created[s.ID] {
			if _, err := db.CreateShare(metadb.CreateOptions{ID: s.ID, Name: s.Name, Owner: s.Owner}); err != nil {
				t.Fatal(err)
			}
			created[s.ID] = true
		} else if _, err := db.DeclareFile(s.ID, fmt.Sprintf("f%d.txt", k), 1); err != nil {
			t.Fatal(err)
		}
	}
	want := journalIDs(t, openCompared(t, ref).db)

	gen := filepath.Join(t.TempDir(), "gen")
	if err := os.Mkdir(gen, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := openWriter(gen, p, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if err := w.journal(context.Background(), events(0)); err != nil {
		t.Fatal(err)
	}
	if got := journalIDs(t, openCompared(t, gen).db); !slices.Equal(got, want) {
		t.Fatalf("journal rows %v, the server's %v", got, want)
	}

	// The same writes a year before the Epoch are past the journal's
	// retention: the generator prunes them as housekeeping would, and a
	// cursor from before the prune is told to re-walk.
	old := filepath.Join(t.TempDir(), "old")
	if err := os.Mkdir(old, 0o700); err != nil {
		t.Fatal(err)
	}
	w2, err := openWriter(old, p, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.close()
	recent := event{at: ns(p.Epoch.Add(-time.Hour)), idx: int32(y.Index)}
	if err := w2.journal(context.Background(), append(events(365*24*time.Hour), recent)); err != nil {
		t.Fatal(err)
	}
	if got := journalIDs(t, openCompared(t, old).db); !slices.Equal(got, []string{y.ID}) {
		t.Fatalf("after the prune the journal holds %v, want only the write within the retention", got)
	}
	b, err := w2.db.Since("0", y.Owner, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Reset {
		t.Fatalf("a cursor from before the pruned journal answered %+v, want a reset", b)
	}
}

func journalIDs(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT share_id FROM changes ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

// TestFinishRefusesALogItCouldNotEmpty holds a read transaction open on the
// database while finish checkpoints it, so the checkpoint cannot empty the
// log, and holds finish to an error rather than a volume marked complete
// with its rows still in the log.
func TestFinishRefusesALogItCouldNotEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gen")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := openWriter(dir, NewPlan(300, 1), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if _, err := w.accounts(); err != nil {
		t.Fatal(err)
	}
	reader := openCompared(t, dir).db
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bulk.Exec(`INSERT INTO owner_stats(owner, shares, bytes, committed) VALUES(?, 0, 0, 0)
		ON CONFLICT(owner) DO UPDATE SET shares = shares`, w.plan.Account(0)); err != nil {
		t.Fatal(err)
	}
	if err := w.finish(); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("finish with a reader holding the log = %v, want the checkpoint's refusal", err)
	}
}

package volume

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hyperdrop/server/internal/housekeep"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

func TestMain(m *testing.M) {
	// The cheapest cost keeps account and share passwords quick to make; a
	// hash of any cost verifies the same way.
	metadb.BcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}

// snapshot lists everything under dir with its mode, size and time, so a
// test can prove a call changed nothing there.
func snapshot(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out = append(out, fmt.Sprintf("%s %v %d %d", p, fi.Mode(), fi.Size(), fi.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAGeneratedVolumeServesAsAServerWould(t *testing.T) {
	if testing.Short() {
		t.Skip("generates a 2,000-share volume")
	}
	dir := filepath.Join(t.TempDir(), "volume")
	p := NewPlan(2000, 3)
	m, err := Generate(context.Background(), Options{Dir: dir, Plan: p, Workers: 8})
	if err != nil {
		t.Fatal(err)
	}
	files, byKind := p.Totals()
	if !m.Complete || m.Shares != int64(p.Shares) || m.Files != files || len(m.Accounts) != p.Accounts {
		t.Fatalf("manifest: complete %v, %d shares, %d files, %d accounts; want %d shares, %d files, %d accounts",
			m.Complete, m.Shares, m.Files, len(m.Accounts), p.Shares, files, p.Accounts)
	}
	if read, err := ReadManifest(dir); err != nil || !read.Complete || read.Files != files || read.Plan != p {
		t.Fatalf("ReadManifest: complete %v, %d files, plan %+v, %v; want the plan %+v", read.Complete, read.Files, read.Plan, err, p)
	}

	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := sharefs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	largest, owned := p.Largest()
	listed := 0
	for _, kind := range []string{"", "receive"} {
		page, err := db.List(metadb.ListQuery{Owner: largest, Kind: kind, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		listed += page.Total
	}
	if listed != owned {
		t.Errorf("%s lists %d shares, the plan gives it %d", largest, listed, owned)
	}

	total := 0
	for _, a := range m.Accounts {
		u, err := db.UserByToken(a.Token, metadb.ClientInfo{})
		if err != nil || u.Username != a.Name {
			t.Errorf("token of %s: %q, %v", a.Name, u.Username, err)
		}
		if u.Role != metadb.RoleUser {
			t.Errorf("%s is %s, want a user", a.Name, u.Role)
		}
		if a.Name == largest && a.Shares != owned {
			t.Errorf("manifest gives %s %d shares, the plan %d", a.Name, a.Shares, owned)
		}
		total += a.Shares
	}
	if total != p.Shares {
		t.Errorf("the manifest's accounts own %d shares, want %d", total, p.Shares)
	}
	for _, i := range []int{0, p.Accounts - 1} {
		if _, err := db.Authenticate(p.Account(i), Password); err != nil {
			t.Errorf("account %s does not sign in with Password: %v", p.Account(i), err)
		}
	}

	// A year of history leaves only the journal's retention: a client with
	// nothing is told to re-walk, as on any server older than that.
	if b, err := db.Since("0", largest, 10); err != nil || !b.Reset {
		t.Errorf("a walk of the journal from zero answered %+v, %v; want a reset", b, err)
	}

	// The pass's clock decides what is due: every share whose expiry is
	// past it, which on the day the volume is generated is the Expired kind.
	now := time.Now()
	var expired []string
	for i := 0; i < p.Shares; i++ {
		if s := p.Share(i); !s.ExpiresAt.IsZero() && s.ExpiresAt.Before(now) {
			expired = append(expired, s.ID)
		}
	}
	if len(expired) != byKind[Expired] {
		t.Errorf("%d shares are due at %v, the plan has %d expired ones", len(expired), now, byKind[Expired])
	}
	pass := &housekeep.Pass{DB: db, FS: store, Now: func() time.Time { return now }}
	if s := pass.Integrity(context.Background()); s.Cancelled || s.Files == 0 || s.Missing != 0 {
		t.Errorf("integrity: %+v, want every stored file on disk", s)
	}
	r := pass.Run(context.Background())
	if r.Expired != len(expired) || r.ExpiredErr != nil {
		t.Errorf("the expiry sweep removed %d shares (%v), want the %d due", r.Expired, r.ExpiredErr, len(expired))
	}
	if r.Empty != 0 || r.StalledRows != 0 || r.StalledParts != 0 || r.Publishes != 0 {
		t.Errorf("the pass removed %d empty shares, %d stalled rows, %d parts, %d publishes; want none",
			r.Empty, r.StalledRows, r.StalledParts, r.Publishes)
	}
	for _, id := range expired {
		if _, err := db.Share(id); !errors.Is(err, metadb.ErrNotFound) {
			t.Errorf("expired share %s: %v, want it gone", id, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "shares", id)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("expired share %s's directory: %v, want it gone", id, err)
		}
	}
	ids, err := db.ShareIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != p.Shares-len(expired) {
		t.Errorf("%d shares remain, want %d", len(ids), p.Shares-len(expired))
	}

	before := snapshot(t, filepath.Join(dir, "shares"))
	if _, err := Generate(context.Background(), Options{Dir: dir, Plan: p}); !errors.Is(err, ErrExists) {
		t.Errorf("generating into a complete volume: %v, want ErrExists", err)
	}
	if after := snapshot(t, filepath.Join(dir, "shares")); !slices.Equal(before, after) {
		t.Error("a refused generate changed the volume")
	}
}

// TestEveryAccountSignsInAndHoldsItsToken covers the accounts past the
// ones metadb.CreateUser makes, which carry a copy of the first one's hash.
func TestEveryAccountSignsInAndHoldsItsToken(t *testing.T) {
	p := NewPlan(300, 1)
	p.Accounts = signedInAccounts + 5
	dir := filepath.Join(t.TempDir(), "volume")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := openWriter(dir, p, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	accounts, err := w.accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != p.Accounts {
		t.Fatalf("%d accounts, want %d", len(accounts), p.Accounts)
	}
	// A copied-hash account's row is a CreateUser row in every column but
	// its name and creation time.
	v := openCompared(t, dir)
	cols := columnsOf(t, v.db, "users")
	rule := tableRule{
		exact: []string{"password_hash", "role", "disabled", "account_expires_at", "quota_bytes", "no_embed",
			"totp_secret", "totp_confirmed_at", "totp_last_step", "invite_hash", "invite_expires_at", "totp_pending"},
		norm: map[string]normaliser{"username": present("username"), "created_at": present("created_at")},
	}
	checkRuleColumns(t, "users", rule, cols)
	user := func(name string) []string {
		row := map[string]any{}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := v.db.QueryRow(`SELECT * FROM users WHERE username = ?`, name).Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, c := range cols {
			row[c] = vals[i]
		}
		return compared(v, rule, []map[string]any{row})
	}
	if made, copied := user(p.Account(0)), user(p.Account(p.Accounts-1)); !slices.Equal(made, copied) {
		t.Errorf("a copied-hash account differs from a created one:\n created %v\n copied  %v", made, copied)
	}
	for _, a := range accounts {
		if _, err := w.db.Authenticate(a.Name, Password); err != nil {
			t.Errorf("%s does not sign in with Password: %v", a.Name, err)
		}
		if u, err := w.db.UserByToken(a.Token, metadb.ClientInfo{}); err != nil || u.Username != a.Name || u.Role != metadb.RoleUser {
			t.Errorf("token of %s: %q %q, %v", a.Name, u.Username, u.Role, err)
		}
	}
}

func TestGenerateRefusesAPlanFarFromToday(t *testing.T) {
	for _, days := range []int{-8, 8} {
		dir := filepath.Join(t.TempDir(), "volume")
		p := NewPlanAt(300, 1, time.Now().AddDate(0, 0, days))
		if _, err := Generate(context.Background(), Options{Dir: dir, Plan: p}); err == nil || !strings.Contains(err.Error(), "epoch") {
			t.Errorf("a plan %d days from today: %v, want a refusal naming the epoch", days, err)
		}
		if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a refused plan %d days from today created %s: %v", days, dir, err)
		}
	}
}

func TestGenerateRefusesADirectoryItDidNotCreate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hyperdrop.db"), []byte("a real server's database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "shares", "a123456789", "files"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	_, err := Generate(context.Background(), Options{Dir: dir, Plan: NewPlan(300, 1)})
	if !errors.Is(err, ErrNotOurs) {
		t.Fatalf("Generate into a foreign directory: %v, want ErrNotOurs", err)
	}
	if after := snapshot(t, dir); !slices.Equal(before, after) {
		t.Fatalf("a refused generate changed the directory:\nbefore %v\nafter  %v", before, after)
	}
	if _, err := ReadManifest(dir); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("ReadManifest of a foreign directory: %v, want ErrNotOurs", err)
	}
}

func TestAnInterruptedVolumeIsRefusedByName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "volume")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Generate(ctx, Options{Dir: dir, Plan: NewPlan(300, 1), Progress: func(int, int) { cancel() }})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled generate answered %v", err)
	}
	m, err := readMarker(dir)
	if err != nil || m.Complete {
		t.Fatalf("marker after a cancel: complete %v, %v; want an incomplete marker", m.Complete, err)
	}
	if _, err := ReadManifest(dir); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("ReadManifest: %v, want ErrIncomplete", err)
	}
	before := snapshot(t, dir)
	_, err = Generate(context.Background(), Options{Dir: dir, Plan: NewPlan(300, 1)})
	if !errors.Is(err, ErrIncomplete) || !strings.Contains(err.Error(), dir) {
		t.Fatalf("generating into an interrupted volume: %v, want ErrIncomplete naming %s", err, dir)
	}
	if after := snapshot(t, dir); !slices.Equal(before, after) {
		t.Fatal("a refused generate changed the interrupted volume")
	}
}

func TestProjectFollowsTheFiles(t *testing.T) {
	small := Manifest{Plan: NewPlan(1000, 1), Files: 100_000, DiskBytes: 1 << 30, Inodes: 110_000, Took: time.Minute}
	large := Manifest{Plan: NewPlan(10000, 1), Files: 600_000, DiskBytes: 6 << 30, Inodes: 610_000, Took: 6 * time.Minute}
	files, _ := NewPlan(100000, 1).Totals()
	got := Project(large, small, 100000)
	line := func(s, l int64) int64 { return l + (l-s)*(files-large.Files)/(large.Files-small.Files) }
	want := Projection{Shares: 100000, Files: files, DiskBytes: line(small.DiskBytes, large.DiskBytes),
		Inodes: line(small.Inodes, large.Inodes), Took: time.Duration(line(int64(small.Took), int64(large.Took)))}
	near := func(a, b int64) bool { return a-b < 2 && b-a < 2 }
	if got.Shares != want.Shares || got.Files != want.Files || !near(got.DiskBytes, want.DiskBytes) ||
		!near(got.Inodes, want.Inodes) || !near(int64(got.Took), int64(want.Took)) {
		t.Fatalf("Project: %+v, want %+v", got, want)
	}
}

// TestNoBlobFileTakesMoreLinksThanTheLimit links many files to a few blobs
// from many goroutines with the limit lowered, and holds every blob file to
// the limit and every placed file to its blob's bytes.
func TestNoBlobFileTakesMoreLinksThanTheLimit(t *testing.T) {
	dir := t.TempDir()
	p, err := newBlobPool(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	const limit, perBlob, workers = 7, 40, 8
	p.maxLinks = limit
	blobs := []int{0, 1, 5}
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	type placed struct {
		path string
		blob int
	}
	var all []placed
	for _, k := range blobs {
		for n := range perBlob {
			all = append(all, placed{filepath.Join(out, fmt.Sprintf("%d-%d", k, n)), k})
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(all))
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; i < len(all); i += workers {
				if err := p.link(all[i].blob, all[i].path); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(filepath.Join(dir, blobDirName))
	if err != nil {
		t.Fatal(err)
	}
	var sources []os.FileInfo
	for _, e := range entries {
		fi, err := os.Stat(filepath.Join(dir, blobDirName, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, fi)
	}
	links := map[string]int{}
	for _, f := range all {
		got, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, p.content[f.blob]) {
			t.Fatalf("%s does not hold blob %d's bytes", f.path, f.blob)
		}
		fi, err := os.Stat(f.path)
		if err != nil {
			t.Fatal(err)
		}
		source := ""
		for _, s := range sources {
			if os.SameFile(fi, s) {
				source = s.Name()
			}
		}
		if source == "" {
			t.Fatalf("%s is not a link to any file of %s", f.path, blobDirName)
		}
		if !strings.HasPrefix(source, fmt.Sprintf("blob-%02d", f.blob)) {
			t.Fatalf("%s of blob %d links to %s", f.path, f.blob, source)
		}
		links[source]++
	}
	for source, n := range links {
		if n > limit {
			t.Fatalf("%s took %d links, over the limit of %d", source, n, limit)
		}
	}
	if want := len(blobs) * ((perBlob + limit - 1) / limit); len(links) != want {
		t.Fatalf("the links went to %d blob files, want %d: %v", len(links), want, links)
	}
}

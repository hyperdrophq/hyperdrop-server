package volume

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/mimetype"
	"hyperdrop/server/internal/sealpw"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// Options is one generation: the plan to write into Dir, how many
// goroutines lay files on disk (0 = one per CPU), and an optional progress
// report of shares written out of the plan's total, called from one
// goroutine at a time.
type Options struct {
	Dir      string
	Plan     Plan
	Workers  int
	Progress func(done, total int)
}

const (
	// signedInAccounts are created through metadb.CreateUser, each with its
	// own bcrypt of Password; the rest carry a copy of the first one's hash,
	// which a bcrypt hash allows: it binds the password and its own salt,
	// never the account's name.
	signedInAccounts = 20
	// txFileRows is about how many file rows one bulk transaction writes.
	txFileRows = 50000
	// rowsPerInsert is how many rows one multi-row INSERT carries.
	rowsPerInsert = 100
	// epochSlack is how far a plan's Epoch may lie from the day it is
	// generated: a volume describes a year of use ending at its Epoch, and a
	// server pruning its journal by its own clock would discard the history
	// of a plan much older than that.
	epochSlack = 7 * 24 * time.Hour
	// commitStep is how long after the previous one each file of an
	// uploading share commits: the batch route's pace for small files.
	commitStep = 20 * time.Millisecond
	// sendersPer is how many of an inbox's files one sender uploads.
	sendersPer = 25
	// blobDirName holds the blob pool every stored file is placed from.
	blobDirName = "loadrig-blobs"
	tokenLabel  = "loadrig"
)

// Generate writes the plan into o.Dir as a data directory a server opens
// as its own: the schema metadb.Open creates, accounts with one token each,
// and every planned share with its rows, its change journal and its files
// on disk. It refuses a directory it did not create (ErrNotOurs), one whose
// earlier generation did not finish (ErrIncomplete) and one that already
// holds a volume (ErrExists), before changing anything there, and a plan
// whose Epoch is more than epochSlack from now before touching the disk.
// It removes nothing. A generation that stops for any reason leaves the
// marker incomplete.
func Generate(ctx context.Context, o Options) (Manifest, error) {
	if o.Dir == "" || o.Plan.Shares <= 0 || o.Plan.Accounts <= 0 {
		return Manifest{}, errors.New("generate: a directory and a plan of at least one share are required")
	}
	if d := time.Since(o.Plan.Epoch); d > epochSlack || d < -epochSlack {
		return Manifest{}, fmt.Errorf("generate: the plan's epoch %s is more than %d days from now: plan the volume for today",
			o.Plan.Epoch.Format(time.DateOnly), int(epochSlack/(24*time.Hour)))
	}
	workers := o.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if err := claim(o.Dir); err != nil {
		return Manifest{}, err
	}
	start := time.Now()
	m := Manifest{Plan: o.Plan, ServerVersion: buildVersion()}
	if err := writeMarker(o.Dir, m); err != nil {
		return Manifest{}, err
	}
	freeBefore, inodesBefore, measured := fsState(o.Dir)

	w, err := openWriter(o.Dir, o.Plan, workers)
	if err != nil {
		return m, err
	}
	defer w.close()
	if m.Accounts, err = w.accounts(); err != nil {
		return m, err
	}
	order := idOrder(o.Plan)
	progress := func(done int) {
		if o.Progress != nil {
			o.Progress(done, o.Plan.Shares)
		}
	}
	progress(0)
	res, err := w.shares(ctx, len(order), func(k int) ShareSpec { return o.Plan.Share(order[k]) }, progress)
	if err != nil {
		return m, err
	}
	if err := w.journal(ctx, res.events); err != nil {
		return m, err
	}
	if err := w.finish(); err != nil {
		return m, err
	}
	if m.Shares, m.Files, err = verify(o.Dir, res, len(m.Accounts)); err != nil {
		return m, err
	}
	for i := range m.Accounts {
		m.Accounts[i].Shares = res.owned[m.Accounts[i].Name]
	}
	syncAll()
	if freeAfter, inodesAfter, ok := fsState(o.Dir); ok && measured {
		m.DiskBytes, m.Inodes = freeBefore-freeAfter, inodesAfter-inodesBefore
	}
	progress(o.Plan.Shares)
	m.Took = time.Since(start)
	m.Complete = true
	if err := writeMarker(o.Dir, m); err != nil {
		return m, err
	}
	return m, nil
}

// idOrder is the plan's share indexes in the order of their ids. Rows
// written in key order append to every index the files table keeps instead
// of landing on random pages of a table far larger than any cache.
func idOrder(p Plan) []int {
	order := make([]int, p.Shares)
	for i := range order {
		order[i] = i
	}
	key := func(i int) int64 { return int64(i) * idStride % idSpace }
	slices.SortFunc(order, func(a, b int) int { return int(key(a) - key(b)) })
	return order
}

// writer writes shares into one data directory: rows through its own bulk
// connection, files through the blob pool's place.
type writer struct {
	dir     string
	plan    Plan
	workers int
	db      *metadb.DB
	bulk    *sql.DB
	pool    *blobPool
	secret  []byte
	pwHash  string
}

// openWriter opens the data directory the way a server's first boot does
// (metadb.Open creates the schema and the volume secret, sharefs.Open the
// shares directory) and readies the bulk connection and the blob pool.
func openWriter(dir string, p Plan, workers int) (*writer, error) {
	db, err := metadb.Open(dir)
	if err != nil {
		return nil, err
	}
	w := &writer{dir: dir, plan: p, workers: workers, db: db}
	store, err := sharefs.Open(dir)
	if err != nil {
		w.close()
		return nil, err
	}
	w.secret = store.Secret()
	if w.bulk, err = openBulk(dir); err != nil {
		w.close()
		return nil, err
	}
	if w.pool, err = newBlobPool(dir, p.Seed); err != nil {
		w.close()
		return nil, err
	}
	// One hash serves every password-protected share: bcrypt binds only the
	// password and the hash's own salt, and the sealed copy beside it binds
	// the share id.
	hash, err := bcrypt.GenerateFromPassword([]byte(SharePassword), metadb.BcryptCost)
	if err != nil {
		w.close()
		return nil, err
	}
	w.pwHash = string(hash)
	return w, nil
}

func (w *writer) close() {
	if w.bulk != nil {
		w.bulk.Close()
		w.bulk = nil
	}
	if w.db != nil {
		w.db.Close()
		w.db = nil
	}
}

// fileURI is path as the file: URI SQLite opens, escaped as metadb escapes
// it so a ? or # in a directory name cannot cut the pragmas off.
func fileURI(path string) string {
	return "file:" + strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path)
}

// openBulk opens the generator's own connection to the database metadb
// created. It runs with metadb's pragmas except synchronous, which is off:
// nothing is durable until finish checkpoints the log and syncs the file,
// and the marker says complete only after that. Its cache is large enough
// to hold the right-hand edge of every index while rows append to it.
func openBulk(dir string) (*sql.DB, error) {
	dsn := fileURI(filepath.Join(dir, metadb.FileName)) +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(OFF)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)" +
		"&_pragma=cache_size(-1048576)&_pragma=temp_store(MEMORY)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// accounts creates the plan's accounts, every one a user, and mints one
// token for each through metadb.
func (w *writer) accounts() ([]Account, error) {
	n := w.plan.Accounts
	for i := 0; i < min(n, signedInAccounts); i++ {
		if _, err := w.db.CreateUser(w.plan.Account(i), Password, metadb.RoleUser, metadb.Settings{}); err != nil {
			return nil, err
		}
	}
	if n > signedInAccounts {
		u, err := w.db.User(w.plan.Account(0))
		if err != nil {
			return nil, err
		}
		created := time.Now().UTC().Truncate(time.Second).UnixNano()
		err = inTx(w.bulk, func(tx *sql.Tx) error {
			ins, err := tx.Prepare(`INSERT INTO users(username, password_hash, role, created_at) VALUES(?, ?, ?, ?)`)
			if err != nil {
				return err
			}
			defer ins.Close()
			for i := signedInAccounts; i < n; i++ {
				if _, err := ins.Exec(w.plan.Account(i), u.PasswordHash, metadb.RoleUser, created); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	out := make([]Account, n)
	for i := range out {
		raw, err := w.db.MintToken(w.plan.Account(i), tokenLabel)
		if err != nil {
			return nil, err
		}
		out[i] = Account{Name: w.plan.Account(i), Token: raw}
	}
	return out, nil
}

func inTx(db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// job is one share as both halves of the writer need it.
type job struct {
	spec     ShareSpec
	folder   bool
	folders  []string
	files    []fileRow
	modified int64 // the share's last write, unix nanoseconds
	sealed   []byte
}

// fileRow is one stored file: where it is, which blob holds its bytes, and
// what its upload left on the row.
type fileRow struct {
	path      string
	blob      int
	slug      string
	declared  int64
	committed int64
	session   string
}

// event is one write the change journal records: the share at plan index
// idx changed at unix nanoseconds at.
type event struct {
	at  int64
	idx int32
}

// written is what shares wrote: the journal's events, the counts verify
// holds the database to and how many shares each account owns.
type written struct {
	shares, files int64
	events        []event
	owned         map[string]int
}

// shares writes n shares, the k-th being spec(k), and reports progress in
// shares written. One goroutine builds each share, one writes the rows and
// w.workers lay the files on disk, so the single SQL writer never waits on
// the disk.
func (w *writer) shares(ctx context.Context, n int, spec func(k int) ShareSpec, progress func(done int)) (written, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	res := written{owned: map[string]int{}}
	rows := make(chan *job, 512)
	disk := make(chan *job, 512)
	var diskDone atomic.Int64
	var wg sync.WaitGroup
	for range w.workers {
		wg.Go(func() {
			for j := range disk {
				if ctx.Err() != nil {
					continue
				}
				if err := w.place(j); err != nil {
					cancel(err)
					continue
				}
				diskDone.Add(1)
			}
		})
	}
	sqlDone := make(chan error, 1)
	go func() {
		err := w.writeRows(ctx, rows, func(done int) { progress(min(done, int(diskDone.Load()))) })
		if err != nil {
			cancel(err)
			drain(rows)
		}
		sqlDone <- err
	}()

	var buildErr error
	for k := 0; k < n && buildErr == nil; k++ {
		j, err := w.build(spec(k))
		if err != nil {
			buildErr = err
			break
		}
		res.shares++
		res.files += int64(len(j.files))
		res.owned[j.spec.Owner]++
		if j.spec.Kind == Inbox {
			for _, f := range j.files {
				res.events = append(res.events, event{f.committed, int32(j.spec.Index)})
			}
		} else {
			res.events = append(res.events, event{j.modified, int32(j.spec.Index)})
		}
		select {
		case rows <- j:
		case <-ctx.Done():
			buildErr = context.Cause(ctx)
		}
		if buildErr == nil {
			select {
			case disk <- j:
			case <-ctx.Done():
				buildErr = context.Cause(ctx)
			}
		}
	}
	close(rows)
	close(disk)
	if buildErr != nil {
		cancel(buildErr)
	}
	<-sqlDone
	wg.Wait()
	if err := context.Cause(ctx); err != nil {
		return res, err
	}
	return res, nil
}

// build is spec as the API would have left it: the rows of a share created
// with a manifest (or, for an inbox, filled by strangers' uploads) whose
// files were then uploaded one after another.
func (w *writer) build(s ShareSpec) (*job, error) {
	j := &job{spec: s, folder: folderFlag(s), folders: emptyFolders(s)}
	created := s.CreatedAt
	last := created
	for k := range j.folders {
		last = created.Add(time.Duration(k+1) * time.Millisecond)
	}
	j.files = make([]fileRow, s.Files)
	for f := range j.files {
		name := w.plan.FileName(s, f)
		blob := pickBlob(w.plan.Seed, s.Index, f, name)
		at := commitTime(w.plan, s, f, len(j.folders))
		declared := created
		session := ""
		if s.Kind == Inbox {
			declared, session = at, sender(w.plan.Seed, s.Index, f)
		}
		if s.Kind == Gallery {
			if mt := w.pool.mime(blob, name); !mimetype.GalleryPlayable(mt) {
				return nil, fmt.Errorf("gallery file %s sniffs as %q, which no browser plays", name, mt)
			}
		}
		j.files[f] = fileRow{path: name, blob: blob, slug: slug(w.plan.Seed, s.Index, f),
			declared: ns(declared), committed: ns(at), session: session}
		if at.After(last) {
			last = at
		}
	}
	j.modified = ns(last)
	if s.Kind == Protected {
		sealed, err := sealpw.Seal(w.secret, s.ID, w.pwHash, SharePassword)
		if err != nil {
			return nil, err
		}
		j.sealed = sealed
	}
	return j, nil
}

func ns(t time.Time) int64 { return t.UTC().UnixNano() }

// folderFlag is the folder field a client sends: a share of several files
// reads as a folder, a share of one file, a note or an inbox does not.
func folderFlag(s ShareSpec) bool {
	return s.Kind == Folders || (s.Files > 1 && s.Kind != Inbox && s.Kind != Text)
}

// emptyFolders are the explicit folder records a Folders share carries: the
// empty folders of the tree it was shared from.
func emptyFolders(s ShareSpec) []string {
	if s.Kind != Folders {
		return nil
	}
	return []string{"alpha/empty", "café/drafts", "misc/empty"}
}

// commitTime is when file f of s committed. An uploading share's files
// commit one after another right after its creation and its folder records;
// an inbox's arrive spread from its creation to just before the plan's
// Epoch.
func commitTime(p Plan, s ShareSpec, f, folders int) time.Time {
	created := s.CreatedAt
	if s.Kind != Inbox {
		return created.Add(time.Duration(folders)*time.Millisecond + time.Duration(f+1)*commitStep)
	}
	start, end := created.Add(time.Minute), p.Epoch.Add(-time.Minute)
	if least := start.Add(time.Duration(s.Files+1) * commitStep); end.Before(least) {
		end = least
	}
	span := int64(end.Sub(start))
	return start.Add(time.Duration(span / int64(s.Files+1) * int64(f+1)))
}

// Salts keep the generator's derived values apart from each other and from
// the plan's.
const (
	saltBlob uint64 = (iota + 1) << 40
	saltSlug
	saltSender
	saltContent
)

// slug is file f's public token: a UUIDv4 derived from the seed, so a
// volume regenerated from one seed hands out the same links.
func slug(seed int64, i, f int) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], mix(seed, i, saltSlug+uint64(2*f)))
	binary.BigEndian.PutUint64(b[8:], mix(seed, i, saltSlug+uint64(2*f+1)))
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// sender is the grouping token the inbox page minted for whoever uploaded
// file f: 22 base64url characters, one sender per sendersPer files.
func sender(seed int64, i, f int) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], mix(seed, i, saltSender+uint64(2*(f/sendersPer))))
	binary.BigEndian.PutUint64(b[8:], mix(seed, i, saltSender+uint64(2*(f/sendersPer)+1)))
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// writeRows writes every job's rows through the bulk connection, in
// transactions of about txFileRows file rows, and reports the shares
// committed after each. On an error it rolls back and returns; the caller
// drains what is still queued.
func (w *writer) writeRows(ctx context.Context, jobs <-chan *job, progress func(done int)) (err error) {
	conn, err := w.bulk.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer func() {
		if err != nil {
			conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	ins, err := newInserter(ctx, conn)
	if err != nil {
		return err
	}
	defer ins.close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	done, inTx := 0, 0
	for j := range jobs {
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		if err := w.insertShare(ctx, ins, j); err != nil {
			return fmt.Errorf("share %s: %w", j.spec.ID, err)
		}
		done++
		if inTx += len(j.files) + 1; inTx >= txFileRows {
			if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
				return err
			}
			progress(done)
			if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
				return err
			}
			inTx = 0
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	progress(done)
	return nil
}

func drain(jobs <-chan *job) {
	for range jobs {
	}
}

// insertShare writes one share's row, then its folder records and files:
// the share row first, so the files triggers find it and keep its counters
// and the owner's.
func (w *writer) insertShare(ctx context.Context, ins *inserter, j *job) error {
	s := j.spec
	var pw, sealed, expires any
	if s.Kind == Protected {
		pw, sealed = w.pwHash, j.sealed
	}
	if !s.ExpiresAt.IsZero() {
		expires = ns(s.ExpiresAt)
	}
	if _, err := ins.share.ExecContext(ctx, s.ID, s.Owner, s.Name, strings.ToLower(s.Name), j.folder,
		s.Kind == Gallery, s.Kind == Inbox, s.Kind == Text, pw, sealed, ns(s.CreatedAt), j.modified, expires); err != nil {
		return err
	}
	for _, p := range j.folders {
		if _, err := ins.folder.ExecContext(ctx, s.ID, p, shareid.FoldPath(p)); err != nil {
			return err
		}
	}
	args := make([]any, 0, rowsPerInsert*fileCols)
	for at := 0; at < len(j.files); at += rowsPerInsert {
		chunk := j.files[at:min(at+rowsPerInsert, len(j.files))]
		args = args[:0]
		for _, f := range chunk {
			b := w.pool.blobs[f.blob]
			args = append(args, s.ID, f.path, f.slug, b.size, b.sha256, w.pool.mime(f.blob, f.path),
				f.committed, f.committed, f.session, f.declared, shareid.FoldPath(f.path))
		}
		stmt, err := ins.files(ctx, len(chunk))
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return err
		}
	}
	return nil
}

// fileCols is how many values one files row of the bulk insert carries.
const fileCols = 11

// inserter holds the bulk connection's prepared statements: the columns an
// API-created share's rows hold once its uploads committed, every other
// column keeping the default CreateShare and CommitFile leave it.
type inserter struct {
	conn   *sql.Conn
	share  *sql.Stmt
	folder *sql.Stmt
	byRows map[int]*sql.Stmt
}

func newInserter(ctx context.Context, conn *sql.Conn) (*inserter, error) {
	ins := &inserter{conn: conn, byRows: map[int]*sql.Stmt{}}
	var err error
	if ins.share, err = conn.PrepareContext(ctx, `INSERT INTO shares(id, owner, name, name_lower, folder,
		media, inbox, text, password_hash, password_sealed, created_at, modified_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`); err != nil {
		return nil, err
	}
	if ins.folder, err = conn.PrepareContext(ctx, `INSERT INTO folders(share_id, path, fold_key) VALUES(?, ?, ?)`); err != nil {
		ins.close()
		return nil, err
	}
	return ins, nil
}

// files is the statement inserting n files rows at once.
func (ins *inserter) files(ctx context.Context, n int) (*sql.Stmt, error) {
	if s := ins.byRows[n]; s != nil {
		return s, nil
	}
	row := "(?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)"
	q := `INSERT INTO files(share_id, path, slug, size, sha256, mime, pending, committed_at, added_at,
		upload_session, declared_at, fold_key) VALUES ` + strings.TrimSuffix(strings.Repeat(row+", ", n), ", ")
	s, err := ins.conn.PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	ins.byRows[n] = s
	return s, nil
}

func (ins *inserter) close() {
	for _, s := range []*sql.Stmt{ins.share, ins.folder} {
		if s != nil {
			s.Close()
		}
	}
	for _, s := range ins.byRows {
		s.Close()
	}
}

// place lays one share's directory out as its uploads left it: files/ with
// every stored file, and the empty parts/ its staging left behind. Modes are
// the ones sharefs creates them with.
func (w *writer) place(j *job) error {
	root := filepath.Join(w.dir, "shares", j.spec.ID)
	files := filepath.Join(root, "files")
	for _, d := range []string{root, filepath.Join(root, "parts"), files} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return err
		}
	}
	made := map[string]bool{files: true}
	for _, f := range j.files {
		dst := filepath.Join(files, filepath.FromSlash(f.path))
		if d := filepath.Dir(dst); !made[d] {
			if err := os.MkdirAll(d, 0o700); err != nil {
				return err
			}
			made[d] = true
		}
		if err := w.pool.place(f.blob, dst); err != nil {
			return err
		}
	}
	return nil
}

// journal writes the change journal the volume's history leaves: one row
// per write in time order, consecutive writes to one share coalesced into
// the newest as recordChange coalesces them, and then pruned through
// metadb as a server's housekeeping prunes it, so the journal holds only
// the last metadb.ChangesRetention before the plan's Epoch and remembers
// how far it was pruned. It sorts and reuses events in place.
func (w *writer) journal(ctx context.Context, events []event) error {
	slices.SortFunc(events, func(a, b event) int {
		if a.at != b.at {
			if a.at < b.at {
				return -1
			}
			return 1
		}
		return int(a.idx - b.idx)
	})
	kept := events[:0]
	for _, e := range events {
		if n := len(kept); n > 0 && kept[n-1].idx == e.idx {
			kept[n-1] = e
			continue
		}
		kept = append(kept, e)
	}
	err := inTx(w.bulk, func(tx *sql.Tx) error {
		ins, err := tx.PrepareContext(ctx, `INSERT INTO changes(owner, share_id, deleted, at) VALUES(?, ?, 0, ?)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, e := range kept {
			s := w.plan.Share(int(e.idx))
			if _, err := ins.ExecContext(ctx, s.Owner, s.ID, e.at); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	_, err = w.db.PruneChanges(w.plan.Epoch.Add(-metadb.ChangesRetention))
	return err
}

// finish leaves the database as a server that has run on it leaves it:
// analysed by the optimize every housekeeping pass runs, the log
// checkpointed into the file and the file synced, in WAL mode.
func (w *writer) finish() error {
	if _, err := w.bulk.Exec(`PRAGMA optimize=0x10002`); err != nil {
		return err
	}
	if err := w.db.Optimize(); err != nil {
		return err
	}
	// The checkpoint answers one row: busy is 1 when a reader kept it from
	// copying the whole log into the file and emptying the log.
	var busy, logFrames, checkpointed int
	if err := w.bulk.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		return err
	}
	if busy != 0 {
		return fmt.Errorf("the checkpoint of the database's log did not finish: %d of %d frames copied", checkpointed, logFrames)
	}
	w.close()
	f, err := os.Open(filepath.Join(w.dir, metadb.FileName))
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// blobCount is the size of the blob pool: four flavours of content, each in
// sixteen sizes from 1 KiB to 256 KiB.
const (
	blobCount = 64
	flavours  = 4
	blobSizes = blobCount / flavours
)

// maxLinksPerBlob is how many hard links the pool makes to one blob file
// before it writes a fresh copy of the blob and links to that: ext4 allows
// 65,000 links to an inode.
const maxLinksPerBlob = 50000

// The flavours: the bytes a file of each extension starts with, so what
// mimetype.Detect sniffs agrees with the name even on a box whose mime
// table does not know the extension.
const (
	flavourText = iota // printable words
	flavourJPEG        // a JPEG start of image, then noise
	flavourPNG         // a PNG signature, then noise
	flavourMP4         // an MP4 ftyp box, then noise
)

type blob struct {
	path   string
	size   int64
	sha256 string
}

// blobFile is the file the next hard link to one blob is made to: path is
// the blob's own file while copies is 0 and its newest copy after, and links
// is how many links have been made to that file.
type blobFile struct {
	mu     sync.Mutex
	path   string
	copies int
	links  int
}

// blobPool is the files every stored file is placed from, and the type
// mimetype.Detect gives each blob under each extension.
type blobPool struct {
	blobs   [blobCount]blob
	content [blobCount][]byte
	files   [blobCount]blobFile
	// maxLinks is how many links one blob file takes: maxLinksPerBlob, or
	// less in a test.
	maxLinks int
	mu       sync.Mutex
	mimes    map[string]string
}

// newBlobPool writes the pool under <dir>/loadrig-blobs.
func newBlobPool(dir string, seed int64) (*blobPool, error) {
	p := &blobPool{mimes: map[string]string{}, maxLinks: maxLinksPerBlob}
	bdir := filepath.Join(dir, blobDirName)
	if err := os.Mkdir(bdir, 0o700); err != nil {
		return nil, err
	}
	for k := range p.blobs {
		c := blobContent(seed, k)
		sum := sha256.Sum256(c)
		path := filepath.Join(bdir, fmt.Sprintf("blob-%02d", k))
		if err := os.WriteFile(path, c, 0o600); err != nil {
			return nil, err
		}
		p.blobs[k] = blob{path: path, size: int64(len(c)), sha256: hex.EncodeToString(sum[:])}
		p.content[k] = c
		p.files[k].path = path
	}
	return p, nil
}

// place makes dst a file holding blob k's bytes: a clone where the file
// system makes one, otherwise a hard link through link.
func (p *blobPool) place(k int, dst string) error {
	if cloned, err := cloneFile(p.blobs[k].path, dst); cloned || err != nil {
		return err
	}
	return p.link(k, dst)
}

// link makes dst a hard link to a file holding blob k's bytes. Once a blob
// file has taken maxLinks links, it writes the next copy of the blob,
// loadrig-blobs/blob-<k>-<n>, and links to that from then on. Safe for
// concurrent use.
func (p *blobPool) link(k int, dst string) error {
	f := &p.files[k]
	f.mu.Lock()
	if f.links >= p.maxLinks {
		f.copies++
		path := fmt.Sprintf("%s-%d", p.blobs[k].path, f.copies)
		if err := os.WriteFile(path, p.content[k], 0o600); err != nil {
			f.mu.Unlock()
			return err
		}
		f.path, f.links = path, 0
	}
	f.links++
	src := f.path
	f.mu.Unlock()
	return os.Link(src, dst)
}

// mime is what mimetype.Detect answers for blob k stored under name, which
// is what a commit of those bytes under that name records.
func (p *blobPool) mime(k int, name string) string {
	key := fmt.Sprintf("%d%s", k, path.Ext(name))
	p.mu.Lock()
	defer p.mu.Unlock()
	mt, ok := p.mimes[key]
	if !ok {
		mt = mimetype.Detect(bytes.NewReader(p.content[k]), path.Base(name))
		p.mimes[key] = mt
	}
	return mt
}

// blobSize is blob k's size: sixteen steps, evenly spaced in log, from
// 1 KiB to 256 KiB.
func blobSize(k int) int {
	step := k / flavours
	return int(math.Round(1024 * math.Pow(2, 8*float64(step)/float64(blobSizes-1))))
}

// flavourOf is the flavour of bytes a file named name holds.
func flavourOf(name string) int {
	switch path.Ext(name) {
	case ".txt", ".md":
		return flavourText
	case ".jpg", ".jpeg":
		return flavourJPEG
	case ".png":
		return flavourPNG
	}
	return flavourMP4
}

// pickBlob is the blob file f of share i is placed from: one of its
// flavour, its size drawn evenly from the sixteen.
func pickBlob(seed int64, i, f int, name string) int {
	return int(mix(seed, i, saltBlob+uint64(f))%blobSizes)*flavours + flavourOf(name)
}

// blobContent is blob k's bytes, a function of the seed.
func blobContent(seed int64, k int) []byte {
	size := blobSize(k)
	out := make([]byte, 0, size)
	switch k % flavours {
	case flavourJPEG:
		out = append(out, 0xFF, 0xD8, 0xFF, 0xE0)
	case flavourPNG:
		out = append(out, 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n')
	case flavourMP4:
		out = append(out, 0, 0, 0, 16, 'f', 't', 'y', 'p', 'm', 'p', '4', '2', 0, 0, 0, 0)
	}
	words := []string{"load", "volume", "share", "river", "harbor", "invoice", "photo", "budget", "design", "trip"}
	for n := uint64(0); len(out) < size; n++ {
		r := mix(seed, k, saltContent+n)
		if k%flavours == flavourText {
			out = append(out, words[r%uint64(len(words))]...)
			if r>>32%12 == 0 {
				out = append(out, '\n')
			} else {
				out = append(out, ' ')
			}
			continue
		}
		out = binary.LittleEndian.AppendUint64(out, r)
	}
	return out[:size]
}

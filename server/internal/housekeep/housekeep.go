package housekeep

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

const (
	// Interval is how often a pass runs.
	Interval = 5 * time.Minute
	// DeclaredLifetime is how long a pending row with nothing staged for it
	// (a manifest entry whose upload never began) is kept before the stalled
	// sweep removes it: long enough for the slowest folder upload to reach
	// its last file, short enough that a row no byte ever backs does not
	// hold the account's file limit for good.
	DeclaredLifetime = 7 * 24 * time.Hour
	// EmptyGrace is how long a share with no committed file is left alone
	// before the sweep takes it as abandoned: long enough that a slow first
	// upload, or a client that went offline mid-share, is never mistaken for
	// a crash.
	EmptyGrace = time.Hour
	// DeviceLinkMaxAge is how long a device link's row is kept after its
	// mint, whatever its state: long past its last use, which ends minutes
	// after the mint.
	DeviceLinkMaxAge = 24 * time.Hour
)

const (
	// BackupInterval is how old the newest backup may be before a pass
	// writes another.
	BackupInterval = 24 * time.Hour
	// MissingInterval is how long a count of stored files missing from disk
	// stands before the integrity scan counts again (IntegrityDue).
	MissingInterval = 24 * time.Hour
	// RecoveredMarkerAge is how long the recovered marker (a boot that
	// restored the database from a backup) stays for the health verdict.
	RecoveredMarkerAge = 7 * 24 * time.Hour
)

// Pass is one housekeeping run over a database and its file layer.
// stalledBatch bounds the pending rows one pass examines; the next pass
// continues after the last row this one examined (Pass.stalledAfter), and
// starts over from the oldest once a pass comes up short, so a volume holding
// many stays within a pass's time and memory and a row a pass keeps does not
// hide the rows behind it. A variable so a test can shorten it.
var stalledBatch = 10000

// expiryDirWorkers is how many expired shares' directories are removed at
// once, each under its own share lock (sharefs.RemoveShare).
var expiryDirWorkers = 4

type Pass struct {
	DB *metadb.DB
	FS *sharefs.FS
	// DataDir holds backups/ and the recovered marker; empty skips both.
	DataDir string
	Now     func() time.Time
	// Alive answers whether a share's sender has reported preparing one of
	// its files after since (the api's preparing tracker). A share so
	// reported on is as alive to the empty sweep as one whose part grew: the
	// bytes are still being made. Nil means no such reports exist.
	Alive func(shareID string, since time.Time) bool
	// MissingFiles, when set, receives the latest count of stored files
	// missing from disk, for the health verdict to read: the stored one
	// (LoadIntegrity), then each finished scan's (Integrity).
	MissingFiles *atomic.Int64

	// scannedAt is when this process's last integrity scan that was not
	// cancelled started, zero before one ends. It, beforeCheck and storedFiles
	// belong to the integrity scan alone, which runs beside Run in its own
	// goroutine; no step of Run reads them.
	scannedAt time.Time
	// ran is whether a Run has completed, so the next one is not the first.
	ran bool
	// stalledAfter is the last pending row the stalled sweep examined, which
	// the next pass continues after; zero starts from the oldest.
	stalledAfter metadb.PendingRef
	// beforeCheck, when set, runs before the integrity scan checks a piece
	// of one share's rows on disk: the tests' seam between reading the rows
	// and the disk.
	beforeCheck func(shareID string, rels []string)
	// storedFiles, when set, stands in for DB.EachStoredFile as the
	// integrity scan's row stream: the tests' seam for a stream that fails
	// partway.
	storedFiles func(fn func(shareID, relPath string) error) error
	// afterRows, when set, runs after a share the empty sweep removes lost
	// its rows and before its directory goes: the tests' seam between the
	// two halves.
	afterRows func(shareID string)
	// beforeExpiredDirs, when set, runs after a batch of expired shares lost
	// their rows and before any of their directories goes: the tests' seam
	// between the two halves.
	beforeExpiredDirs func(ids []string)
}

// Result is what one pass did. Counts are zero and errors nil on a quiet
// volume, which is the normal case: the caller logs only what happened, so
// an idle server says nothing.
type Result struct {
	Reservations int
	Due          int
	DueErr       error
	Expired      int
	ExpiredErr   error
	StalledParts int
	StalledRows  int
	StalledErr   error
	Publishes    int // open publishes swept after the abandoned-upload window of quiet
	// PublishesFinished counts the commits whose renames failed after their
	// rows and that this pass finished (RetryPublishes).
	PublishesFinished int
	PublishesErr      error
	Empty             int
	EmptyErr          error
	Changes           int
	ChangesErr        error
	// DeviceLinks counts the sign-in links swept a day after their mint.
	DeviceLinks    int
	DeviceLinksErr error
	// FileLinks counts the direct-link keys swept once their file was gone.
	FileLinks    int
	FileLinksErr error
	// WebSessions counts the web sessions swept past their idle or
	// absolute limit.
	WebSessions    int
	WebSessionsErr error
	// SignInEvents counts the audit rows of computers signed in by phone
	// swept metadb.SignInEventsFor after they were written.
	SignInEvents    int
	SignInEventsErr error
	// ActivitySpans counts the spans of a computer in use swept
	// metadb.ActivitySpansFor after they ended.
	ActivitySpans    int
	ActivitySpansErr error
	OptimizeErr      error
	BackedUp         bool
	BackupErr        error

	// Steps is how long each step that ran took, in run order; Took is the
	// whole pass. First is set on the process's first pass.
	Steps []Step
	Took  time.Duration
	First bool
	// ExpiryRows and ExpiryDirs are how much of the expiry step went to
	// deleting the rows and to removing the directories; Steps names each
	// right after "expiry".
	ExpiryRows, ExpiryDirs time.Duration
	// Cancelled is whether the pass's context ended before the pass
	// returned: no step after that point ran, and a step it stopped inside
	// reports what it did up to there.
	Cancelled bool
}

// Step is one named step of a pass and how long it took.
type Step struct {
	Name string
	Took time.Duration
}

// stepLeftOut is the shortest step Timing names.
const stepLeftOut = 10 * time.Millisecond

// Timing is the one line a pass reports about how long it took, or "" for a
// quiet pass: only the process's first pass and a pass of a second or longer
// report. Steps under 10 ms are left out.
func (r Result) Timing() string {
	if !r.First && r.Took < time.Second {
		return ""
	}
	head := "housekeeping pass: "
	if r.First {
		head = "housekeeping first pass: "
	}
	var parts []string
	for _, s := range r.Steps {
		if s.Took >= stepLeftOut {
			parts = append(parts, s.Name+" "+s.Took.Round(time.Millisecond).String())
		}
	}
	line := head + r.Took.Round(time.Millisecond).String()
	if len(parts) > 0 {
		line += " (" + strings.Join(parts, ", ") + ")"
	}
	return line
}

// Lines is what the caller logs: one line per thing that happened or
// failed, nothing on a quiet pass.
func (r Result) Lines() []string {
	var out []string
	add := func(n int, err error, did, what string) {
		if err != nil {
			out = append(out, fmt.Sprintf("%s: %v", what, err))
		} else if n > 0 {
			out = append(out, fmt.Sprintf("%s: %s %d", what, did, n))
		}
	}
	add(r.Reservations, nil, "dropped idle holds:", "reservation sweep")
	add(r.Due, r.DueErr, "applied due changes:", "scheduled changes")
	add(r.Expired, r.ExpiredErr, "removed expired shares:", "expiry sweep")
	if r.StalledErr != nil {
		out = append(out, fmt.Sprintf("stalled uploads: %v", r.StalledErr))
	} else if r.StalledParts > 0 || r.StalledRows > 0 {
		out = append(out, fmt.Sprintf("stalled uploads: dropped %d partial(s) and %d pending file(s)", r.StalledParts, r.StalledRows))
	}
	add(r.PublishesFinished, r.PublishesErr, "finished interrupted commits:", "publishes")
	add(r.Publishes, nil, "removed abandoned publishes:", "publish sweep")
	add(r.Empty, r.EmptyErr, "removed abandoned shares:", "empty sweep")
	add(r.Changes, r.ChangesErr, "pruned journal rows:", "change journal")
	add(r.DeviceLinks, r.DeviceLinksErr, "removed old links:", "device links")
	add(r.FileLinks, r.FileLinksErr, "removed keys of deleted files:", "file links")
	add(r.WebSessions, r.WebSessionsErr, "removed expired sessions:", "web sessions")
	add(r.SignInEvents, r.SignInEventsErr, "removed old records:", "sign-in records")
	add(r.ActivitySpans, r.ActivitySpansErr, "removed old spans:", "activity spans")
	if r.OptimizeErr != nil {
		out = append(out, fmt.Sprintf("optimize: %v", r.OptimizeErr))
	}
	switch {
	case errors.Is(r.BackupErr, metadb.ErrCopyDamaged):
		out = append(out, fmt.Sprintf("backup: the database's own pages are damaged (%v); the older copies are kept and <data>/%s asks for a check", r.BackupErr, metadb.CheckOwedFile))
	case r.BackupErr != nil:
		out = append(out, fmt.Sprintf("backup: %v", r.BackupErr))
	case r.BackedUp:
		out = append(out, "backup: wrote a copy of the database")
	}
	if r.Cancelled {
		out = append(out, "housekeeping: stopped for shutdown")
	}
	return out
}

func (p *Pass) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Run performs one pass. Every step asks the database or memory whether it
// has work and reads the disk only for the shares a query or that memory
// named, so a volume with nothing due costs no syscalls under shares/ and a
// NAS disk can stay spun down between requests. The integrity scan, which
// reads every stored file, is not a step: it runs in its own loop
// (Integrity). Stalled uploads are swept with their rows first, and then the
// parts no pending row leads to, which the boot pass would otherwise be the
// only one to remove; then the commits whose renames failed after their rows
// are finished, and the open publishes nothing has written to for the same
// window go. They go before empty shares, deliberately: removing a dead
// pending row or a quiet publish is what leaves a share with nothing, and the
// empty sweep then removes it in the same pass rather than an hour later.
//
// ctx stops the pass: it is checked before every step, between the expiry
// sweep's batches (and between the shares of a failed batch it judges
// again one by one), between the shares the empty sweep removes, between the
// stalled sweep's rows, and between the backup copy's page steps. A share
// whose rows went (for the expiry sweep, every share of the batch whose rows
// went) loses its directory before the next check, so a stop never leaves
// rows-less bytes the boot pass would have to find. A pass cancelled before
// it starts runs no step and leaves the next one first.
func (p *Pass) Run(ctx context.Context) Result {
	var r Result
	if ctx.Err() != nil {
		r.Cancelled = true
		return r
	}
	r.First = !p.ran
	p.ran = true
	start := time.Now()
	// step runs fn and records how long it took under name, unless ctx has
	// ended, which marks the pass cancelled and skips fn.
	step := func(name string, fn func()) {
		if ctx.Err() != nil {
			r.Cancelled = true
			return
		}
		t := time.Now()
		fn()
		r.Steps = append(r.Steps, Step{Name: name, Took: time.Since(t)})
	}
	now := p.now()
	step("reservations", func() { r.Reservations = p.FS.SweepReservations() })
	step("scheduled", func() { r.Due, r.DueErr = p.DB.ApplyDue(now) })
	step("expiry", func() { r.Expired, r.ExpiredErr = p.sweepExpired(ctx, now, &r.ExpiryRows, &r.ExpiryDirs) })
	if n := len(r.Steps); n > 0 && r.Steps[n-1].Name == "expiry" {
		r.Steps = append(r.Steps, Step{Name: "expiry-rows", Took: r.ExpiryRows}, Step{Name: "expiry-dirs", Took: r.ExpiryDirs})
	}
	step("stalled", func() {
		r.StalledParts, r.StalledRows, r.StalledErr = p.sweepStalled(ctx, now)
		if ctx.Err() == nil {
			r.StalledParts += p.FS.SweepStaleParts()
		}
	})
	step("publishes", func() {
		r.PublishesFinished, r.PublishesErr = RetryPublishes(p.DB, p.FS)
		r.Publishes = p.FS.SweepStages()
	})
	step("empty", func() { r.Empty, r.EmptyErr = p.sweepEmpty(ctx, now) })
	step("prunes", func() {
		r.Changes, r.ChangesErr = p.DB.PruneChanges(now.Add(-metadb.ChangesRetention))
		r.DeviceLinks, r.DeviceLinksErr = p.DB.PruneDeviceLinks(now.Add(-DeviceLinkMaxAge))
		r.FileLinks, r.FileLinksErr = p.DB.PruneOrphanFileLinks()
		r.WebSessions, r.WebSessionsErr = p.DB.PruneWebSessions(now)
		r.SignInEvents, r.SignInEventsErr = p.DB.PruneSignInEvents(now.Add(-metadb.SignInEventsFor))
		r.ActivitySpans, r.ActivitySpansErr = p.DB.PruneActivitySpans(now.Add(-metadb.ActivitySpansFor))
	})
	step("optimize", func() { r.OptimizeErr = p.DB.Optimize() })
	if p.DataDir != "" {
		step("backup", func() {
			r.BackedUp, r.BackupErr = p.backup(ctx, now)
			if r.BackupErr != nil && ctx.Err() != nil && !errors.Is(r.BackupErr, metadb.ErrCopyDamaged) {
				// A copy stopped by ctx is no failure to report: Backup
				// removed its part file and the older copies stand.
				r.BackupErr = nil
				return
			}
			p.expireRecovered(now)
		})
	}
	if ctx.Err() != nil {
		r.Cancelled = true
	}
	r.Took = time.Since(start)
	return r
}

// backup writes a copy when the newest one is older than BackupInterval.
// The newest copy's name carries its time, so no other state is kept. ctx
// stops a copy under way between its steps.
func (p *Pass) backup(ctx context.Context, now time.Time) (bool, error) {
	dir := filepath.Join(p.DataDir, "backups")
	if newest := metadb.NewestBackup(dir); newest != "" {
		if at := metadb.BackupTime(newest); !at.IsZero() && now.Sub(at) < BackupInterval {
			return false, nil
		}
	}
	_, err := metadb.Backup(ctx, p.DB, dir, now)
	return err == nil, err
}

// expireRecovered drops the recovered marker once it is older than
// RecoveredMarkerAge: a week is long enough for the owner to have seen the
// warning, and a boot never clears it, or a restart could hide it first.
func (p *Pass) expireRecovered(now time.Time) {
	if rec, ok := metadb.ReadRecovered(p.DataDir); ok && now.Sub(rec.At) > RecoveredMarkerAge {
		metadb.ClearRecovered(p.DataDir)
	}
}

// sweepExpired removes shares whose expiry has passed, in batches, in id
// order so each batch visits the id-keyed trees in order: a batch's rows go
// in one write transaction, each share under its own expiry re-check and
// with its own journal row (metadb.DeleteExpiredShares, bounded by
// metadb.ExpiredBatchBudget and ExpiredBatchMax), and only then do that
// batch's directories go, expiryDirWorkers at a time. A batch that fails
// rolls back whole, so its shares are judged again one transaction each
// (expireOneByOne): a share whose delete always fails then keeps only
// itself, not the shares batched with it, as the ids and so the batches are
// the same on every pass. ctx is checked only before a batch's rows, so
// every share of a batch whose rows went loses its directory too. A crash
// between a batch's rows and its directories leaves
// rowless directories, which the boot pass removes once nothing has written
// to them for the abandoned-upload window. rows and dirs receive how long
// the batches' row deletions and their directory removals took.
func (p *Pass) sweepExpired(ctx context.Context, now time.Time, rows, dirs *time.Duration) (int, error) {
	ids, err := p.DB.Expired(now)
	if err != nil {
		return 0, err
	}
	slices.Sort(ids)
	n := 0
	var errs []error
	for i := 0; i < len(ids) && ctx.Err() == nil; {
		t := time.Now()
		deleted, judged, err := p.DB.DeleteExpiredShares(ids[i:], now)
		*rows += time.Since(t)
		if judged == 0 {
			// The batch could not begin: nothing was judged, so trying the
			// same ids again would only meet the same failure.
			errs = append(errs, err)
			break
		}
		batch := ids[i : i+judged]
		i += judged
		if err != nil {
			if judged == 1 {
				errs = append(errs, err)
				continue
			}
			var failed []error
			deleted, failed = p.expireOneByOne(ctx, batch, now, rows)
			errs = append(errs, failed...)
		}
		if len(deleted) == 0 {
			continue
		}
		if p.beforeExpiredDirs != nil {
			p.beforeExpiredDirs(deleted)
		}
		t = time.Now()
		removed, err := p.removeDirs(deleted)
		*dirs += time.Since(t)
		n += removed
		if err != nil {
			errs = append(errs, err)
		}
	}
	return n, errors.Join(errs...)
}

// expireOneByOne judges the shares of a batch that failed one write
// transaction each (metadb.DeleteExpiredShare), so the failure stays with the
// share it belongs to, and answers the ids whose rows went and the failures,
// each naming its share. The caller removes the directories afterwards. ctx
// stops it between shares. rows receives how long the deletes took.
func (p *Pass) expireOneByOne(ctx context.Context, ids []string, now time.Time, rows *time.Duration) (deleted []string, errs []error) {
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		t := time.Now()
		ok, err := p.DB.DeleteExpiredShare(id, now)
		*rows += time.Since(t)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		if ok {
			deleted = append(deleted, id)
		}
	}
	return deleted, errs
}

// removeDirs removes the directories of shares whose rows already went,
// expiryDirWorkers at a time, and answers how many went.
func (p *Pass) removeDirs(ids []string) (int, error) {
	work := make(chan string)
	var (
		mu   sync.Mutex
		n    int
		errs []error
		wg   sync.WaitGroup
	)
	for range min(max(expiryDirWorkers, 1), len(ids)) {
		wg.Go(func() {
			for id := range work {
				err := p.FS.RemoveShare(id)
				mu.Lock()
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", id, err))
				} else {
					n++
				}
				mu.Unlock()
			}
		})
	}
	for _, id := range ids {
		work <- id
	}
	close(work)
	wg.Wait()
	return n, errors.Join(errs...)
}

// removeShares deletes each share's rows through del, which re-tests the
// sweep's condition inside its write transaction and answers false when it no
// longer holds, and only then removes the share's directory. It answers how
// many shares went. ctx is checked only before a share's rows, so a share
// whose rows went always loses its directory too.
func (p *Pass) removeShares(ctx context.Context, ids []string, del func(id string) (bool, error)) (int, error) {
	n := 0
	var errs []error
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		ok, err := del(id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !ok {
			continue
		}
		if p.afterRows != nil {
			p.afterRows(id)
		}
		if err := p.FS.RemoveShare(id); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// sweepStalled clears the staging of uploads that stopped: a pending row
// declared more than the window ago loses the file it names, its part and
// its row when its part has not been written for the window, or when a
// final file already stands under files/ for it, which is a commit that
// renamed the part in and then failed to record its row and so leaves
// bytes nothing serves. The share then stops telling visitors a file is
// still uploading when nothing is.
//
// Two rows stay. One whose part is fresh is a live upload. One with
// neither a part nor a file has nothing staged to clear: the client that
// declared it may not have sent a byte yet and its slug may already be in a
// link, so it stays for DeclaredLifetime, and goes once that has passed
// since it was declared, since a row no byte ever backs would otherwise
// hold the account's file limit (metadb.checkPendingLimit) for good. The
// candidate list is bounded (stalledBatch), oldest first.
//
// The candidates are a snapshot, so the removal re-checks under the path's
// lock that the row is still pending and its part still quiet: an upload
// resumed or committed since (a commit renames and writes its row under
// that lock) keeps its bytes.
//
// ctx stops the sweep between rows; the next pass then continues after the
// last row this one examined.
func (p *Pass) sweepStalled(ctx context.Context, now time.Time) (parts, rows int, err error) {
	window := p.FS.AbandonedUploadWindow()
	from := p.stalledAfter
	refs, err := p.DB.PendingFiles(now.Add(-window), from, stalledBatch)
	if err != nil {
		return 0, 0, err
	}
	if len(refs) < stalledBatch {
		p.stalledAfter = metadb.PendingRef{}
	} else {
		p.stalledAfter = refs[len(refs)-1]
	}
	var errs []error
	for i, ref := range refs {
		if ctx.Err() != nil {
			p.stalledAfter = from
			if i > 0 {
				p.stalledAfter = refs[i-1]
			}
			break
		}
		staged := false
		if age, ok := p.FS.PartAge(ref.ShareID, ref.Path); ok {
			if age < window {
				continue
			}
			staged = true
		} else if _, err := p.FS.Stat(ref.ShareID, ref.Path); err != nil {
			if now.Sub(ref.DeclaredAt) < DeclaredLifetime {
				continue
			}
			// Nothing staged and nothing served: only the row goes, decided
			// under the path's lock like the removal below, so an upload
			// that stages its part this instant keeps its row. A commit since
			// the snapshot has set pending = 0, which RemovePending leaves
			// alone.
			bare, err := p.FS.RemoveFileIf(ref.ShareID, ref.Path, func() bool {
				if f, err := p.DB.File(ref.ShareID, ref.Path); err != nil || !f.Pending {
					return false
				}
				if _, ok := p.FS.PartAge(ref.ShareID, ref.Path); ok {
					return false
				}
				_, err := p.FS.Stat(ref.ShareID, ref.Path)
				return err != nil
			})
			if err != nil {
				errs = append(errs, fmt.Errorf("%s/%s: %w", ref.ShareID, ref.Path, err))
				continue
			}
			if !bare {
				continue
			}
			if err := p.DB.RemovePending(ref.ShareID, ref.Path); err != nil {
				errs = append(errs, fmt.Errorf("%s/%s: %w", ref.ShareID, ref.Path, err))
				continue
			}
			rows++
			continue
		}
		// The file goes before the row: a removal that fails leaves the row
		// for the next pass to try again, where dropping the row first would
		// strand the bytes with nothing naming them.
		removed, err := p.FS.RemoveFileIf(ref.ShareID, ref.Path, func() bool {
			if f, err := p.DB.File(ref.ShareID, ref.Path); err != nil || !f.Pending {
				return false
			}
			age, ok := p.FS.PartAge(ref.ShareID, ref.Path)
			return !ok || age >= window
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", ref.ShareID, ref.Path, err))
			continue
		}
		if !removed {
			continue
		}
		if staged {
			parts++
		}
		if err := p.DB.RemovePending(ref.ShareID, ref.Path); err != nil {
			errs = append(errs, fmt.Errorf("%s/%s: %w", ref.ShareID, ref.Path, err))
			continue
		}
		rows++
	}
	return parts, rows, errors.Join(errs...)
}

// sweepEmpty removes shares that never received a file, past the grace: an
// inbox waits empty by design, a linked share holds no uploads by
// construction, a share with folder records is being built, and a share with
// fresh staging (a part, or an open publish written within the window) is a
// transfer that may still resume. The database re-tests the first three
// inside the delete; the file layer answers the last.
func (p *Pass) sweepEmpty(ctx context.Context, now time.Time) (int, error) {
	cutoff := now.Add(-EmptyGrace)
	ids, err := p.DB.EmptyShares(cutoff)
	if err != nil {
		return 0, err
	}
	return p.removeShares(ctx, ids, func(id string) (bool, error) {
		if p.FS.HasRecentPart(id, p.FS.AbandonedUploadWindow()) {
			return false, nil
		}
		if p.Alive != nil && p.Alive(id, cutoff) {
			return false, nil
		}
		return p.DB.DeleteEmptyShare(id, cutoff)
	})
}

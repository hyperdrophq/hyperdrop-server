package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sealpw"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// Duplicating a share (POST /api/shares/{id}/duplicate): the route decides
// and writes the copy's rows in one transaction (metadb.DuplicateShare), its
// files pending under new slugs and the share marked copying_from, answers
// 201, and hands the bytes to the copy line. The line stages each stored
// file beside its pending row (sharefs.StageCopy, a clone where the
// filesystem makes one) and commits it through the upload commit
// (commitWith), so its triggers, journal row and quota charge are an
// upload's; then it copies the tiles and the poster and clears the mark. A
// copy that fails is deleted whole, rows then directory; one a shutdown
// stops is left marked, and the boot pass removes it
// (RemoveUnfinishedCopies), so a half copy is never left for the owner.
//
// While a copy is waiting or running, what its original holds is frozen:
// every content edit of the original (its delete, a file's delete, a move,
// an upload or replace, a publish) is refused 409 copy-in-progress
// (copyRefusal), and so is every content edit of the copy itself, whose
// files are the worker's; a metadata edit applies to both. The
// copy itself can still be deleted: its worker then drops the rest of the
// job. The worker reads its work from the database a page at a time
// (metadb.CopyJobs), so the line holds ids and counts, never a share's
// entries.

// stageCopy stages one stored file's copy; a test stands in a failure.
var stageCopy = (*sharefs.FS).StageCopy

// copyJobsPage is how many entries the worker reads from the database at a
// time; a test pages it smaller.
var copyJobsPage = 500

// duplicateBodyLimit bounds the request body: a name and a flag.
const duplicateBodyLimit = 4 << 10

// The copy line's bounds. One copy runs per owner and copyMaxRunning at once;
// the rest wait in memory, at most copyMaxWaiting in all and
// copyMaxWaitingPerOwner for one account, so no account fills the line, and
// at most copyMaxWaitingEntries file entries between them, past the first
// (counted from the original's row: a waiting copy holds only ids, and the
// bound keeps the line's wait in proportion to the work it has taken on). A
// duplicate past a bound is refused 503 busy before anything is written. Nothing waits on a request: the route
// answers at once and the copy fills in like an upload.
const (
	copyMaxRunning         = 2
	copyMaxWaiting         = 32
	copyMaxWaitingPerOwner = 4
	copyMaxWaitingEntries  = 200000
)

// copyStopWait is how long a shutdown waits for the running copies to stop.
// A copy stops between files; one still in its file at the deadline dies
// with the process, and the boot pass removes its share.
const copyStopWait = 10 * time.Second

// errCopyBusy is the copy line refusing another copy.
var errCopyBusy = errors.New("the server is copying other shares")

// errCopyInProgress refuses a content edit of a share a copy is reading or of
// a copy still being made.
var errCopyInProgress = refuse(http.StatusConflict, "copy-in-progress",
	"a copy of this share is still being made: try again when it has finished")

// errCopyChanged is a copied file that is not the bytes the original's row
// names: the original was replaced since the duplicate was asked for.
var errCopyChanged = errors.New("the original changed while it was copied")

// errDuplicateUnsupported answers an inbox and a live share.
var errDuplicateUnsupported = refuse(http.StatusConflict, "duplicate-unsupported",
	"a Receive Inbox or a Live Share cannot be duplicated")

// errShareBusy answers a share still uploading.
var errShareBusy = refuse(http.StatusConflict, "share-busy",
	"the share is still uploading: duplicate it once every file is in")

func (h *handler) duplicateShare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		LinksOff *bool  `json:"linksOff,omitempty"`
	}
	if !decodeOptionalJSONBody(w, r, duplicateBodyLimit, &req) {
		return
	}
	if req.Name != "" {
		clean, err := cleanShareName(req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = clean
	}
	u := reqUser(r)
	id := r.PathValue("id")
	v, err := h.ownedView(id, u, h.viewMeta)
	if err != nil {
		// A live share is never in the database; its owner is told why it
		// cannot be copied, anyone else gets the plain 404.
		if errors.Is(err, metadb.ErrNotFound) {
			if rec, ok := h.liveShareReg.Get(id); ok && rec.Owner == u.Username {
				err = errDuplicateUnsupported
			}
		}
		writeRefusal(w, err)
		return
	}
	if err := h.duplicateRefusal(v, u); err != nil {
		writeRefusal(w, err)
		return
	}
	if !h.allowCreate(w, u) {
		return
	}
	slot, err := h.copies.reserve(u.Username, v.ID, v.FileCount)
	if err != nil {
		w.Header().Set("Retry-After", busyRetryAfter)
		writeErrorCode(w, http.StatusServiceUnavailable, "busy",
			"The server is copying other shares, try again in a minute.")
		return
	}
	newID := shareid.NewID()
	d, err := h.db.DuplicateShare(v.ID, metadb.DuplicateOptions{NewID: newID, Name: req.Name,
		LinksOff: req.LinksOff, Reseal: h.resealFor(v.ID, newID)})
	if err != nil {
		h.copies.unreserve(slot)
		writeRefusal(w, duplicateRefusalOf(err))
		return
	}
	// Asked again now the copy exists, as a create asks: an allowlist
	// narrowed in between refuses it.
	if lost, err := h.ungranted(u.Username, sourcePaths(v.Sources)); err != nil || len(lost) > 0 {
		h.copies.unreserve(slot)
		_ = h.removeShare(d.ID)
		if err == nil {
			err = refuse(http.StatusForbidden, "source-forbidden", "this account may not share from "+lost[0])
		}
		writeRefusal(w, err)
		return
	}
	if err := h.fs.Reserve(d.ID, u.Username, v.Bytes); err != nil {
		h.copies.unreserve(slot)
		_ = h.removeShare(d.ID)
		writeErrorCode(w, http.StatusInsufficientStorage, "no-space", spaceMessage(err, u.IsAdmin()))
		return
	}
	h.copies.submit(slot, copyTask{src: v.ID, dst: d.ID, owner: u.Username}, h.runCopy)
	writeJSON(w, http.StatusCreated, h.resolvedRow(h.viewFrom(d)))
}

// duplicateRefusal is what refuses a duplicate of v before anything is
// written: an inbox, a share still uploading (a pending file, a publish
// open, itself a copy in progress), a revoked source, a source the owner's
// allowlist no longer covers, and a copy past the owner's quota. The
// transaction decides the row checks again.
func (h *handler) duplicateRefusal(v shareView, u metadb.User) error {
	switch {
	case v.Inbox:
		return errDuplicateUnsupported
	case v.CopyingFrom != "" || v.FileCount != v.Committed || h.fs.HasOpenPublish(v.ID):
		return errShareBusy
	}
	for _, s := range v.Sources {
		if s.Revoked() {
			return duplicateRefusalOf(metadb.ErrSourceRevoked)
		}
	}
	if sources := sourcePaths(v.Sources); len(sources) > 0 {
		if _, err := h.sourceListRefusal(u, sources); err != nil {
			return err
		}
	}
	return h.copyRoom(u, v)
}

// copyRoom is the quota check of a whole copy: every stored byte and every
// tile and poster byte of the original, and its files against the account's
// file limit. CommitFile charges each file as it lands; this refuses up
// front a copy that would be refused part way.
func (h *handler) copyRoom(u metadb.User, v shareView) error {
	if err := h.ownerRoom(u, "", "", v.Bytes+h.fs.ShareSidecarBytes(v.ID)); err != nil {
		return err
	}
	limit := metadb.FileLimit(u.QuotaBytes)
	if limit == 0 || v.Committed == 0 {
		return nil
	}
	usage, err := h.db.Usage(u.Username)
	if err == nil && int64(usage.Committed)+int64(v.Committed) > limit {
		return fmt.Errorf("%w: this account holds %d files and the copy %d more, past the %d its quota allows",
			metadb.ErrQuota, usage.Committed, v.Committed, limit)
	}
	return nil
}

// duplicateRefusalOf maps DuplicateShare's refusals to their 409s; anything
// else answers through refusalOf.
func duplicateRefusalOf(err error) error {
	switch {
	case errors.Is(err, metadb.ErrDuplicateUnsupported):
		return errDuplicateUnsupported
	case errors.Is(err, metadb.ErrShareBusy):
		return errShareBusy
	case errors.Is(err, metadb.ErrSourceRevoked):
		return refuse(http.StatusConflict, "source-revoked", err.Error())
	}
	return err
}

// copyRefusal refuses a content edit of v while a copy is reading it (the
// original of a duplicate waiting or running) or while v is itself a copy
// still being made.
func (h *handler) copyRefusal(v shareView) error {
	if v.CopyingFrom != "" {
		return errCopyInProgress
	}
	return h.copySourceRefusal(v.ID)
}

// copySourceRefusal refuses the delete of a share a copy is reading. A copy
// still being made is not refused: deleting it ends its copy.
func (h *handler) copySourceRefusal(id string) error {
	if h.copies.reading(id) {
		return errCopyInProgress
	}
	return nil
}

// sourcePaths is the paths of a linked share's sources.
func sourcePaths(sources []metadb.Source) []string {
	out := make([]string, 0, len(sources))
	for _, s := range sources {
		out = append(out, s.Path)
	}
	return out
}

// resealFor answers DuplicateShare's Reseal: a readable password copy sealed
// for srcID opened and sealed again for newID, since the seal binds the share
// id. A copy that does not open is no readable copy (nil): the hash still
// verifies, so the same password opens the duplicate.
func (h *handler) resealFor(srcID, newID string) func(hash string, sealed []byte) ([]byte, error) {
	return func(hash string, sealed []byte) ([]byte, error) {
		pw, err := sealpw.Open(h.fs.Secret(), srcID, hash, sealed)
		if err != nil {
			return nil, nil
		}
		return h.sealPassword(newID, hash, pw)
	}
}

// copyTask is one duplicate's copy work: the original, the copy and its
// owner. The entries are the database's (metadb.CopyJobs).
type copyTask struct {
	src, dst, owner string
}

// runCopy fills the copy t names and finishes it, or deletes it when the
// copy fails. A copy a shutdown stopped stays marked for the boot pass.
func (h *handler) runCopy(ctx context.Context, t copyTask) {
	err := h.copyFiles(ctx, t)
	switch {
	case err == nil:
	case ctx.Err() != nil:
		log.Printf("duplicate %s: stopped by the shutdown; the next start removes it", t.dst)
	default:
		// A copy its owner deleted while it copied failed by design: only
		// what it left on disk goes, quietly.
		if _, gone := h.db.ShareCapped(t.dst, 1); !errors.Is(gone, metadb.ErrNotFound) {
			log.Printf("duplicate %s of %s failed, removing it: %v", t.dst, t.src, err)
		}
		h.dropCopy(t.dst)
	}
}

// copyFiles stages and commits every stored file of t a page of jobs at a
// time, copying each page's tiles under the new slugs, then the poster, and
// clears the copy's mark. It stops between files once ctx is done.
func (h *handler) copyFiles(ctx context.Context, t copyTask) error {
	after := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		jobs, err := h.db.CopyJobs(t.dst, after, copyJobsPage)
		if err != nil {
			return err
		}
		slugs := make(map[string]string, len(jobs))
		for _, j := range jobs {
			if j.OldSlug == "" {
				return fmt.Errorf("%s: %w", j.Rel, errCopyChanged)
			}
			slugs[j.OldSlug] = j.NewSlug
			if j.Linked {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := h.copyFile(t, j); err != nil {
				return fmt.Errorf("%s: %w", j.Rel, err)
			}
		}
		if err := h.fs.CopyThumbs(t.src, t.dst, slugs, t.owner); err != nil {
			return fmt.Errorf("tiles: %w", err)
		}
		if len(jobs) < copyJobsPage {
			break
		}
		after = jobs[len(jobs)-1].Cursor()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := h.fs.CopyPoster(t.src, t.dst, t.owner, func(old string) (string, bool, error) {
		slug, err := h.db.CopiedSlug(t.dst, old)
		if errors.Is(err, metadb.ErrNotFound) {
			return "", false, nil
		}
		return slug, err == nil, err
	})
	if err != nil {
		return fmt.Errorf("poster: %w", err)
	}
	h.fs.RecountSidecars(t.dst, t.owner)
	if err := h.db.FinishCopy(t.dst); err != nil {
		return err
	}
	h.fs.ReleaseReservation(t.dst)
	return nil
}

// copyFile stages one stored file's copy beside its pending row and commits
// it as an upload commits, holding it to the original's size and hash and
// keeping the original's type.
func (h *handler) copyFile(t copyTask, j metadb.CopyJob) error {
	n, err := stageCopy(h.fs, t.src, j.Rel, t.dst, j.Rel)
	if err != nil {
		return err
	}
	if n != j.Size {
		return fmt.Errorf("%w: copied %d bytes of %d", errCopyChanged, n, j.Size)
	}
	in := metadb.CommitInput{ShareID: t.dst, Path: j.Rel, Size: j.Size, SHA256: j.SHA256, Mime: j.Mime}
	_, err = h.commitWith(in, func(record sharefs.Record) (sharefs.Committed, error) {
		return h.fs.Commit(t.dst, j.Rel, j.Size, func(c sharefs.Committed) error {
			if j.SHA256 != "" && c.SHA256 != j.SHA256 {
				return errCopyChanged
			}
			if j.Mime != "" {
				c.Mime = j.Mime
			}
			return record(c)
		})
	})
	return err
}

// dropCopy deletes a copy that failed: the rows, then the directory. A copy
// whose rows its owner already deleted still has its directory removed, in
// case a part landed after the delete.
func (h *handler) dropCopy(id string) {
	err := h.removeShare(id)
	if errors.Is(err, metadb.ErrNotFound) {
		if err := h.fs.RemoveShare(id); err != nil {
			log.Printf("duplicate %s: removing directory: %v", id, err)
		}
		return
	}
	if err != nil {
		log.Printf("duplicate %s: removing it: %v", id, err)
	}
}

// RemoveUnfinishedCopies deletes every duplicate a stopped process left
// copying (copying_from still set), rows then directory, and answers how
// many went. A copy's worker dies with its process, so such a share would
// never fill. The boot pass runs it first, on every boot, before it lists
// the share ids and before the listener starts.
func RemoveUnfinishedCopies(db *metadb.DB, fs *sharefs.FS) (int, error) {
	ids, err := db.CopyingShares()
	if err != nil {
		return 0, err
	}
	removed := 0
	var errs []error
	for _, id := range ids {
		if err := db.DeleteShare(id); err != nil && !errors.Is(err, metadb.ErrNotFound) {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		if err := fs.RemoveShare(id); err != nil {
			errs = append(errs, fmt.Errorf("%s: removing directory: %w", id, err))
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

// copier is the copy line: the copies running and the copies waiting for a
// place, within the bounds above. Its zero value is ready; stop ends it.
type copier struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
	running int
	busy    map[string]bool // owners with a copy running
	queue   []queuedCopy
	// readers counts the copies reserved, waiting or running of each
	// original, for reading and so copyRefusal.
	readers map[string]int
	// The waiting tally: the queue plus the places reserved and not yet
	// submitted, in all, per owner and in entries.
	waiting, waitingEntries int
	waitingBy               map[string]int
	wg                      sync.WaitGroup
}

// queuedCopy is a copy waiting for a place, in the slot reserve gave it.
type queuedCopy struct {
	task copyTask
	slot copySlot
	run  func(context.Context, copyTask)
}

// copySlot is a place reserve held for a copy of src before its rows exist,
// and the copy's place while it waits.
type copySlot struct {
	owner, src string
	entries    int
}

// reserve holds a waiting place for a copy of src, about entries entries,
// owned by owner, or answers errCopyBusy past a bound or once the line has
// stopped. From here until the copy ends src is being read (reading). A slot
// is given back by submit or unreserve.
func (c *copier) reserve(owner, src string, entries int) (copySlot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped || c.waiting >= copyMaxWaiting || c.waitingBy[owner] >= copyMaxWaitingPerOwner ||
		c.waiting > 0 && c.waitingEntries+entries > copyMaxWaitingEntries {
		return copySlot{}, errCopyBusy
	}
	s := copySlot{owner: owner, src: src, entries: entries}
	c.holdLocked(s, 1)
	c.readLocked(src, 1)
	return s, nil
}

// unreserve gives back a slot whose copy was never made.
func (c *copier) unreserve(s copySlot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.holdLocked(s, -1)
	c.readLocked(s.src, -1)
}

// reading reports whether a copy of src is reserved, waiting or running.
func (c *copier) reading(src string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readers[src] > 0
}

// readLocked moves src's count of copies reading it by n. Unlike the waiting
// tally it is kept after stop: a copy still running reads its original until
// it ends.
func (c *copier) readLocked(src string, n int) {
	if c.readers == nil {
		c.readers = map[string]int{}
	}
	if c.readers[src] += n; c.readers[src] <= 0 {
		delete(c.readers, src)
	}
}

// holdLocked moves the waiting tally by one place of s, up (n = 1) or down
// (n = -1).
func (c *copier) holdLocked(s copySlot, n int) {
	if c.stopped {
		return // stop cleared the tally
	}
	if c.waitingBy == nil {
		c.waitingBy = map[string]int{}
	}
	c.waiting += n
	c.waitingEntries += n * s.entries
	if c.waitingBy[s.owner] += n; c.waitingBy[s.owner] <= 0 {
		delete(c.waitingBy, s.owner)
	}
}

// submit queues task in the place s held and starts what the bounds allow.
// After stop it queues nothing: the copy stays marked for the boot pass.
func (c *copier) submit(s copySlot, task copyTask, run func(context.Context, copyTask)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		c.readLocked(s.src, -1)
		return
	}
	c.queue = append(c.queue, queuedCopy{task: task, slot: s, run: run})
	c.startLocked()
}

// startLocked starts the oldest waiting copies whose owner has none running,
// up to copyMaxRunning at once.
func (c *copier) startLocked() {
	if c.ctx == nil {
		c.ctx, c.cancel = context.WithCancel(context.Background())
	}
	if c.busy == nil {
		c.busy = map[string]bool{}
	}
	for i := 0; i < len(c.queue) && c.running < copyMaxRunning; {
		q := c.queue[i]
		if c.busy[q.task.owner] {
			i++
			continue
		}
		c.queue = append(c.queue[:i], c.queue[i+1:]...)
		c.holdLocked(q.slot, -1)
		c.running++
		c.busy[q.task.owner] = true
		c.wg.Add(1)
		go c.run(c.ctx, q)
	}
}

// run runs one copy and then starts the next.
func (c *copier) run(ctx context.Context, q queuedCopy) {
	defer c.wg.Done()
	q.run(ctx, q.task)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running--
	delete(c.busy, q.task.owner)
	c.readLocked(q.slot.src, -1)
	if !c.stopped {
		c.startLocked()
	}
}

// stop ends the line at shutdown: the waiting copies are dropped and the
// running ones told to stop, and it waits up to wait for them. Every copy it
// leaves unfinished stays marked, and the next boot removes it.
func (c *copier) stop(wait time.Duration) {
	c.mu.Lock()
	c.stopped = true
	for _, q := range c.queue {
		c.readLocked(q.slot.src, -1)
	}
	c.queue, c.waiting, c.waitingEntries, c.waitingBy = nil, 0, 0, nil
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(wait):
		log.Printf("duplicates: copies still running at shutdown; the next start removes them")
	}
}

// stopping reports whether stop has been called.
func (c *copier) stopping() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped
}

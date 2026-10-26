package api

import (
	"sort"
	"strconv"
	"time"
)

// Upload progress: how an inbox's owner watches a stranger's upload move.
//
// Every change to an account's uploads in flight (a claim taken, an upload
// ended, and while bytes arrive at most one tick per inboxProgressInterval
// per inbox) advances one in-memory sequence and wakes that account's held
// watches (watch.go), which answer the account's uploads in flight. Nothing
// here is written to the database or the journal: a byte count is
// transient, and a journal row per tick would make every device re-read
// the row. The sequence is the watch's `progress` cursor, so a tick landing
// between two of a client's watch requests is answered by the next one
// rather than lost.
//
// Memory: the per-upload state lives in its claim and goes with it; what
// stays is one sequence number per account that has received an upload
// since the server started.

// inboxProgressInterval paces the byte ticks of one inbox.
const inboxProgressInterval = time.Second

// progress is the sequence and its subscribers, guarded by the claims' lock.
type progress struct {
	// seq is the newest progress cursor; floor is the first this process
	// issued. Both start at the boot time in nanoseconds, so a cursor from
	// an earlier process reads as older than anything this one vouches for.
	seq, floor uint64
	// owners is each account's last progress change.
	owners map[string]uint64
	// subs are the held watches of each account, an entry only while one
	// is parked.
	subs map[string]map[chan struct{}]struct{}
}

func newProgress() progress {
	start := uint64(time.Now().UnixNano())
	return progress{seq: start, floor: start, owners: map[string]uint64{},
		subs: map[string]map[chan struct{}]struct{}{}}
}

// inboxUploadsOut is one inbox's uploads in flight as the watch answers
// them, in the shape a listing row's `incoming` carries.
type inboxUploadsOut struct {
	Share    string        `json:"share"`
	Incoming []incomingOut `json:"incoming"`
}

// bumpLocked records a progress change for owner and wakes its watches.
func (c *inboxClaims) bumpLocked(owner string) {
	c.seq++
	c.owners[owner] = c.seq
	for ch := range c.subs[owner] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// tick is a byte tick for shareID's uploads: a progress change when the
// inbox's last one is at least inboxProgressInterval old.
func (c *inboxClaims) tick(shareID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sc := c.byShare[shareID]
	if sc == nil {
		return
	}
	now := c.now()
	if now.Sub(sc.ticked) < inboxProgressInterval {
		return
	}
	sc.ticked = now
	c.bumpLocked(sc.owner)
}

// subscribe wakes the returned channel on every progress change of owner's
// inboxes until cancel is called.
func (c *inboxClaims) subscribe(owner string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.subs[owner] == nil {
		c.subs[owner] = map[chan struct{}]struct{}{}
	}
	c.subs[owner][ch] = struct{}{}
	return ch, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.subs[owner], ch)
		if len(c.subs[owner]) == 0 {
			delete(c.subs, owner)
		}
	}
}

// progressSince answers owner's uploads in flight when they changed after
// the cursor since: every inbox of owner's with an upload in flight, in id
// order, and the cursor to send next; moved is false, and next is since,
// while nothing changed. A cursor this process did not issue (empty,
// unparseable, older than its first or past its newest) always answers.
// The uploads are read under the same lock as the cursor, so the cursor
// never names a change the uploads do not show.
func (c *inboxClaims) progressSince(owner, since string) (next string, uploads []inboxUploadsOut, moved bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.movedLocked(owner, since) {
		return since, nil, false
	}
	for id, sc := range c.byShare {
		if sc.owner != owner {
			continue
		}
		if in := c.incomingLocked(sc); len(in) > 0 {
			uploads = append(uploads, inboxUploadsOut{Share: id, Incoming: in})
		}
	}
	sort.Slice(uploads, func(i, j int) bool { return uploads[i].Share < uploads[j].Share })
	return strconv.FormatUint(c.seq, 10), uploads, true
}

// progressMoved is progressSince's verdict alone, for a watch deciding
// whether to answer.
func (c *inboxClaims) progressMoved(owner, since string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.movedLocked(owner, since)
}

func (c *inboxClaims) movedLocked(owner, since string) bool {
	p, err := strconv.ParseUint(since, 10, 64)
	return err != nil || p < c.floor || p > c.seq || c.owners[owner] > p
}

package api

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

// A public read of a linked share composes it: a walk of up to
// linked.MaxWalk files under its sources, the filter read, and the share's
// slug map. Every /view, /download, /site and /zip request and every tick of
// the status poll asks for it, so a visitor paging through a linked gallery,
// a video seeking by Range, or anyone looping on the status route would
// otherwise pay a whole walk per request. linkedWalks keeps each share's
// composed walk for linkedWalkTTL after it ends and lets concurrent readers
// of one share share one walk in flight, within the bounds below.
//
// The cache never serves an edit late. Its key is the share row's
// modifiedAt, which every write to the share's sources, filters and revoke
// state moves in the same transaction (finishShareWrite, UpdateUserAccess),
// plus each source's path, fixed flag, hidden count and revoke time, all
// read from the row the request itself just read, plus whether each source
// opens right now (sourcesOpen, one open per source rather than a walk), so
// a folder unmounted or brought back answers on the next read. What it may
// serve late is the folder's CONTENT: a file added on disk shows up within
// the TTL, and a file removed from disk answers 404 when its bytes are
// opened, since every open goes through linked.Opener and never through
// the cache.
//
// Owner reads (the share view, an edit's answer) compose fresh, so the owner
// always sees the folder as it is.
const (
	linkedWalkTTL = 2 * time.Second
	// linkedWalkMax bounds the shares cached at once, and linkedWalkEntries
	// the listing entries their finished walks hold together (each with its
	// slug, about 200 B), so the cache stays a few MB on a small NAS
	// whatever the shares hold. A full cache drops its oldest finished walks
	// first; a walk still in flight is never dropped, so its readers keep
	// sharing it.
	linkedWalkMax     = 256
	linkedWalkEntries = 4 * linked.MaxWalk
)

type linkedWalks struct {
	mu      sync.Mutex
	byShare map[string]*linkedWalk
	entries int // the listing entries the finished walks in byShare hold
	// ttl overrides linkedWalkTTL in tests; 0 keeps it.
	ttl time.Duration
}

// linkedWalk is one share's composed walk. done closes once listing and
// readable are set, or once failed is, and none of them changes after.
// finished is when the walk ended, which the TTL counts from, so a walk
// slower than the TTL is still joined while it runs and fresh when it ends.
// known is the slug map the walk's readers have filled so far, replaced
// whole on every addition and never written in place, so a reader may keep
// the map it was handed.
type linkedWalk struct {
	key      string
	finished time.Time
	done     chan struct{}
	listing  linked.Listing
	readable bool
	failed   bool // the compose did not return (it panicked); never served

	mu    sync.Mutex
	known map[string]string
}

// walkKey is the identity of a share's linked composition as one row read
// states it.
func walkKey(d metadb.Share) string {
	var b strings.Builder
	if d.ModifiedAt != nil {
		b.WriteString(strconv.FormatInt(d.ModifiedAt.UnixNano(), 10))
	}
	for _, s := range d.Sources {
		b.WriteString("\x00")
		b.WriteString(s.Path)
		b.WriteString("\x00")
		b.WriteString(strconv.FormatBool(s.Fixed))
		b.WriteString(strconv.Itoa(s.Hidden))
		if s.RevokedAt != nil {
			b.WriteString("r" + strconv.FormatInt(s.RevokedAt.UnixNano(), 10))
		}
	}
	return b.String()
}

// sourcesOpen answers, one byte per source, whether it is revoked ("r"),
// opens ("1") or does not ("0") right now: the part of a linked share's
// state a walk would learn first and a cache must not hold past a change.
func (h *handler) sourcesOpen(d metadb.Share) string {
	b := make([]byte, 0, len(d.Sources)+1)
	b = append(b, 0)
	for _, s := range d.Sources {
		switch {
		case s.Revoked():
			b = append(b, 'r')
		default:
			root, _, err := h.roots.Open(s.Path)
			if err != nil {
				b = append(b, '0')
				continue
			}
			root.Close()
			b = append(b, '1')
		}
	}
	return string(b)
}

// get answers the share's composed walk for key, composing it with compose
// when no live entry holds that key. A reader that arrives while another
// composes the same key waits for that walk rather than starting its own.
// A finished walk leaves the cache when its TTL runs out, read or not.
func (c *linkedWalks) get(id, key string, compose func() (linked.Listing, bool)) *linkedWalk {
	ttl := c.ttl
	if ttl <= 0 {
		ttl = linkedWalkTTL
	}
	for {
		c.mu.Lock()
		if w, ok := c.byShare[id]; ok && w.key == key && (w.finished.IsZero() || time.Since(w.finished) < ttl) {
			c.mu.Unlock()
			<-w.done
			if w.failed {
				continue // its composer is gone; compose afresh
			}
			return w
		}
		w := &linkedWalk{key: key, done: make(chan struct{})}
		c.put(id, w)
		c.mu.Unlock()
		c.compose(id, w, ttl, compose)
		return w
	}
}

// put makes w the share's entry, making room first. Called with c.mu held.
func (c *linkedWalks) put(id string, w *linkedWalk) {
	if c.byShare == nil {
		c.byShare = map[string]*linkedWalk{}
	}
	c.drop(id)
	c.shrink(linkedWalkMax-1, linkedWalkEntries)
	c.byShare[id] = w
}

// compose runs one walk and publishes it: done closes however compose
// ends, a walk that did not return is dropped and marked failed for its
// waiters, and a finished one is counted against the entry budget and
// timed out after ttl.
func (c *linkedWalks) compose(id string, w *linkedWalk, ttl time.Duration, compose func() (linked.Listing, bool)) {
	ok := false
	defer func() {
		c.mu.Lock()
		if !ok {
			w.failed = true
			if c.byShare[id] == w {
				delete(c.byShare, id)
			}
		} else if c.byShare[id] == w {
			w.finished = time.Now()
			c.entries += len(w.listing.Entries)
			c.shrink(linkedWalkMax, linkedWalkEntries)
			time.AfterFunc(ttl, func() {
				c.mu.Lock()
				if c.byShare[id] == w {
					c.drop(id)
				}
				c.mu.Unlock()
			})
		}
		c.mu.Unlock()
		close(w.done)
	}()
	w.listing, w.readable = compose()
	ok = true
}

// drop removes the share's entry. Called with c.mu held.
func (c *linkedWalks) drop(id string) {
	w, ok := c.byShare[id]
	if !ok {
		return
	}
	if !w.finished.IsZero() {
		c.entries -= len(w.listing.Entries)
	}
	delete(c.byShare, id)
}

// shrink drops finished walks, oldest first, until at most shares are
// cached and their walks hold at most entries. A walk in flight is never
// dropped, and holds no entries yet. Called with c.mu held.
func (c *linkedWalks) shrink(shares, entries int) {
	for len(c.byShare) > shares || c.entries > entries {
		oldest := ""
		var at time.Time
		for id, w := range c.byShare {
			if !w.finished.IsZero() && (oldest == "" || w.finished.Before(at)) {
				oldest, at = id, w.finished
			}
		}
		if oldest == "" {
			return
		}
		c.drop(oldest)
	}
}

// slugs answers a slug for every rel, asking fill only for the rels this
// walk has not yet been handed one for. fill's answers are lasting (stored
// in linked_slugs), so they are kept for the next reader.
func (w *linkedWalk) slugs(rels []string, fill func([]string) (map[string]string, error)) (map[string]string, error) {
	w.mu.Lock()
	known := w.known
	w.mu.Unlock()
	var missing []string
	for _, rel := range rels {
		if _, ok := known[rel]; !ok {
			missing = append(missing, rel)
		}
	}
	if len(missing) == 0 {
		return known, nil
	}
	got, err := fill(missing)
	if err != nil {
		return nil, err
	}
	merged := maps.Clone(known)
	if merged == nil {
		merged = make(map[string]string, len(got))
	}
	maps.Copy(merged, got)
	w.mu.Lock()
	if len(w.known) > len(known) {
		// Another reader kept slugs meanwhile: keep theirs too.
		maps.Copy(merged, w.known)
	}
	w.known = merged
	w.mu.Unlock()
	return merged, nil
}

// sortEntriesByPath orders a walk's entries by relpath in byte order, the
// order the files table keeps, so a public page merges the two halves and
// takes one range of the walk by binary search. A cached walk is sorted once,
// before any reader sees it.
func sortEntriesByPath(entries []linked.Entry) {
	slices.SortFunc(entries, func(a, b linked.Entry) int { return strings.Compare(a.Rel, b.Rel) })
}

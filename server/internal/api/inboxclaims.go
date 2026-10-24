package api

import (
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"hyperdrop/core/uniquename"
	"hyperdrop/server/internal/shareid"
)

// inboxClaims is the set of inbox uploads in flight, per share: the names
// claimed, how much each declared and how many bytes each has received. A
// claim renames a colliding basename (a blind share: a second sender must
// never overwrite the first) and keeps two same-name uploads off one
// staging part. Request state, not row state: a pending row is written only
// once the name is settled. It also carries the owners' upload progress
// (inboxprogress.go), which is transient by nature and never reaches the
// database or the journal.
type inboxClaims struct {
	mu      sync.Mutex
	byShare map[string]*inboxShareClaims
	// now is the clock the byte ticks are paced by; a test sets it.
	now func() time.Time
	progress
}

// inboxShareClaims is one inbox's uploads in flight, under the account that
// owns the inbox, and when its byte progress last woke that account's
// watchers.
type inboxShareClaims struct {
	owner  string
	claims map[string]*inboxClaim
	ticked time.Time
}

// inboxClaim is one in-flight anonymous upload: the size its sender
// declared, the visitor token grouping it with that sender's other files
// (empty when the sender carries no cookie), the bytes received so far, and
// whether the upload has ended. An ended claim still holds its name until
// it is released, and is not listed as incoming.
type inboxClaim struct {
	Total int64
	By    string
	bytes atomic.Int64
	done  bool
}

func newInboxClaims() *inboxClaims {
	return &inboxClaims{byShare: map[string]*inboxShareClaims{}, now: time.Now, progress: newProgress()}
}

// inboxNameWalk bounds how many numbered candidates a claim tries: a link
// flooded with one name refuses the next such file rather than walk every
// earlier one.
const inboxNameWalk = 1000

// claim picks the name this upload lands under: name when nothing holds it,
// else "name 2.ext", "name 3.ext" and so on (core/uniquename, the one
// collision scheme every client numbers with too, its stem shortened where
// the number would push a name past shareid.MaxNameBytes), against the
// claims in flight and held, which answers which of the candidates the
// share holds a row at. held is asked under the claims' lock, so the
// decision cannot cross an upload committing that name: a claim is taken
// before its upload declares a row and released only after the row is
// committed or withdrawn, so a name is always visible as a claim, a row, or
// neither because it is free. held is asked twice at most, for name alone
// and then for every numbered candidate at once, so a name sent a thousand
// times costs one read rather than a thousand under the lock. It answers
// false when the first inboxNameWalk candidates are all taken. A claim
// taken is progress: owner's watchers wake.
func (c *inboxClaims) claim(shareID, owner, name string, held func(candidates []string) map[string]bool, total int64, by string) (*inboxUpload, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := c.byShare[shareID]
	free := func(candidate string) bool {
		if live == nil {
			return true
		}
		_, claimed := live.claims[candidate]
		return !claimed
	}
	chosen := ""
	if free(name) && !held([]string{name})[name] {
		chosen = name
	} else {
		var candidates []string
		for n := 2; n <= inboxNameWalk; n++ {
			if candidate := numberedName(name, n); candidate != "" && free(candidate) {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) > 0 {
			taken := held(candidates)
			for _, candidate := range candidates {
				if !taken[candidate] {
					chosen = candidate
					break
				}
			}
		}
	}
	if chosen == "" {
		return nil, false
	}
	if live == nil {
		live = &inboxShareClaims{owner: owner, claims: map[string]*inboxClaim{}}
		c.byShare[shareID] = live
	}
	cl := &inboxClaim{Total: total, By: by}
	live.claims[chosen] = cl
	live.ticked = c.now()
	c.bumpLocked(live.owner)
	return &inboxUpload{c: c, shareID: shareID, Name: chosen, cl: cl}, true
}

// inboxUpload is one claim as its upload holds it: the name it lands under,
// the byte counter its body feeds, and its end.
type inboxUpload struct {
	c       *inboxClaims
	shareID string
	cl      *inboxClaim
	// Name is the claimed name, the one the upload lands under.
	Name string
}

// Reader counts what r hands on as this upload's received bytes.
func (u *inboxUpload) Reader(r io.Reader) io.Reader { return &countingReader{r: r, u: u} }

// Finish ends the upload: it leaves the inbox's incoming list, and the
// owner's watchers wake to see it go. Called before the upload's last
// journal write (its commit, or the withdrawal of its pending row), so
// every row resolved after that write is without it. Safe to call more
// than once.
func (u *inboxUpload) Finish() {
	u.c.mu.Lock()
	defer u.c.mu.Unlock()
	u.finishLocked()
}

func (u *inboxUpload) finishLocked() {
	if u.cl.done {
		return
	}
	u.cl.done = true
	if sc := u.c.byShare[u.shareID]; sc != nil {
		u.c.bumpLocked(sc.owner)
	}
}

// Release gives the name back, finishing the upload first when it has not
// ended. The inbox's entry goes with its last claim.
func (u *inboxUpload) Release() {
	u.c.mu.Lock()
	defer u.c.mu.Unlock()
	u.finishLocked()
	sc := u.c.byShare[u.shareID]
	if sc == nil || sc.claims[u.Name] != u.cl {
		return
	}
	delete(sc.claims, u.Name)
	if len(sc.claims) == 0 {
		delete(u.c.byShare, u.shareID)
	}
}

// countingReader adds every byte read to its upload's count, and paces the
// owner's progress wake (tick).
type countingReader struct {
	r io.Reader
	u *inboxUpload
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.u.cl.bytes.Add(int64(n))
		cr.u.c.tick(cr.u.shareID)
	}
	return n, err
}

// numberedName is uniquename.Numbered(name, n) for one path segment, its stem
// cut back on a character boundary when the number would push the name past
// shareid.MaxNameBytes, the extension kept. It answers "" when no stem fits
// beside the number and the extension.
func numberedName(name string, n int) string {
	c := uniquename.Numbered(name, n)
	if shareid.ValidRelPath(c) {
		return c
	}
	if len(c) <= shareid.MaxNameBytes {
		return ""
	}
	stem, ext := name, ""
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		stem, ext = name[:i], name[i:]
	}
	keep := len(stem) - (len(c) - shareid.MaxNameBytes)
	for keep > 0 && !utf8.RuneStart(stem[keep]) {
		keep--
	}
	if keep <= 0 {
		return ""
	}
	c = uniquename.Numbered(stem[:keep]+ext, n)
	if !shareid.ValidRelPath(c) {
		return ""
	}
	return c
}

// commonPrefix is the longest prefix every one of names begins with, cut
// back to a character boundary.
func commonPrefix(names []string) string {
	if len(names) == 0 {
		return ""
	}
	p := names[0]
	for _, n := range names[1:] {
		i := 0
		for i < len(p) && i < len(n) && p[i] == n[i] {
			i++
		}
		p = p[:i]
	}
	for len(p) > 0 && !utf8.ValidString(p) {
		p = p[:len(p)-1]
	}
	return p
}

// incoming lists the uploads in flight into a share, in name order: every
// claim not yet ended, with the bytes it has received.
func (c *inboxClaims) incoming(shareID string) []incomingOut {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.incomingLocked(c.byShare[shareID])
}

func (c *inboxClaims) incomingLocked(sc *inboxShareClaims) []incomingOut {
	if sc == nil {
		return []incomingOut{}
	}
	out := make([]incomingOut, 0, len(sc.claims))
	for name, cl := range sc.claims {
		if cl.done {
			continue
		}
		out = append(out, incomingOut{Name: name, Bytes: cl.bytes.Load(), Total: cl.Total, By: cl.By})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

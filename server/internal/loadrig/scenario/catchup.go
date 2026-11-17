package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/target"
	"hyperdrop/server/internal/loadrig/volume"
	"hyperdrop/server/internal/metadb"
)

const (
	opFeedZero     = "catchup feed from zero"
	opCatchupPage  = "catchup walk page"
	opCatchupWalk  = "catchup walk"
	opFeedPage     = "catchup feed page"
	opCatchupWatch = "catchup watch"
	opWatchWrite   = "watch write"

	valFeedReset      = "catchup feed from zero answered reset"
	valCatchupPages   = "catchup walk pages"
	valCatchupRows    = "catchup walk rows"
	valCatchupShares  = "catchup walk shares (distinct)"
	valCatchupTotal   = "catchup listing total"
	valCatchupTook    = "catchup walk took"
	valCatchupRate    = "catchup walk rows per second"
	valFeedPages      = "catchup feed pages"
	valFeedRows       = "catchup feed rows"
	valCaughtUp       = "caught up after"
	valWatchAnswered  = "catchup watch answered after write"
	valWatchPerOwner  = "watchers per account (cap)"
	valWatchTotal     = "watchers per server (cap)"
	valAcrossWatchers = "watchers across accounts"
	valAcrossAccounts = "accounts watched across"
	valAcrossBound    = "watchers past the server-wide cap"

	// watchHold is how long each step's watchers hold, scaled, and never
	// less than one write interval.
	watchHold = 60 * time.Second
	// watchWriteEvery is the pace of the writes the watchers wait for.
	watchWriteEvery = 5 * time.Second
	// watchOver is how many watchers past a cap a step adds.
	watchOver = 4
	// watchHeadroom is how many of an address's requests the steps leave to
	// the writer and the probes beside the held watches.
	watchHeadroom = 8
	// watchWriteTries is how many times a write the watchers wait for is
	// tried while a limit refuses it.
	watchWriteTries = 5
	// watchSettle is how long the caught-up client's watch parks before the
	// write it waits for.
	watchSettle = time.Second
)

func watchStepOp(n int) string          { return fmt.Sprintf("watch @%d", n) }
func watchAcrossOp(n int) string        { return fmt.Sprintf("watch @%d across accounts", n) }
func watchAnsweredOp(n int) string      { return fmt.Sprintf("watch @%d answered after write", n) }
func watchRefusedName(op string) string { return op + " refused too-many-watchers" }
func watchNoSlotName(op string) string  { return op + " took no slot or came late" }

var catchupScenario = Scenario{
	Name: "catchup",
	About: "A fresh device of the largest account catching up as a client does: it asks the change feed from " +
		"cursor zero (a volume whose journal is pruned answers reset), walks the whole listing by cursor at the " +
		"page cap, follows the feed from the cursor the reset gave and starts the watch, answered by a write. Then " +
		"watchers hold for 60 s while each watched account takes a write every 5 s: 16 of one account (its cap), " +
		"16 + 4 (the 4 refused too-many-watchers), and across accounts up to 4 past the server-wide cap of 256, " +
		"or as many as the load guard's 128 requests per address allow. Reported: how long after each write the " +
		"watchers were answered. The catchup walk's time includes the rig decoding each page; a watch @n op's " +
		"latency is how long a watch was parked waiting for a change, not what the server spent on it.",
	Run: catchup,
}

// watched is an account the watch steps write to: each write pins or
// unpins share, which moves the account's change feed and nothing else.
type watched struct {
	name, token, share string
	// pinned is the share's pin as read before the first write and as each
	// landed write left it; only one goroutine writes at a time.
	pinned bool
	mu     sync.Mutex
	// writes is when each write was sent, oldest first.
	writes []time.Time
}

// newWatched is account name's watched share, its pin read from the server,
// so a pin an earlier run left cannot make a write change nothing.
func newWatched(ctx context.Context, probe *target.Client, name, token, share string) (*watched, error) {
	s, err := readShare(ctx, probe, "probe", share, token)
	if err != nil {
		return nil, fmt.Errorf("reading share %s: %w", share, err)
	}
	return &watched{name: name, token: token, share: share, pinned: s.PinnedAt != ""}, nil
}

// written is how many writes a has had sent.
func (a *watched) written() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.writes)
}

// answered is how long after the watcher's oldest write not yet answered
// (the seen-th) its answer at at came, and moves seen past every write sent
// by at. It reports false when no such write was sent by at, so a latency
// is never negative.
func (a *watched) answered(seen *int, at time.Time) (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if *seen >= len(a.writes) || a.writes[*seen].After(at) {
		return 0, false
	}
	d := at.Sub(a.writes[*seen])
	for *seen < len(a.writes) && !a.writes[*seen].After(at) {
		*seen++
	}
	return d, true
}

func catchup(ctx context.Context, e Env, rec *report.Recorder) error {
	acct, err := e.largest()
	if err != nil {
		return err
	}
	shares := pinnable(e.Plan)
	if shares[acct.Name] == "" {
		return Skip(acct.Name + " owns no share a write can pin")
	}
	probe := e.probe()
	defer probe.Close()
	largest, err := newWatched(ctx, probe, acct.Name, acct.Token, shares[acct.Name])
	if err != nil {
		return err
	}
	c := e.client(rec, 0)
	defer c.Close()

	began := time.Now()
	var zero feedPage
	if err := c.Do(ctx, opFeedZero, http.MethodGet, "/api/shares/changes?since=0&limit="+strconv.Itoa(metadb.MaxListLimit), acct.Token, nil, func(r *http.Response) error {
		return decodeOK(r, &zero)
	}); err != nil {
		return err
	}
	cursor := "0"
	if zero.Reset {
		rec.Text(valFeedReset, "yes")
		walkBegan := time.Now()
		w, err := walk(ctx, c, rec, acct.Token, walkOps{page: opCatchupPage, whole: opCatchupWalk})
		if err != nil {
			return err
		}
		took := time.Since(walkBegan)
		rec.Value(valCatchupPages, float64(w.pages), "pages")
		rec.Value(valCatchupRows, float64(w.rows), "rows")
		rec.Value(valCatchupTook, took.Seconds(), "s")
		rec.Value(valCatchupRate, float64(w.rows)/took.Seconds(), "rows/s")
		if w.cut {
			rec.NotAvailable(valCatchupShares, "a page longer than the client keeps was cut before its rows were counted")
		} else {
			rec.Value(valCatchupShares, float64(w.distinct), "shares")
		}
		if w.total >= 0 {
			rec.Value(valCatchupTotal, float64(w.total), "shares")
		}
		cursor = zero.Cursor
	} else {
		rec.Text(valFeedReset, "no")
		rec.NotAvailable(valCatchupTook, "the feed from zero answered changes, so the client follows it instead of walking")
	}
	pages, rows, cursor, err := follow(ctx, c, rec, acct.Token, cursor)
	if err != nil {
		return err
	}
	rec.Value(valFeedPages, float64(pages), "pages")
	rec.Value(valFeedRows, float64(rows), "rows")
	rec.Value(valCaughtUp, time.Since(began).Seconds(), "s")
	if err := firstWatch(ctx, e, rec, c, probe, largest, cursor); err != nil {
		return err
	}

	rec.Value(valWatchPerOwner, watchMaxPerOwner, "watches")
	rec.Value(valWatchTotal, watchMaxTotal, "watches")
	rec.Value(valSources, float64(e.addresses()), "addresses")
	rec.Value(valPerAddress, perAddressRequests, "requests")
	hold := max(e.hold(watchHold), watchWriteEvery)
	for _, n := range []int{watchMaxPerOwner, watchMaxPerOwner + watchOver} {
		if err := watchStep(ctx, e, rec, probe, []*watched{largest}, n, watchStepOp(n), watchMaxPerOwner, hold); err != nil {
			return err
		}
	}

	n := min(watchMaxTotal+watchOver, e.addresses()*(perAddressRequests-watchHeadroom))
	accts := []*watched{largest}
	for _, a := range e.Volume.Accounts {
		if len(accts)*watchMaxPerOwner >= n {
			break
		}
		if a.Token != "" && a.Name != largest.name && shares[a.Name] != "" {
			w, err := newWatched(ctx, probe, a.Name, a.Token, shares[a.Name])
			if err != nil {
				return err
			}
			accts = append(accts, w)
		}
	}
	switch {
	case len(accts)*watchMaxPerOwner < n:
		n = len(accts) * watchMaxPerOwner
		rec.NotAvailable(valAcrossBound, fmt.Sprintf("the volume has %d accounts with a share a write can pin, %d watchers at %d each",
			len(accts), n, watchMaxPerOwner))
	case n <= watchMaxTotal:
		rec.NotAvailable(valAcrossBound, fmt.Sprintf("the load guard's %d requests per address bound the step at %d watchers from %d address(es), short of the server-wide cap of %d",
			perAddressRequests, n, e.addresses(), watchMaxTotal))
	}
	rec.Value(valAcrossWatchers, float64(n), "watches")
	rec.Value(valAcrossAccounts, float64(len(accts)), "accounts")
	return watchStep(ctx, e, rec, probe, accts, n, watchAcrossOp(n), watchMaxTotal, hold)
}

// feedPage is what the scenarios read of one GET /api/shares/changes answer.
type feedPage struct {
	Reset   bool   `json:"reset"`
	Cursor  string `json:"cursor"`
	More    bool   `json:"more"`
	Changes []struct {
		Share *struct {
			ID string `json:"id"`
		} `json:"share"`
		Deleted string `json:"deleted"`
	} `json:"changes"`
}

// follow reads the change feed from cursor at the page cap until it has no
// more, and answers the pages, the rows and the cursor it ends on. A reset of
// a cursor the server answered is wrong.
func follow(ctx context.Context, c *target.Client, rec *report.Recorder, token, cursor string) (pages, rows int, next string, err error) {
	for {
		var p feedPage
		path := "/api/shares/changes?since=" + url.QueryEscape(cursor) + "&limit=" + strconv.Itoa(metadb.MaxListLimit)
		if err := c.Do(ctx, opFeedPage, http.MethodGet, path, token, nil, func(r *http.Response) error {
			if err := decodeOK(r, &p); err != nil {
				return err
			}
			if p.Reset && cursor != "0" {
				return fmt.Errorf("the feed reset cursor %s, which it answered", cursor)
			}
			return nil
		}); err != nil {
			return pages, rows, cursor, err
		}
		pages++
		rows += len(p.Changes)
		cursor = p.Cursor
		if !p.More {
			return pages, rows, cursor, nil
		}
	}
}

// firstWatch starts the caught-up client's watch from cursor, writes to the
// account once the watch has parked, and reports how long after the write
// the watch was answered.
func firstWatch(ctx context.Context, e Env, rec *report.Recorder, c, probe *target.Client, a *watched, cursor string) error {
	type answer struct {
		changed bool
		at      time.Time
		err     error
	}
	seen := a.written()
	done := make(chan answer, 1)
	go func() {
		w, err := watchOnce(ctx, c, opCatchupWatch, a.token, cursor)
		done <- answer{w.Changed, time.Now(), err}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(watchSettle):
	}
	wc := e.client(rec, 0)
	defer wc.Close()
	err := landWrite(ctx, e, wc, a, watchWriteTries)
	got := <-done
	defer unpin(ctx, probe, a)
	switch {
	case got.err != nil || err != nil:
		if !answering(e.Target) {
			return errStopped
		}
		return nil
	case !got.changed:
		rec.Wrong(opCatchupWatch, "the watch was answered with no change after a write to its account")
	default:
		if d, ok := a.answered(&seen, got.at); ok {
			rec.Value(valWatchAnswered, d.Seconds()*1000, "ms")
		} else {
			rec.NotAvailable(valWatchAnswered, "the watch was answered before a write to its account landed")
		}
	}
	return nil
}

// watchAnswer is a watch's answer.
type watchAnswer struct {
	Cursor  string `json:"cursor"`
	Changed bool   `json:"changed"`
	// refused is set when a limit refused the watch, with the code it gave.
	refused bool
	code    string
}

// watchOnce holds one watch from cursor until the server answers it.
func watchOnce(ctx context.Context, c *target.Client, op, token, cursor string) (watchAnswer, error) {
	var w watchAnswer
	err := c.Do(ctx, op, http.MethodGet, "/api/shares/watch?since="+url.QueryEscape(cursor), token, nil, func(r *http.Response) error {
		if refusedByLimit(r) {
			var body struct {
				Code string `json:"code"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			w.refused, w.code = true, body.Code
			return nil
		}
		return decodeOK(r, &w)
	})
	return w, err
}

// watchStep holds n watchers over accts, watcher w on accts[w%len(accts)],
// for hold while a writer writes to every account of accts every
// watchWriteEvery and once more at the hold's end. A watcher answered with a
// change records how long after the oldest write it had not been answered
// for it was answered, and holds again until the hold has passed;
// a watcher a limit refuses stops there, as a client that falls back to
// polling does.
//
// capacity is how many of the step's watchers the caps let the server hold
// at once, so it refuses n-capacity of them too-many-watchers when every
// watcher takes a slot. A watcher the load guard refuses, whose request
// fails, or that starts after the first write (when held watchers are
// briefly between two holds) may take no slot, so the step is wrong only
// when the server refused more than n-capacity, or fewer than n-capacity
// less those watchers.
func watchStep(ctx context.Context, e Env, rec *report.Recorder, probe *target.Client, accts []*watched, n int, op string, capacity int, hold time.Duration) error {
	cursor, err := headCursor(ctx, probe, accts[0].token)
	if err != nil {
		return err
	}
	base := make([]int, len(accts))
	for i, a := range accts {
		base[i] = a.written()
	}
	answered := watchAnsweredOp(n)
	end := time.Now().Add(hold)
	var firstWrite, tooMany, noSlot atomic.Int64
	var wg sync.WaitGroup
	var writeErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		wc := e.client(rec, 0)
		defer wc.Close()
		writeErr = writer(ctx, e, wc, accts, end, &firstWrite)
	}()
	err = parallel(ctx, e, rec, n, count(1), func(w int, c *target.Client) error {
		a, seen := accts[w%len(accts)], base[w%len(accts)]
		started := time.Now()
		since := cursor
		held := false
		for {
			ans, err := watchOnce(ctx, c, op, a.token, since)
			at := time.Now()
			switch {
			case err != nil:
				if !held {
					noSlot.Add(1)
				}
				return err
			case ans.refused && ans.code == "too-many-watchers":
				tooMany.Add(1)
				return nil
			case ans.refused:
				if !held {
					noSlot.Add(1)
				}
				return nil
			}
			if !held {
				held = true
				if first := firstWrite.Load(); first != 0 && started.UnixNano() > first {
					noSlot.Add(1)
				}
			}
			if !ans.Changed {
				rec.Wrong(op, "a watcher was answered with no change while its account took a write every "+watchWriteEvery.String())
			} else if d, ok := a.answered(&seen, at); ok {
				rec.Observe(answered, d, http.StatusOK, "")
			}
			since = ans.Cursor
			if at.After(end) {
				return nil
			}
		}
	})
	wg.Wait()
	for _, a := range accts {
		unpin(ctx, probe, a)
	}
	if err != nil {
		return err
	}
	if writeErr != nil {
		return writeErr
	}
	want, got, short := max(0, n-capacity), int(tooMany.Load()), int(noSlot.Load())
	rec.Value(watchRefusedName(op), float64(got), "watches")
	rec.Value(watchNoSlotName(op), float64(short), "watches")
	switch {
	case got > want:
		rec.Wrong(op, fmt.Sprintf("%d of %d watchers were refused too-many-watchers, more than the %d past the caps' %d", got, n, want, capacity))
	case got < want-short:
		rec.Wrong(op, fmt.Sprintf("%d of %d watchers were refused too-many-watchers, fewer than the %d past the caps' %d less the %d that took no slot or came late",
			got, n, want, capacity, short))
	}
	return nil
}

// writer writes to every account of accts every watchWriteEvery until end,
// and once more at end, that last write retried while a limit refuses it so
// every watcher is answered. first is set to when the first write was sent.
func writer(ctx context.Context, e Env, c *target.Client, accts []*watched, end time.Time, first *atomic.Int64) error {
	tick := time.NewTicker(watchWriteEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		case <-time.After(time.Until(end)):
		}
		last := !time.Now().Before(end)
		tries := 1
		if last {
			tries = watchWriteTries
		}
		first.CompareAndSwap(0, time.Now().UnixNano())
		for _, a := range accts {
			if err := landWrite(ctx, e, c, a, tries); err != nil {
				return err
			}
		}
		if last {
			return nil
		}
	}
}

// landWrite writes to a, trying again a second later while a limit refuses
// the write, at most tries times. It fails only when the server stopped
// answering.
func landWrite(ctx context.Context, e Env, c *target.Client, a *watched, tries int) error {
	for k := range tries {
		landed, err := pinWrite(ctx, c, a)
		if err != nil && !answering(e.Target) {
			return errStopped
		}
		if landed || err != nil || k == tries-1 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil
}

// headCursor is the change journal's head, from the feed's answer to no
// cursor, which holds none of the watch's slots.
func headCursor(ctx context.Context, c *target.Client, token string) (string, error) {
	var p feedPage
	err := c.Do(ctx, "probe", http.MethodGet, "/api/shares/changes", token, nil, func(r *http.Response) error {
		if err := decodeOK(r, &p); err != nil {
			return err
		}
		if !p.Reset || p.Cursor == "" {
			return fmt.Errorf("the feed asked for no cursor answered no reset and cursor %q", p.Cursor)
		}
		return nil
	})
	return p.Cursor, err
}

// pinWrite flips a's pin, recorded under opWatchWrite, and reports whether
// it landed: a refusal by the server's limits changes nothing. The write is
// in a's writes from just before it is sent, so a watcher answered before
// the writer reads the answer finds it, and leaves them when it did not land.
func pinWrite(ctx context.Context, c *target.Client, a *watched) (bool, error) {
	a.mu.Lock()
	a.writes = append(a.writes, time.Now())
	a.mu.Unlock()
	refused := false
	err := c.Do(ctx, opWatchWrite, http.MethodPatch, "/api/shares/"+a.share, a.token, pinBody(!a.pinned), func(r *http.Response) error {
		if refusedByLimit(r) {
			refused = true
			return nil
		}
		return wantStatus(http.StatusOK)(r)
	})
	if err != nil || refused {
		a.mu.Lock()
		a.writes = a.writes[:len(a.writes)-1]
		a.mu.Unlock()
		return false, err
	}
	a.pinned = !a.pinned
	return true, nil
}

// unpin leaves a's share unpinned, as the volume has it.
func unpin(ctx context.Context, probe *target.Client, a *watched) {
	if !a.pinned {
		return
	}
	if probe.Do(ctx, "probe", http.MethodPatch, "/api/shares/"+a.share, a.token, pinBody(false), wantStatus(http.StatusOK)) == nil {
		a.pinned = false
	}
}

func pinBody(pinned bool) io.Reader {
	return strings.NewReader(`{"pinned":` + strconv.FormatBool(pinned) + `}`)
}

// pinnable is, for each owner, the first share of the plan a write can pin:
// any but an inbox, which takes no pin, and an expired share, which the
// first housekeeping pass removes.
func pinnable(p volume.Plan) map[string]string {
	out := map[string]string{}
	for i := 0; i < p.Shares; i++ {
		s := p.Share(i)
		if s.Kind != volume.Inbox && s.Kind != volume.Expired && out[s.Owner] == "" {
			out[s.Owner] = s.ID
		}
	}
	return out
}

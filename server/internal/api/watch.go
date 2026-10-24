package api

import (
	"context"
	"net/http"
	"time"
)

// The long-poll notification route behind the clients' live refresh of an
// account's shares.
//
// Long-poll rather than SSE or WebSocket. One bit travels
// one way, so full duplex buys nothing and WebSocket would cost the server its
// first dependency past CertMagic (the stdlib has none) plus an Upgrade path
// to reason about in origins.go. Against SSE the deciding property is the
// "?since=" cursor: a change that lands while the client is disconnected is
// reported the instant it comes back, which an SSE reconnect only matches with
// Last-Event-ID plumbing, and a change lost across a reconnect is the one
// thing this route must never allow. The client's retry loop IS its reconnect
// logic, which is what makes sleep, a Wi-Fi change and a server restart
// uneventful.
const (
	// defaultWatchTimeout is how long a request parks before answering
	// "nothing happened". Comfortably under the 60 s that proxies and load
	// balancers commonly cut idle connections at.
	defaultWatchTimeout = 50 * time.Second
	// watchMaxPerOwner bounds one account's held connections. Every running
	// app holds one (each Mac, PC and Linux desktop, each phone in use, a
	// stray CLI), and a device back from sleep holds a new one while its old
	// connection lingers until the park ends. Past it the server REFUSES
	// rather than queues: a held connection is the point, so a queued caller
	// would wait for a disconnect that may never come. Refusing lets the
	// client fall back to polling instead.
	watchMaxPerOwner = 16
	// watchMaxTotal bounds the server. This is the guest-containment model:
	// an invited account must not be able to exhaust a 1-vCPU box, and a
	// parked request costs a goroutine and a socket for as long as it holds.
	watchMaxTotal = 256
)

// watchShares blocks until the caller's share listing changes, or, for a
// caller following upload progress, until the uploads into its inboxes
// move. A listing change is a NOTIFICATION, not data: clients re-read
// GET /api/shares (or the change feed), so the listing shape has no second
// place to drift. Upload progress is the one thing the watch answers as
// data, because it is never journaled and so has no other place to be
// read from as it moves (inboxprogress.go).
//
// A caller follows progress by sending `progress` (the cursor the last
// answer carried); a call with no `since` always does. Its answers carry
// `progress`, the cursor to send next, and when that differs from the one
// sent, `uploads`: EVERY inbox of the caller's with an upload in flight, so
// an inbox missing from it has none.
func (h *handler) watchShares(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	// The key is the authenticated account, never request input: it keys a
	// map, and a caller-controlled key grows it without bound (see fairSem).
	owner := u.Username
	if !h.watch.watchSem.tryAcquire(owner) {
		w.Header().Set("Retry-After", "5")
		writeErrorCode(w, http.StatusTooManyRequests, "too-many-watchers",
			"too many open watchers for this account")
		return
	}
	defer h.watch.watchSem.release(owner)

	q := r.URL.Query()
	since, progress := q.Get("since"), q.Get("progress")
	follow := since == "" || q.Has("progress")
	cursor, changed, err := h.waitForChange(r.Context(), since, owner, progress, follow)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	out := map[string]any{"cursor": cursor, "changed": changed}
	if follow {
		next, uploads, _ := h.claims.progressSince(owner, progress)
		out["progress"] = next
		if len(uploads) > 0 {
			out["uploads"] = uploads
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// waitForChange parks until something of the caller's changed since the
// cursor, the timeout passes, the request ends or the server drains. The
// cursor is the journal's own (metadb.Cursor); a client that holds no
// cursor is answered at once with the current one, so it can start
// watching without a first re-walk. With follow set, owner's upload
// progress moving past the progress cursor ends the wait too, the journal
// cursor unchanged.
func (h *handler) waitForChange(ctx context.Context, since, owner, progress string, follow bool) (cursor string, changed bool, err error) {
	if since == "" {
		cursor, err = h.db.Cursor()
		return cursor, false, err
	}
	// Subscribe BEFORE the first check: a change landing between a check
	// and the subscription would otherwise be missed until the timeout.
	wake, cancel := h.db.Subscribe()
	defer cancel()
	var moved <-chan struct{}
	if follow {
		var cancelProgress func()
		moved, cancelProgress = h.claims.subscribe(owner)
		defer cancelProgress()
	}
	changedSince := func() (string, bool, error) {
		b, err := h.db.Since(since, owner, 1)
		if err != nil {
			return "", false, err
		}
		if b.Reset || len(b.Changes) > 0 {
			return b.Next, true, nil
		}
		return since, false, nil
	}
	if cursor, changed, err = changedSince(); err != nil || changed {
		return cursor, changed, err
	}
	if follow && h.claims.progressMoved(owner, progress) {
		return since, false, nil
	}
	timeout := h.watch.watchTimeout
	if timeout <= 0 {
		timeout = defaultWatchTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-wake:
			if cursor, changed, err = changedSince(); err != nil || changed {
				return cursor, changed, err
			}
		case <-moved:
			if h.claims.progressMoved(owner, progress) {
				return changedSince()
			}
		case <-timer.C:
			return since, false, nil
		case <-ctx.Done():
			return since, false, nil
		case <-h.watch.drain:
			return since, false, nil
		}
	}
}

// watchState is the long-poll surface's own state. Grouped so watch.go and
// shareschanges.go carry it together rather than as loose fields on a handler
// that has nothing else to do with them.
type watchState struct {
	// watchSem bounds how many connections each account may park at once.
	watchSem *fairSem
	// watchTimeout overrides defaultWatchTimeout in tests, where waiting out
	// the real 50 s park would take minutes. Zero = the default.
	watchTimeout time.Duration
	// drain is closed once at shutdown: a closed channel wins every later
	// select, so parked watchers release and new ones never park.
	drain chan struct{}
}

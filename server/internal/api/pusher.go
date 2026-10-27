package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"hyperdrop/core/domainconn"
	"hyperdrop/core/inboxannounce"
	"hyperdrop/core/pushseal"
	"hyperdrop/core/updatenotice"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/pushrelay"
)

const (
	// pushTick re-examines a delivery waiting out its quiet window: the
	// window is an interval, and nothing else would look at the clock.
	pushTick = 2 * time.Second
	// pushSweep is the slow pass that catches what no share commit wakes:
	// the domain's state and an owner's seen mark settling a held delivery.
	// It also prunes forgotten accounts and writes the heartbeat.
	pushSweep = time.Minute
	// pushAbsence is how old the heartbeat may be for this process to trust
	// what the pusher remembered. Past it, another server (a rolled-back
	// release) may have served the volume meanwhile, and the remembered
	// state would announce everything that arrived in that window at once.
	pushAbsence = 2*pushSweep + desktopIdleLimit
)

// The server's own rows in push_state live under the empty owner, which no
// account can have and PrunePushState never removes.
const (
	pushStateServer = ""
	pushStateAlive  = "alive"        // the heartbeat: unix seconds of the last sweep
	pushStateInbox  = "inbox"        // an owner's inboxannounce.State
	pushStateRevoke = "revoke"       // an owner's revokeannounce.State
	pushStateDomain = "domain"       // the server's domainconn.Memory
	pushStateUpdate = "serverUpdate" // the server-update reminder keys pushed
	pushStateSignIn = "signIn"       // an owner's announced phone sign-ins (pushsignin.go)
)

// pushLogEvery is how often one recurring failure is logged: a pass runs
// every pushTick while a delivery waits, and a failure that holds one
// would otherwise log on every tick.
const pushLogEvery = time.Minute

// serverActivity is the server's own verdict for inboxannounce and
// revokeannounce: always "at it". Whether a computer of the account speaks
// instead is decided per owner (quiet): a quiet owner's announcements are
// recorded like sent ones and never pushed, so what the Mac announced is
// settled and never pushed later.
var serverActivity = inboxannounce.Activity{OnConsole: true}

// pusher decides what to announce from the server's own rows, with the
// client core's pure rules, and sends each announcement to every
// registered device of its account that has not muted the kind. It runs
// only in the serving process (NewServer starts it, Drain stops it).
type pusher struct {
	db       *metadb.DB
	relay    pushrelay.Sender
	relayURL string
	incoming func(shareID string) []inboxannounce.Claim
	domain   func() (domainconn.Facts, string) // nil = no free name to watch
	updates  func() []updatenotice.Notice      // nil = nothing to watch
	revoked  func(owner string) ([]metadb.RevokedSource, error)
	now      func() time.Time
	// setState, unseenOf and adminNames are the database calls whose
	// failure changes what is sent; tests replace them to fail.
	setState   func(owner, kind, value string) error
	unseenOf   func(owner string) (int, error)
	adminNames func() ([]string, error)

	mu      sync.Mutex
	pending bool

	// users are the accounts the previous pass evaluated; one missing now
	// unregistered its last device, and its memory is pruned at once.
	users []string
	// amnesia makes passes treat an owner's memory as unknown until a pass
	// has recorded that owner completely (recorded): it records what exists
	// and announces nothing (resume).
	amnesia  bool
	recorded map[string]bool

	// logged is when each recurring failure was last logged (logEvery).
	logged map[string]time.Time

	// signInMu serialises recording phone sign-ins: a read and a write of
	// one owner's push_state row (pushsignin.go), and signInSending, the
	// token ids of the sign-ins being sent now.
	signInMu      sync.Mutex
	signInSending map[string]bool

	// sends are the deliveries running on their own goroutine (sendSoon),
	// under sendsCtx; stop cancels it and waits for them, after which
	// sendSoon starts none.
	sendsMu      sync.Mutex
	sends        sync.WaitGroup
	sendsCtx     context.Context
	sendsCancel  context.CancelFunc
	sendsStopped bool

	cancel context.CancelFunc
	done   chan struct{}
}

func newPusher(db *metadb.DB, relay pushrelay.Sender, relayURL string) *pusher {
	ctx, cancel := context.WithCancel(context.Background())
	return &pusher{db: db, relay: relay, relayURL: relayURL, now: time.Now,
		incoming: func(string) []inboxannounce.Claim { return nil },
		setState: db.SetPushState, unseenOf: db.UnseenInboxFiles, adminNames: db.AdminNames,
		revoked: db.RevokedSources, sendsCtx: ctx, sendsCancel: cancel}
}

func (p *pusher) waiting() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pending
}

// start runs the pusher until stop: a pass on every share commit, on the
// tick while a delivery waits out its quiet window, and on the sweep. It
// first sends the phone sign-ins a previous process left owed.
func (p *pusher) start() {
	p.resume()
	p.resumeSignIns()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel, p.done = cancel, make(chan struct{})
	wake, unsubscribe := p.db.Subscribe()
	go func() {
		defer close(p.done)
		defer unsubscribe()
		tick, sweep := time.NewTicker(pushTick), time.NewTicker(pushSweep)
		defer tick.Stop()
		defer sweep.Stop()
		p.sweep(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-wake:
				p.pass(ctx)
			case <-tick.C:
				if p.waiting() {
					p.pass(ctx)
				}
			case <-sweep.C:
				p.sweep(ctx)
			}
		}
	}()
}

// stop ends the loop and the deliveries sendSoon started, and waits for a
// send in flight to finish. Calling it again, or on a pusher never
// started, is fine.
func (p *pusher) stop() {
	p.sendsMu.Lock()
	p.sendsStopped = true
	p.sendsCancel()
	p.sendsMu.Unlock()
	p.sends.Wait()
	if p.cancel == nil {
		return
	}
	p.cancel()
	<-p.done
}

// sendSoon runs send on its own goroutine, so a request that announces
// something answers without waiting on the relay, and reports whether it
// started it. A stopped pusher starts nothing.
func (p *pusher) sendSoon(send func(ctx context.Context)) bool {
	p.sendsMu.Lock()
	defer p.sendsMu.Unlock()
	if p.sendsStopped {
		return false
	}
	p.sends.Add(1)
	go func() {
		defer p.sends.Done()
		send(p.sendsCtx)
	}()
	return true
}

// resume decides whether this process may trust what the pusher remembered:
// only when the heartbeat says a pusher swept within pushAbsence. Otherwise
// the first pass records and announces nothing.
func (p *pusher) resume() {
	raw, ok, err := p.db.PushState(pushStateServer, pushStateAlive)
	if err != nil {
		log.Printf("push: heartbeat: %v", err)
	}
	at, perr := strconv.ParseInt(raw, 10, 64)
	p.amnesia = !ok || err != nil || perr != nil || p.now().Sub(time.Unix(at, 0)) > pushAbsence
	p.recorded = map[string]bool{}
}

// sweep is the slow pass: it forgets accounts with no registered device,
// evaluates every account, sends the phone sign-ins whose next try is due
// (pushsignin.go), and writes the heartbeat. While some owner is
// still unrecorded after an absence the heartbeat is not written, so a
// restart in that time distrusts the memory again instead of trusting an
// owner's state from before the absence.
func (p *pusher) sweep(ctx context.Context) {
	if err := p.db.PrunePushState(); err != nil {
		log.Printf("push: prune: %v", err)
	}
	p.pass(ctx)
	if ctx.Err() != nil {
		return
	}
	p.sendOwedSignIns()
	if p.amnesia {
		return
	}
	if err := p.db.SetPushState(pushStateServer, pushStateAlive, strconv.FormatInt(p.now().Unix(), 10)); err != nil {
		log.Printf("push: heartbeat: %v", err)
	}
}

// pass evaluates every account with a registered device. Accounts without
// one are not evaluated at all, and their memory is pruned, so a device
// registering later starts from what exists then.
func (p *pusher) pass(ctx context.Context) {
	users, err := p.db.PushUsers()
	if err != nil {
		log.Printf("push: %v", err)
		return
	}
	if gone(p.users, users) {
		if err := p.db.PrunePushState(); err != nil {
			log.Printf("push: prune: %v", err)
		}
	}
	p.users = users
	pending, complete := false, true
	for _, u := range users {
		if ctx.Err() != nil {
			return
		}
		waits, done := p.inboxPass(ctx, u)
		pending = pending || waits
		done = p.revokePass(ctx, u) && done
		p.settled(u, done, &complete)
	}
	if ctx.Err() != nil {
		return
	}
	d := p.domainPass(ctx)
	u := p.updatePass(ctx)
	p.settled(pushStateServer, d && u, &complete)
	if complete {
		p.amnesia, p.recorded = false, nil
	}
	p.mu.Lock()
	p.pending = pending
	p.mu.Unlock()
}

// settled notes one owner's (or the server's own) verdict for this pass:
// recorded completely, which after an absence makes its memory trusted
// again, or not, which keeps the absence in force for everyone.
func (p *pusher) settled(owner string, done bool, complete *bool) {
	if !done {
		*complete = false
	} else if p.amnesia {
		p.recorded[owner] = true
	}
}

// logEvery logs a recurring failure at most once per pushLogEvery for key.
// Nothing secret goes in: callers pass a kind and a username at most.
func (p *pusher) logEvery(key, format string, args ...any) {
	now := p.now()
	if at, ok := p.logged[key]; ok && now.Sub(at) < pushLogEvery {
		return
	}
	if p.logged == nil {
		p.logged = map[string]time.Time{}
	}
	p.logged[key] = now
	log.Printf(format, args...)
}

// gone reports whether some account in before is missing from after; both
// are sorted (PushUsers).
func gone(before, after []string) bool {
	j := 0
	for _, u := range before {
		for j < len(after) && after[j] < u {
			j++
		}
		if j == len(after) || after[j] != u {
			return true
		}
	}
	return false
}

// quiet reports whether a computer of the account saw its owner recently:
// that computer announces, so the phone is not told twice. A phone sign-in
// (pushsignin.go) never asks it: a computer's activity must not silence
// the alarm about a computer.
func (p *pusher) quiet(username string) bool {
	active, err := p.db.DesktopActiveSince(username, p.now().Add(-desktopIdleLimit))
	return err == nil && active
}

// loadState reads what was announced; false when nothing was remembered,
// or when this process does not trust the owner's memory yet (resume).
func (p *pusher) loadState(owner, kind string, v any) bool {
	if p.amnesia && !p.recorded[owner] {
		return false
	}
	raw, ok, err := p.db.PushState(owner, kind)
	if err != nil || !ok {
		return false
	}
	return json.Unmarshal([]byte(raw), v) == nil
}

// saveState records it and reports whether it is durable (an unchanged
// value is). It is written BEFORE anything is sent, and nothing is sent
// unless it is durable: a crash or a failed write loses a notification,
// which delivery never promised, rather than repeating it on every pass.
func (p *pusher) saveState(owner, kind string, v any) bool {
	raw, err := json.Marshal(v)
	if err != nil {
		return false
	}
	if old, ok, _ := p.db.PushState(owner, kind); ok && old == string(raw) {
		return true
	}
	if err := p.setState(owner, kind, string(raw)); err != nil {
		log.Printf("push: remember %s for %s: %v", kind, owner, err)
		return false
	}
	return true
}

// deliver seals m to every registered device of username that takes kind
// and registered with this server's relay, and sends it. A handle the
// relay calls gone is dropped; any other failure keeps the registration
// and drops this one notification. No log line names a handle or carries
// a ciphertext.
func (p *pusher) deliver(ctx context.Context, username, kind, collapse string, m pushseal.Message) {
	p.deliverTo(ctx, username, nil, kind, collapse, m)
}

// deliverTo is deliver to every such device but those whose token id skip
// names. It answers the devices (their token ids) the relay answered about,
// and whether it finished: the devices were read, ctx did not end, and the
// relay answered about every device sent to. A device whose message cannot
// be sealed counts as answered, since no later send could seal it either.
func (p *pusher) deliverTo(ctx context.Context, username string, skip []string, kind, collapse string, m pushseal.Message) (answered []string, finished bool) {
	targets, err := p.db.PushTargets(username)
	if err != nil {
		log.Printf("push: devices of %s: %v", username, err)
		return nil, false
	}
	finished = true
	for _, t := range targets {
		if ctx.Err() != nil {
			return answered, false // stopping: the rest of this notification is dropped quietly
		}
		if t.Relay != p.relayURL || t.Mutes(kind) || slices.Contains(skip, t.TokenID) {
			continue
		}
		msg := m
		msg.V, msg.Kind, msg.Tag = 1, kind, t.Tag
		ct, err := pushseal.Seal(t.PublicKey, msg)
		if err != nil {
			log.Printf("push: seal for a device of %s: %v", username, err)
			answered = append(answered, t.TokenID)
			continue
		}
		err = p.relay.Send(ctx, pushrelay.Message{Handle: t.Handle, Ciphertext: ct, CollapseID: collapse})
		if ctx.Err() != nil {
			return answered, false
		}
		if errors.Is(err, pushrelay.ErrGone) {
			if err := p.db.DropPushHandle(t.Handle); err != nil {
				log.Printf("push: drop a gone device of %s: %v", username, err)
			}
		} else if err != nil {
			log.Printf("push: %s to a device of %s: %v", kind, username, err)
		}
		if relayAnswered(err) {
			answered = append(answered, t.TokenID)
		} else {
			finished = false
		}
	}
	return answered, finished
}

// relayAnswered reports whether a send's outcome is the relay's answer
// about the device: a success, or a refusal of this message for it (a 4xx,
// Gone among them). A transport error, a redirect, a 5xx and a 429 say
// nothing about the device; the relay or the way to it failed, and a later
// send can succeed.
func relayAnswered(err error) bool {
	var re *pushrelay.Error
	switch {
	case err == nil, errors.Is(err, pushrelay.ErrGone):
		return true
	case errors.As(err, &re):
		return re.Status >= 400 && re.Status < 500 && re.Status != http.StatusTooManyRequests
	default:
		return false
	}
}

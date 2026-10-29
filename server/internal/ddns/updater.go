package ddns

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"
)

const (
	// Public address observation is a credential-free request to HyperDrop's
	// names service. Five minutes detects a changed home address promptly while
	// jittering the fleet far below a request per server per minute.
	TickInterval = 5 * time.Minute
	// Periodically confirm DNS even when the public address has not changed.
	Heartbeat = 12 * time.Hour
	// MaxBackoff caps how long a persistently failing server waits between
	// attempts. It prevents a disconnected fleet from hammering the service
	// on every tick while still recovering within an hour once connectivity
	// returns.
	MaxBackoff = time.Hour
)

type Updater struct {
	RecipeHTTP *http.Client       // test transport; production uses the restricted HTTPS client
	Connected  func(string) error // adopt and manage certificates after approved publication
	Domain     func() string
	ServerID   func() string
	ProbeHost  func(ctx context.Context, host, ip string, pin []byte) HostStatus // test hook for probeHost
	// LocalLeaf answers the DER leaf certificate this process serves for
	// host, or nil while it holds none. Custom DDNS pins its HTTPS checks to
	// it, so an address answering with another certificate is never taken
	// for this server's.
	LocalLeaf func(host string) []byte
	// PrivateRecipes is the operator's HYPERDROP_DDNS_ALLOW_PRIVATE=1: only
	// then may a recipe's allowPrivate reach private or reserved addresses.
	// The admin role writes recipes and is not the network's operator, so
	// without it a recipe dials public addresses alone.
	PrivateRecipes bool
	store          *Store
	names          *Client
	addr           func(context.Context) (string, bool)

	// Now and Interval are seams for tests; production leaves them alone.
	Now      func() time.Time
	Interval time.Duration

	// runMu guards stop: Start and Stop are called from HTTP handlers (PUT
	// and DELETE /api/ddns) that can race each other and the boot-time
	// call, and both must agree on whether a loop is currently running.
	// stop is nil exactly when no loop is running; a fresh channel is
	// allocated on every Start, so a Stop from an earlier run can never
	// reach a later one.
	runMu    sync.Mutex
	stop     chan struct{}
	done     chan struct{}
	stopping bool

	// tickMu serializes Tick: PUT /api/ddns forces one while the run loop
	// may be ticking on its own schedule, and both reading the same
	// "not due" snapshot before either writes back would post twice.
	tickMu sync.Mutex

	// failStreak and backoffUntil hold the consecutive-failure backoff.
	// Both are touched only from inside Tick, which tickMu already
	// serializes, so they need no lock of their own. A restart forgets
	// them, so a server that was backed off retries once immediately after
	// coming back up, which is fine: one extra attempt costs nothing next
	// to the budget a stuck backoff would otherwise burn.
	failStreak   int
	backoffUntil time.Time

	// lastClaimError holds why the most recent claim was refused, guarded
	// by tickMu. A refused claim leaves the store holding no name, and
	// Store.Record is a no-op with no name to attach a reason to, so this
	// is where GET /api/ddns finds it instead. Cleared the moment a claim
	// succeeds.
	lastClaimError string
}

func NewUpdater(s *Store, c *Client, addr func(context.Context) (string, bool)) *Updater {
	return &Updater{
		store: s, names: c, addr: addr,
		Now: time.Now, Interval: TickInterval,
	}
}

func (u *Updater) Store() *Store { return u.store }

// ObservedIPv4 is the public IPv4 the names service sees this server come
// from, through the same observation the update loop makes; false when it
// could not be learned.
func (u *Updater) ObservedIPv4(ctx context.Context) (string, bool) { return u.addr(ctx) }

// Take claims a name for this install and starts holding it: durably stage a
// generated token, claim idempotently, confirm locally, then post the first
// update so the address is published.
// Completion waits until the Connected callback is installed at boot.
//
// A name already held is left exactly as it is. Without that a restart
// would claim again on every boot, burning the per-address limit against a
// name this server already owns.
func (u *Updater) Take(ctx context.Context, name, serverID string) error {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	st := u.store.Snapshot()
	if st.Disconnected {
		return nil
	}
	if st.Pending && st.Name == name {
		return u.finishClaimLocked(ctx, st)
	}
	if st.Name != "" && st.Token != "" {
		return nil
	}
	return u.beginClaimLocked(ctx, name, serverID)
}

func (u *Updater) beginClaimLocked(ctx context.Context, name, serverID string) error {
	raw := make([]byte, 32)
	if _, err := crand.Read(raw); err != nil {
		return err
	}
	if err := u.store.BeginClaim(name, base64.RawURLEncoding.EncodeToString(raw), serverID); err != nil {
		return err
	}
	return u.finishClaimLocked(ctx, u.store.Snapshot())
}

func (u *Updater) finishClaimLocked(ctx context.Context, st State) error {
	if st.Cancelled {
		return errors.New("the previous connection is being cancelled; retry after disconnect completes")
	}
	if !st.Approved {
		_, err := u.names.Claim(ctx, st.Name, st.ServerID, st.Token)
		if err != nil {
			var approval *ServiceError
			if errors.As(err, &approval) && approval.Code == "account-required" {
				if saveErr := u.rememberEnrollment(approval); saveErr != nil {
					return saveErr
				}
			}
			u.lastClaimError = err.Error()
			if errors.Is(err, ErrNameTaken) || errors.Is(err, ErrNameRefused) || errors.Is(err, ErrClaimRateLimited) {
				_ = u.store.Clear()
			}
			return err
		}
		// Approval is durable, but the transition is still pending until the
		// first publication and domain/certificate adoption both succeed.
		if err := u.store.change(func(s *State) { s.Approved = true; s.Enrollment = nil }); err != nil {
			return err
		}
		u.lastClaimError = ""
		u.failStreak = 0
		u.backoffUntil = time.Time{}
	}
	if err := u.managedPostLocked(ctx); err != nil {
		if current := u.store.Snapshot(); current.LastUpdate == 0 || current.LastError != "" {
			return err
		}
	}
	if published := u.store.Snapshot(); published.LastUpdate == 0 || published.LastError != "" {
		return nil
	} // publication is backed off
	if u.Connected != nil {
		if err := u.Connected(FQDN(st.Name)); err != nil {
			return err
		}
	}
	return u.store.ConfirmClaim()
}

// Choose starts or retries account approval for this server. Disconnect an
// existing connection before choosing a different name.
func (u *Updater) Choose(ctx context.Context, name, serverID string) error {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	st := u.store.Snapshot()
	if st.Name != "" && st.Name != name {
		return ErrNamePermanent
	}
	if st.Pending {
		return u.finishClaimLocked(ctx, st)
	}
	if st.Name == "" || st.Token == "" || st.tokenRefused() {
		return u.beginClaimLocked(ctx, name, serverID)
	}
	err := u.postLocked(ctx)
	if errors.Is(err, ErrUnknownToken) || errors.Is(err, ErrReleased) {
		return u.beginClaimLocked(ctx, name, serverID)
	}
	return err
}

// Release disconnects the machine after durable central DNS cleanup. The
// name stays owned by its account until its owner explicitly releases it.
func (u *Updater) Release(ctx context.Context) error {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	return u.releaseLocked(ctx)
}

func (u *Updater) releaseLocked(ctx context.Context) error {
	st := u.store.Snapshot()
	if st.Name == "" || st.Token == "" {
		return nil
	}
	if err := u.names.Release(ctx, st.Token); err != nil && !errors.Is(err, ErrReleased) && !errors.Is(err, ErrUnknownToken) {
		return err
	}
	if err := u.store.Disconnect(); err != nil {
		return err
	}
	u.failStreak = 0
	u.backoffUntil = time.Time{}
	return nil
}

// ChangeDomain serializes the user-selected domain with enrollment completion.
// The durable cancellation intent prevents a crash or failed central disconnect
// from letting an old approval replace the user's new custom domain later.
func (u *Updater) ChangeDomain(ctx context.Context, change func() error) error {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	before := u.store.Snapshot()
	pending := before.Pending
	if pending {
		if err := u.store.change(func(s *State) { s.Cancelled = true; s.Enrollment = nil }); err != nil {
			return err
		}
	}
	if err := change(); err != nil {
		if pending {
			_ = u.store.change(func(s *State) { s.Cancelled = before.Cancelled; s.Enrollment = before.Enrollment })
		}
		return err
	}
	if pending {
		return u.releaseLocked(ctx)
	}
	return nil
}

// Replace disconnects this install only; account ownership remains unchanged.
func (u *Updater) Replace(ctx context.Context, name, serverID string) error {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	st := u.store.Snapshot()
	if st.Name != "" && st.Name != name {
		if err := u.releaseLocked(ctx); err != nil {
			return err
		}
	}
	st = u.store.Snapshot()
	if st.Pending {
		return u.finishClaimLocked(ctx, st)
	}
	if st.Name == name && st.Token != "" && !st.tokenRefused() {
		return u.managedPostLocked(ctx)
	}
	return u.beginClaimLocked(ctx, name, serverID)
}

// CancelCandidate is conditional: an old UI task cannot cancel a later name.
func (u *Updater) CancelCandidate(ctx context.Context, name string) error {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	st := u.store.Snapshot()
	if st.Name != name || !st.Pending {
		return nil
	}
	if err := u.store.change(func(s *State) { s.Cancelled = true; s.Enrollment = nil }); err != nil {
		return err
	}
	return u.releaseLocked(ctx)
}

// LastClaimError is why the most recent claim was refused, or empty if none
// has been refused or the most recent one succeeded.
func (u *Updater) LastClaimError() string {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	return u.lastClaimError
}

// Tick decides whether to post, and posts: the update loop's step. A server
// holding neither a free name nor a DDNS recipe is not watched, and its tick
// sends nothing anywhere: no observation of its public IPv4 through the names
// service and no lookup at a public resolver.
func (u *Updater) Tick(ctx context.Context) error {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	return u.postLocked(ctx)
}

// CheckNow is POST /api/connectivity/check, a tick an administrator asked
// for. On a watched server it is Tick, and respects a provider or registry
// retry deadline like a scheduled one. On a server that is not watched it
// runs the one address and hostname check that server ever makes: the names
// service's observation of its public IPv4, then both hostnames through the
// public resolvers and over HTTPS. Its result schedules no retry and raises
// no alert, because nothing follows it up.
func (u *Updater) CheckNow(ctx context.Context) error {
	u.tickMu.Lock()
	defer u.tickMu.Unlock()
	if !watched(u.store.Snapshot()) {
		return u.checkUnwatchedLocked(ctx)
	}
	return u.postLocked(ctx)
}

// watched reports whether the update loop keeps an address current for st:
// a free name (held, or being connected) or a DDNS recipe, custom or
// external. Only a watched server observes its address on a schedule.
func watched(st State) bool { return st.Name != "" || st.Custom != nil }

// checkUnwatchedLocked is CheckNow on a server that is not watched.
func (u *Updater) checkUnwatchedLocked(ctx context.Context) error {
	if u.hostNames() == nil {
		return nil
	}
	now := u.Now().Unix()
	ip, known := u.addr(ctx)
	if !known {
		_ = u.observe("", now)
		return u.failure(ctx, "Public IPv4 observation failed", 0, false)
	}
	if err := u.observe(ip, now); err != nil {
		return err
	}
	return u.verify(ctx, ip)
}

// settleUnwatchedLocked is a scheduled tick on a server that is not watched.
// It observes and resolves nothing. A retry time, an incident or an alert in
// the status would describe monitoring this server does not do, so any the
// status holds is cleared; the readings of the last check stay.
func (u *Updater) settleUnwatchedLocked() error {
	c := u.store.Snapshot().Connectivity
	if c.NextAttempt == 0 && c.IncidentAt == 0 && !c.Alert {
		return nil
	}
	return u.store.change(func(s *State) {
		s.Connectivity.NextAttempt = 0
		s.Connectivity.IncidentAt = 0
		s.Connectivity.Alert = false
	})
}

// postLocked is Tick's body, called with tickMu already held. Take needs
// the same posting logic under the same lock it takes for the claim and
// persist that precede it, so the lock and the body are two separate
// functions rather than Tick calling itself.
func (u *Updater) postLocked(ctx context.Context) error {
	st := u.store.Snapshot()
	if st.Cancelled {
		return u.releaseLocked(ctx)
	}
	if st.Pending {
		// The selected custom domain remains live throughout approval and
		// publication retries. Its provider must continue receiving IP moves.
		if st.Custom != nil {
			_ = u.customTick(ctx)
		}
		return u.finishClaimLocked(ctx, u.store.Snapshot())
	}
	return u.managedPostLocked(ctx)
}

func (u *Updater) managedPostLocked(ctx context.Context) error {
	st := u.store.Snapshot()
	if st.Name == "" || st.Token == "" {
		if st.Custom == nil {
			return u.settleUnwatchedLocked()
		}
		if u.Domain != nil && u.Domain() != "" {
			return u.customTick(ctx)
		}
		return nil
	}
	nowTime := u.Now()
	if st.LastError != "" && st.RetryAt > nowTime.Unix() {
		return nil
	}
	if u.failStreak == 0 && st.LastError != "" {
		u.failStreak = st.ManagedFailures
	}
	if u.failStreak > 0 && nowTime.Before(u.backoffUntil) {
		// A consecutive failure is backing this tick off: attempting again
		// before the deadline would only spend another request against the
		// same daily budget the whole cadence protects, for a service that
		// is already refusing this token or this server's requests.
		return nil
	}
	addr, known := u.addr(ctx)
	now := nowTime.Unix()
	if err := u.observe(addr, now); err != nil {
		return err
	}

	// Two reasons to post, and only two: the address moved, or the scheduled
	// heartbeat is due. The unauthenticated observation is only a TRIGGER,
	// so it is compared against the PREVIOUS PROBE, never against LastIP:
	// it and the authenticated update use separate connections and can take
	// different egress paths on a multi-homed server. An unknown probe is no news, so it
	// triggers nothing; the heartbeat still fires and the service writes
	// whatever source address it sees. A row that has never posted has
	// LastUpdate zero, which is always overdue, so the very first tick
	// always posts.
	moved := known && addr != st.LastProbe
	due := now-st.LastUpdate >= int64(Heartbeat/time.Second)
	if !moved && !due {
		if !known {
			return u.failure(ctx, "Public IPv4 observation failed", now+300, false)
		}
		return u.verify(ctx, addr)
	}

	_ = u.store.change(func(s *State) {
		s.Connectivity.LastAttempt = now
		addEvent(&s.Connectivity, now, "update-started", "Updating managed DNS")
	})
	res, err := u.names.Update(ctx, st.Token)
	if err != nil {
		_ = u.store.Record("", "", now, err.Error())
		u.failStreak++
		u.backoffUntil = nowTime.Add(backoffFor(u.failStreak))
		var serviceErr *ServiceError
		if errors.As(err, &serviceErr) && serviceErr.RetryAfter > u.backoffUntil.Unix() {
			u.backoffUntil = time.Unix(serviceErr.RetryAfter, 0)
		}
		_ = u.store.change(func(s *State) { s.RetryAt = u.backoffUntil.Unix(); s.ManagedFailures = u.failStreak })
		_ = u.failure(ctx, err.Error(), u.backoffUntil.Unix(), errors.Is(err, ErrReleased) || errors.Is(err, ErrUnknownToken))
		return err
	}
	u.failStreak = 0
	u.backoffUntil = time.Time{}
	// The probe this tick becomes the value the NEXT tick compares
	// against, unless it came back unknown, in which case there is
	// nothing new to remember and the previous probe stands.
	probe := st.LastProbe
	if known {
		probe = addr
	}
	if err := u.store.Record(res.IP, probe, now, ""); err != nil {
		return err
	}
	_ = u.store.change(func(s *State) {
		s.Connectivity.LastSuccess = now
		addEvent(&s.Connectivity, now, "update-accepted", "Managed DNS update accepted")
	})
	return u.verify(ctx, res.IP)
}

// backoffFor is the wait before the next attempt after streak consecutive
// failures: one tick interval after the first, doubling per further
// failure, capped at MaxBackoff so a server stuck failing settles near the
// heartbeat rate instead of retrying forever.
func backoffFor(streak int) time.Duration {
	d := TickInterval
	for i := 1; i < streak; i++ {
		if d >= MaxBackoff {
			return MaxBackoff
		}
		d *= 2
	}
	if d > MaxBackoff {
		d = MaxBackoff
	}
	return d
}

// Start launches the update loop on its own goroutine, unless one is
// already running, in which case it does nothing. Safe to call from more
// than one goroutine, and safe to call again after Stop: each launch opens
// a fresh stop channel, so a loop stopped and restarted keeps running
// until its own Stop call, never an earlier one's.
func (u *Updater) Start(ctx context.Context) {
	u.runMu.Lock()
	if u.stop != nil {
		u.runMu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	u.stop = stop
	u.done = done
	u.stopping = false
	u.runMu.Unlock()
	go u.run(ctx, stop, done)
}

// Stop ends the running loop, if one is running, and is safe to call from
// more than one goroutine and more than once: a call with no loop running
// does nothing.
func (u *Updater) Stop() {
	u.runMu.Lock()
	if u.stop == nil {
		u.runMu.Unlock()
		return
	}
	stop, done := u.stop, u.done
	if !u.stopping {
		close(stop)
		u.stopping = true
	}
	u.runMu.Unlock()
	<-done
}

// run is the loop Start launches: it ticks until the context ends or Stop
// closes stop. The jitter matters at scale: without it every server in the
// fleet queries on the same second.
//
// On the way out it clears the stop channel, so a loop that ends on its
// own (a terminal error, or ctx.Done) leaves the updater restartable
// exactly like an explicit Stop would. Comparing against the channel this
// call was given, rather than unconditionally clearing u.stop, means a
// goroutine finishing late (after Stop already opened a fresh one for a
// new Start) never clobbers the run it does not own.
func (u *Updater) run(ctx context.Context, stop, done chan struct{}) {
	defer func() {
		u.runMu.Lock()
		if u.stop == stop {
			u.stop = nil
			u.done = nil
			u.stopping = false
		}
		close(done)
		u.runMu.Unlock()
	}()
	for {
		if err := u.Tick(ctx); err != nil {
			if errors.Is(err, ErrReleased) || errors.Is(err, ErrUnknownToken) {
				// Terminal: the name is not ours. Retrying every tick
				// would achieve nothing, and GET /api/ddns carries the
				// reason for the app to show.
				log.Printf("ddns: %v; the updater is stopping", err)
				return
			}
			log.Printf("ddns: update failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-time.After(u.jittered()):
		}
	}
}

// jittered spreads the fleet across the interval rather than having every
// server query on the same second.
func (u *Updater) jittered() time.Duration {
	if u.Interval <= 0 {
		return TickInterval
	}
	return u.Interval + time.Duration(rand.Int64N(max(int64(u.Interval/2), 1))) // #nosec G404 -- a schedule spread, not a secret
}

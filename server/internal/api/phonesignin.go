package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"hyperdrop/server/internal/metadb"
)

// Signing a browser in with a phone. A public computer has no account to
// mint from, so the browser asks for a sign-in request and shows its code
// (a hdweb1 join code) as a QR code; a phone already signed in to the
// account claims it with its bearer, the browser then shows a two-digit
// number, and the phone's owner types that number on the phone, which
// approves the request (with the account's code when it has a second
// factor). The browser's next poll collects a public web session: never a
// kept one, and never a token.
//
// Requests live in memory only (webSignIns), never in the database, its
// journal or a backup, so a restart forgets every one and the browser asks
// for a new code. The browser's two routes ask the web sign-in's conditions
// of their request (webCookieAccepted) and refuse while the web client is
// not served; the phone's three are a device token's alone (cookieNever).
//
// The secret and the poll secret are 32 random bytes each, so a guess at
// either is not counted on the lockout: an unknown request is answered as a
// lapsed one, the browser's ordinary state after two minutes on the page,
// which must never lock its address out of signing in.

// webSignInPrefix starts a sign-in request's code, core/joincode's
// WebSignInPrefix: the server builds the code itself, since it imports no
// client package that is not pure. TestWebSignInCodeFixture here and
// core/joincode's TestServerWebSignInCodeDecodes hold one fixture, so the
// two spellings cannot drift apart.
const webSignInPrefix = "hdweb1."

// desktopSignInPrefix starts a desktop app's sign-in request code,
// core/joincode's DesktopSignInPrefix. TestDesktopSignInCodeFixture here and
// core/joincode's TestServerDesktopSignInCodeDecodes hold one fixture.
const desktopSignInPrefix = "hddesk1."

const (
	// webSignInUnclaimedFor is how long a request waits for a phone.
	webSignInUnclaimedFor = 2 * time.Minute
	// webSignInClaimedFor is how long a claimed request waits for the
	// approval and, once approved, for the browser's poll.
	webSignInClaimedFor = 5 * time.Minute
	// webSignInPerAddress bounds the live requests one address key (an IPv6
	// address by its /64) holds.
	webSignInPerAddress = 3
	// webSignInPerNetwork bounds the live requests one IPv6 /48, a single
	// site's allocation, holds across its /64s.
	webSignInPerNetwork = 32
	// webSignInPerWideNetwork bounds the live requests one IPv6 /32, a
	// provider's allocation, holds across its /48s.
	webSignInPerWideNetwork = 128
	// webSignInMax bounds the live requests the server holds.
	webSignInMax = 4096
)

// webSignInCode is the hdweb1 code for a request: the server's address,
// its identity and the request's one-time secret, as core/joincode encodes
// a WebSignIn code.
func webSignInCode(server, serverID, secret string) string {
	return signInCode(webSignInPrefix, server, serverID, secret)
}

// desktopSignInCode is the hddesk1 code for a desktop app's request: the
// payload of a web code under the desktop prefix.
func desktopSignInCode(server, serverID, secret string) string {
	return signInCode(desktopSignInPrefix, server, serverID, secret)
}

func signInCode(prefix, server, serverID, secret string) string {
	b, _ := json.Marshal(struct {
		S string `json:"s"`
		I string `json:"i"`
		W string `json:"w"`
	}{server, serverID, secret})
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

type webSignInState int

const (
	webSignInWaiting webSignInState = iota
	webSignInClaimed
	webSignInApproved
)

// webSignIn is one request, a browser's or a computer's. The secrets are
// kept as their hashes; addr is the requester's address, shown to the
// approving phone and dropped with the request.
type webSignIn struct {
	secretHash, pollHash string
	// addrKey is the requester's lockout address key, netKey its IPv6 /48 and
	// wideKey its IPv6 /32 ("" for an IPv4 address, whose key is the address
	// itself).
	addrKey, netKey, wideKey, addr string
	addrMark                       string
	browser                        string
	// wantUser is the account a computer's request is for, the username
	// typed there (signInUsername): only that account's claim matches it.
	// It is "" on a browser's request, which any account may claim. label
	// and platform are what the computer calls itself.
	wantUser, label, platform string
	state                     webSignInState
	until                     time.Time
	// The claim: the account and the device token that claimed it, and the
	// number the browser shows.
	user, tokenID string
	number        int
}

// webSignIns holds the live requests by id. Every call first drops the
// requests that ran out; a burned, denied or spent request is dropped at
// once, so a request yields at most one session.
type webSignIns struct {
	mu sync.Mutex
	m  map[string]*webSignIn
	// clock is the book's time, time.Now when nil.
	clock func() time.Time
}

func (b *webSignIns) now() time.Time {
	if b.clock != nil {
		return b.clock()
	}
	return time.Now()
}

// sweep drops every request that ran out; b.mu is held.
func (b *webSignIns) sweep(now time.Time) {
	for id, s := range b.m {
		if !now.Before(s.until) {
			delete(b.m, id)
		}
	}
}

// errWebSignInsFull is a request refused because the server holds
// webSignInMax already.
var errWebSignInsFull = errors.New("too many sign-in requests are waiting")

// webSecret is 32 random bytes, base64url.
func webSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("web sign-in: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// webSignInNetKey is the IPv6 prefix of bits an address belongs to, "" for
// an IPv4 address or one that does not parse.
func webSignInNetKey(ip string, bits int) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return ""
	}
	return netip.PrefixFrom(a, bits).Masked().String()
}

// webSignInFrom is a new request's address: the requester at ip, its
// address keys and its keyed mark addrMark.
func webSignInFrom(ip, addrMark string) webSignIn {
	return webSignIn{addrKey: addrKey(ip), netKey: webSignInNetKey(ip, 48), wideKey: webSignInNetKey(ip, 32),
		addr: ip, addrMark: addrMark}
}

// create starts request req, whose address fields webSignInFrom filled and
// whose secrets, state and lifetime create sets. Past webSignInPerAddress
// live requests for its addrKey, webSignInPerNetwork for its netKey or
// webSignInPerWideNetwork for its wideKey, it answers ok false and when the
// oldest of those runs out.
func (b *webSignIns) create(req webSignIn, now time.Time) (id, secret, pollSecret string, until time.Time, ok bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	held, inNet, inWide := 0, 0, 0
	var free, netFree, wideFree time.Time
	earliest := func(t *time.Time, u time.Time) {
		if t.IsZero() || u.Before(*t) {
			*t = u
		}
	}
	for _, s := range b.m {
		if s.addrKey == req.addrKey {
			held++
			earliest(&free, s.until)
		}
		if req.netKey != "" && s.netKey == req.netKey {
			inNet++
			earliest(&netFree, s.until)
		}
		if req.wideKey != "" && s.wideKey == req.wideKey {
			inWide++
			earliest(&wideFree, s.until)
		}
	}
	switch {
	case held >= webSignInPerAddress:
		return "", "", "", free, false, nil
	case inNet >= webSignInPerNetwork:
		return "", "", "", netFree, false, nil
	case inWide >= webSignInPerWideNetwork:
		return "", "", "", wideFree, false, nil
	}
	if len(b.m) >= webSignInMax {
		return "", "", "", time.Time{}, false, errWebSignInsFull
	}
	if b.m == nil {
		b.m = map[string]*webSignIn{}
	}
	id, secret, pollSecret = webSecret(), webSecret(), webSecret()
	until = now.Add(webSignInUnclaimedFor)
	s := req
	s.secretHash, s.pollHash = metadb.TokenHash(secret), metadb.TokenHash(pollSecret)
	s.state, s.until, s.user, s.tokenID, s.number = webSignInWaiting, until, "", "", 0
	b.m[id] = &s
	return id, secret, pollSecret, until, true, nil
}

// webSignInPoll is what a poll finds: the request's state, its number once
// claimed, and once approved the account and device token that approved
// it, the request spent by that poll, with what the requester said of
// itself and its address mark.
type webSignInPoll struct {
	state                    webSignInState
	number                   int
	user, tokenID            string
	browser, label, platform string
	addrMark                 string
}

// poll reads request id with its poll secret. An approved request is
// spent by the poll that finds it, before the session is minted, so a
// second poll finds nothing.
func (b *webSignIns) poll(id, pollSecret string, now time.Time) (webSignInPoll, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	s, ok := b.m[id]
	if !ok || subtle.ConstantTimeCompare([]byte(s.pollHash), []byte(metadb.TokenHash(pollSecret))) != 1 {
		return webSignInPoll{}, false
	}
	if s.state == webSignInApproved {
		delete(b.m, id)
	}
	return webSignInPoll{state: s.state, number: s.number, user: s.user, tokenID: s.tokenID,
		browser: s.browser, label: s.label, platform: s.platform, addrMark: s.addrMark}, true
}

// claim is account user's device token tokenID presenting secret. A request
// bound to another account (wantUser) is answered as an unknown one and
// left exactly as it was, so no other account can burn it. The first claim
// of a waiting request draws its number and gives it webSignInClaimedFor; a
// claim of a request already claimed burns it. A claim also burns every
// other live request the account claimed in this book, so one account
// approves one request at a time.
func (b *webSignIns) claim(secret, user, tokenID string, now time.Time) (id string, s webSignIn, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	hash := metadb.TokenHash(secret)
	for rid, r := range b.m {
		if r.secretHash == hash {
			id = rid
			break
		}
	}
	r, found := b.m[id]
	if !found || (r.wantUser != "" && r.wantUser != user) {
		return "", webSignIn{}, false
	}
	if r.state != webSignInWaiting {
		delete(b.m, id)
		return "", webSignIn{}, false
	}
	for oid, o := range b.m {
		if o.state != webSignInWaiting && o.user == user {
			delete(b.m, oid)
		}
	}
	r.state, r.user, r.tokenID = webSignInClaimed, user, tokenID
	r.number = randomWebSignInNumber()
	r.until = now.Add(webSignInClaimedFor)
	return id, *r, true
}

// randomWebSignInNumber is a uniform integer in 10..99.
func randomWebSignInNumber() int {
	for {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("web sign-in: " + err.Error())
		}
		// 180 is the largest multiple of 90 below 256, so the draw is
		// uniform.
		if b[0] < 180 {
			return 10 + int(b[0])%90
		}
	}
}

// claimedBy is request id when account user's token tokenID claimed it and
// it waits for the approval; b.mu is held.
func (b *webSignIns) claimedBy(id, user, tokenID string) (*webSignIn, bool) {
	s, ok := b.m[id]
	if !ok || s.state != webSignInClaimed || s.user != user || s.tokenID != tokenID {
		return nil, false
	}
	return s, true
}

// match judges number against request id, claimed by user's token
// tokenID: ok false when there is no such claim, and wrong when the number
// is another, which burns the request.
func (b *webSignIns) match(id, user, tokenID string, number int, now time.Time) (ok, wrong bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	s, ok := b.claimedBy(id, user, tokenID)
	if !ok {
		return false, false
	}
	if s.number != number {
		delete(b.m, id)
		return true, true
	}
	return true, false
}

// approve approves request id, still claimed by user's token tokenID with
// number, for the browser's next poll.
func (b *webSignIns) approve(id, user, tokenID string, number int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	s, ok := b.claimedBy(id, user, tokenID)
	if !ok || s.number != number {
		return false
	}
	s.state = webSignInApproved
	return true
}

// deny burns request id, claimed or approved by user's token tokenID.
func (b *webSignIns) deny(id, user, tokenID string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	s, ok := b.m[id]
	if !ok || s.state == webSignInWaiting || s.user != user || s.tokenID != tokenID {
		return false
	}
	delete(b.m, id)
	return true
}

// clear drops every request.
func (b *webSignIns) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m = nil
}

// writeWebSignInExpired answers a request that is unknown, ran out, was
// burned, denied or spent, or is another device's: one answer for all, and
// the cue for the browser to ask for a new code.
func writeWebSignInExpired(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusGone, "web-sign-in-expired", "this sign-in code is not valid any more; ask the browser for a new one")
}

// webSignInRequestRefused answers a browser's request the web sign-in's
// conditions refuse (the version window, the app's own host and origin, the
// address lockout) and reports whether it did; otherwise it answers the
// admitted attempt, which the caller settles.
func (h *handler) webSignInRequestRefused(w http.ResponseWriter, r *http.Request, now time.Time) (*pwAttempt, bool) {
	w.Header().Set("Cache-Control", "no-store")
	client := metadb.ParseClientHeader(r.Header.Get("X-HyperDrop-Client"))
	if h.refuseClientOutsideWindow(w, r, client.Version) {
		return nil, true
	}
	if !h.webCookieAccepted(r) {
		writeErrorCode(w, http.StatusForbidden, "web-session-refused", "sign in from the web client on this server's own address")
		return nil, true
	}
	att, ok := h.admitLogin(w, r, now)
	return att, !ok
}

// createWebSignIn is the browser asking for a request: its id and poll
// secret, the code it shows and when the code runs out.
func (h *handler) createWebSignIn(w http.ResponseWriter, r *http.Request) {
	now := h.signIns.now()
	att, refused := h.webSignInRequestRefused(w, r, now)
	if refused {
		return
	}
	defer att.abandon()
	var req struct{}
	if !decodeOptionalJSONBody(w, r, 4<<10, &req) {
		return
	}
	s := webSignInFrom(clientIP(r), h.linkAddrMark(r))
	s.browser = uaSummary(r.UserAgent())
	id, secret, pollSecret, until, ok, err := h.signIns.create(s, now)
	if refuseSignInCreate(w, ok, err, until, now) {
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		ID         string    `json:"id"`
		PollSecret string    `json:"pollSecret"`
		Code       string    `json:"code"`
		ExpiresAt  time.Time `json:"expiresAt"`
	}{id, pollSecret, webSignInCode(h.canonicalBase(r), h.fs.ServerID(), secret), until})
}

// refuseSignInCreate answers a create the book refused, with err and until
// as create answered them, and reports whether it did.
func refuseSignInCreate(w http.ResponseWriter, ok bool, err error, until, now time.Time) bool {
	switch {
	case errors.Is(err, errWebSignInsFull):
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusServiceUnavailable, "the server is holding too many sign-in requests, try again shortly")
		return true
	case !ok:
		writeLockedOut(w, until, now, "too many sign-in requests from your address, try again later")
		return true
	}
	return false
}

// pollWebSignIn is the browser waiting for its request: 202 with the state
// (and the number to show once a phone claimed it), then, once approved,
// the public web session in the cookie, answered as the web sign-in answers
// it. The session is minted after the poll spent the request, from the
// device token that approved it while that token is still signed in.
func (h *handler) pollWebSignIn(w http.ResponseWriter, r *http.Request) {
	now := h.signIns.now()
	att, refused := h.webSignInRequestRefused(w, r, now)
	if refused {
		return
	}
	defer att.abandon()
	var req struct {
		ID         string `json:"id"`
		PollSecret string `json:"pollSecret"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	p, ok := h.signIns.poll(req.ID, req.PollSecret, now)
	switch {
	case !ok:
		writeWebSignInExpired(w)
		return
	case p.state == webSignInWaiting:
		writeJSON(w, http.StatusAccepted, map[string]any{"state": "waiting"})
		return
	case p.state == webSignInClaimed:
		// The account whose phone claimed it, so the browser can say whose
		// phone approves; only the poll secret's holder reads it.
		writeJSON(w, http.StatusAccepted, map[string]any{"state": "claimed", "number": p.number, "username": p.user})
		return
	}
	minted := time.Now()
	u, raw, err := h.db.MintWebSessionApprovedBy(p.user, p.tokenID, webSignInLabelPrefix+p.browser, minted)
	switch {
	case errors.Is(err, metadb.ErrNoSuchToken):
		writeWebSignInExpired(w)
		return
	case err != nil:
		writeRefusal(w, err)
		return
	}
	idle, absolute := metadb.WebSessionLimits(false)
	setWebCookie(w, raw, false)
	writeJSON(w, http.StatusOK, map[string]any{"user": h.toUserOut(u), "session": map[string]any{
		"keep": false, "expiresAt": minted.Add(absolute), "idleSeconds": int(idle / time.Second),
	}})
}

// claimWebSignIn is a signed-in phone presenting the secret it scanned.
// The calling device token must have been signed in for freshDeviceAge and
// must not itself be a computer a phone signed in (refuseApproverByPhone).
// The answer names what is asking: the browser, its address and whether
// the phone is on the browser's network.
func (h *handler) claimWebSignIn(w http.ResponseWriter, r *http.Request) {
	tok := h.callerToken(r)
	if tok.ID == "" {
		writeNoCallerToken(w)
		return
	}
	if h.refuseApproverByPhone(w, tok) {
		return
	}
	if tooNew(tok) {
		writeDeviceTooNew(w)
		return
	}
	var req struct {
		Secret string `json:"secret"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	id, s, ok := h.signIns.claim(req.Secret, reqUser(r).Username, tok.ID, h.signIns.now())
	if !ok {
		writeWebSignInExpired(w)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		ID          string `json:"id"`
		Browser     string `json:"browser"`
		Address     string `json:"address"`
		SameNetwork bool   `json:"sameNetwork"`
	}{id, s.browser, s.addr, s.addrMark == h.linkAddrMark(r)})
}

// approveWebSignIn approves the calling token's claimed browser request
// (approveSignIn).
func (h *handler) approveWebSignIn(w http.ResponseWriter, r *http.Request) {
	h.approveSignIn(w, r, &h.signIns, writeWebSignInExpired, "browser")
}

// approveSignIn approves the calling token's claimed request in book with
// the number the requester (named by who) shows; another two-digit number
// burns it, and a number outside 10 to 99 is a 400 that leaves it claimed.
// The number is judged first; then an account with a second factor gives
// its code, and a missing or wrong one leaves the request claimed for
// another try. expired answers a request book does not hold as claimed by
// the caller.
func (h *handler) approveSignIn(w http.ResponseWriter, r *http.Request, book *webSignIns, expired func(http.ResponseWriter), who string) {
	var req struct {
		Number *int   `json:"number"`
		TOTP   string `json:"totp"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	if req.Number == nil || *req.Number < 10 || *req.Number > 99 {
		writeError(w, http.StatusBadRequest, "the number is two digits, 10 to 99")
		return
	}
	u, tokenID, id := reqUser(r), h.callerToken(r).ID, r.PathValue("id")
	switch ok, wrong := book.match(id, u.Username, tokenID, *req.Number, book.now()); {
	case !ok:
		expired(w)
		return
	case wrong:
		writeErrorCode(w, http.StatusConflict, "device-link-wrong-number", "that is not the number the "+who+" shows")
		return
	}
	if u.TwoFactorEnabled() && !h.stepUpCode(w, r, req.TOTP) {
		return
	}
	if !book.approve(id, u.Username, tokenID, *req.Number, book.now()) {
		expired(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// denyWebSignIn burns the calling token's claimed browser request.
func (h *handler) denyWebSignIn(w http.ResponseWriter, r *http.Request) {
	h.denySignIn(w, r, &h.signIns, writeWebSignInExpired)
}

// denySignIn burns the calling token's claimed request in book, answering
// expired when book holds no such claim.
func (h *handler) denySignIn(w http.ResponseWriter, r *http.Request, book *webSignIns, expired func(http.ResponseWriter)) {
	if !book.deny(r.PathValue("id"), reqUser(r).Username, h.callerToken(r).ID, book.now()) {
		expired(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

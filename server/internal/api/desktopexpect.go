package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"hyperdrop/server/internal/metadb"
)

// Signing a computer in phone first. The computer, which knows nothing yet,
// makes a one-time Ed25519 key pair and shows a hddesk2 code carrying the
// public key, its label and its system; a phone signed in to an account
// scans it and tells its server to expect a computer holding that key
// (expectDesktopSignIn), then shows the server's address for the person to
// type on the computer. The computer arrives at the typed address and signs
// desktopArriveMessage with the private key (arriveDesktopSignIn); a
// matching arrival becomes a claimed request of the hddesk1 flow, in the
// same book (h.desktopSignIns), with the number the computer shows, the
// address the computer arrived from and the phone's account and token. From
// there the hddesk1 routes carry it: the phone reads it
// (desktopSignInArrival), the person types the number the computer shows,
// the phone approves with it or denies through /approve and /deny, and the
// computer's /poll collects the token metadb.MintDesktopSignIn mints.
//
// The phone's expect asks everything the hddesk1 claim asks
// (desktopApproverRefused). The computer's arrival is unauthenticated, asks
// what the computer's hddesk1 routes ask (desktopSignInRequestRefused: the
// client header, no browser, the version window, the switch, the address
// lockout), and answers every arrival it cannot match, whatever the reason,
// with the one 404 no-expected-sign-in, counted on the lockout as a wrong
// guess: the answer says nothing about which keys any account expects. A
// burned key is one of those: no request expects it, and none can until
// it is forgotten.

// desktopArrivePrefix starts the text a phone-first computer signs, core/
// joincode's DesktopArrivePrefix. TestDesktopArriveMessageFixture here and
// core/joincode's TestServerDesktopArriveMessageFixture hold one fixture.
const desktopArrivePrefix = "hddesk2-arrive\n"

// desktopArriveTarget is the lockout target every arrival guesses at.
const desktopArriveTarget = "desktop-arrive"

// desktopArriveMessage is the text a phone-first computer signs to prove it
// holds key (base64url) at the server whose identity is serverID.
func desktopArriveMessage(serverID, key string) string {
	return desktopArrivePrefix + serverID + "\n" + key
}

// desktopExpectFor is how long an expectation waits for its computer: as
// long as the computer shows its code (core/cli phoneSignInCodeFor, which
// is core/joincode.ComputerCodeFor; TestTheExpectationLastsAsLongAsTheCode
// there reads this line), so an address typed while the code shows finds
// the expectation.
const desktopExpectFor = 5 * time.Minute

// burnedKeyFor is how long a burned key stays burned: the longest a request
// for it could have lived, expected and then arrived.
const burnedKeyFor = desktopExpectFor + webSignInClaimedFor

// burnedPerAccount is how many live burned keys one account may hold before
// its expects are refused (errTooManyExpects): every burn is charged to the
// account whose action made it, so no account fills the shared book.
const burnedPerAccount = 8

// burnedKey is a burned phone-first key: until when, and the account it is
// charged to.
type burnedKey struct {
	until   time.Time
	account string
}

// errTooManyExpects is an expect refused because its account holds
// burnedPerAccount live burned keys.
var errTooManyExpects = errors.New("this account burned too many sign-in codes")

// burnKey burns key until burnedKeyFor from now, charged to account; b.mu
// is held. A burn always lands: it takes a live request with it, so it never
// grows the book, and expect bounds what any account is charged.
func (b *webSignIns) burnKey(key, account string, now time.Time) {
	if b.burned == nil {
		b.burned = map[string]burnedKey{}
	}
	b.burned[key] = burnedKey{until: now.Add(burnedKeyFor), account: account}
}

// burnedBy is how many live burned keys are charged to account; b.mu is
// held.
func (b *webSignIns) burnedBy(account string) int {
	n := 0
	for _, k := range b.burned {
		if k.account == account {
			n++
		}
	}
	return n
}

// computerPlatforms are the systems a phone-first computer may name.
var computerPlatforms = map[string]bool{"macos": true, "windows": true, "linux": true}

// decodeB64 is s decoded as unpadded base64url when it decodes to exactly n
// bytes and s is that value's one spelling (its unused trailing bits zero,
// as core/joincode writes it), so one key is always one string; ok is
// false otherwise.
func decodeB64(s string, n int) ([]byte, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != n || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// expect starts a phone-first request: account user's token tokenID
// expects a computer holding key, which calls itself label on platform,
// for desktopExpectFor. A burned key starts nothing (ok false). An account
// holding burnedPerAccount live burned keys is refused errTooManyExpects
// before anything else, so it can neither burn another account's request
// nor be charged a burn. Otherwise a key some live request already expects
// burns that request and the key, charged to user: two phones scanned one
// code, so neither signs the computer in (ok false). Like a claim, an
// expect then burns every other request the account claimed or expects
// (dropAccountsRequests).
//
// No account holds more than burnedPerAccount+1 live burned keys. Every
// burn charged to an account consumes a request: another account's, here,
// after the account passed the share check, or the account's own, by deny,
// replacement, a wrong number or the switch. An account holds at most one
// live request at a time (each expect and claim drops its others), and
// only an expect that passed the share check starts one, so once at its
// share an account burns at most that one more.
func (b *webSignIns) expect(key, label, platform, user, tokenID string, now time.Time) (id string, until time.Time, ok bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	if _, burned := b.burned[key]; burned {
		return "", time.Time{}, false, nil
	}
	if b.burnedBy(user) >= burnedPerAccount {
		return "", time.Time{}, false, errTooManyExpects
	}
	for rid, r := range b.m {
		if r.key == key {
			b.dropRequest(rid, user, now)
			return "", time.Time{}, false, nil
		}
	}
	b.dropAccountsRequests(user, now)
	if len(b.m)+len(b.burned) >= webSignInMax {
		return "", time.Time{}, false, errWebSignInsFull
	}
	if b.m == nil {
		b.m = map[string]*webSignIn{}
	}
	id, until = webSecret(), now.Add(desktopExpectFor)
	b.m[id] = &webSignIn{key: key, label: label, platform: platform, state: webSignInExpected,
		user: user, tokenID: tokenID, until: until}
	return id, until, true, nil
}

// arrive matches a computer arriving with key from the address in from
// (webSignInFrom), naming platform in its client header, when proved says
// its proof verified: the expected request becomes claimed, with a poll
// secret, a number and webSignInClaimedFor. ok is false for a key no live
// request expects, and for a proof that did not verify, which leaves the
// request expected.
func (b *webSignIns) arrive(key, platform string, from webSignIn, proved bool, now time.Time) (id, pollSecret string, number int, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	var r *webSignIn
	for rid, s := range b.m {
		if s.key == key && s.state == webSignInExpected {
			id, r = rid, s
			break
		}
	}
	if r == nil || !proved {
		return "", "", 0, false
	}
	pollSecret = webSecret()
	r.addrKey, r.netKey, r.wideKey, r.addr, r.addrMark = from.addrKey, from.netKey, from.wideKey, from.addr, from.addrMark
	r.pollHash, r.platform = metadb.TokenHash(pollSecret), platform
	r.state, r.number, r.until = webSignInClaimed, metadb.RandomLinkNumber(), now.Add(webSignInClaimedFor)
	return id, pollSecret, r.number, true
}

// arrival is request id as account user's token tokenID expects it: still
// expected, or arrived and waiting for the approval (claimed). ok is false
// for any other request, and for one another token expects.
func (b *webSignIns) arrival(id, user, tokenID string, now time.Time) (webSignIn, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	s, ok := b.m[id]
	if !ok || s.key == "" || s.user != user || s.tokenID != tokenID ||
		(s.state != webSignInExpected && s.state != webSignInClaimed) {
		return webSignIn{}, false
	}
	return *s, true
}

// expectDesktopSignIn is a signed-in phone telling its server to expect the
// computer whose hddesk2 code it scanned: the computer's public key, its
// label and its system. The token and account must pass
// desktopApproverRefused. The answer is the request's id, with which the
// phone reads the arrival and approves or denies it, and when the
// expectation runs out.
func (h *handler) expectDesktopSignIn(w http.ResponseWriter, r *http.Request) {
	tok, u, refused := h.desktopApproverRefused(w, r)
	if refused {
		return
	}
	var req struct {
		Key      string `json:"key"`
		Label    string `json:"label"`
		Platform string `json:"platform"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	if _, ok := decodeB64(req.Key, ed25519.PublicKeySize); !ok {
		writeErrorCode(w, http.StatusBadRequest, "invalid", "key: the computer's public key, as its sign-in code carries it")
		return
	}
	if !computerPlatforms[req.Platform] {
		writeErrorCode(w, http.StatusBadRequest, "invalid", "platform: macos, windows or linux")
		return
	}
	now := h.desktopSignIns.now()
	id, until, ok, err := h.desktopSignIns.expect(req.Key, sanitizeSignInLabel(req.Label), req.Platform, u.Username, tok.ID, now)
	if errors.Is(err, errTooManyExpects) {
		writeErrorCode(w, http.StatusTooManyRequests, "desktop-sign-in-attempts",
			"too many sign-in attempts from this account; wait a few minutes")
		return
	}
	if err != nil {
		refuseSignInCreate(w, ok, err, until, now)
		return
	}
	if !ok {
		writeDesktopSignInExpired(w)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expiresAt"`
	}{id, until})
}

// writeNoExpectedSignIn answers an arrival the server cannot match: an
// unknown or burned key, an expectation that ran out, was cancelled or
// already arrived, or a proof that does not verify. One answer for all.
func writeNoExpectedSignIn(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusNotFound, "no-expected-sign-in", "this server expects no computer holding this sign-in code's key")
}

// arriveDesktopSignIn is a phone-first computer arriving at the server the
// phone named, with the public key its code carries and its proof: an
// Ed25519 signature over desktopArriveMessage for this server's identity.
// The answer is the request's id, the poll secret only this computer holds
// and the number to show. Every arrival it cannot match is answered
// writeNoExpectedSignIn and counted on the lockout.
func (h *handler) arriveDesktopSignIn(w http.ResponseWriter, r *http.Request) {
	now := h.desktopSignIns.now()
	att, client, refused := h.desktopSignInRequestRefused(w, r, now)
	if refused {
		return
	}
	defer att.abandon()
	var req struct {
		Key   string `json:"key"`
		Proof string `json:"proof"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	// The proof is checked whether or not any request expects the key, so
	// how long the answer takes says nothing about which keys are expected.
	pub, keyOK := decodeB64(req.Key, ed25519.PublicKeySize)
	sig, sigOK := decodeB64(req.Proof, ed25519.SignatureSize)
	proved := keyOK && sigOK && ed25519.Verify(pub, []byte(desktopArriveMessage(h.fs.ServerID(), req.Key)), sig)
	id, pollSecret, number, ok := h.desktopSignIns.arrive(req.Key, client.Platform, webSignInFrom(clientIP(r), h.linkAddrMark(r)), proved, now)
	if !ok {
		if lockedOutBy(w, att, desktopArriveTarget, writeLoginLockedOut) {
			return
		}
		writeNoExpectedSignIn(w)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		ID         string `json:"id"`
		PollSecret string `json:"pollSecret"`
		Number     int    `json:"number"`
	}{id, pollSecret, number})
}

// desktopSignInArrival is the phone reading the request it expects: 202
// {"state":"expected"} until the computer arrives, then what the computer
// arrived as: its label, its system, its address and whether the phone is
// on its network. The number the computer shows is never in the answer:
// the person types it on the phone, and the approve judges it
// (approveSignIn). A request that ran out, was burned or is another
// token's is desktop-sign-in-expired.
func (h *handler) desktopSignInArrival(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireClientHeader(w, r); !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	tok := h.callerToken(r)
	if tok.ID == "" {
		writeNoCallerToken(w)
		return
	}
	id := r.PathValue("id")
	s, ok := h.desktopSignIns.arrival(id, reqUser(r).Username, tok.ID, h.desktopSignIns.now())
	switch {
	case !ok:
		writeDesktopSignInExpired(w)
	case s.state == webSignInExpected:
		writeJSON(w, http.StatusAccepted, map[string]any{"state": "expected"})
	default:
		writeJSON(w, http.StatusOK, struct {
			State       string `json:"state"`
			ID          string `json:"id"`
			Label       string `json:"label"`
			Platform    string `json:"platform"`
			Address     string `json:"address"`
			SameNetwork bool   `json:"sameNetwork"`
		}{"arrived", id, s.label, s.platform, s.addr, s.addrMark == h.linkAddrMark(r)})
	}
}

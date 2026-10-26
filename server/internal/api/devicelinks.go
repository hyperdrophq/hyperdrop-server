package api

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"hyperdrop/server/internal/metadb"
)

// The desktop's half of signing a phone in (metadb.MintDeviceLink has the
// link's life): the signed-in device mints a link, renews its secret while
// the code is on screen, follows the phone's claim, and approves it with
// the number the phone shows or denies it. The mint asks no password:
// whoever holds the signed-in desktop holds the account. A password sent
// anyway is checked as every step-up checks it and marks the link stepped
// up. An account with a second factor approves a link that was not stepped
// up with its code beside the number, so a stolen desktop token alone
// cannot add a phone to it. Every route reads and moves only links the
// CALLING token minted, so another device of the same account, like another
// account, gets device-link-invalid.

// freshDeviceAge is how long a device token must have been signed in before
// it may revoke another token (DELETE /api/me/tokens/{id}) or mint a device
// link. A password change that signs other devices out is outside the rule:
// it proves the password and code, and it is the owner's recovery path.
var freshDeviceAge = 24 * time.Hour

// callerToken is the calling token's own row as auth found it, the device
// token or the web session, zero when the request carries none of the
// account's tokens. A route that judges the caller by its row refuses a
// zero one (writeNoCallerToken) rather than reading its zero sign-in time as
// a device signed in for centuries.
func (h *handler) callerToken(r *http.Request) metadb.Token {
	tok, _ := r.Context().Value(tokenKey).(metadb.Token)
	return tok
}

// writeNoCallerToken answers a request whose bearer names none of the
// account's tokens as auth answers an unknown token.
func writeNoCallerToken(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "invalid or missing token")
}

// tooNew reports whether tok has been signed in for less than freshDeviceAge.
func tooNew(tok metadb.Token) bool {
	return time.Since(tok.CreatedAt) < freshDeviceAge
}

// writeDeviceTooNew answers a request the fresh-device rule refuses.
func writeDeviceTooNew(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusForbidden, "device-too-new",
		"This device signed in less than a day ago. Sign other devices out, or sign in a phone, from a device that has been signed in longer.")
}

// linkAddrMark is what a device link keeps of a request's address: an HMAC
// under the volume secret, which a copy of the database alone cannot turn
// back into the address, of the address as the lockout keys it (an IPv6
// address by its /64), so a phone on the desktop's IPv6 network claims from
// the same network.
func (h *handler) linkAddrMark(r *http.Request) string {
	m := h.visitorHash("device-link-addr", addrKey(clientIP(r)))
	return hex.EncodeToString(m[:])
}

// linkAddrClaimFor is how long a claim's address is kept: as long as the
// claim itself lives.
const linkAddrClaimFor = 5 * time.Minute

// linkAddrBook keeps the address each device link was claimed from, by
// link id, so the minting desktop can show it beside the phone's name. It
// lives in memory only, never in the database, its journal or a backup: an
// entry is dropped when the link is denied or spent, when the desktop reads
// the link in any other state, and once its claim has run out. A restart
// forgets every entry, and the desktop then shows no address.
type linkAddrBook struct {
	mu sync.Mutex
	m  map[string]linkAddr
}

type linkAddr struct {
	claimID, addr string
	until         time.Time
}

// keep records the address link id was claimed from at now, under the
// claim claimID.
func (b *linkAddrBook) keep(id, claimID, addr string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	if b.m == nil {
		b.m = map[string]linkAddr{}
	}
	b.m[id] = linkAddr{claimID, addr, now.Add(linkAddrClaimFor)}
}

// get answers id's address while its claim lives.
func (b *linkAddrBook) get(id string, now time.Time) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweep(now)
	a, ok := b.m[id]
	return a.addr, ok
}

// forget drops id's address.
func (b *linkAddrBook) forget(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, id)
}

// forgetClaim drops the address of the link claimed as claimID.
func (b *linkAddrBook) forgetClaim(claimID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, a := range b.m {
		if a.claimID == claimID {
			delete(b.m, id)
		}
	}
}

// has reports whether an address is kept for id, whatever its age.
func (b *linkAddrBook) has(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.m[id]
	return ok
}

// sweep drops every entry whose claim has run out; b.mu is held.
func (b *linkAddrBook) sweep(now time.Time) {
	for id, a := range b.m {
		if !now.Before(a.until) {
			delete(b.m, id)
		}
	}
}

// deviceLinkOut is a minted or renewed link: its raw secret is answered here
// once and never again.
type deviceLinkOut struct {
	ID           string    `json:"id"`
	Secret       string    `json:"secret"`
	ExpiresAt    time.Time `json:"expiresAt"`
	WindowEndsAt time.Time `json:"windowEndsAt"`
}

// mintDeviceLink starts a link from the calling token. The age check runs
// first, so a fresh token is refused without a password guess being checked
// or counted. A body without a password mints at once; one with a password
// is a step-up, checked with the code as every step-up is.
func (h *handler) mintDeviceLink(w http.ResponseWriter, r *http.Request) {
	tok := h.callerToken(r)
	if tok.ID == "" {
		writeNoCallerToken(w)
		return
	}
	if tooNew(tok) {
		writeDeviceTooNew(w)
		return
	}
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		TOTP            string `json:"totp"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	steppedUp := req.CurrentPassword != ""
	if steppedUp && !h.requireCurrentPasswordAndCode(w, r, req.CurrentPassword, req.TOTP) {
		return
	}
	link, secret, err := h.db.MintDeviceLink(reqUser(r).Username, tok.ID, h.linkAddrMark(r), steppedUp, time.Now())
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, deviceLinkOut{ID: link.ID, Secret: secret,
		ExpiresAt: link.ExpiresAt, WindowEndsAt: link.WindowEndsAt})
}

// renewDeviceLink gives the calling token's unclaimed link a new secret.
func (h *handler) renewDeviceLink(w http.ResponseWriter, r *http.Request) {
	link, secret, err := h.db.RenewDeviceLink(reqUser(r).Username, h.callerToken(r).ID, r.PathValue("id"), time.Now())
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, deviceLinkOut{ID: link.ID, Secret: secret,
		ExpiresAt: link.ExpiresAt, WindowEndsAt: link.WindowEndsAt})
}

// deviceLinkStatus is what the desktop shows while it waits: the state and,
// once a phone claimed the link, the name and system it gave, whether it
// claimed from the desktop's own address, and while the claim waits the
// address it claimed from.
func (h *handler) deviceLinkStatus(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	link, err := h.db.DeviceLinkFor(reqUser(r).Username, h.callerToken(r).ID, r.PathValue("id"), now)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	var addr string
	if link.State == "claimed" || link.State == "approved" {
		addr, _ = h.linkAddrs.get(link.ID, now)
	} else {
		h.linkAddrs.forget(link.ID)
	}
	writeJSON(w, http.StatusOK, struct {
		State       string    `json:"state"`
		ExpiresAt   time.Time `json:"expiresAt"`
		Label       string    `json:"label,omitempty"`
		Platform    string    `json:"platform,omitempty"`
		SameNetwork bool      `json:"sameNetwork,omitempty"`
		Address     string    `json:"address,omitempty"`
	}{link.State, link.ExpiresAt, link.ClaimLabel, link.ClaimPlatform, link.ClaimSameAddr, addr})
}

// approveDeviceLink approves the calling token's claimed link with the
// number the phone shows; another two-digit number burns it. A missing
// number, or one that is not two digits, is a 400 that leaves the link as
// it was, since no phone ever shows one. The number is judged first; then
// an account with a second factor gives its code for a link minted without
// the step-up, and a missing or wrong code leaves the link claimed for
// another try.
func (h *handler) approveDeviceLink(w http.ResponseWriter, r *http.Request) {
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
	name, tokenID, id := reqUser(r).Username, h.callerToken(r).ID, r.PathValue("id")
	steppedUp, err := h.db.MatchDeviceLinkNumber(name, tokenID, id, *req.Number, time.Now())
	if err != nil {
		writeRefusal(w, err)
		return
	}
	if !steppedUp && reqUser(r).TwoFactorEnabled() && !h.stepUpCode(w, r, req.TOTP) {
		return
	}
	if err := h.db.ApproveDeviceLink(name, tokenID, id, *req.Number, time.Now()); err != nil {
		writeRefusal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// denyDeviceLink burns the calling token's link in any state before spent.
func (h *handler) denyDeviceLink(w http.ResponseWriter, r *http.Request) {
	if err := h.db.BurnDeviceLink(reqUser(r).Username, h.callerToken(r).ID, r.PathValue("id")); err != nil {
		writeRefusal(w, err)
		return
	}
	h.linkAddrs.forget(r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// The phone's half, unauthenticated: the scanned secret is the claim's only
// credential and the claim's poll secret the poll's. Both share the login
// lockout like spendInvite: a locked-out address is refused before any
// lookup, every unknown or malformed secret counts as a wrong password
// does, and only a poll that collects a token clears the address's guessed
// secrets. A pending poll counts nothing either way, so a phone waiting on
// its owner is never locked out by its own polling.

// wellFormedLinkSecret reports whether s is 32 bytes of unpadded base64url,
// the shape of every secret and poll secret the server mints.
func wellFormedLinkSecret(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// refuseDeviceLink answers device-link-invalid and counts the failure on
// the login lockout, answering 429 instead once the address is locked out.
func refuseDeviceLink(w http.ResponseWriter, att *pwAttempt) {
	if !lockedOutBy(w, att, deviceLinkTarget, writeLoginLockedOut) {
		writeRefusal(w, metadb.ErrDeviceLinkInvalid)
	}
}

// deviceLinkTarget is what a guessed device-link secret is aimed at on the
// login lockout.
const deviceLinkTarget = "device-link"

// claimDeviceLink is a phone presenting the secret it scanned. The platform
// the desktop shows is the request's X-HyperDrop-Client system; the answer
// carries the number the phone displays for its owner to type on the
// desktop, and the claim id and poll secret the phone polls with.
func (h *handler) claimDeviceLink(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	att, ok := h.admitLogin(w, r, now)
	if !ok {
		return
	}
	defer att.abandon()
	var req struct {
		Secret string `json:"secret"`
		// Label names the phone on the desktop and in the token list.
		Label string `json:"label"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	if !wellFormedLinkSecret(req.Secret) {
		refuseDeviceLink(w, att)
		return
	}
	platform := metadb.ParseClientHeader(r.Header.Get("X-HyperDrop-Client")).Platform
	claim, err := h.db.ClaimDeviceLink(req.Secret, req.Label, platform, h.linkAddrMark(r), now)
	switch {
	case errors.Is(err, metadb.ErrDeviceLinkInvalid):
		refuseDeviceLink(w, att)
		return
	case err != nil:
		writeRefusal(w, err)
		return
	}
	h.linkAddrs.keep(claim.LinkID, claim.ClaimID, clientIP(r), now)
	writeJSON(w, http.StatusAccepted, struct {
		ClaimID    string `json:"claimId"`
		PollSecret string `json:"pollSecret"`
		Number     int    `json:"number"`
		Approver   string `json:"approver"`
		Username   string `json:"username"`
	}{claim.ClaimID, claim.PollSecret, claim.Number, claim.Approver, claim.Username})
}

// pollDeviceLink is the claiming phone waiting for the desktop: 202 while
// the claim waits for approval, then once the device token, answered as a
// login answers it.
func (h *handler) pollDeviceLink(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	att, ok := h.admitLogin(w, r, now)
	if !ok {
		return
	}
	defer att.abandon()
	var req struct {
		ClaimID    string `json:"claimId"`
		PollSecret string `json:"pollSecret"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	if req.ClaimID == "" || !wellFormedLinkSecret(req.PollSecret) {
		refuseDeviceLink(w, att)
		return
	}
	u, token, pending, err := h.db.SpendDeviceLink(req.ClaimID, req.PollSecret, now)
	switch {
	case errors.Is(err, metadb.ErrDeviceLinkInvalid):
		refuseDeviceLink(w, att)
		return
	case err != nil:
		writeRefusal(w, err)
		return
	case pending:
		writeJSON(w, http.StatusAccepted, struct{}{})
		return
	}
	att.succeeded(deviceLinkTarget)
	h.linkAddrs.forgetClaim(req.ClaimID)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": h.toUserOut(u)})
}

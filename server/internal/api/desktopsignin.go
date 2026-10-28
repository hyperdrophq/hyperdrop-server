package api

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"hyperdrop/core/signinannounce"
	"hyperdrop/server/internal/metadb"
)

// Signing a desktop app in with a phone. The computer, which has no
// credential yet, asks for a request bound to the username typed there and
// shows its code (a hddesk1 join code) as a QR code; a phone signed in to
// that account claims it with its bearer, the computer then shows a
// two-digit number, and the phone's owner types it on the phone, which
// approves the request (with the account's code when it has a second
// factor). The computer's next poll collects an ordinary device token
// stamped as signed in by phone (metadb.MintDesktopSignIn).
//
// It is the browser's flow (phonesignin.go) on a second book of its own,
// h.desktopSignIns, so neither kind of request is ever claimed, polled,
// approved or capped as the other. Requests live in memory only; a restart
// forgets every one. All five routes need the X-HyperDrop-Client header
// (requireClientHeader), which also puts them under the version window.
// The computer's two are unauthenticated and answer only an installed app:
// they refuse anything a browser sends (an Origin, a Sec-Fetch-Site, the
// web client's header). The phone's three are a device token's alone
// (cookieNever).
//
// A device token gives lasting access, so the claim asks more of the phone
// than the browser's does: the account must be the one the computer typed,
// must not be an administrator's, the phone must not itself be a computer
// signed in this way (refuseApproverByPhone), and it may sign in at most
// metadb.DesktopSignInsPerDay computers a day. The mint asks it all again.
// An administrator turns the whole flow off with the desktopSignIn setting.

// desktopSwitchKey is the administrator's switch: "0" is off, absent or
// "1" is on.
const desktopSwitchKey = "desktop_sign_in"

// desktopSignInLabelPrefix starts the label of every token a phone signed
// in, written by the server so a computer cannot pass itself off as
// another kind of sign-in.
const desktopSignInLabelPrefix = "Phone sign-in: "

// signInLabelMax is the most runes a computer's label keeps.
const signInLabelMax = 40

// signInLabelDefault names a computer that gave no usable label.
const signInLabelDefault = "Computer"

// desktopSignInOn reports whether the administrator's switch is on. A
// setting that cannot be read is off: a device token is never minted on a
// guess. The log says when reading it starts failing and when it works
// again, not on every read (the unauthenticated routes read it before the
// lockout admits them).
func (h *handler) desktopSignInOn() bool {
	v, ok, err := h.db.Setting(desktopSwitchKey)
	if err != nil {
		if !h.desktopSwitchUnread.Swap(true) {
			log.Printf("desktop sign-in: reading the switch: %v; signing computers in by phone is off until it can be read", err)
		}
		return false
	}
	if h.desktopSwitchUnread.Swap(false) {
		log.Printf("desktop sign-in: the switch can be read again")
	}
	return !ok || v != "0"
}

// requireClientHeader answers 400 client-required when the request names
// no client in a well-formed X-HyperDrop-Client header, and reports whether
// it did; otherwise it answers that client. Every desktop sign-in route
// asks for it, since refuseClientOutsideWindow passes a request without
// one, so the header is what puts these routes under the version window.
func requireClientHeader(w http.ResponseWriter, r *http.Request) (metadb.ClientInfo, bool) {
	client := metadb.ParseClientHeader(r.Header.Get("X-HyperDrop-Client"))
	if client.Version == "" {
		writeErrorCode(w, http.StatusBadRequest, "client-required", "this request needs the X-HyperDrop-Client header the HyperDrop apps send")
		return client, false
	}
	return client, true
}

// setDesktopSwitch turns signing computers in by phone on or off. Off is
// stored first and then every live request is dropped.
func (h *handler) setDesktopSwitch(on bool) error {
	if on {
		return h.db.SetSetting(desktopSwitchKey, "1")
	}
	if err := h.db.SetSetting(desktopSwitchKey, "0"); err != nil {
		return err
	}
	h.desktopSignIns.clear()
	return nil
}

// sanitizeSignInLabel is what a computer's label keeps: control and format
// characters (bidi overrides and zero-width characters among them) and
// invalid UTF-8 removed, every double quotation mark an apostrophe
// (signinannounce.SafeLabel: the label is shown between double quotes),
// every run of whitespace one space, no space at either end, and at most
// signInLabelMax runes; signInLabelDefault when nothing is left.
func sanitizeSignInLabel(s string) string {
	s = signinannounce.SafeLabel(s)
	var b strings.Builder
	space, n := false, 0
	for i, r := range s {
		switch {
		case r == utf8.RuneError && !strings.HasPrefix(s[i:], "\uFFFD"):
			continue
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r):
			continue
		}
		if n == signInLabelMax {
			break
		}
		if space {
			if n+1 == signInLabelMax {
				break
			}
			b.WriteByte(' ')
			n++
			space = false
		}
		b.WriteRune(r)
		n++
	}
	if b.Len() == 0 {
		return signInLabelDefault
	}
	return b.String()
}

// signInUsername is the account a computer's request is for: the typed
// name with surrounding space removed and ASCII letters lowered, the only
// letters an account name holds (metadb.ValidUsername), so "Alice" is
// alice's request. ok is false for a name no account can have.
func signInUsername(typed string) (name string, ok bool) {
	name = strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, strings.TrimSpace(typed))
	return name, metadb.ValidUsername(name)
}

// refuseApproverByPhone answers 403 desktop-sign-in-refused when tok is a
// computer a phone signed in, which never approves another sign-in (a
// computer, a browser, or a phone through a device link), and reports
// whether it did. A planted computer therefore cannot plant another device.
func (h *handler) refuseApproverByPhone(w http.ResponseWriter, tok metadb.Token) bool {
	if tok.SignInMethod != metadb.SignInMethodPhone {
		return false
	}
	writeErrorCode(w, http.StatusForbidden, "desktop-sign-in-refused",
		"a computer signed in by phone cannot approve another sign-in; approve it from a device signed in with the password")
	return true
}

// writeDesktopSignInExpired answers a computer's request that is unknown,
// ran out, was burned, denied or spent, or is another account's or
// device's: one answer for all, and the cue for the computer to ask for a
// new code.
func writeDesktopSignInExpired(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusGone, "desktop-sign-in-expired", "this sign-in code is not valid any more; start the sign-in on the computer again")
}

func writeDesktopSignInOff(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusForbidden, "desktop-sign-in-off", "signing a computer in with a phone is turned off on this server")
}

func writeDesktopSignInAdmin(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusForbidden, "desktop-sign-in-admin", "an administrator's account cannot sign a computer in with a phone")
}

func writeDesktopSignInLimit(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusTooManyRequests, "desktop-sign-in-limit", "this device has signed in as many computers as it may today")
}

// desktopSignInRequestRefused answers a computer's request its conditions
// refuse, in this order, and reports whether it did: no client header, a
// browser's request, the version window, the switch, the address lockout.
// Otherwise it answers the client the header names and the admitted
// attempt, which the caller settles.
func (h *handler) desktopSignInRequestRefused(w http.ResponseWriter, r *http.Request, now time.Time) (*pwAttempt, metadb.ClientInfo, bool) {
	w.Header().Set("Cache-Control", "no-store")
	client, ok := requireClientHeader(w, r)
	if !ok {
		return nil, client, true
	}
	if len(r.Header.Values("Origin")) > 0 || len(r.Header.Values("Sec-Fetch-Site")) > 0 || client.Platform == "web" {
		writeErrorCode(w, http.StatusForbidden, "desktop-sign-in-refused", "signing a computer in with a phone is for the HyperDrop apps, never a web page")
		return nil, client, true
	}
	if h.refuseClientOutsideWindow(w, r, client.Version) {
		return nil, client, true
	}
	if !h.desktopSignInOn() {
		writeDesktopSignInOff(w)
		return nil, client, true
	}
	att, ok := h.admitLogin(w, r, now)
	return att, client, !ok
}

// createDesktopSignIn is the computer asking for a request for the account
// it names: its id and poll secret, the code it shows and when the code
// runs out. Any well-formed username is answered the same way, whether or
// not an account has it, is suspended or is an administrator's: only the
// claim, made with that account's own token, judges the account.
func (h *handler) createDesktopSignIn(w http.ResponseWriter, r *http.Request) {
	now := h.desktopSignIns.now()
	att, client, refused := h.desktopSignInRequestRefused(w, r, now)
	if refused {
		return
	}
	defer att.abandon()
	var req struct {
		Label    string `json:"label"`
		Username string `json:"username"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	name, ok := signInUsername(req.Username)
	if !ok {
		writeErrorCode(w, http.StatusBadRequest, "invalid", "username: the account's name is required, as it is typed to sign in")
		return
	}
	s := webSignInFrom(clientIP(r), h.linkAddrMark(r))
	s.wantUser, s.label, s.platform = name, sanitizeSignInLabel(req.Label), client.Platform
	id, secret, pollSecret, until, ok, err := h.desktopSignIns.create(s, now)
	if refuseSignInCreate(w, ok, err, until, now) {
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		ID         string    `json:"id"`
		PollSecret string    `json:"pollSecret"`
		Code       string    `json:"code"`
		ExpiresAt  time.Time `json:"expiresAt"`
	}{id, pollSecret, desktopSignInCode(h.canonicalBase(r), h.fs.ServerID(), secret), until})
}

// pollDesktopSignIn is the computer waiting for its request: 202 with the
// state (and the number to show once a phone claimed it), then, once
// approved, the device token and the account, answered as a login answers
// them. The poll spends the request before the mint, and the mint asks
// again of the approving token and the account everything the claim asked.
// A minted sign-in is announced to the account's other devices
// (announceDeviceSignedIn), which never holds up or fails the answer.
func (h *handler) pollDesktopSignIn(w http.ResponseWriter, r *http.Request) {
	now := h.desktopSignIns.now()
	att, _, refused := h.desktopSignInRequestRefused(w, r, now)
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
	p, ok := h.desktopSignIns.poll(req.ID, req.PollSecret, now)
	switch {
	case !ok:
		writeDesktopSignInExpired(w)
		return
	case p.state == webSignInWaiting:
		writeJSON(w, http.StatusAccepted, map[string]any{"state": "waiting"})
		return
	case p.state == webSignInClaimed:
		writeJSON(w, http.StatusAccepted, map[string]any{"state": "claimed", "number": p.number})
		return
	}
	u, raw, err := h.db.MintDesktopSignIn(p.user, p.tokenID, desktopSignInLabelPrefix+p.label, p.platform, p.addrMark, time.Now())
	switch {
	case errors.Is(err, metadb.ErrNoSuchToken), errors.Is(err, metadb.ErrInactive):
		writeDesktopSignInExpired(w)
		return
	case errors.Is(err, metadb.ErrAdminRefused):
		writeDesktopSignInAdmin(w)
		return
	case errors.Is(err, metadb.ErrSignInLimit):
		writeDesktopSignInLimit(w)
		return
	case errors.Is(err, metadb.ErrTooManyDevices):
		writeErrorCode(w, http.StatusConflict, "too-many-devices",
			"this account is signed in on as many devices as it may be; sign one out, then try again")
		return
	case err != nil:
		writeRefusal(w, err)
		return
	}
	tok := tokenNamed(u, metadb.TokenHash(raw))
	h.announceDeviceSignedIn(u, tok.ID, signinannounce.SignIn{Label: p.label, Platform: tok.ClientPlatform,
		ApprovedBy: tok.ApprovedByLabel, At: tok.CreatedAt})
	writeJSON(w, http.StatusOK, map[string]any{"token": raw, "user": h.toUserOut(u)})
}

// claimDesktopSignIn is a signed-in phone presenting the secret it
// scanned. The calling device token must not be a computer a phone signed
// in, must have been signed in for freshDeviceAge, and must have signed in
// fewer than metadb.DesktopSignInsPerDay computers in the last day; the
// account must not be an administrator's, and must be the one the
// computer named, or the claim is answered as an unknown code and leaves
// the request waiting. The answer is what the computer says of itself and
// where it is: its label, its system, its address and whether the phone is
// on its network.
func (h *handler) claimDesktopSignIn(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireClientHeader(w, r); !ok {
		return
	}
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
	if !h.desktopSignInOn() {
		writeDesktopSignInOff(w)
		return
	}
	u := reqUser(r)
	if u.IsAdmin() {
		writeDesktopSignInAdmin(w)
		return
	}
	now := h.desktopSignIns.now()
	n, err := h.db.SignInsApprovedSince(tok.ID, time.Now().Add(-metadb.DesktopSignInWindow))
	if err != nil {
		writeRefusal(w, err)
		return
	}
	if n >= metadb.DesktopSignInsPerDay {
		writeDesktopSignInLimit(w)
		return
	}
	var req struct {
		Secret string `json:"secret"`
	}
	if !decodeJSONBody(w, r, 4<<10, &req) {
		return
	}
	id, s, ok := h.desktopSignIns.claim(req.Secret, u.Username, tok.ID, now)
	if !ok {
		writeDesktopSignInExpired(w)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		ID          string `json:"id"`
		Label       string `json:"label"`
		Platform    string `json:"platform"`
		Address     string `json:"address"`
		SameNetwork bool   `json:"sameNetwork"`
	}{id, s.label, s.platform, s.addr, s.addrMark == h.linkAddrMark(r)})
}

// approveDesktopSignIn approves the calling token's claimed computer
// request (approveSignIn).
func (h *handler) approveDesktopSignIn(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireClientHeader(w, r); !ok {
		return
	}
	h.approveSignIn(w, r, &h.desktopSignIns, writeDesktopSignInExpired, "computer")
}

// denyDesktopSignIn burns the calling token's claimed computer request.
func (h *handler) denyDesktopSignIn(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireClientHeader(w, r); !ok {
		return
	}
	var req struct{}
	if !decodeOptionalJSONBody(w, r, 4<<10, &req) {
		return
	}
	h.denySignIn(w, r, &h.desktopSignIns, writeDesktopSignInExpired)
}

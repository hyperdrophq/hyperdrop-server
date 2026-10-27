package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"hyperdrop/server/internal/metadb"
)

// userOut is the sanitized user view for API responses: the password hash
// and token hashes never leave the server.
type userOut struct {
	Username         string     `json:"username"`
	Role             string     `json:"role"`
	CreatedAt        time.Time  `json:"createdAt"`
	Disabled         bool       `json:"disabled,omitempty"`
	AccountExpiresAt *time.Time `json:"accountExpiresAt,omitempty"`
	QuotaBytes       int64      `json:"quotaBytes,omitempty"`
	NoEmbed          bool       `json:"noEmbed,omitempty"`
	// SourceRoots is this account's allowlist of server folders it may
	// create linked shares from; absent means the account carries none.
	SourceRoots []string `json:"sourceRoots,omitempty"`
	// TwoFactorEnabled reports a CONFIRMED second factor; an enrollment the
	// user never finished reads as off, like everywhere else.
	TwoFactorEnabled bool  `json:"twoFactorEnabled,omitempty"`
	UsedBytes        int64 `json:"usedBytes"`
	ShareCount       int   `json:"shareCount"`
	// LatestClient is the newest app version any of this account's tokens
	// reported itself as; nil when none has reported one yet.
	LatestClient *clientOut `json:"latestClient,omitempty"`
}

// clientOut is the newest client an account was seen from.
type clientOut struct {
	Version    string    `json:"version"`
	Platform   string    `json:"platform,omitempty"`
	LastUsedAt time.Time `json:"lastUsedAt,omitzero"`
}

func (h *handler) toUserOut(u metadb.User) userOut {
	// The counters are decoration on an account row: a read that fails
	// reports zeroes rather than failing the account response.
	usage, _ := h.db.Usage(u.Username)
	out := userOut{
		Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt,
		Disabled: u.Disabled, AccountExpiresAt: u.AccountExpiresAt,
		QuotaBytes: u.QuotaBytes, NoEmbed: u.NoEmbed,
		SourceRoots:      u.SourceRoots,
		TwoFactorEnabled: u.TwoFactorEnabled(),
		UsedBytes:        usage.Bytes, ShareCount: usage.Shares,
	}
	if tok, ok := u.LatestClient(); ok {
		out.LatestClient = &clientOut{Version: tok.ClientVersion, Platform: tok.ClientPlatform, LastUsedAt: tok.LastUsedAt}
	}
	return out
}

// login exchanges username+password for a long-lived device token, the only
// time the raw token exists in a response. Per-address lockout like the
// share password form (10 wrong guesses / 1 h → 12 h block), and a wrong
// second-factor code also counts under the account (totpLoginKey).
func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	att, ok := h.admitLogin(w, r, now)
	if !ok {
		return
	}
	defer att.abandon()
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		// Label names the device in the token list (optional).
		Label string `json:"label"`
		// TOTP is the second factor for an account that has one: a 6-digit
		// authenticator code, or one of the recovery codes.
		TOTP string `json:"totp"`
	}
	if !decodeJSONBody(w, r, 64<<10, &req) {
		return
	}
	u, token, ok := h.signIn(w, r, att, req.Username, req.Password, writeLoginLockedOut, func(u metadb.User) (string, error) {
		return h.db.MintTokenIfPasswordIs(u.Username, req.Label, u.PasswordHash, req.TOTP, now)
	})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": h.toUserOut(u)})
}

// signIn is every sign-in's check of a username and password, on the
// attempt att the caller admitted on the login lockout: the bcrypt cap, the
// password counted under the attempt's keys, the account's code key, and
// mint, the guarded mint that checks the second factor in its own critical
// section and answers the credential. A guess that locks the caller out is
// answered by lockedOut. It answers the account and that credential, or
// writes the refusal itself and reports false.
func (h *handler) signIn(w http.ResponseWriter, r *http.Request, att *pwAttempt, username, password string,
	lockedOut func(http.ResponseWriter, time.Time, time.Time), mint func(u metadb.User) (string, error)) (metadb.User, string, bool) {
	if username == "" || password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return metadb.User{}, "", false
	}
	u, err := h.authenticate(r.Context(), username, password)
	switch {
	case errors.Is(err, metadb.ErrBadCredentials):
		if !lockedOutBy(w, att, loginTarget(username), lockedOut) {
			writeRefusal(w, err)
		}
		return metadb.User{}, "", false
	case err != nil:
		writeAuthenticateError(w, r, err)
		return metadb.User{}, "", false
	}
	// The code is guessed only by someone holding the password, so it also
	// counts under the account, from every address: an account key that the
	// password alone cannot reach keeps a stranger from locking the owner out.
	if until, ok := att.extend(totpLoginKey(u.Username)); !ok {
		lockedOut(w, until, att.now)
		return metadb.User{}, "", false
	}
	// The guarded mint: a password change landing between the Authenticate
	// above and this mint must invalidate the sign-in, not hand out a
	// credential authorized by the replaced password. The second factor is
	// checked in that same critical section, so its spend cannot be raced.
	raw, err := mint(u)
	if err != nil {
		// A wrong code counts exactly like a wrong password. A MISSING code
		// is not counted: the caller has not guessed anything yet (this does
		// tell them the password was right, as every 2FA prompt anywhere
		// does).
		if errors.Is(err, metadb.ErrTOTPInvalid) && lockedOutBy(w, att, u.Username, lockedOut) {
			return metadb.User{}, "", false
		}
		writeRefusal(w, err)
		return metadb.User{}, "", false
	}
	// Cleared only once the WHOLE sign-in succeeded. Clearing it on the
	// password alone would let a caller holding a correct password reset the
	// counter on every attempt and guess codes forever.
	att.succeeded(u.Username)
	return u, raw, true
}

// loginTarget is what a wrong sign-in is aimed at on the login lockout: the
// username when it is one an account can have, and unnamedTarget otherwise,
// so a malformed name counts under the address without the limiter keeping
// what the caller typed.
func loginTarget(username string) string {
	if metadb.ValidUsername(username) {
		return username
	}
	return unnamedTarget
}

// unnamedTarget is the target of a wrong sign-in at a name no account can
// have. No sign-in proves it, so its guesses expire with the window.
const unnamedTarget = "?"

// totpLoginKey is the login lockout's key for the codes guessed at an
// account's sign-in. Step-ups never read it, and login reads it only once
// the password was right.
func totpLoginKey(name string) string {
	return "totp:" + name
}

// admitLogin admits one guess from the caller's address on the login
// lockout, answering 429 itself when the address is refused. The attempt
// must be settled; a deferred abandon settles whatever path returns first.
func (h *handler) admitLogin(w http.ResponseWriter, r *http.Request, now time.Time) (*pwAttempt, bool) {
	att, until, ok := h.limits.login.admit(now, addrKey(clientIP(r)))
	if !ok {
		writeLoginLockedOut(w, until, now)
	}
	return att, ok
}

// lockedOutBy settles att as a wrong guess at target and, when that locks
// the caller out, answers the lockout with write and reports true; otherwise
// the caller answers its own refusal.
func lockedOutBy(w http.ResponseWriter, att *pwAttempt, target string, write func(http.ResponseWriter, time.Time, time.Time)) bool {
	until, blocked := att.failed(target)
	if blocked {
		write(w, until, att.now)
	}
	return blocked
}

// writeLoginLockedOut answers a sign-in from an address, or a code for an
// account, that the login lockout refuses.
func writeLoginLockedOut(w http.ResponseWriter, until, now time.Time) {
	writeLockedOut(w, until, now, "too many failed logins from your address, try again later")
}

// writeLockedOut is the lockout's 429: coded locked-out, with Retry-After
// naming when the block ends.
func writeLockedOut(w http.ResponseWriter, until, now time.Time, msg string) {
	secs := int(until.Sub(now).Round(time.Second) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
	writeErrorCode(w, http.StatusTooManyRequests, "locked-out", msg)
}

// bcryptQueueMax bounds the requests waiting for a bcrypt slot to sign in
// or step up. Each holds a goroutine and its body while it waits, so past
// it a request is answered 503 rather than queued behind work it would
// have to outlast.
const bcryptQueueMax = 32

var bcryptQueued atomic.Int32

// errBcryptBusy is the answer to a sign-in that found the queue full.
var errBcryptBusy = refuse(http.StatusServiceUnavailable, "", "the server is busy checking passwords, try again shortly")

// authenticate checks an account's password under the bcrypt cap. It waits
// for a slot only while the client does, and refuses with errBcryptBusy when
// bcryptQueueMax requests are already waiting.
func (h *handler) authenticate(ctx context.Context, name, password string) (metadb.User, error) {
	if bcryptQueued.Add(1) > bcryptQueueMax {
		bcryptQueued.Add(-1)
		return metadb.User{}, errBcryptBusy
	}
	select {
	case bcryptSem <- struct{}{}:
		bcryptQueued.Add(-1)
	case <-ctx.Done():
		bcryptQueued.Add(-1)
		return metadb.User{}, ctx.Err()
	}
	defer func() { <-bcryptSem }()
	return h.db.Authenticate(name, password)
}

// writeAuthenticateError answers an authenticate error other than a wrong
// password: nothing for a client that left, Retry-After on a full queue,
// and the error's own refusal otherwise.
func writeAuthenticateError(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		return
	}
	if errors.Is(err, errBcryptBusy) {
		w.Header().Set("Retry-After", "2")
	}
	writeRefusal(w, err)
}

// logout revokes the calling device token, a self sign-out: the computers
// it signed in by phone and the web sessions it approved go with it, the
// phones it linked stay (RevokeTokenCascade). A token already gone is
// already signed out.
func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if id := h.callerToken(r).ID; id != "" {
		if _, err := h.db.RevokeTokenCascade(reqUser(r).Username, id, nil); err != nil && !errors.Is(err, metadb.ErrNotFound) {
			writeRefusal(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.toUserOut(reqUser(r)))
}

// listMyTokens shows the calling USER's device tokens - id, label, dates,
// and which row is the caller itself - never the hashes. This is the only
// place tokens are visible at all: they never expire, so without a list the
// question "what can still sign in as me?" has no answer.
func (h *handler) listMyTokens(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	cur := h.callerToken(r).ID
	rows := make([]map[string]any, 0, len(u.Tokens))
	for _, tok := range u.Tokens {
		row := map[string]any{"id": tok.ID, "label": tok.Label, "createdAt": tok.CreatedAt}
		if !tok.LastUsedAt.IsZero() {
			row["lastUsedAt"] = tok.LastUsedAt
		}
		if tok.ID == cur {
			row["current"] = true
		}
		if tok.ClientVersion != "" {
			row["clientVersion"] = tok.ClientVersion
			row["clientPlatform"] = tok.ClientPlatform
		}
		if tok.ViaToken != "" {
			row["viaToken"] = tok.ViaToken
		}
		// A web session says so: a revoke of the device that approved it
		// always takes it along, and a client names it before confirming.
		if tok.Kind != "" {
			row["kind"] = tok.Kind
		}
		// A computer a phone signed in says so, and names the device that
		// approved it as it was labelled then, kept after that device goes.
		if tok.SignInMethod != "" {
			row["method"] = tok.SignInMethod
		}
		if tok.ApprovedByLabel != "" {
			row["approvedBy"] = tok.ApprovedByLabel
		}
		rows = append(rows, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": rows})
}

// revokeMyToken signs one device out by token id - the surgical alternative
// to a password change, which signs out everything. Self-scope: the id is
// looked up in the CALLER's own token list, so another user's id is simply
// unknown here. Revoking the calling token is always allowed (it is a
// logout, and clears a web session's cookie); revoking another is refused
// while the caller is younger than freshDeviceAge.
func (h *handler) revokeMyToken(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	id := r.PathValue("id")
	caller := h.callerToken(r)
	if caller.ID == "" {
		writeNoCallerToken(w)
		return
	}
	if id != caller.ID && tooNew(caller) {
		writeDeviceTooNew(w)
		return
	}
	// The revoke takes the computers the device signed in by phone and the
	// web sessions it approved with it, transitively, even when the device
	// signs itself out. The phones it linked through Sign In a Phone go only
	// when alsoLinked names them, which a self sign-out never does.
	var alsoLinked []string
	if id != caller.ID {
		alsoLinked = splitIDList(r.URL.Query().Get("alsoLinked"), metadb.MaxTokensPerAccount)
	}
	revoked, err := h.db.RevokeTokenCascade(u.Username, id, alsoLinked)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// A web session among the revoked rows is signed out, so when it is the
	// caller its cookie goes with it, as at DELETE /api/web/session.
	if caller.Kind == metadb.TokenKindWeb && slices.Contains(revoked, caller.ID) {
		clearWebCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

// splitIDList is a comma-separated query value's first max non-empty items.
func splitIDList(v string, max int) []string {
	var out []string
	for id := range strings.SplitSeq(v, ",") {
		if len(out) == max {
			break
		}
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

// changeOwnPassword sets a new password, which revokes every token the user
// has, including the calling one, and returns a freshly minted replacement
// so the calling device stays signed in: a token to a device, a new session
// cookie to a web session.
func (h *handler) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	var req struct {
		Password string `json:"password"`
		// CurrentPassword is REQUIRED. Without it a stolen device token could
		// change the password and, because SetPassword revokes every token,
		// sign the real owner's devices out with nothing but the token it
		// already had.
		CurrentPassword string `json:"currentPassword"`
		// TOTP is required when the account has a second factor.
		TOTP string `json:"totp"`
		// SignOutOthers revokes every other device. ABSENT MEANS TRUE, so a
		// request that does not state it signs every other device out; a
		// pointer rather than a bool, because a plain one cannot tell "false"
		// from "not sent".
		SignOutOthers *bool `json:"signOutOthers"`
	}
	if !decodeJSONBody(w, r, 64<<10, &req) {
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}
	// Measured before the step-up, which spends the code: a refused password
	// must leave the caller holding a code the server has not accepted.
	if err := checkChosenPassword(req.Password); err != nil {
		writeRefusal(w, err)
		return
	}
	signOutOthers := req.SignOutOthers == nil || *req.SignOutOthers
	if !h.requireCurrentPasswordAndCode(w, r, req.CurrentPassword, req.TOTP) {
		return
	}
	// Keeping every device signed in needs no re-mint at all: the caller's own
	// token still authorizes it, so the response carries no token and the
	// client keeps the one it has.
	if !signOutOthers {
		if err := h.db.SetPasswordKeepingTokens(u.Username, req.Password); err != nil {
			writeRefusal(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"signedOutOthers": false})
		return
	}
	caller := h.callerToken(r)
	// A browser never holds a device token: a web session's replacement is
	// a new web session of the same kind, label and sign-in time, set as the
	// cookie, and the answer carries no token.
	if caller.Kind == metadb.TokenKindWeb {
		raw, err := h.db.SetPasswordMintingWebSession(u.Username, req.Password, caller.Label, caller.Keep, caller.CreatedAt, time.Now())
		if err != nil {
			writeRefusal(w, err)
			return
		}
		setWebCookie(w, raw, caller.Keep)
		writeJSON(w, http.StatusOK, map[string]any{"signedOutOthers": true})
		return
	}
	// The replacement token keeps the calling device's label and sign-in
	// time: the mint below is a continuation of this device's session, not a
	// new anonymous one. A blank row in the token list defeats the list's
	// purpose, and the device's age is what freshDeviceAge reads. A bearer
	// naming no row has no sign-in time to keep, so its replacement is
	// signed in now.
	signedIn := caller.CreatedAt
	if signedIn.IsZero() {
		signedIn = time.Now()
	}
	if err := h.db.SetPassword(u.Username, req.Password); err != nil {
		writeRefusal(w, err)
		return
	}
	token, err := h.db.MintTokenCreatedAt(u.Username, caller.Label, signedIn)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "signedOutOthers": true})
}

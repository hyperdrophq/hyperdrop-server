package api

import (
	"errors"
	"net/http"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/totp"
)

// totpIssuer is the name an authenticator app shows above the account.
const totpIssuer = "HyperDrop"

// totpAccount names the account inside the app. It carries the SERVER, so
// someone with accounts on two HyperDrop servers sees two distinguishable
// rows rather than two identical ones.
func (h *handler) totpAccount(name string) string {
	if id := h.dom.Identity(); id != "" {
		return name + "@" + id
	}
	return name
}

// twoFactorBody is what the enrollment routes accept. The current password is
// required on every one that CHANGES the factor, so a stolen device token can
// neither enrol 2FA (locking the real owner out) nor strip it.
type twoFactorBody struct {
	CurrentPassword string `json:"currentPassword"`
	Code            string `json:"code"`
}

// decodeTwoFactorBody reads an enrollment route's body, which may be empty,
// writing the 400 itself and reporting false when it cannot.
func decodeTwoFactorBody(w http.ResponseWriter, r *http.Request) (twoFactorBody, bool) {
	var b twoFactorBody
	return b, decodeOptionalJSONBody(w, r, 64<<10, &b)
}

// writeStepUpRequired is the one refusal of a route that needs the caller's
// own password and was sent none: 403 step-up-required, coded so a client
// asks for the password (and code) and sends the request again.
func writeStepUpRequired(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusForbidden, "step-up-required",
		"confirm with your own password (and authenticator code)")
}

// requireCurrentPassword re-authenticates the caller by password alone, for
// the one step-up that runs before the account can have a second factor
// (enrolment's start), and writes the failure response itself, returning
// false when the caller must stop.
func (h *handler) requireCurrentPassword(w http.ResponseWriter, r *http.Request, password string) bool {
	if password == "" {
		writeStepUpRequired(w)
		return false
	}
	return h.stepUp(w, r, password, "", false)
}

// requireCurrentPasswordAndCode re-authenticates the caller by password and,
// when the account has a second factor, its code, and writes the failure
// response itself, returning false when the caller must stop. No password is
// 403 step-up-required, a wrong one 401 wrong-password, a missing or wrong
// code 401 totp-required or totp-invalid (all coded, so a client asks again
// rather than giving up); a code, once accepted, cannot be replayed, and
// wrong guesses count on the login lockout (stepUp). On an admin route, an
// elevated web session (webElevated) is asked the password alone.
func (h *handler) requireCurrentPasswordAndCode(w http.ResponseWriter, r *http.Request, password, code string) bool {
	if password == "" {
		writeStepUpRequired(w)
		return false
	}
	return h.stepUp(w, r, password, code, !h.webElevated(r))
}

// webElevated reports whether the request is on an admin route (h.admin
// marked it adminRouteKey) from a web session elevated now
// (POST /api/web/session/elevate). The elevation proved the account's
// password and second factor within webElevateFor, so an admin route's own
// step-up does not ask that session for a code again: one admin change
// from the web never needs two codes. Every other route's step-up (the
// caller's own password, its second factor, its recovery codes) asks the
// code of every caller. The elevation itself always asks for the code
// (webElevate calls stepUp directly), so it cannot extend itself on the
// password alone.
func (h *handler) webElevated(r *http.Request) bool {
	if onAdmin, _ := r.Context().Value(adminRouteKey).(bool); !onAdmin {
		return false
	}
	tok := h.callerToken(r)
	return tok.Kind == metadb.TokenKindWeb && tok.ElevatedUntil.After(time.Now())
}

// stepUp checks the caller's own password and, with withCode, the second
// factor (login folds the same check into its guarded mint), on the login
// lockout: a wrong password or a wrong code counts exactly as it does at
// login, a missing code does not, and a locked-out caller is refused before
// anything is checked. It counts under admitStepUp's keys: the address,
// the calling token and the account. Only a step-up that proved everything
// the account has clears the guesses aimed at it, so a caller holding the
// right password cannot reset the count between guesses of the code.
func (h *handler) stepUp(w http.ResponseWriter, r *http.Request, password, code string, withCode bool) bool {
	u := reqUser(r)
	now := time.Now()
	att, until, ok := h.admitStepUp(r, now)
	if !ok {
		writeStepUpLockedOut(w, until, now)
		return false
	}
	defer att.abandon()
	switch _, err := h.authenticate(r.Context(), clientIP(r), u.Username, password); {
	case errors.Is(err, metadb.ErrBadCredentials):
		if !lockedOutBy(w, att, u.Username, writeStepUpLockedOut) {
			writeErrorCode(w, http.StatusUnauthorized, "wrong-password", "the current password is wrong")
		}
		return false
	case err != nil:
		writeAuthenticateError(w, r, err)
		return false
	}
	switch {
	case withCode:
		if err := h.db.VerifySecondFactor(u.Username, code, now); err != nil {
			if errors.Is(err, metadb.ErrTOTPInvalid) && lockedOutBy(w, att, u.Username, writeStepUpLockedOut) {
				return false
			}
			writeRefusal(w, err)
			return false
		}
	case u.TwoFactorEnabled():
		// The password alone is not everything this account has.
		return true
	}
	att.succeeded(u.Username)
	return true
}

// stepUpCode checks the caller's second-factor code alone, for a route
// whose caller proved nothing else and needs nothing more than the code, on
// the same lockout keys as stepUp: a wrong code counts, a missing one is
// 401 totp-required and counts nothing, and an accepted code cannot be
// replayed. A right code clears nothing, so guesses spread around right
// codes still add up. On an admin route, an elevated web session
// (webElevated) is not asked.
func (h *handler) stepUpCode(w http.ResponseWriter, r *http.Request, code string) bool {
	if h.webElevated(r) {
		return true
	}
	u := reqUser(r)
	now := time.Now()
	att, until, ok := h.admitStepUp(r, now)
	if !ok {
		writeStepUpLockedOut(w, until, now)
		return false
	}
	defer att.abandon()
	if err := h.db.VerifySecondFactor(u.Username, code, now); err != nil {
		if errors.Is(err, metadb.ErrTOTPInvalid) && lockedOutBy(w, att, u.Username, writeStepUpLockedOut) {
			return false
		}
		writeRefusal(w, err)
		return false
	}
	return true
}

// admitStepUp admits one step-up guess on the login lockout under three
// keys. The caller's address. The calling token (stepUpTokenKey), at the
// address's limit and block, because a step-up runs under a bearer token
// and a stolen one could otherwise spread its guesses over as many
// addresses as it has. The account (stepUpAccountKey), at a higher limit
// and a short wait (stepUpAccountFailLimit), because a token can mint more
// tokens (approving a browser sign-in takes no step-up on an account
// without a second factor) and each brings guesses of its own. One token's
// guesses therefore block that token for pwBlockFor and the owner's other
// devices for stepUpAccountWait at most. Login reads none of these account
// keys, so guesses made with a stolen token cannot lock the owner out of
// signing in. A bearer naming no token row counts under "account:" in the
// token's place.
func (h *handler) admitStepUp(r *http.Request, now time.Time) (*pwAttempt, time.Time, bool) {
	username := reqUser(r).Username
	own := "account:" + username
	if id := h.callerToken(r).ID; id != "" {
		own = stepUpTokenKey(id)
	}
	return h.limits.login.admit(now, append(addrKeys(clientIP(r)), own, stepUpAccountKey(username))...)
}

// stepUpTokenKey is the step-up's key for the token whose id is id.
func stepUpTokenKey(id string) string {
	return "token:" + id
}

// stepUpAccountPrefix starts the step-up's account keys.
const stepUpAccountPrefix = "stepup:"

// stepUpAccountKey is the step-up's key for the account username, counted
// from all of its tokens together.
func stepUpAccountKey(username string) string {
	return stepUpAccountPrefix + username
}

// writeStepUpLockedOut answers a step-up the login lockout has blocked.
func writeStepUpLockedOut(w http.ResponseWriter, until, now time.Time) {
	writeLockedOut(w, until, now, "too many wrong passwords or codes, try again later")
}

// totpStatus reports the caller's own second factor. Never the secret: it is
// readable exactly once, in the enrollment response.
func (h *handler) totpStatus(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	out := map[string]any{
		"enabled":           u.TwoFactorEnabled(),
		"recoveryCodesLeft": u.RecoveryCodesLeft,
	}
	if u.TwoFactorEnabled() {
		out["confirmedAt"] = u.TOTPConfirmedAt
	}
	// pending distinguishes "never started" from "started, never confirmed",
	// which is what lets a client offer Resume rather than silently restarting.
	out["pending"] = u.TOTPStored != "" && !u.TwoFactorEnabled()
	writeJSON(w, http.StatusOK, out)
}

// totpStart mints a PENDING secret and returns it with its otpauth:// URI.
// Nothing is enabled until totpConfirm, so an abandoned enrollment costs
// nothing and starting again simply replaces the pending secret.
func (h *handler) totpStart(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	body, ok := decodeTwoFactorBody(w, r)
	if !ok {
		return
	}
	if !h.requireCurrentPassword(w, r, body.CurrentPassword) {
		return
	}
	secret, err := h.db.StartTOTP(u.Username)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	account := h.totpAccount(u.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":  secret,
		"uri":     totp.URI(secret, totpIssuer, account),
		"issuer":  totpIssuer,
		"account": account,
	})
}

// totpConfirm finishes enrollment and returns the recovery codes ONCE. A
// wrong code counts on the step-up's keys: confirming takes no password,
// so a stolen token could otherwise guess the code of an enrollment its
// owner left pending, turn the factor on and collect the recovery codes. A
// right code clears nothing, since it proves only the pending secret.
func (h *handler) totpConfirm(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	body, ok := decodeTwoFactorBody(w, r)
	if !ok {
		return
	}
	now := time.Now()
	att, until, ok := h.admitStepUp(r, now)
	if !ok {
		writeStepUpLockedOut(w, until, now)
		return
	}
	defer att.abandon()
	codes, err := h.db.ConfirmTOTP(u.Username, body.Code, now)
	if err != nil {
		if errors.Is(err, metadb.ErrTOTPInvalid) && lockedOutBy(w, att, u.Username, writeStepUpLockedOut) {
			return
		}
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "recoveryCodes": codes})
}

// twoFactorOwed reports whether u must keep a second factor: every admin,
// and every account while the "require two-factor for every account" switch
// is on, whatever the sign-in time of the token asking.
func (h *handler) twoFactorOwed(u metadb.User) bool {
	if u.Role == metadb.RoleAdmin {
		return true
	}
	_, on := h.requireTwoFactorSince()
	return on
}

// totpDisable turns the factor off. Password AND a valid code: possession of
// the token alone must not be able to strip the protection the token's owner
// added. An account that must keep a factor (twoFactorOwed) is refused with
// 409 two-factor-required before any code is checked; another admin's reset
// is the way to clear it.
func (h *handler) totpDisable(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	body, ok := decodeTwoFactorBody(w, r)
	if !ok {
		return
	}
	if !u.TwoFactorEnabled() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	if h.twoFactorOwed(u) {
		writeErrorCode(w, http.StatusConflict, "two-factor-required",
			"This server requires two-factor for this account, so it cannot be turned off.")
		return
	}
	if !h.requireCurrentPasswordAndCode(w, r, body.CurrentPassword, body.Code) {
		return
	}
	if err := h.db.DisableTOTP(u.Username); err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

// totpRecovery issues a fresh set of codes and invalidates every old one.
func (h *handler) totpRecovery(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	body, ok := decodeTwoFactorBody(w, r)
	if !ok {
		return
	}
	if !u.TwoFactorEnabled() {
		writeRefusal(w, metadb.ErrTOTPOff)
		return
	}
	if !h.requireCurrentPasswordAndCode(w, r, body.CurrentPassword, body.Code) {
		return
	}
	codes, err := h.db.ResetRecoveryCodes(u.Username)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// adminResetTOTP clears another user's second factor, the answer to a guest
// who lost their phone and their codes.
//
// It REFUSES to target the caller. An admin clearing their own 2FA with
// nothing but a bearer token would mean a stolen admin token defeats 2FA
// outright, and would make recovery codes decorative for the one account that
// has no second admin to unlock it. An admin's own factor is cleared by
// another admin's reset or by Server Management's SSH reset (reset2fa); a
// recovery code signs in but clears nothing.
//
// Clearing ANOTHER admin's factor needs the caller's step-up
// ({"currentPassword","totp"} in the body), for the same reason: with the
// factor gone, a bearer token that can also set that admin's password holds
// an admin identity it chose.
func (h *handler) adminResetTOTP(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == reqUser(r).Username {
		writeErrorCode(w, http.StatusForbidden, "totp-self-reset",
			"turn your own two-factor off with your password and a code, or use a recovery code")
		return
	}
	var creds stepUpCreds
	if !decodeOptionalJSONBody(w, r, 64<<10, &creds) {
		return
	}
	target, err := h.db.User(name)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// An account read as not an admin is cleared only if it still is not
	// one in the clearing write, so a promotion in between cannot skip the
	// step-up.
	disable := h.db.DisableNonAdminTOTP
	if target.IsAdmin() {
		if !h.requireCurrentPasswordAndCode(w, r, creds.CurrentPassword, creds.TOTP) {
			return
		}
		disable = h.db.DisableTOTP
	} else if (creds.CurrentPassword != "" || creds.TOTP != "") &&
		!h.requireCurrentPasswordAndCode(w, r, creds.CurrentPassword, creds.TOTP) {
		// Credentials a plain user's reset carries are verified.
		return
	}
	switch err := disable(name); {
	case errors.Is(err, metadb.ErrIsAdmin):
		writeStepUpRequired(w)
		return
	case err != nil:
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": name, "enabled": false})
}

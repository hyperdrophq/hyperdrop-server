package api

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

// Admin user management. Two roles exist, "admin" and "user", and both are
// set at creation and editable afterwards. An admin cannot lock themselves
// out through the API: demoting, disabling, expiring or deleting the
// CALLER's own account is refused (403 self-target). The store keeps the
// rest of the guarantee that a server holds an active admin: an edit or a
// delete that would leave none, or would take away the last admin whose
// access never expires, is refused 409 last-admin (metadb.ErrLastAdmin), so
// two admins acting on each other at once, or expiring each other, cannot
// leave the server without one.
//
// The second rule is STEP-UP on every edit that hands out an admin identity:
// creating an admin, promoting an account to admin, setting an admin's
// password, and clearing an admin's second factor all need the CALLER's own
// password (and authenticator code, when the caller has a second factor) in
// the body as currentPassword and totp. A bearer token alone must not be able
// to produce an admin whose password and factor the token holder chose,
// because such an account passes the step-up on POST /api/server/update, and
// that route grants root on the box.

func (h *handler) listUsers(w http.ResponseWriter, r *http.Request) {
	list, err := h.db.Users()
	if err != nil {
		writeRefusal(w, err)
		return
	}
	out := make([]userOut, 0, len(list))
	for _, u := range list {
		out = append(out, h.toUserOut(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// userSettingsReq is the shared settings body for create and PATCH. Pointer
// fields: absent = leave unchanged (create treats absent as zero/off).
type userSettingsReq struct {
	QuotaBytes         *int64     `json:"quotaBytes"`
	NoEmbed            *bool      `json:"noEmbed"`
	Disabled           *bool      `json:"disabled"`
	AccountExpiresAt   *time.Time `json:"accountExpiresAt"`
	ClearAccountExpiry bool       `json:"clearAccountExpiry"`
	SourceRoots        *[]string  `json:"sourceRoots"`
	// Role is "admin" or "user"; absent leaves it unchanged (create reads
	// absent as "user").
	Role *string `json:"role"`
	// ConfirmRevoke accepts the revoke a narrower allowlist (or a demotion)
	// causes on the account's existing linked shares; without it such an
	// edit is refused 409 revokes-shares with the list of what would be lost.
	ConfirmRevoke bool `json:"confirmRevoke"`
}

// errBadRole is the 400 a role outside the two known ones earns.
var errBadRole = refuse(http.StatusBadRequest, "bad-role", `role must be "admin" or "user"`)

// maxPasswordBytes is the most of a password bcrypt reads.
const maxPasswordBytes = metadb.MaxPasswordBytes

// checkChosenPassword refuses a chosen password outside metadb's bounds.
func checkChosenPassword(pw string) error {
	switch err := metadb.CheckChosenPassword(pw); {
	case errors.Is(err, metadb.ErrPasswordTooShort):
		return refuse(http.StatusBadRequest, "password-too-short", err.Error())
	case errors.Is(err, metadb.ErrPasswordTooLong):
		return refuse(http.StatusBadRequest, "password-too-long", err.Error())
	}
	return nil
}

// settings validates the request into the rows' form, refusing with a 400.
func (r userSettingsReq) settings() (metadb.Settings, error) {
	if r.Role != nil && !metadb.ValidRole(*r.Role) {
		return metadb.Settings{}, errBadRole
	}
	if r.QuotaBytes != nil && *r.QuotaBytes < 0 {
		return metadb.Settings{}, refuse(http.StatusBadRequest, "", "negative quotaBytes")
	}
	if r.SourceRoots != nil {
		for _, rel := range *r.SourceRoots {
			if !linked.ValidRel(rel) {
				return metadb.Settings{}, refuse(http.StatusBadRequest, "bad-source",
					"sourceRoots entry "+strconv.Quote(rel)+" is not a root-relative path")
			}
			if linked.Hidden(rel) {
				return metadb.Settings{}, refuse(http.StatusBadRequest, "bad-source", "sourceRoots entry names a hidden folder")
			}
		}
	}
	return metadb.Settings{QuotaBytes: r.QuotaBytes, NoEmbed: r.NoEmbed, Disabled: r.Disabled,
		AccountExpiresAt: r.AccountExpiresAt, ClearAccountExpiry: r.ClearAccountExpiry,
		SourceRoots: r.SourceRoots, Role: r.Role}, nil
}

// locksOutCaller reports whether a PATCH aimed at the caller's own account
// would take its admin access away: a demotion, a suspension, or an expiry
// (a future one included, since the moment it lands there would be no admin
// left to undo it). Clearing an expiry and every limit stay allowed.
func locksOutCaller(req userSettingsReq) bool {
	return (req.Role != nil && *req.Role != metadb.RoleAdmin) ||
		(req.Disabled != nil && *req.Disabled) ||
		req.AccountExpiresAt != nil
}

// writeSelfTarget is the refusal for an admin aiming a lock-out at their own
// account. Coded, so a client can tell it from a plain permission refusal.
func writeSelfTarget(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusForbidden, "self-target",
		"you cannot demote, suspend, expire or delete your own account; ask another admin")
}

// stepUpCreds is the caller's own proof of identity on an admin-granting
// edit. It names the CALLER, never the account being edited.
type stepUpCreds struct {
	CurrentPassword string `json:"currentPassword"`
	TOTP            string `json:"totp"`
}

// grantsAdminIdentity reports whether an edit of target hands out an admin
// identity: a promotion to admin, or a new password on an account that is
// already an admin (the caller's own included).
func grantsAdminIdentity(target metadb.User, role *string, setsPassword bool) bool {
	promotes := role != nil && *role == metadb.RoleAdmin && !target.IsAdmin()
	return promotes || (target.IsAdmin() && setsPassword)
}

func (h *handler) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		// Password "" = the server generates one and returns it once.
		Password string `json:"password"`
		userSettingsReq
		stepUpCreds
	}
	if !decodeJSONBody(w, r, 64<<10, &req) {
		return
	}
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if req.Password != "" {
		if err := checkChosenPassword(req.Password); err != nil {
			writeRefusal(w, err)
			return
		}
	}
	role := metadb.RoleUser
	if req.Role != nil {
		role = *req.Role
	}
	if !metadb.ValidRole(role) {
		writeRefusal(w, errBadRole)
		return
	}
	// A user with no quota is not merely generous: an unset limit skips the
	// per-owner admission check entirely, so the only thing between that
	// account and a full disk is the system reserve floor. Creation therefore
	// refuses to guess: send a quota, or 0 to mean "no limit" deliberately.
	// An admin is trusted with the disk already (no create rate limit, every
	// server root), so an absent quota there means no limit.
	if req.QuotaBytes == nil && role == metadb.RoleUser {
		writeErrorCode(w, http.StatusBadRequest, "quota-required",
			"set a storage quota for this account (quotaBytes; send 0 for no limit)")
		return
	}
	s, err := req.settings()
	if err != nil {
		writeRefusal(w, err)
		return
	}
	s.Role = nil
	if role == metadb.RoleAdmin && !h.requireCurrentPasswordAndCode(w, r, req.CurrentPassword, req.TOTP) {
		return
	}
	password, generated := req.Password, false
	if password == "" {
		password, generated = metadb.GeneratePassword(), true
	}
	u, err := h.db.CreateUser(req.Username, password, role, s)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	out := map[string]any{"user": h.toUserOut(u)}
	if generated {
		out["password"] = password
	}
	if err := h.mintInviteInto(out, u.Username); err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (h *handler) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := h.db.User(r.PathValue("name"))
	if err != nil {
		writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.toUserOut(u))
}

func (h *handler) updateUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		userSettingsReq
		// ResetPassword: mint a new generated password (returned once) and
		// revoke every device token the user has.
		ResetPassword bool `json:"resetPassword"`
		// Password non-empty: set exactly this password instead of a
		// generated one, with the same token revocation. It is never echoed
		// back; the caller already holds it.
		Password string `json:"password"`
		stepUpCreds
	}
	if !decodeJSONBody(w, r, 64<<10, &req) {
		return
	}
	if req.ResetPassword && req.Password != "" {
		writeError(w, http.StatusBadRequest, "send either resetPassword or password, not both")
		return
	}
	if req.Password != "" {
		if err := checkChosenPassword(req.Password); err != nil {
			writeRefusal(w, err)
			return
		}
	}
	s, err := req.settings()
	if err != nil {
		writeRefusal(w, err)
		return
	}
	if name == reqUser(r).Username && locksOutCaller(req.userSettingsReq) {
		writeSelfTarget(w)
		return
	}
	current, err := h.db.User(name)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// A missing password is refused before anything else is decided, but the
	// credentials are only CHECKED after the revoke question below: checking
	// spends the authenticator code, and a 409 that the client answers with
	// confirmRevoke must not leave it holding a code the server has already
	// accepted.
	stepUp := grantsAdminIdentity(current, req.Role, req.ResetPassword || req.Password != "")
	if stepUp && req.CurrentPassword == "" {
		writeStepUpRequired(w)
		return
	}
	flips, losses, err := h.sourceAccessChanges(current, s)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	if len(losses) > 0 && !req.ConfirmRevoke {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this change takes folders away that the account has already shared; confirm to unpublish them",
			"code":  "revokes-shares", "shares": losses})
		return
	}
	if stepUp && !h.requireCurrentPasswordAndCode(w, r, req.CurrentPassword, req.TOTP) {
		return
	}
	// The password is set in the transaction that applies the settings, so
	// an edit is applied whole or not at all.
	password := req.Password
	if req.ResetPassword {
		password = metadb.GeneratePassword()
	}
	if password != "" {
		s.Password = &password
	}
	u, err := h.db.UpdateUserAccess(name, s, flips)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// The edit is committed from here on, and the answer reports it: a
	// generated password exists nowhere else, so nothing after this point
	// may turn the answer into an error. The second revoke pass and the
	// invite are logged when they fail; the answer then carries no invite.
	if err := h.revokeLateSources(name, s); err != nil {
		log.Printf("users: %s: second revoke pass: %v", name, err)
	}
	out := map[string]any{"user": h.toUserOut(u)}
	if req.ResetPassword {
		out["password"] = password
	}
	// A new password is a new invite: the one-time link the admin sends
	// beside it. Minted after the password is set, since setting one clears
	// the invite it replaces.
	if req.ResetPassword || req.Password != "" {
		if err := h.mintInviteInto(out, name); err != nil {
			log.Printf("users: %s: minting the invite: %v", name, err)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// deleteUser removes the account AND all its shares, bytes included.
func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == reqUser(r).Username {
		writeSelfTarget(w)
		return
	}
	if _, err := h.db.User(name); err != nil {
		writeRefusal(w, err)
		return
	}
	// Asked before the shares go, which nothing undoes; DeleteUser asks
	// again in the write that removes the row.
	if err := h.db.DeleteKeepsAnAdmin(name); err != nil {
		writeRefusal(w, err)
		return
	}
	// The shares go first: an account that still owns one cannot be
	// deleted at all.
	if err := h.deleteUserShares(name); err != nil {
		writeRefusal(w, err)
		return
	}
	if err := h.db.DeleteUser(name); errors.Is(err, metadb.ErrConflict) {
		writeErrorCode(w, http.StatusConflict, "user-has-shares",
			"this account still owns shares")
		return
	} else if err != nil {
		writeRefusal(w, err)
		return
	}
	// Live shares live in the registry, not the rows, and are keyed by the
	// name: one left running would pass to the next account of that name.
	h.liveShareReg.DeleteOwner(name)
	w.WriteHeader(http.StatusNoContent)
}

// deleteUserShares removes every share the account owns, ordinary ones and
// inboxes alike, rows before bytes. Each pass re-reads the first page, so
// the loop shortens by a page per round and needs no cursor.
func (h *handler) deleteUserShares(name string) error {
	for _, kind := range []string{"", kindInbox} {
		for {
			page, err := h.db.List(metadb.ListQuery{Owner: name, Kind: kind, MaxFiles: 1})
			if err != nil {
				return err
			}
			if len(page.Shares) == 0 {
				break
			}
			for _, d := range page.Shares {
				// A share gone between the page and the delete is gone.
				if err := h.removeShare(d.ID); err != nil && !errors.Is(err, metadb.ErrNotFound) {
					return err
				}
			}
		}
	}
	return nil
}

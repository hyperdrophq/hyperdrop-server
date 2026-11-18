package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strconv"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// refusal is how a route turns a request away: the HTTP status, the
// machine-readable code ("" when the refusal has none) and the message. It is
// an error, so a rule that can refuse returns one and the handler that asked
// writes it with writeRefusal, wherever in the call chain the rule sits.
type refusal struct {
	status int
	code   string
	msg    string
	// extra holds fields the answer carries beside "error" and "code".
	extra map[string]any
}

func (r *refusal) Error() string { return r.msg }

// refuse builds a refusal.
func refuse(status int, code, msg string) error {
	return &refusal{status: status, code: code, msg: msg}
}

// refusalOf is the one table from an error to the answer a route gives: a
// refusal answers as itself, a metadb or sharefs sentinel through the rows
// below, and anything else is a 500 (internalError). One table, so the
// single-file upload, the batch upload, every edit and every account route
// answer alike.
func refusalOf(err error) *refusal {
	var r *refusal
	if errors.As(err, &r) {
		return r
	}
	var status int
	var extra map[string]any
	code, msg := "", err.Error()
	var conflict *metadb.ErrPublishConflict
	switch {
	case errors.As(err, &conflict):
		status, code = http.StatusConflict, "publish-conflict"
		extra = map[string]any{"conflicts": conflict.Conflicts}
	// metadb names what is missing ("file a/b.txt not found"), so its
	// message is relayed; sharefs names nothing, and the share is what the
	// caller asked about.
	case errors.Is(err, metadb.ErrNotFound):
		status, code = http.StatusNotFound, "not-found"
	case errors.Is(err, sharefs.ErrNotFound):
		status, code, msg = http.StatusNotFound, "not-found", "share not found"
	case errors.Is(err, sharefs.ErrNoStage):
		status, code, msg = http.StatusNotFound, "no-such-publish", errNoSuchPublish.Error()
	case errors.Is(err, sharefs.ErrStageFull):
		status, code, msg = http.StatusConflict, "publish-limit",
			"a publish holds at most "+strconv.Itoa(publishMaxFiles)+" files: commit this one and open another"
	case errors.Is(err, sharefs.ErrStageCommitting):
		status, code, msg = http.StatusConflict, "conflict", errPublishCommitted.Error()
	case errors.Is(err, metadb.ErrQuota):
		status, code = http.StatusInsufficientStorage, "quota"
	case errors.Is(err, metadb.ErrInboxFull):
		status, code = http.StatusRequestEntityTooLarge, "receive-full"
	case errors.Is(err, metadb.ErrPathTaken):
		status, code = http.StatusBadRequest, "path-taken"
	case errors.Is(err, metadb.ErrTooManyFolders):
		status, code, msg = http.StatusBadRequest, "too-many-folders", "this share holds as many folders as it can"
	case errors.Is(err, metadb.ErrFolderNotEmpty):
		status, code, msg = http.StatusConflict, "not-empty", "the folder still holds files"
	case errors.Is(err, metadb.ErrIntoItself):
		status, code, msg = http.StatusBadRequest, "into-itself", "a folder cannot move into itself"
	case errors.Is(err, metadb.ErrMovePending):
		status, code, msg = http.StatusConflict, "share-incomplete", "a file still uploading cannot be moved"
	case errors.Is(err, metadb.ErrNotASource):
		status, code = http.StatusBadRequest, "not-a-source"
	case errors.Is(err, metadb.ErrLinkedFilterTooBig):
		status, code = http.StatusRequestEntityTooLarge, "linked-filter-too-big"
	case errors.Is(err, metadb.ErrInbox):
		status, code, msg = http.StatusConflict, "file-link-inbox", "a Receive Inbox has no direct links"
	case errors.Is(err, metadb.ErrTextShare):
		status, code = http.StatusConflict, "text-share"
	case errors.Is(err, metadb.ErrUserNotFound):
		status, code = http.StatusNotFound, "user-not-found"
	case errors.Is(err, metadb.ErrExists):
		status, code = http.StatusConflict, "user-exists"
	case errors.Is(err, metadb.ErrBadName):
		status, code = http.StatusBadRequest, "bad-name"
	case errors.Is(err, metadb.ErrBadCredentials):
		status, code = http.StatusUnauthorized, "bad-credentials"
	case errors.Is(err, metadb.ErrInactive):
		// Coded, because clients must tell THIS 403 apart from the admin
		// gate's: a long-poll host treats a disabled account as permanent
		// and stops respawning, and it must never do that for a mere
		// permission refusal.
		status, code = http.StatusForbidden, "account-disabled"
	case errors.Is(err, metadb.ErrTOTPRequired):
		status, code, msg = http.StatusUnauthorized, "totp-required", "this account needs an authenticator code"
	case errors.Is(err, metadb.ErrTOTPInvalid):
		status, code, msg = http.StatusUnauthorized, "totp-invalid", "that authenticator code is wrong or already used"
	case errors.Is(err, metadb.ErrTOTPNotPending):
		status, code = http.StatusConflict, "totp-not-pending"
	case errors.Is(err, metadb.ErrTOTPAlreadyOn):
		status, code = http.StatusConflict, "totp-already-on"
	case errors.Is(err, metadb.ErrTOTPOff):
		status, code = http.StatusConflict, "totp-off"
	case errors.Is(err, metadb.ErrDeviceLinkInvalid):
		status, code = http.StatusNotFound, "device-link-invalid"
	case errors.Is(err, metadb.ErrDeviceLinkWrongNumber):
		status, code = http.StatusConflict, "device-link-wrong-number"
	case errors.Is(err, metadb.ErrLastAdmin):
		status, code = http.StatusConflict, "last-admin"
	case errors.Is(err, metadb.ErrConflict):
		status, code = http.StatusConflict, "conflict"
	case errors.Is(err, metadb.ErrBadRequest), errors.Is(err, sharefs.ErrBadRequest):
		status = http.StatusBadRequest
	case errors.Is(err, sharefs.ErrDiskFull), errors.Is(err, sharefs.ErrNoSpace):
		status, code = http.StatusInsufficientStorage, "no-space"
	default:
		return internalError(err)
	}
	return &refusal{status: status, code: code, msg: msg, extra: extra}
}

// internalError is the 500 for an error no row above names. Its text can
// carry a driver message, a table or column name or a path on the data
// volume, so it goes to the log under a short random reference and the
// client is answered the reference alone, which is what an operator
// searches the log for.
func internalError(err error) *refusal {
	var b [4]byte
	_, _ = rand.Read(b[:])
	ref := hex.EncodeToString(b[:])
	log.Printf("internal error ref=%s: %v", ref, err)
	return &refusal{status: http.StatusInternalServerError, msg: "internal error (ref " + ref + ")"}
}

// writeRefusal answers err through refusalOf: the one writer for every
// refusal a route gives, coded or not.
func writeRefusal(w http.ResponseWriter, err error) {
	r := refusalOf(err)
	if len(r.extra) > 0 {
		body := map[string]any{"error": r.msg, "code": r.code}
		for k, v := range r.extra {
			body[k] = v
		}
		writeJSON(w, r.status, body)
		return
	}
	if r.code != "" {
		writeErrorCode(w, r.status, r.code, r.msg)
		return
	}
	writeError(w, r.status, r.msg)
}

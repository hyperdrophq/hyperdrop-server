package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// refusalOf is the one table from an error to a route's answer. These pin
// the rows a client branches on, so a sentinel that loses its code is a red
// test rather than a client that silently stops recognizing a refusal.
func TestRefusalOfMapsEverySentinelItOwns(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{metadb.ErrNotFound, http.StatusNotFound, "not-found"},
		{sharefs.ErrNotFound, http.StatusNotFound, "not-found"},
		{metadb.ErrQuota, http.StatusInsufficientStorage, "quota"},
		{metadb.ErrPathTaken, http.StatusBadRequest, "path-taken"},
		{metadb.ErrTextShare, http.StatusConflict, "text-share"},
		{metadb.ErrUserNotFound, http.StatusNotFound, "user-not-found"},
		{metadb.ErrExists, http.StatusConflict, "user-exists"},
		{metadb.ErrBadName, http.StatusBadRequest, "bad-name"},
		{metadb.ErrBadCredentials, http.StatusUnauthorized, "bad-credentials"},
		{metadb.ErrInactive, http.StatusForbidden, "account-disabled"},
		{metadb.ErrTOTPRequired, http.StatusUnauthorized, "totp-required"},
		{metadb.ErrTOTPInvalid, http.StatusUnauthorized, "totp-invalid"},
		{metadb.ErrTOTPNotPending, http.StatusConflict, "totp-not-pending"},
		{metadb.ErrTOTPAlreadyOn, http.StatusConflict, "totp-already-on"},
		{metadb.ErrTOTPOff, http.StatusConflict, "totp-off"},
		{metadb.ErrBadRequest, http.StatusBadRequest, ""},
		{errors.New("disk on fire"), http.StatusInternalServerError, ""},
	} {
		r := refusalOf(fmt.Errorf("wrapped: %w", tc.err))
		if r.status != tc.status || r.code != tc.code {
			t.Errorf("%v = %d %q, want %d %q", tc.err, r.status, r.code, tc.status, tc.code)
		}
	}
}

// A refusal answers as itself, however deep a helper wrapped it.
func TestRefusalOfPassesARefusalThrough(t *testing.T) {
	err := fmt.Errorf("context: %w", refuse(http.StatusTeapot, "teapot", "short and stout"))
	r := refusalOf(err)
	if r.status != http.StatusTeapot || r.code != "teapot" || r.msg != "short and stout" {
		t.Fatalf("refusal = %+v", *r)
	}
}

// metadb names what is missing, and the message a client shows says which.
func TestWriteRefusalRelaysWhatIsMissing(t *testing.T) {
	db := testBackend(t).DB
	if _, err := db.CreateUser("bob", "a-long-password", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	d, err := db.CreateShare(metadb.CreateOptions{Name: "x", Owner: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.RemoveFolder(d.ID, "nope")
	w := httptest.NewRecorder()
	writeRefusal(w, err)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `folder nope not found`) ||
		!strings.Contains(w.Body.String(), `"code":"not-found"`) {
		t.Fatalf("answer = %d %s", w.Code, w.Body)
	}
}

// An error no row names is a 500 whose text stays in the log: the client
// reads a reference to it, never the driver message or a path on the volume.
func TestAnUnmappedErrorAnswersAReferenceNotItsText(t *testing.T) {
	var logged strings.Builder
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rec := httptest.NewRecorder()
	writeRefusal(rec, errors.New("constraint failed: UNIQUE constraint failed: folders.share_id (1555) at /data/shares"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "constraint") || strings.Contains(body, "/data") {
		t.Fatalf("the 500 relays the error's text: %s", body)
	}
	ref := regexp.MustCompile(`internal error \(ref ([0-9a-f]{8})\)`).FindStringSubmatch(body)
	if ref == nil {
		t.Fatalf("the 500 carries no reference: %s", body)
	}
	if !strings.Contains(logged.String(), "ref="+ref[1]+": constraint failed") {
		t.Fatalf("the log does not hold the error under its reference: %q", logged.String())
	}
}

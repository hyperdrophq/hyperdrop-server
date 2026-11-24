package api

import (
	"net/http"
	"testing"
)

// A database that cannot answer is a server fault, never a wrong password
// or a revoked token: a client that read it as one would stop syncing or
// send its owner to sign in again, and the address would be counted as if
// it had guessed.
func TestADatabaseFaultIsNotABadCredential(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	db.Close()
	for _, tc := range []struct{ method, path, token, body string }{
		{"POST", "/api/auth/login", "", loginBody("admin", testAdminPassword, "")},
		{"GET", "/api/me", testToken, ""},
	} {
		rec := doReq(t, h, tc.method, tc.path, tc.token, tc.body)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s %s on a closed database = %d %s, want 500", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}

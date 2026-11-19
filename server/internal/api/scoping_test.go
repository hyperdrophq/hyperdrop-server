package api

import (
	"net/http"
	"strings"
	"testing"
)

// createShareAs makes a share with the given bearer and returns its ID.
func createShareAs(t *testing.T, h http.Handler, token, body string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", token, body)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &out)
	return out.ID
}

func TestListingIsOwnerScoped(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	bob := seedUser(t, um, "bob")
	aliceID := createShareAs(t, h, alice, `{"name":"alices"}`)
	createShareAs(t, h, bob, `{"name":"bobs"}`)

	var listing struct {
		Shares []struct {
			ID    string  `json:"id"`
			Owner *string `json:"owner"`
		} `json:"shares"`
	}
	rec := doReq(t, h, "GET", "/api/shares", alice, "")
	unmarshal(t, rec, &listing)
	if len(listing.Shares) != 1 || listing.Shares[0].ID != aliceID {
		t.Fatalf("alice's listing: %+v", listing.Shares)
	}
	if listing.Shares[0].Owner != nil {
		t.Fatalf("owner travels on a share view: %+v", listing.Shares[0])
	}

	// An admin's own listing is empty until it makes its own shares: it is
	// owner-scoped exactly like alice and bob, never a view of everyone's.
	rec = doReq(t, h, "GET", "/api/shares", testToken, "")
	unmarshal(t, rec, &listing)
	if len(listing.Shares) != 0 {
		t.Fatalf("admin listing before any admin share: %+v", listing.Shares)
	}
	adminID := createShareAs(t, h, testToken, `{"name":"admins"}`)
	rec = doReq(t, h, "GET", "/api/shares", testToken, "")
	unmarshal(t, rec, &listing)
	if len(listing.Shares) != 1 || listing.Shares[0].ID != adminID {
		t.Fatalf("admin listing: %+v, want only %s", listing.Shares, adminID)
	}
	if listing.Shares[0].Owner != nil {
		t.Fatalf("owner travels on a share view: %+v", listing.Shares[0])
	}
}

func TestCrossUserAccessIs404(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	bob := seedUser(t, um, "bob")
	id := createShareAs(t, h, alice, `{"name":"private"}`)
	doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt", alice, "hi")

	cases := []struct{ method, path, body string }{
		{"GET", "/api/shares/" + id, ""},
		{"PATCH", "/api/shares/" + id, `{"expiresInSeconds":60}`},
		{"DELETE", "/api/shares/" + id, ""},
		{"PUT", "/api/shares/" + id + "/files/evil.txt", "boo"},
		{"GET", "/api/shares/" + id + "/uploads/a.txt", ""},
	}
	// Every account but the owner is refused the same way, an admin
	// included: none of these mutate anything, so alice's share survives
	// intact for the check below.
	for _, caller := range []string{bob, testToken} {
		for _, c := range cases {
			if rec := doReq(t, h, c.method, c.path, caller, c.body); rec.Code != 404 {
				t.Errorf("%s %s as %s = %d, want 404", c.method, c.path, caller, rec.Code)
			}
		}
	}
	// The share is untouched: its owner can still reach it.
	if rec := doReq(t, h, "GET", "/api/shares/"+id, alice, ""); rec.Code != 200 {
		t.Fatalf("owner get: %d", rec.Code)
	}
}

func TestQuotaErrorCode(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	rec := doReq(t, h, "PATCH", "/api/users/alice", testToken, `{"quotaBytes":10}`)
	if rec.Code != 200 {
		t.Fatalf("set quota: %d %s", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "POST", "/api/shares", alice, `{"name":"big","reserveBytes":100}`)
	if rec.Code != 507 {
		t.Fatalf("over-quota reserve: %d %s, want 507", rec.Code, rec.Body)
	}
	var e struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	unmarshal(t, rec, &e)
	if e.Code != "quota" || !strings.Contains(e.Error, "quota") {
		t.Fatalf("error payload: %+v", e)
	}
	// Direct upload past quota carries the code too.
	id := createShareAs(t, h, alice, `{"name":"drip"}`)
	rec = doReq(t, h, "PUT", "/api/shares/"+id+"/files/f.bin", alice, strings.Repeat("x", 50))
	if rec.Code != 507 {
		t.Fatalf("over-quota upload: %d %s", rec.Code, rec.Body)
	}
	unmarshal(t, rec, &e)
	if e.Code != "quota" {
		t.Fatalf("upload error payload: %+v", e)
	}
}

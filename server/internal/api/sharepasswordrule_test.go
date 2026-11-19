package api

import (
	"net/http"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// A share password is a chosen password: at least 8 bytes, at most 72 and
// not among the most common, the rule accounts already follow, on create,
// edit and the live-share routes alike. A share whose password predates the
// rule still opens with it; only setting one is judged.
func TestAShareyPasswordIsAChosenPassword(t *testing.T) {
	h := newTestAPI(t)
	for _, tc := range []struct{ pw, code, words string }{
		{"short", "password-too-short", ""},
		{"password", "", "too common"},
		{strings.Repeat("x", 73), "password-too-long", ""},
	} {
		rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"s","password":"`+tc.pw+`"}`)
		if rec.Code != http.StatusBadRequest || (tc.code != "" && errCode(t, rec.Body.String()) != tc.code) ||
			(tc.words != "" && !strings.Contains(rec.Body.String(), tc.words)) {
			t.Fatalf("create with password %q = %d %s, want 400 %s%s", tc.pw, rec.Code, rec.Body, tc.code, tc.words)
		}
	}
	id := createShare(t, h, "s")
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"short"}`); rec.Code != http.StatusBadRequest || errCode(t, rec.Body.String()) != "password-too-short" {
		t.Fatalf("edit with a short password = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":"long-enough-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("edit with a chosen password = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken, `{"password":""}`); rec.Code != http.StatusOK {
		t.Fatalf("removing the password = %d %s", rec.Code, rec.Body)
	}
}

func TestAShareWithAPasswordShorterThanTheRuleStillOpens(t *testing.T) {
	routes, hd := newTestAPIParts(t)
	hash, err := sharePasswordHash("pw")
	if err != nil {
		t.Fatal(err)
	}
	d, err := hd.db.CreateShare(metadb.CreateOptions{Owner: metadb.DefaultAdminName, Name: "old", PasswordHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	rec := doReqForm(t, routes, "POST", "/unlock/"+d.ID, "password=pw")
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
		t.Fatalf("unlocking a share whose password predates the rule = %d %s", rec.Code, rec.Body)
	}
}

package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCreateResponseNeverLeaksHash(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"x","password":"hunter2"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "passwordHash") || strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("response leaked password material: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"hasPassword":true`) {
		t.Fatalf("missing hasPassword: %s", rec.Body)
	}
}

func TestPublicRoutesRequirePasswordViaQuery(t *testing.T) {
	h := newTestAPI(t)
	// create protected share + upload a file
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"secret","password":"hunter2"}`)
	var cr struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &cr)
	slug := uploadGetSlug(t, h, cr.ID, "a.txt", "data")

	// no password → not 200 (form or 401), and MUST NOT serve the bytes
	bare := doReq(t, h, "GET", "/download/"+cr.ID+"/"+slug, "", "")
	if bare.Code == 200 && bare.Body.String() == "data" {
		t.Fatal("served protected file without a password")
	}
	// correct ?pw= → 200 + bytes
	ok := doReq(t, h, "GET", "/download/"+cr.ID+"/"+slug+"?pw=hunter2", "", "")
	if ok.Code != 200 || ok.Body.String() != "data" {
		t.Fatalf("correct pw: code=%d body=%q", ok.Code, ok.Body)
	}
	// wrong ?pw= → not served
	bad := doReq(t, h, "GET", "/download/"+cr.ID+"/"+slug+"?pw=nope", "", "")
	if bad.Code == 200 && bad.Body.String() == "data" {
		t.Fatal("served protected file with a wrong password")
	}
}

func TestPasswordFormBodyCapped(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"p","password":"x"}`)
	var cr struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &cr)
	// The form is capped at 64 KB; an oversized body is rejected, not parsed.
	big := doReqForm(t, h, "POST", "/unlock/"+cr.ID, "password="+strings.Repeat("a", 65<<10))
	if big.Code != 400 {
		t.Fatalf("oversized form status = %d, want 400", big.Code)
	}
}

func TestListReportsHasPassword(t *testing.T) {
	h := newTestAPI(t)
	doReq(t, h, "POST", "/api/shares", testToken, `{"name":"p","password":"x"}`)
	rec := doReq(t, h, "GET", "/api/shares", testToken, "")
	if !strings.Contains(rec.Body.String(), `"hasPassword":true`) {
		t.Fatalf("list missing hasPassword: %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "passwordHash") {
		t.Fatalf("list leaked hash: %s", rec.Body)
	}
}

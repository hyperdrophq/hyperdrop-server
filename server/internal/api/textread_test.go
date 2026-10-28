package api

import (
	"net/http"
	"strings"
	"testing"
)

// textOf asks for a share's text with token and answers the recorder.
func textOf(t *testing.T, h http.Handler, token, id string) (code int, name, text, errcode string, hdr http.Header) {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares/"+id+"/text", token, "")
	if rec.Code != 200 {
		return rec.Code, "", "", errCode(t, rec.Body.String()), rec.Header()
	}
	var out struct {
		Name string `json:"name"`
		Text string `json:"text"`
	}
	unmarshal(t, rec, &out)
	return rec.Code, out.Name, out.Text, "", rec.Header()
}

func TestTheOwnerReadsATextSharesTextAsJSON(t *testing.T) {
	h := newTestAPI(t)
	id := createTextShare(t, h)
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/note.txt", testToken, "héllo <b>there</b>"); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	code, name, text, _, hdr := textOf(t, h, testToken, id)
	if code != 200 || name != "note.txt" || text != "héllo <b>there</b>" {
		t.Fatalf("text = %d %q %q", code, name, text)
	}
	if got := hdr.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := hdr.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := hdr.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
}

func TestTextReadRefusesWhatIsNotAReadableNote(t *testing.T) {
	h, db := newTestAPIWithUsers(t)
	guest := seedUser(t, db, "guest")

	plain := createShare(t, h, "plain")
	uploadGetSlug(t, h, plain, "a.txt", "x")
	if code, _, _, ec, _ := textOf(t, h, testToken, plain); code != 409 || ec != "not-text-share" {
		t.Errorf("ordinary share = %d %s, want 409 not-text-share", code, ec)
	}

	note := createTextShare(t, h)
	if code, _, _, _, _ := textOf(t, h, testToken, note); code != 404 {
		t.Errorf("a text share with no file = %d, want 404", code)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+note+"/files/note.txt", testToken, "mine"); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	if code, _, _, ec, _ := textOf(t, h, guest, note); code != 404 || ec != "not-found" {
		t.Errorf("another account = %d %s, want 404 not-found", code, ec)
	}
	if code, _, _, _, _ := textOf(t, h, "", note); code != 401 {
		t.Errorf("anonymous = %d, want 401", code)
	}

	pending := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"n","text":true,"files":[{"path":"a.txt","size":3}]}`)
	if pending.Code != 201 {
		t.Fatalf("declared text share = %d %s", pending.Code, pending.Body)
	}
	var made struct{ ID string }
	unmarshal(t, pending, &made)
	if code, _, _, ec, _ := textOf(t, h, testToken, made.ID); code != 409 || ec != "file-pending" {
		t.Errorf("pending = %d %s, want 409 file-pending", code, ec)
	}

	bad := createTextShare(t, h)
	if rec := doReq(t, h, "PUT", "/api/shares/"+bad+"/files/note.txt", testToken, "ok \xff\xfe"); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	if code, _, _, ec, _ := textOf(t, h, testToken, bad); code != 409 || ec != "text-not-utf8" {
		t.Errorf("not UTF-8 = %d %s, want 409 text-not-utf8", code, ec)
	}
}

// An administrator reads no other account's note: the share answers as one
// that does not exist.
func TestAnAdminReadsNoOtherAccountsText(t *testing.T) {
	h, db := newTestAPIWithUsers(t)
	guest := seedUser(t, db, "guest")
	rec := doReq(t, h, "POST", "/api/shares", guest, `{"name":"Mine","text":true}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var made struct{ ID string }
	unmarshal(t, rec, &made)
	if rec := doReq(t, h, "PUT", "/api/shares/"+made.ID+"/files/note.txt", guest, "private words"); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	if code, _, text, _, _ := textOf(t, h, guest, made.ID); code != 200 || text != "private words" {
		t.Fatalf("the owner = %d %q", code, text)
	}
	got := doReq(t, h, "GET", "/api/shares/"+made.ID+"/text", testToken, "")
	if got.Code != 404 || errCode(t, got.Body.String()) != "not-found" || strings.Contains(got.Body.String(), "private words") {
		t.Fatalf("the admin = %d %s, want 404 not-found", got.Code, got.Body)
	}
}

func TestTextReadStopsAtTheEditLimit(t *testing.T) {
	h := newTestAPI(t)
	if textReadMaxBytes != 256*1024 {
		t.Fatalf("the limit is the apps' in-place edit limit, 256 KiB: %d", textReadMaxBytes)
	}
	at := createTextShare(t, h)
	full := strings.Repeat("a", int(textReadMaxBytes))
	if rec := doReq(t, h, "PUT", "/api/shares/"+at+"/files/note.txt", testToken, full); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	if code, _, text, _, _ := textOf(t, h, testToken, at); code != 200 || len(text) != len(full) {
		t.Fatalf("at the limit = %d (%d bytes)", code, len(text))
	}
	over := createTextShare(t, h)
	if rec := doReq(t, h, "PUT", "/api/shares/"+over+"/files/note.txt", testToken, full+"b"); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	if code, _, _, ec, _ := textOf(t, h, testToken, over); code != 413 || ec != "text-too-large" {
		t.Fatalf("over the limit = %d %s, want 413 text-too-large", code, ec)
	}
}

func TestAWebSessionReadsItsTextShare(t *testing.T) {
	f := newWebFixture(t, true)
	rec := doReq(t, f.h, "POST", "/api/shares", f.aliceDevice, `{"name":"Note","text":true}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var made struct{ ID string }
	unmarshal(t, rec, &made)
	if rec := doReq(t, f.h, "PUT", "/api/shares/"+made.ID+"/files/note.txt", f.aliceDevice, "from the phone"); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	cookie := f.signIn(t, false)
	got := f.req(t, "GET", "/api/shares/"+made.ID+"/text", cookie, "")
	if got.Code != 200 || !strings.Contains(got.Body.String(), `"text":"from the phone"`) {
		t.Fatalf("web read = %d %s", got.Code, got.Body)
	}
	if got.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", got.Header().Get("Cache-Control"))
	}
}

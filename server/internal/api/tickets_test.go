package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// ticketURL asks for a download ticket and returns the path+query of the
// answered URL, relative to the host.
func ticketURL(t *testing.T, h http.Handler, token, id, slug string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/download-ticket", token, `{"slug":"`+slug+`"}`)
	if rec.Code != 200 {
		t.Fatalf("download-ticket = %d %s", rec.Code, rec.Body)
	}
	var out struct{ URL string }
	unmarshal(t, rec, &out)
	if !strings.HasPrefix(out.URL, "http://") && !strings.HasPrefix(out.URL, "https://") {
		t.Fatalf("ticket url = %q, want an absolute URL", out.URL)
	}
	i := strings.Index(out.URL, "/download/")
	if i < 0 || !strings.Contains(out.URL, "?t=") {
		t.Fatalf("ticket url = %q", out.URL)
	}
	return out.URL[i:]
}

const otherSlug = "00000000-0000-4000-8000-000000000000"

func uploadGetSlugAs(t *testing.T, h http.Handler, token, id, path, content string) string {
	t.Helper()
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+path, token, content)
	if rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	var out struct{ Slug string }
	unmarshal(t, rec, &out)
	return out.Slug
}

func inboxWithFile(t *testing.T, h http.Handler) (id, slug string) {
	t.Helper()
	id, slug = publicProbeShare(t, h, true)
	return id, slug
}

func TestTicketDownloadsAnInboxFile(t *testing.T) {
	h := newTestAPI(t)
	id, slug := inboxWithFile(t, h)
	if got := doReq(t, h, "GET", "/download/"+id+"/"+slug, "", ""); got.Code != 404 {
		t.Fatalf("anonymous inbox download = %d", got.Code)
	}
	u := ticketURL(t, h, testToken, id, slug)
	got := doReq(t, h, "GET", u, "", "")
	if got.Code != 200 || got.Body.String() != "<html>hi</html>" {
		t.Fatalf("ticket download = %d %q", got.Code, got.Body)
	}
	if !strings.Contains(got.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("disposition = %q", got.Header().Get("Content-Disposition"))
	}
}

func TestTicketDownloadsAPasswordShareFile(t *testing.T) {
	h := newTestAPI(t)
	id, slug := protectedShareWithFile(t, h)
	if got := doReq(t, h, "GET", "/download/"+id+"/"+slug, "", ""); got.Body.String() == "data" {
		t.Fatal("protected bytes served without a ticket")
	}
	u := ticketURL(t, h, testToken, id, slug)
	got := doReq(t, h, "GET", u, "", "")
	if got.Code != 200 || got.Body.String() != "data" {
		t.Fatalf("ticket download = %d %q", got.Code, got.Body)
	}
}

func TestTicketIsSingleUse(t *testing.T) {
	h := newTestAPI(t)
	id, slug := inboxWithFile(t, h)
	u := ticketURL(t, h, testToken, id, slug)
	if got := doReq(t, h, "GET", u, "", ""); got.Code != 200 {
		t.Fatalf("first use = %d", got.Code)
	}
	if got := doReq(t, h, "GET", u, "", ""); got.Code != 404 {
		t.Fatalf("second use = %d, want 404", got.Code)
	}
}

func TestTicketExpiresAfterTwoMinutes(t *testing.T) {
	var b ticketBook
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	tk := mustIssue(t, &b, "alice", "tok1", "s1", "slug", t0)
	if _, ok := b.spend(tk, "s1", "slug", t0.Add(2*time.Minute)); ok {
		t.Fatal("ticket spent at exactly two minutes")
	}
	tk = mustIssue(t, &b, "alice", "tok1", "s1", "slug", t0)
	if k, ok := b.spend(tk, "s1", "slug", t0.Add(2*time.Minute-time.Second)); !ok || k.user != "alice" {
		t.Fatalf("ticket just inside two minutes: %+v %v", k, ok)
	}
	tk = mustIssue(t, &b, "alice", "tok1", "s1", "slug", t0)
	mustIssue(t, &b, "alice", "tok1", "s1", "other", t0.Add(3*time.Minute))
	if len(b.m) != 1 {
		t.Fatalf("issue left %d tickets, want the expired one swept", len(b.m))
	}
	if _, ok := b.spend(tk, "s1", "slug", t0.Add(3*time.Minute)); ok {
		t.Fatal("swept ticket spent")
	}
}

func TestTicketBoundToSlug(t *testing.T) {
	h := newTestAPI(t)
	id, slug := inboxWithFile(t, h)
	u := ticketURL(t, h, testToken, id, slug)
	i := strings.Index(u, "?t=")
	other := "/download/" + id + "/" + otherSlug + u[i:]
	if got := doReq(t, h, "GET", other, "", ""); got.Code != 404 {
		t.Fatalf("other slug = %d", got.Code)
	}
	// The mismatch spent the ticket.
	if got := doReq(t, h, "GET", u, "", ""); got.Code != 404 {
		t.Fatalf("spent ticket = %d", got.Code)
	}
	var b ticketBook
	now := time.Now()
	tk := mustIssue(t, &b, "alice", "tok1", "s1", "slug", now)
	if _, ok := b.spend(tk, "s2", "slug", now); ok {
		t.Fatal("ticket spent on another share")
	}
}

func TestTicketIgnoredOnOtherRoutes(t *testing.T) {
	h := newTestAPI(t)
	id, slug := inboxWithFile(t, h)
	u := ticketURL(t, h, testToken, id, slug)
	q := u[strings.Index(u, "?t="):]
	for _, p := range []string{"/zip/" + id, "/view/" + id + "/" + slug, "/thumb/" + id + "/" + slug} {
		if got := doReq(t, h, "GET", p+q, "", ""); got.Code != 404 {
			t.Errorf("GET %s with a ticket = %d, want 404", p, got.Code)
		}
	}
	if got := doReq(t, h, "GET", u, "", ""); got.Code != 200 {
		t.Fatalf("the ticket did not survive the other routes: /download = %d", got.Code)
	}
}

func TestTicketSurvivesHead(t *testing.T) {
	h := newTestAPI(t)
	id, slug := inboxWithFile(t, h)
	u := ticketURL(t, h, testToken, id, slug)
	if got := doReq(t, h, "HEAD", u, "", ""); got.Code != 200 {
		t.Fatalf("HEAD with a ticket = %d", got.Code)
	}
	if got := doReq(t, h, "GET", u, "", ""); got.Code != 200 || got.Body.Len() == 0 {
		t.Fatalf("GET after HEAD = %d", got.Code)
	}
	if got := doReq(t, h, "GET", u, "", ""); got.Code != 404 {
		t.Fatalf("second GET = %d, want 404", got.Code)
	}
}

func TestTicketRefusesAPendingFile(t *testing.T) {
	h := newTestAPI(t)
	id := createInbox(t, h, `{"name":"p","files":[{"path":"a.txt","size":5}]}`)
	var sh struct {
		Files []struct{ Slug string } `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &sh)
	if len(sh.Files) != 1 {
		t.Fatalf("files = %d", len(sh.Files))
	}
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/download-ticket", testToken, `{"slug":"`+sh.Files[0].Slug+`"}`)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "file-pending") {
		t.Fatalf("pending file = %d %s, want 409 file-pending", rec.Code, rec.Body)
	}
}

// A ticket naming the right share and slug but another account is not the
// owner's: the owner check is separate from the binding.
func TestTicketForAnotherAccountIsNotTheOwners(t *testing.T) {
	h, hd := newTestAPIParts(t)
	id, slug := inboxWithFile(t, h)
	tk := mustIssue(t, &hd.tickets, "guest", tokenIDOf(t, hd, testToken), id, slug, time.Now())
	if got := doReq(t, h, "GET", "/download/"+id+"/"+slug+"?t="+tk, "", ""); got.Code != 404 {
		t.Fatalf("download = %d, want 404", got.Code)
	}
}

// A ticket carries the account it was issued to: one a guest holds for the
// guest's own share, replayed on the admin's share path, opens nothing.
func TestTicketOfAnotherUserOpensNothing(t *testing.T) {
	h, db := newTestAPIWithUsers(t)
	guest := seedUser(t, db, "guest")
	id, slug := inboxWithFile(t, h)
	rec := doReq(t, h, "POST", "/api/shares", guest, `{"name":"g","password":"pw"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	gslug := uploadGetSlugAs(t, h, guest, cr.ID, "b.txt", "gdata")
	u := ticketURL(t, h, guest, cr.ID, gslug)
	q := u[strings.Index(u, "?t="):]
	if got := doReq(t, h, "GET", "/download/"+id+"/"+slug+q, "", ""); got.Code != 404 {
		t.Fatalf("a guest's ticket on the admin's inbox = %d, want 404", got.Code)
	}
}

func TestTicketNeedsOwner(t *testing.T) {
	h, db := newTestAPIWithUsers(t)
	guest := seedUser(t, db, "guest")
	id, slug := protectedShareWithFile(t, h)
	ask := func(token, share, sl string) int {
		return doReq(t, h, "POST", "/api/shares/"+share+"/download-ticket", token, `{"slug":"`+sl+`"}`).Code
	}
	if got := ask(guest, id, slug); got != 404 {
		t.Errorf("another account's share = %d, want 404", got)
	}
	if got := ask(testToken, id, otherSlug); got != 404 {
		t.Errorf("unknown slug = %d, want 404", got)
	}
	if got := ask(testToken, "nope", slug); got != 404 {
		t.Errorf("unknown share = %d, want 404", got)
	}
	if got := ask(testToken, id, slug); got != 200 {
		t.Errorf("owner = %d, want 200", got)
	}
}

// mustIssue issues a ticket from b, failing the test on a refusal.
func mustIssue(t *testing.T, b *ticketBook, user, tokenID, shareID, slug string, now time.Time) string {
	t.Helper()
	tk, err := b.issue(user, tokenID, shareID, slug, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tk
}

// tokenIDOf is the id of the token row raw names.
func tokenIDOf(t *testing.T, hd *handler, raw string) string {
	t.Helper()
	u, err := hd.db.UserByToken(raw, metadb.ClientInfo{})
	if err != nil {
		t.Fatal(err)
	}
	id := tokenNamed(u, metadb.TokenHash(raw)).ID
	if id == "" {
		t.Fatal("no row for the token")
	}
	return id
}

// One account holds at most ticketsPerUser live tickets and the server at
// most ticketsTotal; a ticket that runs out frees its place at the next
// sweep.
func TestTicketCaps(t *testing.T) {
	var b ticketBook
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	for i := 0; i < ticketsPerUser; i++ {
		mustIssue(t, &b, "alice", "tok", "s1", "slug", t0)
	}
	if _, err := b.issue("alice", "tok", "s1", "slug", t0); !errors.Is(err, errTooManyTickets) {
		t.Fatalf("alice's ticket past the cap: %v, want errTooManyTickets", err)
	}
	// Spending one frees its place.
	tk := mustIssue(t, &b, "bob", "tok", "s1", "slug", t0)
	if _, ok := b.spend(tk, "s1", "slug", t0); !ok {
		t.Fatal("bob's ticket did not spend")
	}
	for i := 0; i < ticketsPerUser; i++ {
		mustIssue(t, &b, "bob", "tok", "s1", "slug", t0)
	}
	for u := 2; len(b.m) < ticketsTotal; u++ {
		for i := 0; i < ticketsPerUser && len(b.m) < ticketsTotal; i++ {
			mustIssue(t, &b, fmt.Sprintf("user%d", u), "tok", "s1", "slug", t0)
		}
	}
	if _, err := b.issue("carol", "tok", "s1", "slug", t0); !errors.Is(err, errTooManyTickets) {
		t.Fatalf("a ticket past the server's cap: %v, want errTooManyTickets", err)
	}
	later := t0.Add(ticketFor)
	mustIssue(t, &b, "alice", "tok", "s1", "slug", later)
	if len(b.m) != 1 || b.perUser["alice"] != 1 || len(b.perUser) != 1 {
		t.Fatalf("after the sweep: %d tickets, counts %v", len(b.m), b.perUser)
	}
}

// issue walks the book for expired tickets at most once a second.
func TestTicketSweepsAtMostOnceASecond(t *testing.T) {
	var b ticketBook
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	mustIssue(t, &b, "alice", "tok", "s1", "a", t0)
	mustIssue(t, &b, "alice", "tok", "s1", "b", t0.Add(ticketFor-500*time.Millisecond))
	// The first ticket has run out, but the last sweep was 600 ms ago.
	mustIssue(t, &b, "alice", "tok", "s1", "c", t0.Add(ticketFor+100*time.Millisecond))
	if len(b.m) != 3 {
		t.Fatalf("%d tickets, want the expired one kept until the next sweep", len(b.m))
	}
	mustIssue(t, &b, "alice", "tok", "s1", "d", t0.Add(ticketFor+500*time.Millisecond))
	if len(b.m) != 3 || b.perUser["alice"] != 3 {
		t.Fatalf("%d tickets (count %d), want the expired one swept", len(b.m), b.perUser["alice"])
	}
}

func TestTicketMintingCappedPerAccount(t *testing.T) {
	h := newTestAPI(t)
	id, slug := inboxWithFile(t, h)
	for i := 0; i < ticketsPerUser; i++ {
		ticketURL(t, h, testToken, id, slug)
	}
	rec := doReq(t, h, "POST", "/api/shares/"+id+"/download-ticket", testToken, `{"slug":"`+slug+`"}`)
	if rec.Code != 429 || errCode(t, rec.Body.String()) != "too-many-tickets" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a ticket past the cap: %d %s, want 429 too-many-tickets with Retry-After", rec.Code, rec.Body)
	}
}

// A ticket is spendable only while the device token that asked for it is
// signed in.
func TestTicketDiesWithItsDeviceToken(t *testing.T) {
	h, hd := newTestAPIParts(t)
	id, slug := inboxWithFile(t, h)
	u := ticketURL(t, h, testToken, id, slug)
	if err := hd.db.RevokeToken(metadb.DefaultAdminName, tokenIDOf(t, hd, testToken)); err != nil {
		t.Fatal(err)
	}
	if got := doReq(t, h, "GET", u, "", ""); got.Code != 404 {
		t.Fatalf("a ticket after its token was revoked = %d, want 404", got.Code)
	}
}

// webTicketPath asks for a download ticket with the web session cookie and
// returns the answered URL's path and query.
func webTicketPath(t *testing.T, f webFixture, cookie, id, slug string) string {
	t.Helper()
	rec := f.req(t, "POST", "/api/shares/"+id+"/download-ticket", cookie, `{"slug":"`+slug+`"}`)
	if rec.Code != 200 {
		t.Fatalf("download-ticket = %d %s", rec.Code, rec.Body)
	}
	var out struct{ URL string }
	unmarshal(t, rec, &out)
	i := strings.Index(out.URL, "/download/")
	if i < 0 {
		t.Fatalf("ticket url = %q", out.URL)
	}
	return out.URL[i:]
}

// A ticket a web session asked for is spendable only while that session is
// signed in and the web client is on: signing out, a password change and
// the switch each leave it unspendable.
func TestTicketDiesWithItsWebSession(t *testing.T) {
	f := newWebFixture(t, false)
	rec := doReq(t, f.h, "POST", "/api/shares", f.aliceDevice, `{"name":"a","password":"pw"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	var cr struct{ ID string }
	unmarshal(t, rec, &cr)
	slug := uploadGetSlugAs(t, f.h, f.aliceDevice, cr.ID, "a.txt", "alice data")
	served := func(path string) bool { return doReq(t, f.h, "GET", path, "", "").Body.String() == "alice data" }

	session := f.signIn(t, false)
	if !served(webTicketPath(t, f, session, cr.ID, slug)) {
		t.Fatal("a live session's ticket did not download the file")
	}

	signedOut := webTicketPath(t, f, session, cr.ID, slug)
	if rec := f.req(t, "DELETE", "/api/web/session", session, ""); rec.Code != 204 {
		t.Fatalf("sign out: %d", rec.Code)
	}
	if served(signedOut) {
		t.Fatal("a ticket after sign out downloaded the file")
	}

	session = f.signIn(t, false)
	changed := webTicketPath(t, f, session, cr.ID, slug)
	if rec := f.req(t, "PATCH", "/api/me/password", session, `{"password":"alice-new-password-2","currentPassword":"alice-pw"}`); rec.Code != 200 {
		t.Fatalf("password change: %d %s", rec.Code, rec.Body)
	} else {
		session = webCookieOf(t, rec)
	}
	if served(changed) {
		t.Fatal("a ticket after a password change downloaded the file")
	}

	off := webTicketPath(t, f, session, cr.ID, slug)
	if err := f.db.SetSetting(webSwitchKey, "off"); err != nil {
		t.Fatal(err)
	}
	if served(off) {
		t.Fatal("a ticket while the web client is off downloaded the file")
	}
}

// A refused ticket is a navigation on the files origin that replaced the web
// client, so it answers a page leading back to the app origin's /app/: the
// same 404 and the same page whatever the refusal was (a spent ticket, a
// share that does not exist, a protected share), so it tells no one more
// than the refusal did.
func TestARefusedTicketAnswersAPageBackToTheApp(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id, slug := protectedShareWithFile(t, h)
	other, _ := protectedShareWithFile(t, h)
	u := ticketURL(t, h, testToken, id, slug)
	if got := req(t, h, "GET", "files.share.example.com", u); got.Code != 200 {
		t.Fatalf("first use = %d", got.Code)
	}
	spent := req(t, h, "GET", "files.share.example.com", u)
	if spent.Code != 404 {
		t.Fatalf("spent ticket = %d, want 404", spent.Code)
	}
	body := spent.Body.String()
	if !strings.Contains(body, `href="https://share.example.com/app/"`) || !strings.Contains(body, "Back to HyperDrop") {
		t.Fatalf("refusal page has no link back to the app origin:\n%s", body)
	}
	if strings.Contains(body, "files.share.example.com/app") {
		t.Fatal("the link back names the files origin")
	}
	for k, want := range map[string]string{
		"Content-Type":  "text/html; charset=utf-8",
		"Cache-Control": "no-store",
	} {
		if got := spent.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if csp := spent.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "base-uri 'none'") {
		t.Errorf("Content-Security-Policy = %q, want the page policy", csp)
	}
	for name, path := range map[string]string{
		"an unknown share":     "/download/nosuchshare/" + slug + "?t=junk",
		"another share's slug": "/download/" + other + "/" + slug + "?t=junk",
		"an unknown file":      "/download/" + id + "/" + otherSlug + "?t=junk",
	} {
		got := req(t, h, "GET", "files.share.example.com", path)
		if got.Code != 404 || got.Body.String() != body {
			t.Errorf("%s: %d, the same page as a spent ticket: %v", name, got.Code, got.Body.String() == body)
		}
	}
	if got := req(t, h, "HEAD", "files.share.example.com", u); got.Code != 404 || got.Body.Len() != 0 {
		t.Errorf("HEAD = %d with %d bytes, want 404 and no body", got.Code, got.Body.Len())
	}
}

// With no domain the app and the files are one host, so the link back is
// root-relative. An inbox's refused ticket answers the same page.
func TestARefusedTicketLinksBackOnTheSameHostWithoutADomain(t *testing.T) {
	h := newTestAPI(t)
	id, slug := inboxWithFile(t, h)
	got := doReq(t, h, "GET", "/download/"+id+"/"+slug+"?t=junk", "", "")
	if got.Code != 404 || !strings.Contains(got.Body.String(), `href="/app/"`) {
		t.Fatalf("refused ticket = %d:\n%s", got.Code, got.Body)
	}
	plain := doReq(t, h, "GET", "/download/"+id+"/"+slug, "", "")
	if plain.Code != 404 || !strings.Contains(plain.Body.String(), "This link isn’t here") ||
		strings.Contains(plain.Body.String(), "/app/") {
		t.Fatalf("anonymous inbox download = %d:\n%s", plain.Code, plain.Body)
	}
}

// A download without a ticket keeps every answer of /download: the branded 404, the
// password form, the owner's bytes.
func TestADownloadWithoutATicketKeepsItsAnswers(t *testing.T) {
	h := withDomain(t, "share.example.com")
	pid, pslug := protectedShareWithFile(t, h)
	missing := req(t, h, "GET", "files.share.example.com", "/download/nosuchshare/"+pslug)
	if missing.Code != 404 || !strings.Contains(missing.Body.String(), "This link isn’t here") ||
		strings.Contains(missing.Body.String(), "/app/") {
		t.Fatalf("unknown share = %d:\n%s", missing.Code, missing.Body)
	}
	form := req(t, h, "GET", "files.share.example.com", "/download/"+pid+"/"+pslug)
	if form.Code != 200 || !strings.Contains(form.Body.String(), `type="password"`) {
		t.Fatalf("protected download = %d, want the password form:\n%s", form.Code, form.Body)
	}
	r := httptest.NewRequest("GET", "/download/"+pid+"/"+pslug, nil)
	r.Host = "files.share.example.com"
	r.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 || rec.Body.String() != "data" {
		t.Fatalf("owner's bearer download = %d %q", rec.Code, rec.Body)
	}
}

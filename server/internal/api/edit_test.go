package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/housekeep"
	"hyperdrop/server/internal/metadb"
)

func patchShare(t *testing.T, h http.Handler, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doReq(t, h, "PATCH", "/api/shares/"+id, testToken, body)
}

type patchResp struct {
	ID          string `json:"id"`
	HasPassword bool   `json:"hasPassword"`
	ExpiresAt   *time.Time
	Pending     []struct {
		Kind    string    `json:"kind"`
		ApplyAt time.Time `json:"applyAt"`
		Clear   bool      `json:"clear"`
	} `json:"pending"`
}

// decodePatch decodes into a FRESH struct: omitempty fields would
// otherwise keep stale values when reusing one across responses.
func decodePatch(t *testing.T, rec *httptest.ResponseRecorder) patchResp {
	t.Helper()
	var r patchResp
	unmarshal(t, rec, &r)
	return r
}

func TestPatchSetAndRemovePassword(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")

	rec := patchShare(t, h, id, `{"password":"secret"}`)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	resp := decodePatch(t, rec)
	if !resp.HasPassword {
		t.Fatal("hasPassword should be true after set")
	}

	rec = patchShare(t, h, id, `{"password":""}`)
	resp = decodePatch(t, rec)
	if resp.HasPassword {
		t.Fatal("hasPassword should be false after removal")
	}
}

func TestPatchSetAndRemoveExpiry(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")

	rec := patchShare(t, h, id, `{"expiresInSeconds":3600}`)
	resp := decodePatch(t, rec)
	if resp.ExpiresAt == nil {
		t.Fatal("expiresAt not set")
	}

	rec = patchShare(t, h, id, `{"expiresInSeconds":0}`)
	resp = decodePatch(t, rec)
	if resp.ExpiresAt != nil {
		t.Fatalf("expiresAt = %v, want cleared", resp.ExpiresAt)
	}
}

func TestPatchScheduledChange(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "x")

	rec := patchShare(t, h, id, `{"password":"secret","applyInSeconds":3600}`)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	resp := decodePatch(t, rec)
	if resp.HasPassword {
		t.Fatal("password must not apply before its time")
	}
	if len(resp.Pending) != 1 || resp.Pending[0].Kind != "password" || resp.Pending[0].Clear {
		t.Fatalf("pending = %+v", resp.Pending)
	}

	// Force the action due (the schedule-time hash is preserved), then let
	// housekeeping apply it and read the share back.
	if _, err := b.DB.Schedule(id, metadb.Scheduled{Kind: metadb.ScheduledPassword,
		ApplyAt: time.Now().Add(-time.Second), PasswordHash: mustPendingHash(t, b, id)}); err != nil {
		t.Fatal(err)
	}
	pass := housekeep.Pass{DB: b.DB, FS: b.FS}
	if res := pass.Run(); res.Due != 1 {
		t.Fatalf("housekeeping applied %d due changes, want 1", res.Due)
	}
	rec = doReq(t, h, "GET", "/api/shares", testToken, "")
	var list struct {
		Shares []patchResp `json:"shares"`
	}
	unmarshal(t, rec, &list)
	if len(list.Shares) != 1 || !list.Shares[0].HasPassword || len(list.Shares[0].Pending) != 0 {
		t.Fatalf("due schedule not applied: %+v", list.Shares)
	}
}

// mustPendingHash digs the scheduled bcrypt hash back out so the test can
// re-schedule it in the past without knowing bcrypt internals.
func mustPendingHash(t *testing.T, b Backend, id string) string {
	t.Helper()
	d, err := b.DB.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d.Scheduled {
		if p.Kind == metadb.ScheduledPassword {
			return p.PasswordHash
		}
	}
	t.Fatal("no scheduled password change")
	return ""
}

func TestPatchScheduledExpiryStartsAtApply(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")

	rec := patchShare(t, h, id, `{"expiresInSeconds":3600,"applyInSeconds":600}`)
	resp := decodePatch(t, rec)
	if resp.ExpiresAt != nil {
		t.Fatal("expiry must not be live yet")
	}
	if len(resp.Pending) != 1 || resp.Pending[0].Kind != "expiry" {
		t.Fatalf("pending = %+v", resp.Pending)
	}
	// applyAt ≈ now+600s (the stored ExpiresAt = applyAt+3600 is internal).
	wantApply := time.Now().Add(600 * time.Second)
	if d := resp.Pending[0].ApplyAt.Sub(wantApply); d < -5*time.Second || d > 5*time.Second {
		t.Fatalf("applyAt = %v, want ≈ %v", resp.Pending[0].ApplyAt, wantApply)
	}
}

func TestPatchCancelPending(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	patchShare(t, h, id, `{"password":"p","applyInSeconds":3600}`)
	patchShare(t, h, id, `{"expiresInSeconds":60,"applyInSeconds":3600}`)

	rec := patchShare(t, h, id, `{"cancelPending":"password"}`)
	resp := decodePatch(t, rec)
	if len(resp.Pending) != 1 || resp.Pending[0].Kind != "expiry" {
		t.Fatalf("pending = %+v, want only expiry", resp.Pending)
	}

	rec = patchShare(t, h, id, `{"cancelPending":"all"}`)
	resp = decodePatch(t, rec)
	if len(resp.Pending) != 0 {
		t.Fatalf("pending = %+v, want none", resp.Pending)
	}
}

func TestPatchValidation(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	for body, want := range map[string]int{
		``:                                     400,
		`{}`:                                   400,
		`{"cancelPending":"bogus"}`:            400,
		`{"expiresInSeconds":-5}`:              400,
		`{"password":"x","applyInSeconds":-1}`: 400,
	} {
		if rec := patchShare(t, h, id, body); rec.Code != want {
			t.Errorf("body %q: status = %d, want %d (%s)", body, rec.Code, want, rec.Body)
		}
	}
	if rec := patchShare(t, h, "missing123", `{"password":"x"}`); rec.Code != 404 {
		t.Errorf("missing share: status = %d, want 404", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, "", `{"password":"x"}`); rec.Code != 401 {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
}

func TestPasswordChangeRevokesCookies(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"x","password":"first"}`)
	var created struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &created)
	id := created.ID
	doReq(t, h, "PUT", "/api/shares/"+id+"/files/a.txt", testToken, "hello")

	// Unlock with the password → cookie.
	rec = doReqForm(t, h, "POST", "/unlock/"+id, "password=first&next=/share/"+id)
	if rec.Code != 303 {
		t.Fatalf("unlock status = %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no access cookie set")
	}

	withCookie := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/share/"+id, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	// A single-file share listing 302s to the file when access is granted.
	if w := withCookie(); w.Code != 302 {
		t.Fatalf("cookie should grant access (302 to the file): %d %s", w.Code, w.Body)
	}

	// Change the password → old cookie must stop working.
	patchShare(t, h, id, `{"password":"second"}`)
	if w := withCookie(); w.Code != 200 || !strings.Contains(w.Body.String(), "password-protected") {
		t.Fatalf("old cookie survived a password change: %d", w.Code)
	}
}

func TestUploadReplaces(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "x")
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/report-v1.pdf", testToken, "old bytes")
	var up struct {
		Slug string `json:"slug"`
	}
	unmarshal(t, rec, &up)
	oldSlug := up.Slug

	rec = doReq(t, h, "PUT", "/api/shares/"+id+"/files/report-final.pdf?replaces=report-v1.pdf", testToken, "new bytes")
	if rec.Code != 201 {
		t.Fatalf("replace upload status = %d body %s", rec.Code, rec.Body)
	}
	unmarshal(t, rec, &up)
	if up.Slug != oldSlug {
		t.Fatalf("slug = %s, want inherited %s", up.Slug, oldSlug)
	}

	// The old public link now serves the new content under the new name.
	w := doReq(t, h, "GET", "/download/"+id+"/"+oldSlug, "", "")
	if w.Code != 200 || w.Body.String() != "new bytes" {
		t.Fatalf("old link: %d %q", w.Code, w.Body)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "report-final.pdf") {
		t.Fatalf("Content-Disposition = %q, want the new name", cd)
	}

	// Ghost target → 400.
	rec = doReq(t, h, "PUT", "/api/shares/"+id+"/files/other.txt?replaces=ghost.txt", testToken, "x")
	if rec.Code != 400 {
		t.Fatalf("ghost replaces: status = %d, want 400", rec.Code)
	}
}

func TestPatchRenamesTheShare(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "3 files")

	rec := patchShare(t, h, id, `{"name":"Q3 Financials"}`)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Name string `json:"name"`
	}
	unmarshal(t, rec, &out)
	if out.Name != "Q3 Financials" {
		t.Errorf("name = %q, want %q", out.Name, "Q3 Financials")
	}
}

func TestPatchRefusesANameThatWouldBreakAMountFolder(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "3 files")

	for _, body := range []string{
		`{"name":""}`,
		`{"name":"   "}`,
		`{"name":"a/b"}`,
	} {
		if rec := patchShare(t, h, id, body); rec.Code != 400 {
			t.Errorf("PATCH %s = %d, want 400", body, rec.Code)
		}
	}
}

// A name has no "let it lapse later" story, so it is never scheduled: it
// lands now even when the password change beside it is scheduled for later.
func TestARenameAppliesNowEvenAlongsideAScheduledChange(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "3 files")

	rec := patchShare(t, h, id, `{"name":"Q3 Financials","password":"secret","applyInSeconds":3600}`)
	if rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Name    string `json:"name"`
		Pending []struct {
			Kind string `json:"kind"`
		} `json:"pending"`
	}
	unmarshal(t, rec, &out)
	if out.Name != "Q3 Financials" {
		t.Errorf("name = %q, want it applied immediately", out.Name)
	}
	if len(out.Pending) != 1 {
		t.Errorf("pending = %d actions, want the password change still scheduled", len(out.Pending))
	}
}

// The index row carries the name that ?q= searches, and the change hook is
// what tells the Finder mount to re-read a listing. A rename that updated
// neither would be invisible until a restart.
func TestARenameIsVisibleToSearchAndWakesTheWatcher(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "3 files")

	woken, stop := b.DB.Subscribe()
	defer stop()

	if rec := patchShare(t, h, id, `{"name":"Zebra Financials"}`); rec.Code != 200 {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	select {
	case <-woken:
	default:
		t.Error("a rename did not wake the change watcher")
	}

	page, err := b.DB.List(metadb.ListQuery{Owner: metadb.DefaultAdminName, Name: "zebra", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Shares) != 1 || page.Shares[0].ID != id {
		t.Errorf("Name=zebra found %d rows (total %d), want the renamed share", len(page.Shares), page.Total)
	}
}

package api

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

// statusOut mirrors the status poll's answer for these tests.
type statusOut struct {
	Complete  bool `json:"complete"`
	Preparing int  `json:"preparing"`
	File      *struct {
		Complete  bool `json:"complete"`
		Preparing *struct {
			Stage    string  `json:"stage"`
			Fraction float64 `json:"fraction"`
		} `json:"preparing"`
	} `json:"file"`
}

// declaredShare creates a share whose one file a.mp4 is declared and not yet
// uploaded, answering the share id and the file's slug.
func declaredShare(t *testing.T, h http.Handler, size int) (id, slug string) {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"clip","files":[{"path":"a.mp4","size":`+strconv.Itoa(size)+`}]}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created shareResp
	unmarshal(t, rec, &created)
	return created.ID, created.Files[0].Slug
}

func report(t *testing.T, h http.Handler, token, id, rel, body string) int {
	t.Helper()
	return doReq(t, h, "PUT", "/api/shares/"+id+"/preparing/"+rel, token, body).Code
}

func pollStatus(t *testing.T, h http.Handler, id, slug string) statusOut {
	t.Helper()
	rec := doReq(t, h, "GET", "/share/"+id+"/status?slug="+slug, "", "")
	if rec.Code != 200 {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	var st statusOut
	unmarshal(t, rec, &st)
	return st
}

func TestPreparingReportRidesTheStatusPoll(t *testing.T) {
	h := newTestAPI(t)
	id, slug := declaredShare(t, h, 5)
	if code := report(t, h, testToken, id, "a.mp4", `{"fraction":0.75,"stage":"encoding"}`); code != 204 {
		t.Fatalf("report: %d", code)
	}
	st := pollStatus(t, h, id, slug)
	if st.Preparing != 1 || st.File == nil || st.File.Preparing == nil {
		t.Fatalf("status without the report: %+v", st)
	}
	if st.File.Preparing.Stage != "encoding" || st.File.Preparing.Fraction != 0.75 {
		t.Fatalf("report relayed wrong: %+v", st.File.Preparing)
	}
	uploadFile(t, h, testToken, id, "a.mp4", "hello")
	st = pollStatus(t, h, id, slug)
	if st.Preparing != 0 || st.File == nil || st.File.Preparing != nil || !st.File.Complete {
		t.Fatalf("a committed file still carries a report: %+v", st)
	}
}

func TestPreparingRefusals(t *testing.T) {
	h, hd := newTestAPIParts(t)
	id, _ := declaredShare(t, h, 5)
	uploadFile(t, h, testToken, id, "done.txt", "x")
	cases := []struct {
		name, token, rel, body string
		want                   int
	}{
		{"committed path", testToken, "done.txt", `{"fraction":0.5,"stage":"encoding"}`, 404},
		{"unknown path", testToken, "nope.mp4", `{"fraction":0.5,"stage":"encoding"}`, 404},
		{"bad relpath", testToken, "%2e%2e/x", `{"fraction":0.5,"stage":"encoding"}`, 400},
		{"fraction over one", testToken, "a.mp4", `{"fraction":1.5,"stage":"encoding"}`, 400},
		{"negative fraction", testToken, "a.mp4", `{"fraction":-0.1,"stage":"encoding"}`, 400},
		{"unknown stage", testToken, "a.mp4", `{"fraction":0.5,"stage":"x"}`, 400},
		{"not JSON", testToken, "a.mp4", `{`, 400},
		{"another account", seedUser(t, hd.db, "bob"), "a.mp4", `{"fraction":0.5,"stage":"encoding"}`, 404},
	}
	for _, c := range cases {
		if got := report(t, h, c.token, id, c.rel, c.body); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	if hd.prep.fresh(id) != 0 {
		t.Fatal("a refused report was recorded")
	}
	if code := report(t, h, testToken, id, "a.mp4", `{"fraction":0,"stage":"remuxing"}`); code != 204 {
		t.Fatalf("a valid remuxing report: %d", code)
	}
}

func TestStalePreparingIsNotShownButKeepsTheShareAlive(t *testing.T) {
	h, hd := newTestAPIParts(t)
	now := time.Now()
	hd.prep.now = func() time.Time { return now }
	id, slug := declaredShare(t, h, 5)
	if code := report(t, h, testToken, id, "a.mp4", `{"fraction":0.2,"stage":"encoding"}`); code != 204 {
		t.Fatalf("report: %d", code)
	}
	reported := now
	now = now.Add(preparingStale + time.Minute)
	st := pollStatus(t, h, id, slug)
	if st.Preparing != 0 || st.File.Preparing != nil {
		t.Fatalf("a stale report is still shown: %+v", st)
	}
	if !hd.prep.ReportedSince(id, reported.Add(-time.Hour)) {
		t.Fatal("the stale report no longer counts as liveness")
	}
	if hd.prep.ReportedSince(id, reported) {
		t.Fatal("a report counts as newer than itself")
	}
}

func TestDeletingTheShareOrTheFileDropsItsReports(t *testing.T) {
	h, hd := newTestAPIParts(t)
	id, _ := declaredShare(t, h, 5)
	if code := report(t, h, testToken, id, "a.mp4", `{"fraction":0.5,"stage":"encoding"}`); code != 204 {
		t.Fatalf("report: %d", code)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id+"/files/a.mp4", testToken, ""); rec.Code != 200 {
		t.Fatalf("delete file: %d %s", rec.Code, rec.Body)
	}
	if hd.prep.ReportedSince(id, time.Time{}) {
		t.Fatal("a deleted file's report survived")
	}

	id2, _ := declaredShare(t, h, 5)
	if code := report(t, h, testToken, id2, "a.mp4", `{"fraction":0.5,"stage":"encoding"}`); code != 204 {
		t.Fatalf("report: %d", code)
	}
	if rec := doReq(t, h, "DELETE", "/api/shares/"+id2, testToken, ""); rec.Code != 204 {
		t.Fatalf("delete share: %d %s", rec.Code, rec.Body)
	}
	if hd.prep.ReportedSince(id2, time.Time{}) {
		t.Fatal("a deleted share's reports survived")
	}
}

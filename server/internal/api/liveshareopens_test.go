package api

import (
	"strings"
	"testing"
)

// What a share's View link opens is ONE question, refused on the RESULTING
// state of a PATCH. A live share that already opens its file listing and is
// then asked to become a gallery is being given two answers, exactly as an
// ordinary share would be, and owes the same 400.
func TestALiveShareRefusesASecondAnswerAgainstItsStoredState(t *testing.T) {
	h := newTestLiveShareHandler(t)
	api := h.routes()

	sh := createLiveShare(t, api, testToken, `{"name":"pics","files":[
		{"path":"a.jpg","size":3,"mime":"image/jpeg"}]}`)
	id := sh.ID

	// Becomes a file listing. One answer, accepted.
	if rec := doReq(t, api, "PATCH", "/api/live-share/"+id, testToken, `{"listing":true}`); rec.Code != 200 {
		t.Fatalf("listing:true = %d %s", rec.Code, rec.Body.String())
	}
	// Now asked to ALSO be a gallery, without unsetting listing. The resulting
	// state answers the question twice.
	rec := doReq(t, api, "PATCH", "/api/live-share/"+id, testToken, `{"media":true}`)
	if rec.Code != 400 {
		t.Fatalf("listing + media = %d %s, want 400: a gallery is not a file listing",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "file listing") {
		t.Errorf("refusal should name the collision, got %s", rec.Body.String())
	}
	// Answering it once, by sending both fields together, is still fine: that
	// is what every surface does.
	if rec := doReq(t, api, "PATCH", "/api/live-share/"+id, testToken,
		`{"listing":false,"media":true}`); rec.Code != 200 {
		t.Fatalf("listing:false + media:true = %d %s", rec.Code, rec.Body.String())
	}
}

package dsmpage

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSaveAndRescueWaitForAMoveToFinish(t *testing.T) {
	cases := map[string]string{
		"stopped":           `{"state":"stopped-for-move","reason":"","at":1,"job":"stop-for-move"}`,
		"interrupted":       `{"state":"applying","reason":"","at":1,"job":"stop-for-move"}`,
		"failed start":      `{"state":"failed","reason":"The HyperDrop folder is locked or missing. Unlock it in Control Panel, Shared Folder.","at":1,"job":"start"}`,
		"interrupted start": `{"state":"applying","reason":"","at":1,"job":"start"}`,
	}
	for name, last := range cases {
		t.Run(name, func(t *testing.T) {
			r := newSaveRig(t, freeConf)
			r.write("var/last-change.json", last+"\n")
			for _, path := range []string{"/api/settings", "/api/rescue"} {
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
				req.Header.Set("X-SYNO-TOKEN", "tok")
				w := httptest.NewRecorder()
				New(r.deps).ServeHTTP(w, req)
				if w.Code != http.StatusConflict || errorText(t, w) != finishMoveText {
					t.Fatalf("%s: %d %s", path, w.Code, w.Body)
				}
			}
			if len(r.workers) != 0 {
				t.Fatal("a refused request started a worker")
			}
			if rep := r.get().LastChange; rep == nil || !rep.HoldsMove {
				t.Fatalf("%+v", rep)
			}
		})
	}
}

func TestASuccessfulStartAllowsSaveAndRescueAgain(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.write("var/last-change.json", `{"state":"done","reason":"","at":1,"job":"start"}`+"\n")
	for _, path := range []string{"/api/settings", "/api/rescue"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		req.Header.Set("X-SYNO-TOKEN", "tok")
		w := httptest.NewRecorder()
		New(r.deps).ServeHTTP(w, req)
		if w.Code == http.StatusConflict {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
}

func TestAFailedStopOrAFinishedMoveHoldsNothing(t *testing.T) {
	for _, last := range []string{
		`{"state":"failed","reason":"HyperDrop could not be stopped, so nothing was changed.","at":1,"job":"stop-for-move"}`,
		`{"state":"done","reason":"","at":1,"job":"start"}`,
	} {
		r := newSaveRig(t, freeConf)
		r.write("var/last-change.json", last+"\n")
		if rep := r.get().LastChange; rep == nil || rep.HoldsMove {
			t.Fatalf("%s: %+v", last, rep)
		}
	}
}

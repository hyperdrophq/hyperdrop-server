package dsmpage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (r *saveRig) storage(method, path string) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	req.Header.Set("X-SYNO-TOKEN", "tok")
	w := httptest.NewRecorder()
	New(r.deps).ServeHTTP(w, req)
	return w
}

// onVolume1 points the shared folder's link at a folder under a volume1
// directory, as DSM keeps shared folders, and answers the resolved path.
func (r *saveRig) onVolume1() string {
	r.t.Helper()
	dir := filepath.Join(r.root, "volume1", "hyperdrop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	link := filepath.Join(r.root, "shares", "hyperdrop")
	os.Remove(link)
	if err := os.Symlink(dir, link); err != nil {
		r.t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		r.t.Fatal(err)
	}
	return resolved
}

func decodeMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	return m
}

func TestStorageNamesTheFolderItsVolumeAndTheFreeSpace(t *testing.T) {
	r := newSaveRig(t, freeConf)
	want := r.onVolume1()
	w := r.storage(http.MethodGet, "/api/storage")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	m := decodeMap(t, w)
	if m["folder"] != "hyperdrop" || m["path"] != want || m["volume"] != "/volume1" || m["available"] != true || m["locked"] != nil {
		t.Fatalf("%v", m)
	}
	if free, ok := m["freeBytes"].(float64); !ok || free <= 0 {
		t.Fatalf("freeBytes %v", m["freeBytes"])
	}
}

func TestStorageOfALockedFolderSaysSo(t *testing.T) {
	r := newSaveRig(t, freeConf)
	os.Remove(filepath.Join(r.root, "shares", "hyperdrop"))
	m := decodeMap(t, r.storage(http.MethodGet, "/api/storage"))
	if m["folder"] != "hyperdrop" || m["available"] != true || m["locked"] != true || m["text"] != lockedText || m["path"] != nil || m["freeBytes"] != nil {
		t.Fatalf("%v", m)
	}
}

func TestStorageIsUnavailableWithoutASharedFolder(t *testing.T) {
	r := newSaveRig(t, "HYPERDROP_DOMAIN=\nHYPERDROP_DDNS_NAME=alice\nHYPERDROP_HTTP_ADDR=:8080\nHYPERDROP_HTTPS_ADDR=:8443\n")
	if got := strings.TrimSpace(r.storage(http.MethodGet, "/api/storage").Body.String()); got != `{"available":false}` {
		t.Fatal(got)
	}
}

func TestTheMoveRouteIsGone(t *testing.T) {
	r := newSaveRig(t, freeConf)
	if w := r.storage(http.MethodPost, "/api/storage/move"); w.Code != http.StatusNotFound {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// DSM stops the package for a move (the page asks it to, with the
// administrator's own session); the CGI only records the hold.
func TestStoppingForAMoveRecordsTheHoldAndTouchesNoService(t *testing.T) {
	r := newSaveRig(t, freeConf)
	w := r.storage(http.MethodPost, "/api/storage/stop")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if m := decodeMap(t, w); m["state"] != "stopped-for-move" {
		t.Fatalf("%v", m)
	}
	if len(r.workers) != 0 || len(r.svc.calls) != 0 {
		t.Fatalf("workers %v calls %v", r.workers, r.svc.calls)
	}
	if c := r.lastChange(); c.State != "stopped-for-move" || c.Job != "stop-for-move" || c.Reason != "" || c.At == 0 {
		t.Fatalf("%+v", c)
	}
	rep := r.get().LastChange
	if rep == nil || rep.State != "stopped-for-move" || rep.Text != "HyperDrop is stopped for a move." || !rep.HoldsMove {
		t.Fatalf("%+v", rep)
	}
	if lockHeld(filepath.Join(r.root, "var", ".dsmpage.lock")) {
		t.Fatal("the stop left the lock held")
	}
}

func TestADSMStopThatLeftHyperDropRunningClearsTheHold(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.deps.Service = r.svc
	if w := r.storage(http.MethodPost, "/api/storage/stop"); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w := r.storage(http.MethodPost, "/api/storage/stop-failed")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if m := decodeMap(t, w); m["state"] != "failed" {
		t.Fatalf("%v", m)
	}
	if c := r.lastChange(); c.State != "failed" || c.Reason != notStoppedText || c.Job != "stop-for-move" {
		t.Fatalf("%+v", c)
	}
	if rep := r.get().LastChange; rep == nil || rep.HoldsMove {
		t.Fatalf("%+v", rep)
	}
	if len(r.workers) != 0 || len(r.svc.calls) != 0 {
		t.Fatalf("workers %v calls %v", r.workers, r.svc.calls)
	}
}

// A stop DSM did not confirm (no answer, an unreadable one) may still have
// happened: with no server running the hold stays, so nothing starts
// HyperDrop in the middle of a move.
func TestAStopFailureWithNoServerRunningKeepsTheHold(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.deps.Service = r.svc
	r.svc.running, r.svc.healthy = false, false
	if w := r.storage(http.MethodPost, "/api/storage/stop"); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w := r.storage(http.MethodPost, "/api/storage/stop-failed")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if m := decodeMap(t, w); m["state"] != "stopped-for-move" {
		t.Fatalf("%v", m)
	}
	if c := r.lastChange(); c.State != "stopped-for-move" || c.Job != "stop-for-move" {
		t.Fatalf("%+v", c)
	}
	if rep := r.get().LastChange; rep == nil || !rep.HoldsMove {
		t.Fatalf("%+v", rep)
	}
	if len(r.workers) != 0 || len(r.svc.calls) != 0 {
		t.Fatalf("workers %v calls %v", r.workers, r.svc.calls)
	}
}

func TestAStopFailureWithoutAHoldChangesNothing(t *testing.T) {
	for _, last := range []string{
		`{"state":"done","reason":"","at":1,"job":"start"}`,
		`{"state":"failed","reason":"The HyperDrop folder is locked or missing. Unlock it in Control Panel, Shared Folder.","at":1,"job":"start"}`,
		`{"state":"done","reason":"","at":1}`,
	} {
		r := newSaveRig(t, freeConf)
		r.write("var/last-change.json", last+"\n")
		if w := r.storage(http.MethodPost, "/api/storage/stop-failed"); w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", last, w.Code, w.Body)
		}
		if got := r.read("var/last-change.json"); got != last+"\n" {
			t.Fatalf("%s: rewritten as %s", last, got)
		}
	}
}

// The page has DSM start the package, which refreshes DSM's link to the
// moved folder; the worker only waits for HyperDrop as a Save does.
func TestStartingAfterAMoveWaitsForHyperDropWithoutStartingIt(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.write("var/last-change.json", `{"state":"stopped-for-move","reason":"","at":1700000000,"job":"stop-for-move"}`+"\n")
	w := r.storage(http.MethodPost, "/api/storage/start")
	if w.Code != http.StatusAccepted || len(r.workers) != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if c := r.lastChange(); c.State != "applying" || c.Job != "start" {
		t.Fatalf("%+v", c)
	}
	r.lock.Close()
	res := r.page().apply(r.workers[0], r.svc, r.clk)
	if res.State != "done" || res.Job != "start" || res.Text() != "HyperDrop is running again." {
		t.Fatalf("%+v", res)
	}
	if len(r.svc.calls) != 0 || r.svc.checks == 0 {
		t.Fatalf("calls %v checks %d", r.svc.calls, r.svc.checks)
	}
	if rep := r.get().LastChange; rep == nil || rep.HoldsMove {
		t.Fatalf("%+v", rep)
	}
}

func TestStartingAfterAMoveReportsTheStartScriptsReason(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.write("var/last-change.json", `{"state":"stopped-for-move","reason":"","at":1700000000,"job":"stop-for-move"}`+"\n")
	r.status(`{"lastError":"` + lockedText + `","at":1700000500}`)
	r.svc.running, r.svc.healthy = false, false
	if w := r.storage(http.MethodPost, "/api/storage/start"); w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	r.lock.Close()
	res := r.page().apply(r.workers[0], r.svc, r.clk)
	if res.State != "failed" || res.Reason != lockedText || res.Job != "start" || len(r.svc.calls) != 0 {
		t.Fatalf("%+v %v", res, r.svc.calls)
	}
	if rep := r.get().LastChange; rep == nil || !rep.HoldsMove {
		t.Fatalf("%+v", rep)
	}
}

func TestStartingAfterAMoveIgnoresAReasonFromBeforeTheStop(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.write("var/last-change.json", `{"state":"stopped-for-move","reason":"","at":1700000000,"job":"stop-for-move"}`+"\n")
	r.status(`{"lastError":"Port 5443 is already in use by another app.","at":1699999000}`)
	r.svc.running, r.svc.healthy = false, false
	r.storage(http.MethodPost, "/api/storage/start")
	r.lock.Close()
	res := r.page().apply(r.workers[0], r.svc, r.clk)
	if res.State != "failed" || res.Reason != notStartedText {
		t.Fatalf("%+v", res)
	}
}

func TestStartingAfterAMoveGivesUpOnAServerThatNeverAnswers(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.svc.running, r.svc.healthy = true, false
	res := r.page().StartAfterMove(r.svc, r.clk, r.clk.Now())
	if res.State != "failed" || res.Reason != timeoutText || len(r.svc.calls) != 0 {
		t.Fatalf("%+v %v", res, r.svc.calls)
	}
}

func TestAStopForAMoveJobFileIsNotAJob(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.write("var/job.json", `{"job":"stop-for-move"}`)
	res := r.page().apply(filepath.Join(r.root, "var", "job.json"), r.svc, r.clk)
	if res.State != "failed" || res.Reason != workerText || len(r.svc.calls) != 0 {
		t.Fatalf("%+v %v", res, r.svc.calls)
	}
}

func TestStorageRoutesAnswer409WhileAChangeIsApplying(t *testing.T) {
	r := newSaveRig(t, freeConf)
	r.write("var/last-change.json", `{"state":"stopped-for-move","reason":"","at":1,"job":"stop-for-move"}`+"\n")
	lock, busy, err := takeLock(filepath.Join(r.root, "var", ".dsmpage.lock"))
	if err != nil || busy {
		t.Fatal(err, busy)
	}
	defer lock.Close()
	for _, path := range []string{"/api/storage/stop", "/api/storage/stop-failed", "/api/storage/start"} {
		w := r.storage(http.MethodPost, path)
		if w.Code != http.StatusConflict || errorText(t, w) != busyText {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	if len(r.workers) != 0 || !strings.Contains(r.read("var/last-change.json"), `"stopped-for-move"`) {
		t.Fatal("a refused request changed something")
	}
}

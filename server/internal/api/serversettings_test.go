package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type settingsDoc struct {
	AutoUpdate      bool   `json:"autoUpdate"`
	SelfUpdate      string `json:"selfUpdate"`
	UpdateAvailable bool   `json:"updateAvailable"`
}

func settingsHandler(t *testing.T, dep Deployment, updateDir bool) (*handler, string) {
	t.Helper()
	hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, dep)
	if updateDir {
		hd.dep.UpdateDir = t.TempDir()
	}
	return hd, seedUser(t, hd.db, "bob")
}

func readSettings(t *testing.T, body []byte) settingsDoc {
	t.Helper()
	var d settingsDoc
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return d
}

func TestServerSettingsAreAdminOnly(t *testing.T) {
	hd, user := settingsHandler(t, Deployment{}, false)
	h := hd.routes()
	if rec := doReq(t, h, "GET", "/api/server/settings", user, ""); rec.Code != 403 {
		t.Fatalf("a user read the settings: %d", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/server/settings", user, `{"autoUpdate":false}`); rec.Code != 403 {
		t.Fatalf("a user changed the settings: %d", rec.Code)
	}
	rec := doReq(t, h, "GET", "/api/server/settings", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if d := readSettings(t, rec.Body.Bytes()); d.SelfUpdate != "manual" || !d.AutoUpdate || d.UpdateAvailable {
		t.Fatalf("a box with no update directory and no manifest: %+v", d)
	}
}

func TestPatchTurnsAutomaticUpdatesOffAndOn(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{Releases: "https://releases.test/", Official: true}, true)
	h := hd.routes()
	rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"autoUpdate":false}`)
	if d := readSettings(t, rec.Body.Bytes()); rec.Code != 200 || d.AutoUpdate || d.SelfUpdate != "off" {
		t.Fatalf("%d %+v", rec.Code, d)
	}
	rec = doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"autoUpdate":true}`)
	if d := readSettings(t, rec.Body.Bytes()); rec.Code != 200 || !d.AutoUpdate || d.SelfUpdate != "on" {
		t.Fatalf("%d %+v", rec.Code, d)
	}
}

func TestANASCannotTurnAutoUpdateOn(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{Channel: "synology", Releases: "https://releases.test/"}, false)
	h := hd.routes()
	rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"autoUpdate":true}`)
	if rec.Code != 409 || !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var e struct{ Code, Error string }
	json.Unmarshal(rec.Body.Bytes(), &e)
	if e.Code != "self-update-unavailable" || e.Error != "this server is updated in Package Center" {
		t.Fatalf("%+v", e)
	}
	if d := readSettings(t, doReq(t, h, "GET", "/api/server/settings", testToken, "").Body.Bytes()); d.SelfUpdate != "nas" {
		t.Fatalf("%+v", d)
	}
}

// A build HyperDrop's scripts did not make reads the manifest but never
// installs on its own, so the switch is refused with the reason, as on a box
// that cannot stage a release. Update Server (POST /api/server/update) is
// gated on the update directory alone and serves it like any build.
func TestAnUnofficialBuildCannotTurnAutoUpdateOn(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{Releases: "https://releases.test/"}, true)
	h := hd.routes()
	rec := doReq(t, h, "PATCH", "/api/server/settings", testToken, `{"autoUpdate":true}`)
	var e struct{ Code, Error string }
	json.Unmarshal(rec.Body.Bytes(), &e)
	if rec.Code != 409 || e.Code != "self-update-unavailable" || !strings.Contains(e.Error, "not an official HyperDrop build") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if d := readSettings(t, doReq(t, h, "GET", "/api/server/settings", testToken, "").Body.Bytes()); d.SelfUpdate != "manual" {
		t.Fatalf("%+v", d)
	}
}

func TestPatchRefusesABodyWithoutTheSwitch(t *testing.T) {
	hd, _ := settingsHandler(t, Deployment{Releases: "https://releases.test/", Official: true}, true)
	for _, body := range []string{`{}`, `{"autoUpdate":"yes"}`, `nope`} {
		if rec := doReq(t, hd.routes(), "PATCH", "/api/server/settings", testToken, body); rec.Code != 400 {
			t.Errorf("%s: %d", body, rec.Code)
		}
	}
}

// A manual Update Server and the self-updater share one part file, so
// staging is serialized: concurrent stagings each land a complete,
// verifying pair.
func TestConcurrentStagingsDoNotInterleave(t *testing.T) {
	_, dir := updateAPI(t)
	h := newHandler(testBackend(t), "9.9.9", testDomain(t), nil, Deployment{})
	h.dep.UpdateDir = dir
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := elfBody(1<<20 + i)
			errs[i] = h.stageRelease(body, testSignature(testReleaseKey, "9.9.9", runtime.GOARCH, body))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("staging %d: %v", i, err)
		}
	}
	sig, err := os.ReadFile(filepath.Join(dir, stagedSigName))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStaged(filepath.Join(dir, stagedName), sig, "9.9.9"); err != nil {
		t.Fatalf("the staged pair does not verify: %v", err)
	}
}

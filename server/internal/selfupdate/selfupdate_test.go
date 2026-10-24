package selfupdate

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/core/updatenotice"
)

var releaseKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
var otherKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))

// signature is a signature file in core/serversig's format.
func signature(key ed25519.PrivateKey, version, arch string, raw []byte) []byte {
	sum := sha256.Sum256(raw)
	st := "hyperdrop-server-signature 3\nversion " + version + "\narch " + arch + "\nsha256 " + hex.EncodeToString(sum[:]) + "\n"
	return []byte(st + "signature " + base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(st))) + "\n")
}

type memStore struct {
	mu sync.Mutex
	m  map[string]string
	// refuse makes every SetSetting fail, as a full or read-only disk does.
	refuse bool
}

func (s *memStore) Setting(k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}
func (s *memStore) SetSetting(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refuse {
		return errors.New("disk full")
	}
	s.m[k] = v
	return nil
}
func (s *memStore) DeleteSetting(k string) error {
	s.mu.Lock()
	delete(s.m, k)
	s.mu.Unlock()
	return nil
}

// site is the website's downloads/server directory.
type site struct {
	mu      sync.Mutex
	entries []map[string]any
	files   map[string][]byte
	down    map[string]bool // paths that answer 500
	hits    []string
}

func (s *site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := strings.TrimPrefix(r.URL.Path, "/")
	s.hits = append(s.hits, name)
	if s.down[name] || s.down["*"] {
		w.WriteHeader(500)
		return
	}
	if name == "releases.json" {
		json.NewEncoder(w).Encode(map[string]any{"releases": s.entries})
		return
	}
	b, ok := s.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(b)
}

// lockedHits answers the paths fetched so far.
func (s *site) lockedHits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...)
}

// resetHits forgets the paths fetched so far.
func (s *site) resetHits() {
	s.mu.Lock()
	s.hits = nil
	s.mu.Unlock()
}

// setFile replaces a published file.
func (s *site) setFile(name string, b []byte) {
	s.mu.Lock()
	s.files[name] = b
	s.mu.Unlock()
}

// file answers a published file.
func (s *site) file(name string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.files[name]...)
}

// setDown makes a path answer 500 ("*": every path).
func (s *site) setDown(name string) {
	s.mu.Lock()
	s.down[name] = true
	s.mu.Unlock()
}

type rig struct {
	t        *testing.T
	site     *site
	srv      *httptest.Server
	store    *memStore
	staged   [][]byte
	stageErr error
	now      time.Time
	canStage bool
	channel  string
	running  string
	// unofficial builds the checker of a binary HyperDrop's build scripts
	// did not make.
	unofficial bool
}

func newRig(t *testing.T, running string) *rig {
	r := &rig{t: t, site: &site{files: map[string][]byte{}, down: map[string]bool{}},
		store: &memStore{m: map[string]string{}}, now: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC),
		canStage: true, running: running}
	r.srv = httptest.NewServer(r.site)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) checker() *Checker {
	return New(Config{Base: r.srv.URL + "/", HTTP: r.srv.Client(), Version: r.running, Arch: "amd64",
		Channel: r.channel, Official: !r.unofficial, CanStage: func() bool { return r.canStage },
		Store: r.store, Keys: []string{base64.StdEncoding.EncodeToString(releaseKey.Public().(ed25519.PublicKey))},
		Stage: func(raw, sig []byte) error {
			if r.stageErr != nil {
				return r.stageErr
			}
			r.staged = append(r.staged, raw)
			return nil
		},
		Now: func() time.Time { return r.now }})
}

// publish adds a release signed by key for amd64, newest first.
func (r *rig) publish(version, date string, key ed25519.PrivateKey) []byte {
	raw := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("server "+version)...)
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write(raw)
	zw.Close()
	sum := sha256.Sum256(b.Bytes())
	name := "hyperdrop-server-" + version + "-linux-amd64.gz"
	r.site.mu.Lock()
	r.site.files[name] = b.Bytes()
	r.site.files[name+".sig"] = signature(key, version, "amd64", raw)
	r.site.entries = append([]map[string]any{{"version": version, "date": date,
		"linux": map[string]any{"amd64": map[string]any{"length": b.Len(), "sha256": hex.EncodeToString(sum[:])}}}},
		r.site.entries...)
	r.site.mu.Unlock()
	return raw
}

func TestANewerSignedReleaseIsStagedAndTheAttemptRecorded(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.0", "2026-11-01", releaseKey)
	raw := r.publish("1.1.1", "2026-11-02", releaseKey)
	c := r.checker()
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.staged) != 1 || !bytes.Equal(r.staged[0], raw) {
		t.Fatalf("staged %d", len(r.staged))
	}
	if _, ok := r.store.m[keyAttempt]; !ok {
		t.Fatal("no attempt recorded before staging")
	}
	f := c.Facts()
	if f.SelfUpdate != updatenotice.On || f.Latest != "1.1.1" || !f.UpdateAvailable || f.Notices != nil || !f.AutoUpdate {
		t.Fatalf("%+v", f)
	}
	if err := c.Check(context.Background()); err != nil || len(r.staged) != 1 {
		t.Fatalf("staged again while the attempt is in flight: %v %d", err, len(r.staged))
	}
}

func TestARunningVersionAtOrAboveTheNewestStagesNothing(t *testing.T) {
	r := newRig(t, "1.1.1")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	c := r.checker()
	if err := c.Check(context.Background()); err != nil || len(r.staged) != 0 {
		t.Fatalf("%v %d", err, len(r.staged))
	}
	if f := c.Facts(); f.UpdateAvailable || f.Notices != nil {
		t.Fatalf("%+v", f)
	}
}

func TestABadSignatureIsAFailureNotARetryLoop(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", otherKey)
	c := r.checker()
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("a foreign signature was accepted")
	}
	f := c.Facts()
	if f.SelfUpdate != updatenotice.Failed || f.Failed == nil || f.Failed.Version != "1.1.1" ||
		len(f.Notices) != 1 || f.Notices[0].Key != "failed:1.1.1" {
		t.Fatalf("%+v", f)
	}
	r.site.resetHits()
	c.Check(context.Background())
	for _, h := range r.site.lockedHits() {
		if strings.HasSuffix(h, ".gz") {
			t.Fatal("a failed version was downloaded again")
		}
	}
	if len(r.staged) != 0 {
		t.Fatal("staged")
	}
}

func TestAChecksumMismatchIsAFailure(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	name := "hyperdrop-server-1.1.1-linux-amd64.gz"
	r.site.setFile(name, append(r.site.file(name), 0))
	c := r.checker()
	if err := c.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v", err)
	}
	if c.Facts().SelfUpdate != updatenotice.Failed {
		t.Fatal("not a failure")
	}
}

func TestANewerReleaseRetriesAfterAFailure(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", otherKey)
	c := r.checker()
	c.Check(context.Background())
	raw := r.publish("1.1.2", "2026-11-03", releaseKey)
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.staged) != 1 || !bytes.Equal(r.staged[0], raw) {
		t.Fatal("the newer release was not staged")
	}
	if c.Facts().SelfUpdate != updatenotice.On {
		t.Fatal("a failure of an older version still reported")
	}
}

// A failure recorded for a release the manifest no longer offers (one above
// everything it lists) holds back nothing: the newest listed release is
// installed and the box reports no failure.
func TestAFailureOfAReleaseNoLongerOfferedHoldsNothingBack(t *testing.T) {
	r := newRig(t, "1.1.0")
	raw := r.publish("1.1.1", "2026-11-02", releaseKey)
	c := r.checker()
	if err := c.save(keyFailed, Failure{Version: "1.4.0", At: r.now, Reason: "disk full."}); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.staged) != 1 || !bytes.Equal(r.staged[0], raw) {
		t.Fatal("the newest listed release was not staged")
	}
	if f := c.Facts(); f.SelfUpdate != updatenotice.On || f.Failed != nil {
		t.Fatalf("a failure of a release the manifest no longer lists is still reported: %+v", f)
	}
}

func TestAnUnreachableSiteIsNotAFailure(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.site.setDown("*")
	c := r.checker()
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("no error from a site that answers 500")
	}
	if f := c.Facts(); f.SelfUpdate != updatenotice.On || f.Failed != nil || f.Notices != nil {
		t.Fatalf("%+v", f)
	}
}

func TestADownloadThatKeepsFailingBecomesAFailureAfterTwoDays(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	r.site.setDown("hyperdrop-server-1.1.1-linux-amd64.gz")
	c := r.checker()
	c.Check(context.Background())
	if c.Facts().SelfUpdate != updatenotice.On {
		t.Fatal("one failed download is already a failure")
	}
	r.now = r.now.Add(47 * time.Hour)
	c.Check(context.Background())
	if c.Facts().SelfUpdate != updatenotice.On {
		t.Fatal("a failure before two days")
	}
	r.now = r.now.Add(2 * time.Hour)
	c.Check(context.Background())
	f := c.Facts()
	if f.SelfUpdate != updatenotice.Failed || !strings.Contains(f.Failed.Reason, "two days") {
		t.Fatalf("%+v", f)
	}
}

func TestTheNextBootRecordsTheSelfUpdate(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	r.checker().Check(context.Background())
	r.running = "1.1.1" // the installer swapped the binary and restarted
	c := r.checker()
	c.Settle()
	f := c.Facts()
	if f.LastAutoUpdate == nil || f.LastAutoUpdate.From != "1.1.0" || f.LastAutoUpdate.To != "1.1.1" {
		t.Fatalf("%+v", f.LastAutoUpdate)
	}
	if _, ok := r.store.m[keyAttempt]; ok {
		t.Fatal("the attempt outlived its install")
	}
	r.now = r.now.Add(DoneShown + time.Hour)
	if c.Facts().LastAutoUpdate != nil {
		t.Fatal("an old self-update still shown")
	}
}

func TestARolledBackInstallIsAFailureOnceTheSettleTimePasses(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	c := r.checker()
	c.Check(context.Background())
	r.now = r.now.Add(SettleAfter - time.Minute)
	c.Settle()
	if c.Facts().SelfUpdate != updatenotice.On {
		t.Fatal("failed before the installer had its time")
	}
	r.now = r.now.Add(2 * time.Minute)
	c.Settle()
	f := c.Facts()
	if f.SelfUpdate != updatenotice.Failed || f.Failed.Version != "1.1.1" {
		t.Fatalf("%+v", f)
	}
	c.Check(context.Background())
	if len(r.staged) != 1 {
		t.Fatal("a rolled-back version was staged again")
	}
}

// An attempt whose outcome the store refuses to record stays, so the next
// Settle records it: a full disk at boot does not lose a rollback.
func TestASettleTheStoreRefusesKeepsTheAttempt(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	r.checker().Check(context.Background())
	r.now = r.now.Add(SettleAfter + time.Minute)
	c := r.checker()
	r.store.refuse = true
	c.Settle()
	if _, ok := r.store.m[keyAttempt]; !ok {
		t.Fatal("the attempt was forgotten before its failure was recorded")
	}
	r.store.refuse = false
	c.Settle()
	if f := c.Facts(); f.SelfUpdate != updatenotice.Failed || f.Failed.Version != "1.1.1" {
		t.Fatalf("%+v", f)
	}
	if _, ok := r.store.m[keyAttempt]; ok {
		t.Fatal("the attempt outlived its recorded failure")
	}
}

// The rolled-back binary restarts without the manifest and settles the
// attempt into a failure: its admin is told at once, not after the next
// daily check.
func TestARolledBackInstallIsAnnouncedBeforeTheNextCheck(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	r.checker().Check(context.Background())
	r.now = r.now.Add(SettleAfter + time.Minute)
	c := r.checker() // the old binary, restarted
	c.Settle()
	f := c.Facts()
	if f.SelfUpdate != updatenotice.Failed || f.Latest != "" || f.UpdateAvailable ||
		len(f.Notices) != 1 || f.Notices[0].Key != "failed:1.1.1" {
		t.Fatalf("%+v", f)
	}
}

func TestANASNeverDownloadsAndIsReminded(t *testing.T) {
	r := newRig(t, "1.0.1")
	r.channel = "synology"
	r.publish("1.0.1", "2026-10-01", releaseKey)
	r.publish("1.1.0", "2026-11-01", releaseKey)
	c := r.checker()
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, h := range r.site.lockedHits() {
		if h != "releases.json" {
			t.Fatalf("a NAS fetched %s", h)
		}
	}
	f := c.Facts()
	if f.SelfUpdate != updatenotice.NAS ||
		len(f.Notices) != 1 || f.Notices[0].Key != "release:1.1.0" {
		t.Fatalf("%+v", f)
	}
}

func TestABoxWithoutAnUpdateDirectoryIsManual(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.canStage = false
	r.publish("1.1.1", "2026-11-02", releaseKey)
	c := r.checker()
	c.Check(context.Background())
	if len(r.staged) != 0 || c.Facts().SelfUpdate != updatenotice.Manual {
		t.Fatalf("%d %+v", len(r.staged), c.Facts())
	}
	off := New(Config{Version: "1.1.0", Store: r.store, CanStage: func() bool { return true }})
	if off.Facts().SelfUpdate != updatenotice.Manual {
		t.Fatal("a box that never checks is not manual")
	}
}

// A build HyperDrop's scripts did not make (a fork, a plain go build) reads
// the manifest and reminds its admins like a box that cannot install on its
// own, and never downloads a release; the same box stamped official installs it.
func TestOnlyAnOfficialBuildInstallsANewerRelease(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.unofficial = true
	r.publish("1.1.0", "2026-11-01", releaseKey)
	raw := r.publish("1.1.1", "2026-11-02", releaseKey)
	c := r.checker()
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, h := range r.site.lockedHits() {
		if h != "releases.json" {
			t.Fatalf("an unofficial build fetched %s", h)
		}
	}
	if _, ok := r.store.m[keyAttempt]; ok || len(r.staged) != 0 {
		t.Fatalf("an unofficial build staged %d releases", len(r.staged))
	}
	f := c.Facts()
	manual := updatenotice.Due(updatenotice.Facts{Running: "1.1.0", Latest: "1.1.1", SelfUpdate: updatenotice.Manual})
	if f.SelfUpdate != updatenotice.Manual || f.Latest != "1.1.1" || !f.UpdateAvailable || f.CheckedAt.IsZero() ||
		len(f.Notices) != 1 || f.Notices[0] != manual[0] {
		t.Fatalf("%+v", f)
	}
	if why := c.Unsupported(); !strings.Contains(why, "not an official HyperDrop build") {
		t.Fatalf("Unsupported = %q", why)
	}

	r.unofficial = false
	r.site.resetHits()
	official := r.checker()
	if err := official.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.staged) != 1 || !bytes.Equal(r.staged[0], raw) {
		t.Fatalf("the official build staged %d releases", len(r.staged))
	}
	if f := official.Facts(); f.SelfUpdate != updatenotice.On || official.Unsupported() != "" {
		t.Fatalf("%+v %q", f, official.Unsupported())
	}
}

func TestTurningAutoUpdateOffStopsInstallsAndOnClearsAFailure(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", otherKey)
	c := r.checker()
	c.Check(context.Background())
	if err := c.SetAuto(false); err != nil {
		t.Fatal(err)
	}
	r.publish("1.1.2", "2026-11-03", releaseKey)
	c.Check(context.Background())
	if len(r.staged) != 0 || c.Facts().SelfUpdate != updatenotice.Off || c.Facts().AutoUpdate {
		t.Fatal("installed while off")
	}
	if err := c.SetAuto(true); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.store.m[keyFailed]; ok {
		t.Fatal("turning on kept the failure")
	}
	c.Check(context.Background())
	if len(r.staged) != 1 {
		t.Fatal("turning on did not install")
	}
}

// A new volume stores off unless its install chose on; on is the switch's
// absence, which is how a volume made before the choice existed reads.
func TestANewVolumeStartsWithItsChoice(t *testing.T) {
	for _, on := range []bool{false, true} {
		s := &memStore{m: map[string]string{}}
		if err := StartWith(s, on); err != nil {
			t.Fatal(err)
		}
		if got, err := AutoIn(s); err != nil || got != on {
			t.Errorf("StartWith(%v): AutoIn = %v, %v", on, got, err)
		}
	}
	if got, err := AutoIn(&memStore{m: map[string]string{}}); err != nil || !got {
		t.Errorf("a volume with no switch stored: AutoIn = %v, %v; want on", got, err)
	}
	// A first boot that stored off and stopped before its administrator, then
	// a retry that chose on.
	s := &memStore{m: map[string]string{}}
	if err := StartWith(s, false); err != nil {
		t.Fatal(err)
	}
	if err := StartWith(s, true); err != nil {
		t.Fatal(err)
	}
	if got, err := AutoIn(s); err != nil || !got {
		t.Errorf("a retried first boot that chose on: AutoIn = %v, %v", got, err)
	}
}

func TestParseChoice(t *testing.T) {
	for raw, want := range map[string]bool{"": false, "0": false, "off": false, "false": false, " OFF ": false,
		"1": true, "on": true, "true": true, "On": true} {
		if got, err := ParseChoice(raw); err != nil || got != want {
			t.Errorf("ParseChoice(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, raw := range []string{"yes", "2", "enabled"} {
		if _, err := ParseChoice(raw); err == nil {
			t.Errorf("ParseChoice(%q) accepted", raw)
		}
	}
}

// The operator's Switch turns the store exactly as SetAuto does, and a
// running Checker that rereads it checks at once only when it is on.
func TestASwitchTurnedOutsideTheServerIsRereadOnlyWhenOn(t *testing.T) {
	r := newRig(t, "1.1.0")
	c := r.checker()
	r.store.m[keyFailed] = `{"version":"1.1.1"}`
	if err := Switch(r.store, false); err != nil {
		t.Fatal(err)
	}
	c.Reread()
	select {
	case <-c.nudge:
		t.Fatal("a switch turned off asked for a check")
	default:
	}
	if err := Switch(r.store, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.store.m[keyFailed]; ok {
		t.Fatal("turning on kept the failure")
	}
	c.Reread()
	select {
	case <-c.nudge:
	default:
		t.Fatal("a switch turned on did not ask for a check")
	}
}

func TestAStagingRefusalIsAFailureAndForgetsTheAttempt(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	r.stageErr = errors.New("disk full")
	c := r.checker()
	c.Check(context.Background())
	if _, ok := r.store.m[keyAttempt]; ok {
		t.Fatal("an attempt that never staged is still in flight")
	}
	if f := c.Facts(); f.SelfUpdate != updatenotice.Failed || !strings.Contains(f.Failed.Reason, "disk full") {
		t.Fatalf("%+v", f)
	}
}

// The manifest is unsigned, so a redirect may not leave the base's scheme
// and host: a hop elsewhere reads nothing and records nothing.
func TestARedirectOffTheBaseIsRefused(t *testing.T) {
	r := newRig(t, "1.1.0")
	r.publish("1.1.1", "2026-11-02", releaseKey)
	elsewhere := httptest.NewServer(r.site)
	t.Cleanup(elsewhere.Close)
	var hops []string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hops = append(hops, req.URL.Path)
		if req.URL.Path == "/same/releases.json" {
			http.Redirect(w, req, "/releases.json", http.StatusFound)
			return
		}
		http.Redirect(w, req, elsewhere.URL+req.URL.Path, http.StatusFound)
	}))
	t.Cleanup(origin.Close)
	c := New(Config{Base: origin.URL + "/", HTTP: origin.Client(), Version: "1.1.0", Arch: "amd64",
		CanStage: func() bool { return true }, Store: r.store,
		Stage: func(raw, sig []byte) error { r.staged = append(r.staged, raw); return nil },
		Now:   func() time.Time { return r.now }})
	err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "refusing a redirect") {
		t.Fatalf("err = %v", err)
	}
	if got := r.site.lockedHits(); len(got) != 0 {
		t.Fatalf("the other host was fetched: %v", got)
	}
	if f := c.Facts(); f.Latest != "" || f.Notices != nil || len(r.staged) != 0 || len(r.store.m) != 0 {
		t.Fatalf("a refused redirect left state: %+v %v", f, r.store.m)
	}
	// A hop within the base's origin is followed: /same/releases.json goes to
	// /releases.json on the same host, whose own hop off the origin is refused.
	c = New(Config{Base: origin.URL + "/same/", HTTP: origin.Client(), Version: "1.1.0", Store: r.store})
	if _, err := c.get(context.Background(), origin.URL+"/same/releases.json", maxManifest); err == nil ||
		!strings.Contains(err.Error(), "refusing a redirect") {
		t.Fatalf("err = %v", err)
	}
	if len(hops) < 2 || hops[len(hops)-1] != "/releases.json" {
		t.Fatalf("the same-origin hop was not followed: %v", hops)
	}
}

func TestParseBase(t *testing.T) {
	for raw, want := range map[string]string{
		"": "",
		"https://gethyperdrop.com/downloads/server": "https://gethyperdrop.com/downloads/server/",
		"http://127.0.0.1:18099/":                   "http://127.0.0.1:18099/",
		"http://localhost:8/x/":                     "http://localhost:8/x/",
	} {
		if got, err := ParseBase(raw); err != nil || got != want {
			t.Errorf("%q: %q %v", raw, got, err)
		}
	}
	for _, bad := range []string{"http://example.com/", "ftp://x/", "/relative/", "https://u:p@x/", "https://x/?q=1"} {
		if _, err := ParseBase(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

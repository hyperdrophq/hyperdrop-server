package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
)

// The public address the names service reports in these tests, and the one
// a correctly pointed record resolves to.
const testPublicIP = "203.0.113.7"

// namesFake is the names service: /v1/claim answers account approval until
// approved, /v1/update publishes, DELETE /v1/name releases.
type namesFake struct {
	mu          sync.Mutex
	approved    bool
	approvalURL string
	calls       []string
	released    []string // the bearer tokens DELETE /v1/name carried
	// drop closes every connection without an answer, as an unreachable
	// names service looks to the server.
	drop bool
}

func (f *namesFake) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if f.drop {
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
		return
	}
	switch {
	case r.URL.Path == "/v1/claim" && !f.approved:
		w.WriteHeader(http.StatusPreconditionRequired)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": "account-required", "error": "Sign in to approve this free domain",
			"approvalURL": f.approvalURL, "challenge": "nonce", "expiresAt": 4000000000,
		})
	case r.URL.Path == "/v1/claim":
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"name":"bobby"}`))
	case r.URL.Path == "/v1/update":
		_, _ = w.Write([]byte(`{"ip":"` + testPublicIP + `","state":"active","expiresAt":9000}`))
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/name":
		f.released = append(f.released, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	default:
		http.NotFound(w, r)
	}
}

func (f *namesFake) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *namesFake) releasedTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.released...)
}

// addressRig is one behind-NAT server: its domain manager on a fake
// resolver, its updater on the fake names service, its status file and the
// request file DSM writes.
type addressRig struct {
	dom     *domain.Manager
	up      *ddns.Updater
	store   *ddns.Store
	st      *statusWriter
	names   *namesFake
	reqs    *addressRequests
	path    string
	records map[string][]net.IP
	// onLookup, when set, runs before each lookup the resolver answers,
	// outside the rig's lock.
	onLookup func(host string)
	mu       sync.Mutex
}

func newAddressRig(t *testing.T, current string) *addressRig {
	t.Helper()
	dir := t.TempDir()
	r := &addressRig{
		names:   &namesFake{approvalURL: "https://gethyperdrop.com/account/#code=first"},
		path:    filepath.Join(dir, "address-request"),
		records: map[string][]net.IP{},
		st:      newStatusWriter(filepath.Join(dir, "status.json")),
	}
	srv := httptest.NewServer(http.HandlerFunc(r.names.handler))
	t.Cleanup(srv.Close)

	dom, err := domain.Load(filepath.Join(dir, "domain"), "")
	if err != nil {
		t.Fatal(err)
	}
	dom.BehindNAT = true
	dom.Lookup = func(_ context.Context, host string) ([]net.IP, error) {
		if r.onLookup != nil {
			r.onLookup(host)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if ips, ok := r.records[host]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if current != "" {
		if err := dom.Adopt(current); err != nil {
			t.Fatal(err)
		}
	}
	r.dom = dom

	store, err := ddns.Load(filepath.Join(dir, "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	up := ddns.NewUpdater(store, &ddns.Client{BaseURL: srv.URL}, func(context.Context) (string, bool) {
		return testPublicIP, true
	})
	up.Domain = dom.Current
	up.ServerID = func() string { return "server-1" }
	up.Connected = dom.Adopt
	up.ProbeHost = func(_ context.Context, host, _ string) ddns.HostStatus {
		return ddns.HostStatus{Host: host, DNS: "current", HTTPS: "valid"}
	}
	r.up, r.store = up, store
	r.reqs = &addressRequests{path: r.path, dom: dom, up: up, st: r.st}
	return r
}

// point makes host resolve to ip.
func (r *addressRig) point(host, ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[host] = []net.IP{net.ParseIP(ip)}
}

// pointBoth points a domain and its file origin at ip.
func (r *addressRig) pointBoth(d, ip string) {
	r.point(d, ip)
	r.point("files."+d, ip)
}

func (r *addressRig) request(t *testing.T, line string) {
	t.Helper()
	if err := os.WriteFile(r.path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (r *addressRig) apply(t *testing.T) bool {
	t.Helper()
	done, err := r.reqs.apply(context.Background())
	if err != nil {
		t.Logf("apply: %v", err)
	}
	return done
}

func (r *addressRig) requestGone(t *testing.T) bool {
	t.Helper()
	_, err := os.Lstat(r.path)
	return os.IsNotExist(err)
}

// holdFreeName makes the server hold name, published and current.
func (r *addressRig) holdFreeName(t *testing.T, name string) {
	t.Helper()
	if err := r.store.Set(name, "tok-"+name); err != nil {
		t.Fatal(err)
	}
	if err := r.store.Record(testPublicIP, testPublicIP, time.Now().Unix(), ""); err != nil {
		t.Fatal(err)
	}
	if err := r.dom.Adopt(ddns.FQDN(name)); err != nil {
		t.Fatal(err)
	}
}

func TestAnAddressRequestEqualToTheCurrentAddressIsDeleted(t *testing.T) {
	r := newAddressRig(t, "share.example.com")
	r.request(t, "domain share.example.com\n")
	if !r.apply(t) {
		t.Fatal("a request for the current address is not done")
	}
	if !r.requestGone(t) {
		t.Fatal("the request file was kept")
	}
	if got := r.st.Current().AddressPending; got != nil {
		t.Fatalf("pending = %+v", got)
	}
	if n := r.names.callCount(); n != 0 {
		t.Fatalf("the names service was called %d times", n)
	}
}

func TestAMissingAddressRequestIsDone(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	if !r.apply(t) {
		t.Fatal("no request is not done")
	}
	if got := r.st.Current(); got.AddressPending != nil || got.LastError != "" {
		t.Fatalf("status = %+v", got)
	}
}

// A domain is adopted only once it and its file origin resolve to the
// public address the names service sees; until then the old one serves.
func TestADomainRequestWaitsUntilTheNamePointsHere(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.request(t, "domain share.example.com\n")
	r.pointBoth("share.example.com", "198.51.100.9")

	if r.apply(t) {
		t.Fatal("a domain pointing elsewhere was applied")
	}
	if got := r.dom.Current(); got != "old.example.com" {
		t.Fatalf("current = %q while pending", got)
	}
	if r.requestGone(t) {
		t.Fatal("a pending request was deleted")
	}
	want := AddressPending{Address: "share.example.com", Reason: "share.example.com does not point at this NAS yet."}
	if got := r.st.Current().AddressPending; got == nil || *got != want {
		t.Fatalf("pending = %+v, want %+v", got, want)
	}

	// The record is right, the file origin's is not yet.
	r.point("share.example.com", testPublicIP)
	if r.apply(t) {
		t.Fatal("applied while files.share.example.com points elsewhere")
	}
	if got := r.dom.Current(); got != "old.example.com" {
		t.Fatalf("current = %q while pending", got)
	}
	want.Reason = "files.share.example.com does not point at this NAS yet."
	if got := r.st.Current().AddressPending; got == nil || *got != want {
		t.Fatalf("pending = %+v, want %+v", got, want)
	}

	r.point("files.share.example.com", testPublicIP)
	if !r.apply(t) {
		t.Fatal("a domain pointing here was not applied")
	}
	if got := r.dom.Current(); got != "share.example.com" {
		t.Fatalf("current = %q", got)
	}
	if !r.requestGone(t) {
		t.Fatal("the request file was kept")
	}
	if got := r.st.Current().AddressPending; got != nil {
		t.Fatalf("pending = %+v after the switch", got)
	}
}

// Leaving a free name for an own domain adopts the domain, waits for its
// certificate, then releases the free name's DNS: the order the app's own
// switch takes (PUT /api/domain, the HTTPS answer, DELETE /api/ddns).
func TestADomainRequestReleasesTheFreeNameOnceTheDomainServes(t *testing.T) {
	r := newAddressRig(t, "")
	r.holdFreeName(t, "bobby")
	r.request(t, "domain share.example.com\n")
	r.pointBoth("share.example.com", testPublicIP)

	if r.apply(t) {
		t.Fatal("done before the new domain has a certificate")
	}
	if got := r.dom.Current(); got != "share.example.com" {
		t.Fatalf("current = %q, want the adopted domain", got)
	}
	if got := r.names.releasedTokens(); len(got) != 0 {
		t.Fatalf("released %v before the domain has a certificate", got)
	}
	if got := r.store.Snapshot().Name; got != "bobby" {
		t.Fatalf("free name = %q while the domain has no certificate", got)
	}
	want := AddressPending{Address: "share.example.com", Reason: "share.example.com has no certificate yet."}
	if got := r.st.Current().AddressPending; got == nil || *got != want {
		t.Fatalf("pending = %+v, want %+v", got, want)
	}

	r.dom.RecordCertEvent("cert_obtained", map[string]any{"identifier": "share.example.com"})
	if !r.apply(t) {
		t.Fatal("not done once the domain has its certificate")
	}
	if got := r.names.releasedTokens(); len(got) != 1 || got[0] != "tok-bobby" {
		t.Fatalf("released = %v, want the free name's token", got)
	}
	if got := r.store.Snapshot(); got.Name != "" || got.Token != "" {
		t.Fatalf("free name still held: %+v", got)
	}
	if !r.requestGone(t) {
		t.Fatal("the request file was kept")
	}
	if got := r.st.Current().AddressPending; got != nil {
		t.Fatalf("pending = %+v after the switch", got)
	}
}

// A free name over an own domain goes through account approval while the
// own domain keeps serving, and the approval link is the live one.
func TestAFreeNameRequestWaitsForApprovalThenSwitches(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.request(t, "free bobby\n")

	if r.apply(t) {
		t.Fatal("done while the name waits for approval")
	}
	if got := r.dom.Current(); got != "old.example.com" {
		t.Fatalf("current = %q while pending", got)
	}
	if r.requestGone(t) {
		t.Fatal("a pending request was deleted")
	}
	want := AddressPending{
		Address:     "bobby.hyperdrop.link",
		Reason:      "bobby.hyperdrop.link is waiting for approval in your HyperDrop account.",
		ApprovalURL: "https://gethyperdrop.com/account/#code=first",
	}
	if got := r.st.Current().AddressPending; got == nil || *got != want {
		t.Fatalf("pending = %+v, want %+v", got, want)
	}

	// The approval link rotates with each claim retry the updater makes.
	r.names.mu.Lock()
	r.names.approvalURL = "https://gethyperdrop.com/account/#code=second"
	r.names.mu.Unlock()
	_ = r.up.Tick(context.Background())
	r.reqs.syncApproval()
	if got := r.st.Current().AddressPending; got == nil || got.ApprovalURL != "https://gethyperdrop.com/account/#code=second" {
		t.Fatalf("pending = %+v, want the rotated link", got)
	}

	r.names.mu.Lock()
	r.names.approved = true
	r.names.mu.Unlock()
	if !r.apply(t) {
		t.Fatal("not done once approved and published")
	}
	if got := r.dom.Current(); got != "bobby.hyperdrop.link" {
		t.Fatalf("current = %q", got)
	}
	if !r.requestGone(t) {
		t.Fatal("the request file was kept")
	}
	if got := r.st.Current().AddressPending; got != nil {
		t.Fatalf("pending = %+v after the switch", got)
	}
}

// A names service the server cannot reach is named in a plain sentence; the
// transport's own error is what apply returns, which the watch logs.
func TestAFreeNameRequestToAnUnreachableNamesServiceSaysSoPlainly(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.names.drop = true
	r.request(t, "free bobby\n")
	done, err := r.reqs.apply(context.Background())
	if done {
		t.Fatal("done while the names service is unreachable")
	}
	if err == nil || !strings.Contains(err.Error(), "/v1/claim") {
		t.Fatalf("apply returned %v, want the transport error", err)
	}
	want := AddressPending{
		Address: "bobby.hyperdrop.link",
		Reason:  "HyperDrop cannot reach the HyperDrop names service yet.",
	}
	if got := r.st.Current().AddressPending; got == nil || *got != want {
		t.Fatalf("pending = %+v, want %+v", got, want)
	}
	if r.requestGone(t) {
		t.Fatal("a waiting request was deleted")
	}
}

// A free name the server still holds and publishes beside its own domain is
// taken back without a new claim.
func TestAFreeNameRequestForAHeldNameAdoptsIt(t *testing.T) {
	r := newAddressRig(t, "")
	r.holdFreeName(t, "bobby")
	if err := r.dom.Adopt("share.example.com"); err != nil {
		t.Fatal(err)
	}
	r.request(t, "free bobby\n")
	if !r.apply(t) {
		t.Fatal("not done")
	}
	if got := r.dom.Current(); got != "bobby.hyperdrop.link" {
		t.Fatalf("current = %q", got)
	}
	if !r.requestGone(t) {
		t.Fatal("the request file was kept")
	}
	r.names.mu.Lock()
	defer r.names.mu.Unlock()
	for _, c := range r.names.calls {
		if c == "POST /v1/claim" {
			t.Fatalf("a held name was claimed again: %v", r.names.calls)
		}
	}
}

func TestAFreeNameRequestOverADifferentFreeNameIsRefused(t *testing.T) {
	r := newAddressRig(t, "")
	r.holdFreeName(t, "alice")
	r.request(t, "free bobby\n")
	if !r.apply(t) {
		t.Fatal("a refused request is not done")
	}
	if !r.requestGone(t) {
		t.Fatal("a refused request was kept")
	}
	if got := r.dom.Current(); got != "alice.hyperdrop.link" {
		t.Fatalf("current = %q", got)
	}
	got := r.st.Current()
	if got.LastError != "Change your free name in the HyperDrop app." || got.AddressPending != nil {
		t.Fatalf("status = %+v", got)
	}
	if n := r.names.callCount(); n != 0 {
		t.Fatalf("the names service was called %d times", n)
	}
}

func TestAMalformedAddressRequestIsDeletedAndReported(t *testing.T) {
	for _, line := range []string{
		"",
		"\n",
		"free\n",
		"free Bob\n",
		"free b\n",
		"free bobby.hyperdrop.link\n",
		"domain\n",
		"domain localhost\n",
		"domain 203.0.113.7\n",
		"domain bobby.hyperdrop.link\n",
		"domain share.example.com\ndomain other.example.com\n",
		"name share.example.com\n",
		"domain " + strings.Repeat("a", 600) + ".example.com\n",
	} {
		r := newAddressRig(t, "old.example.com")
		r.pointBoth("share.example.com", testPublicIP)
		r.request(t, line)
		if !r.apply(t) {
			t.Errorf("%q: not done", line)
		}
		if !r.requestGone(t) {
			t.Errorf("%q: kept", line)
		}
		got := r.st.Current()
		if got.LastError != "The requested address is not valid." || got.AddressPending != nil {
			t.Errorf("%q: status = %+v", line, got)
		}
		if cur := r.dom.Current(); cur != "old.example.com" {
			t.Errorf("%q: current = %q", line, cur)
		}
	}
}

// The request is read only as a regular file of its own: a link is
// refused and removed, and what it points at is never read or touched.
func TestAnAddressRequestThatIsNotARegularFileIsRefused(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.pointBoth("share.example.com", testPublicIP)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("domain share.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, r.path); err != nil {
		t.Fatal(err)
	}
	if !r.apply(t) {
		t.Fatal("not done")
	}
	if !r.requestGone(t) {
		t.Fatal("the link was kept")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("the link's target: %v", err)
	}
	if got := r.dom.Current(); got != "old.example.com" {
		t.Fatalf("current = %q: a linked request was applied", got)
	}
	if got := r.st.Current().LastError; got != "The requested address is not valid." {
		t.Fatalf("lastError = %q", got)
	}

	// A directory in its place.
	if err := os.Mkdir(r.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if !r.apply(t) {
		t.Fatal("not done")
	}
	if !r.requestGone(t) {
		t.Fatal("the directory was kept")
	}
}

func TestTheAddressRequestWatchStopsOnShutdown(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.request(t, "domain share.example.com\n")
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		r.reqs.watch(ctx, time.Hour, time.Millisecond)
		close(stopped)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for r.st.Current().AddressPending == nil {
		if time.Now().After(deadline) {
			t.Fatal("the watch never checked the request")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not stop on shutdown")
	}
}

// The watch checks again as soon as the record points here, within the
// retry interval rather than only at boot.
func TestTheAddressRequestWatchRetries(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.request(t, "domain share.example.com\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		r.reqs.watch(ctx, 5*time.Millisecond, time.Millisecond)
		close(stopped)
	}()
	r.pointBoth("share.example.com", testPublicIP)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not finish the request")
	}
	if got := r.dom.Current(); got != "share.example.com" {
		t.Fatalf("current = %q", got)
	}
}

// appSetsDomain is what PUT /api/domain does with adopt:true, through the
// deployment's address-change hook.
func (r *addressRig) appSetsDomain(t *testing.T, d string) {
	t.Helper()
	r.reqs.AppChange(func() bool {
		return r.up.ChangeDomain(context.Background(), func() error { return r.dom.Adopt(d) }) == nil
	})
	if got := r.dom.Current(); got != d {
		t.Fatalf("the app's change: current = %q", got)
	}
}

// appChoosesFreeName is what PUT /api/ddns does, through the hook.
func (r *addressRig) appChoosesFreeName(t *testing.T, name string) {
	t.Helper()
	r.reqs.AppChange(func() bool {
		return r.up.Choose(context.Background(), name, "server-1") == nil
	})
	if got := r.dom.Current(); got != ddns.FQDN(name) {
		t.Fatalf("the app's change: current = %q", got)
	}
}

func (f *namesFake) count(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}

// The last writer wins: a domain set in the app replaces a free name DSM
// asked for, and the name is never claimed again.
func TestAnAppDomainChangeReplacesAWaitingFreeNameRequest(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.request(t, "free bobby\n")
	if r.apply(t) {
		t.Fatal("done while waiting for approval")
	}
	claims := r.names.count("POST /v1/claim")

	r.appSetsDomain(t, "other.example.com")
	if !r.requestGone(t) {
		t.Fatal("the app's change left the request in place")
	}
	if got := r.st.Current().AddressPending; got != nil {
		t.Fatalf("pending = %+v after the app's change", got)
	}
	r.names.mu.Lock()
	r.names.approved = true
	r.names.mu.Unlock()
	if !r.apply(t) {
		t.Fatal("not done with the request gone")
	}
	_ = r.up.Tick(context.Background())
	if n := r.names.count("POST /v1/claim"); n != claims {
		t.Fatalf("bobby was claimed again: %d claims, %d before the app's change", n, claims)
	}
	if got := r.dom.Current(); got != "other.example.com" {
		t.Fatalf("current = %q", got)
	}
}

// A request read before the app's change is never acted on: here the app
// claims a free name while the watch is proving the domain, which then
// resolves, and the app's name is never released.
func TestAnAppFreeNameReplacesADomainRequestMidAttempt(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.names.approved = true
	r.request(t, "domain share.example.com\n")
	if r.apply(t) {
		t.Fatal("done while the domain points elsewhere")
	}

	r.pointBoth("share.example.com", testPublicIP)
	var once sync.Once
	r.onLookup = func(string) { once.Do(func() { r.appChoosesFreeName(t, "carol") }) }
	if r.apply(t) {
		t.Fatal("a superseded attempt reported done")
	}
	r.onLookup = nil
	r.dom.RecordCertEvent("cert_obtained", map[string]any{"identifier": "share.example.com"})
	r.apply(t)

	if got := r.dom.Current(); got != "carol.hyperdrop.link" {
		t.Fatalf("current = %q, want the app's free name", got)
	}
	if got := r.names.releasedTokens(); len(got) != 0 {
		t.Fatalf("released %v", got)
	}
	if got := r.store.Snapshot().Name; got != "carol" {
		t.Fatalf("free name = %q", got)
	}
	if !r.requestGone(t) {
		t.Fatal("the app's change left the request in place")
	}
	if got := r.st.Current().AddressPending; got != nil {
		t.Fatalf("pending = %+v", got)
	}
}

// The same, sequentially: the app's free name, then the domain resolving.
func TestAnAppFreeNameReplacesAWaitingDomainRequest(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.names.approved = true
	r.request(t, "domain share.example.com\n")
	if r.apply(t) {
		t.Fatal("done while the domain points elsewhere")
	}
	r.appChoosesFreeName(t, "carol")
	r.pointBoth("share.example.com", testPublicIP)
	r.dom.RecordCertEvent("cert_obtained", map[string]any{"identifier": "share.example.com"})
	if !r.apply(t) {
		t.Fatal("not done with the request gone")
	}
	if got := r.dom.Current(); got != "carol.hyperdrop.link" {
		t.Fatalf("current = %q", got)
	}
	if got := r.names.releasedTokens(); len(got) != 0 {
		t.Fatalf("released %v", got)
	}
}

// A change the app could not make leaves the request waiting.
func TestARefusedAppChangeKeepsTheRequest(t *testing.T) {
	r := newAddressRig(t, "old.example.com")
	r.request(t, "domain share.example.com\n")
	r.apply(t)
	r.reqs.AppChange(func() bool { return false })
	if r.requestGone(t) {
		t.Fatal("a refused app change removed the request")
	}
	if r.st.Current().AddressPending == nil {
		t.Fatal("a refused app change cleared the waiting status")
	}
}

// Only the file that was read is removed: one DSM wrote while the attempt
// ran is the next request.
func TestANewerRequestIsNotRemoved(t *testing.T) {
	r := newAddressRig(t, "share.example.com")
	r.request(t, "domain share.example.com\n")
	l := r.reqs.load()
	// Written beside the first and renamed over it, as the package writes.
	if err := os.WriteFile(r.path+".new", []byte("domain other.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(r.path+".new", r.path); err != nil {
		t.Fatal(err)
	}
	if done, err := r.reqs.applyLoaded(context.Background(), l); !done || err != nil {
		t.Fatalf("done = %v, err = %v", done, err)
	}
	if r.requestGone(t) {
		t.Fatal("the newer request was removed")
	}
	b, _ := os.ReadFile(r.path)
	if string(b) != "domain other.example.com\n" {
		t.Fatalf("request = %q", b)
	}
}

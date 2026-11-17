package ddns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	pinDomain    = "share.example.com"
	pinServerID  = "server-1"
	verifiedAddr = "203.0.113.10" // this server, where the records first verify
	otherAddr    = "203.0.113.20" // another server, with its own trusted certificate
	closedAddr   = "203.0.113.30" // nothing answers
	movedAddr    = "203.0.113.40" // this server again, after a genuine move
)

// pinRig is one custom-DDNS server under test: this server and another one,
// each serving /api/health with the same serverID behind its own
// certificate for both hosts, both trusted; a recipe endpoint recording
// every ipv4 it is sent; and a dial table mapping each test address to the
// listener that answers there.
type pinRig struct {
	t       *testing.T
	u       *Updater
	store   *Store
	now     time.Time
	ip      string
	thisTLS *httptest.Server
	other   *httptest.Server
	leaf    []byte

	mu     sync.Mutex
	routes map[string]string
	sent   []recipeCall
	// onSend runs inside the recipe endpoint for each request it accepts.
	onSend func(recipeCall)
}

type recipeCall struct{ IPv4, Previous string }

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: pinDomain},
		DNSNames:              []string{pinDomain, "files." + pinDomain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func healthServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"serverID":%q}`, pinServerID)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newPinRig(t *testing.T) *pinRig {
	t.Helper()
	r := &pinRig{t: t, now: time.Now().Truncate(time.Second), ip: verifiedAddr, routes: map[string]string{}}
	thisCert, otherCert := selfSigned(t), selfSigned(t)
	r.thisTLS = healthServer(t, thisCert)
	r.other = healthServer(t, otherCert)
	r.leaf = thisCert.Certificate[0]
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedHostPort := closed.Addr().String()
	closed.Close()
	r.routes[verifiedAddr] = r.thisTLS.Listener.Addr().String()
	r.routes[movedAddr] = r.thisTLS.Listener.Addr().String()
	r.routes[otherAddr] = r.other.Listener.Addr().String()
	r.routes[closedAddr] = closedHostPort

	roots := x509.NewCertPool()
	for _, c := range []tls.Certificate{thisCert, otherCert} {
		parsed, _ := x509.ParseCertificate(c.Certificate[0])
		roots.AddCert(parsed)
	}
	savedRoots, savedAddress, savedLookups := probeRoots, probeAddress, hostLookups
	t.Cleanup(func() { probeRoots, probeAddress, hostLookups = savedRoots, savedAddress, savedLookups })
	probeRoots = roots
	probeAddress = func(ip string) string {
		r.mu.Lock()
		defer r.mu.Unlock()
		if a, ok := r.routes[ip]; ok {
			return a
		}
		return closedHostPort
	}
	// No resolver answers: DNS stays "unknown", which verify never counts
	// against the records, and HTTPS is still checked at the address.
	hostLookups = []func(context.Context, string) ([]netip.Addr, error){
		func(context.Context, string) ([]netip.Addr, error) {
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
		},
	}

	recipe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var call recipeCall
		if err := json.NewDecoder(req.Body).Decode(&call); err != nil {
			t.Errorf("recipe body: %v", err)
		}
		r.mu.Lock()
		r.sent = append(r.sent, call)
		onSend := r.onSend
		r.mu.Unlock()
		if onSend != nil {
			onSend(call)
		}
		fmt.Fprint(w, `{"success":true}`)
	}))
	t.Cleanup(recipe.Close)

	s, err := Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	r.store = s
	r.u = NewUpdater(s, &Client{}, func(context.Context) (string, bool) { return r.ip, true })
	r.u.Domain = func() string { return pinDomain }
	r.u.ServerID = func() string { return pinServerID }
	r.u.Now = func() time.Time { return r.now }
	r.u.RecipeHTTP = recipe.Client()
	r.u.LocalLeaf = func(host string) []byte {
		if host != pinDomain && host != "files."+pinDomain {
			t.Errorf("LocalLeaf asked for %q", host)
		}
		return r.leaf
	}
	cfg := HTTPConfig{Mode: "custom", Domain: pinDomain, Requests: []HTTPRequest{{
		Method: "PUT", URL: recipe.URL + "/record",
		Body:        `{"IPv4":{{json .ipv4}},"Previous":{{json .previous_ipv4}}}`,
		SuccessJSON: map[string]any{"success": true},
	}}}
	if err := r.u.ConfigureHTTP(cfg); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *pinRig) route(ip, to string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[ip] = to
}

func (r *pinRig) calls() []recipeCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recipeCall(nil), r.sent...)
}

// tick moves the clock past any retry deadline and ticks once.
func (r *pinRig) tick(ip string) {
	r.t.Helper()
	r.ip = ip
	r.now = r.now.Add(2 * time.Hour)
	_ = r.u.Tick(context.Background())
}

// verified publishes verifiedAddr and checks it, so VerifiedIP is set.
func (r *pinRig) verified() {
	r.t.Helper()
	r.tick(verifiedAddr)
	st := r.store.Snapshot()
	if st.VerifiedIP != verifiedAddr || st.Connectivity.LastError != "" || len(r.calls()) != 1 {
		r.t.Fatalf("the first publication did not verify: VerifiedIP %q, error %q, calls %v", st.VerifiedIP, st.Connectivity.LastError, r.calls())
	}
}

func hasEvent(c Connectivity, kind string) bool {
	for _, e := range c.Events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func TestVerifyPinsTheCertificateThisServerServes(t *testing.T) {
	r := newPinRig(t)
	if err := r.u.verify(context.Background(), otherAddr); err != nil {
		t.Fatal(err)
	}
	st := r.store.Snapshot()
	for _, h := range st.Connectivity.Hosts {
		if h.HTTPS != "server-identity-mismatch" {
			t.Fatalf("%s at another server's certificate: HTTPS %q", h.Host, h.HTTPS)
		}
	}
	if st.VerifiedIP != "" {
		t.Fatalf("another server's address was recorded as verified: %q", st.VerifiedIP)
	}
	if err := r.u.verify(context.Background(), verifiedAddr); err != nil {
		t.Fatal(err)
	}
	st = r.store.Snapshot()
	for _, h := range st.Connectivity.Hosts {
		if h.HTTPS != "valid" {
			t.Fatalf("%s at this server: HTTPS %q", h.Host, h.HTTPS)
		}
	}
	if st.VerifiedIP != verifiedAddr {
		t.Fatalf("VerifiedIP = %q, want %q", st.VerifiedIP, verifiedAddr)
	}
}

func TestAReportedAddressAnsweringWithAnotherCertificateIsNeverPublished(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	r.tick(otherAddr)
	if calls := r.calls(); len(calls) != 1 {
		t.Fatalf("the provider was sent another server's address: %v", calls)
	}
	st := r.store.Snapshot()
	c := r.u.Connectivity()
	if !hasEvent(c, "address-refused") || !c.Alert || st.AddressRefusedAt == 0 {
		t.Fatalf("no refusal recorded: alert %v, refusedAt %d, events %+v", c.Alert, st.AddressRefusedAt, c.Events)
	}
	if !strings.Contains(c.LastError, otherAddr) || !strings.Contains(c.LastError, verifiedAddr) {
		t.Fatalf("the failure does not name both addresses: %q", c.LastError)
	}
	if st.LastProbe != verifiedAddr {
		t.Fatalf("LastProbe moved to %q", st.LastProbe)
	}
}

func TestAnAddressThatDoesNotAnswerStillPublishes(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	r.tick(closedAddr)
	calls := r.calls()
	if len(calls) != 2 || calls[1].IPv4 != closedAddr {
		t.Fatalf("an address without hairpin NAT was not published: %v", calls)
	}
	if st := r.store.Snapshot(); st.AddressRefusedAt != 0 || st.VerifiedIP != verifiedAddr {
		t.Fatalf("an unanswered address changed the strict state: %+v", st)
	}
}

func TestAMismatchAfterPublishingRollsTheRecordsBack(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	// Closed at the pre-check; another server takes the address the moment
	// the provider is told about it.
	r.onSend = func(call recipeCall) {
		if call.IPv4 == closedAddr {
			r.route(closedAddr, r.other.Listener.Addr().String())
		}
	}
	r.tick(closedAddr)
	calls := r.calls()
	if len(calls) != 3 || calls[1].IPv4 != closedAddr || calls[2] != (recipeCall{IPv4: verifiedAddr, Previous: closedAddr}) {
		t.Fatalf("the records were not moved back: %v", calls)
	}
	st := r.store.Snapshot()
	c := r.u.Connectivity()
	if st.LastProbe != verifiedAddr || st.AddressRefusedAt == 0 || !hasEvent(c, "address-rolled-back") || !c.Alert {
		t.Fatalf("rollback state: LastProbe %q, refusedAt %d, alert %v, events %+v", st.LastProbe, st.AddressRefusedAt, c.Alert, c.Events)
	}
	// The next tick sees the same reported address as a change against the
	// restored records, and refuses it rather than publishing it again.
	r.tick(closedAddr)
	if calls := r.calls(); len(calls) != 3 {
		t.Fatalf("the refused address was published again: %v", calls)
	}
}

func TestAfterARefusalOnlyAnAddressThatProvesItselfPublishes(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	r.tick(otherAddr)
	if r.store.Snapshot().AddressRefusedAt == 0 {
		t.Fatal("no refusal")
	}
	r.tick(closedAddr)
	if calls := r.calls(); len(calls) != 1 {
		t.Fatalf("an unproven address published in the strict state: %v", calls)
	}
	if !strings.Contains(r.u.Connectivity().LastError, closedAddr) {
		t.Fatalf("the refusal does not name the address: %q", r.u.Connectivity().LastError)
	}
	r.tick(movedAddr)
	calls := r.calls()
	if len(calls) != 2 || calls[1].IPv4 != movedAddr {
		t.Fatalf("an address answering with this server's certificate was not published: %v", calls)
	}
	st := r.store.Snapshot()
	if st.AddressRefusedAt != 0 || st.VerifiedIP != movedAddr || st.Connectivity.LastError != "" {
		t.Fatalf("a proven address did not end the strict state: refusedAt %d, VerifiedIP %q, error %q", st.AddressRefusedAt, st.VerifiedIP, st.Connectivity.LastError)
	}
}

func TestReplacingTheRecipeClearsTheStrictState(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	r.tick(otherAddr)
	if r.store.Snapshot().AddressRefusedAt == 0 {
		t.Fatal("no refusal")
	}
	if err := r.u.ConfigureHTTP(*r.store.Snapshot().Custom); err != nil {
		t.Fatal(err)
	}
	if st := r.store.Snapshot(); st.AddressRefusedAt != 0 {
		t.Fatalf("a replaced recipe kept the strict state: %d", st.AddressRefusedAt)
	}
}

func TestAServerWithNoCertificateYetProbesUnpinned(t *testing.T) {
	r := newPinRig(t)
	r.u.LocalLeaf = func(string) []byte { return nil }
	r.tick(otherAddr)
	if calls := r.calls(); len(calls) != 1 || calls[0].IPv4 != otherAddr {
		t.Fatalf("an unpinned server did not publish: %v", calls)
	}
	st := r.store.Snapshot()
	for _, h := range st.Connectivity.Hosts {
		if h.HTTPS != "valid" {
			t.Fatalf("an unpinned probe judged %s %q", h.Host, h.HTTPS)
		}
	}
	if st.VerifiedIP != "" {
		t.Fatalf("an unpinned check recorded VerifiedIP %q", st.VerifiedIP)
	}
}

func TestTheNewStateFieldsStayOutOfConnectivity(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	r.tick(otherAddr)
	encoded, err := json.Marshal(r.u.Connectivity())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"verifiedIP", "addressRefusedAt"} {
		if strings.Contains(string(encoded), `"`+key+`"`) {
			t.Fatalf("Connectivity carries %s: %s", key, encoded)
		}
	}
	file, err := json.Marshal(r.store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(file), `"verifiedIP"`) || !strings.Contains(string(file), `"addressRefusedAt"`) {
		t.Fatalf("the ddns file lacks the strict state: %s", file)
	}
}

// sickAddr is this server, behind its own certificate, answering
// /api/health with a 503.
const sickAddr = "203.0.113.50"

func (r *pinRig) sickServer() *httptest.Server {
	r.t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "starting", http.StatusServiceUnavailable)
	}))
	srv.TLS = &tls.Config{Certificates: r.thisTLS.TLS.Certificates}
	srv.StartTLS()
	r.t.Cleanup(srv.Close)
	return srv
}

func TestOnlyAnotherCertificateIsAForeignLeaf(t *testing.T) {
	r := newPinRig(t)
	r.route(sickAddr, r.sickServer().Listener.Addr().String())
	ctx := context.Background()
	if status, _, foreign := probeHTTPS(ctx, pinDomain, sickAddr, pinServerID, r.leaf); foreign || status == "valid" {
		t.Fatalf("this server answering 503: %q foreign %v, want not valid and not foreign", status, foreign)
	}
	if status, _, foreign := probeHTTPS(ctx, pinDomain, otherAddr, pinServerID, r.leaf); !foreign || status != "server-identity-mismatch" {
		t.Fatalf("another certificate: %q foreign %v, want server-identity-mismatch and foreign", status, foreign)
	}
	if _, _, foreign := probeHTTPS(ctx, pinDomain, closedAddr, pinServerID, r.leaf); foreign {
		t.Fatal("an address where nothing answers is foreign")
	}
}

func TestThisServerNotYetHealthyAtTheReportedAddressIsNotRefused(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	r.route(sickAddr, r.sickServer().Listener.Addr().String())
	r.tick(sickAddr)
	calls := r.calls()
	if len(calls) != 2 || calls[1].IPv4 != sickAddr {
		t.Fatalf("this server's own address was refused: %v", calls)
	}
	st := r.store.Snapshot()
	c := r.u.Connectivity()
	if st.AddressRefusedAt != 0 || hasEvent(c, "address-refused") {
		t.Fatalf("this server's own certificate started the strict state: refusedAt %d, events %+v", st.AddressRefusedAt, c.Events)
	}
}

func TestThisServerNotYetHealthyAfterPublishingIsNotRolledBack(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	sick := r.sickServer().Listener.Addr().String()
	r.onSend = func(call recipeCall) {
		if call.IPv4 == closedAddr {
			r.route(closedAddr, sick)
		}
	}
	r.tick(closedAddr)
	calls := r.calls()
	if len(calls) != 2 || calls[1].IPv4 != closedAddr {
		t.Fatalf("the records moved back from this server's own address: %v", calls)
	}
	st := r.store.Snapshot()
	c := r.u.Connectivity()
	if st.AddressRefusedAt != 0 || hasEvent(c, "address-rolled-back") || c.Alert {
		t.Fatalf("a rollback for this server's own certificate: refusedAt %d, alert %v, events %+v", st.AddressRefusedAt, c.Alert, c.Events)
	}
	if st.LastProbe != closedAddr || c.LastError == "" {
		t.Fatalf("LastProbe %q, error %q, want the address kept and a retry owed", st.LastProbe, c.LastError)
	}
}

func TestARefusedReportStillRollsBackAPublishedAddressTakenByAnotherServer(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	r.tick(closedAddr)
	if calls := r.calls(); len(calls) != 2 || calls[1].IPv4 != closedAddr {
		t.Fatalf("an address where nothing answers yet was not published: %v", calls)
	}
	// Another server takes the published address, and the next report is
	// one the server refuses before it checks anything.
	r.route(closedAddr, r.other.Listener.Addr().String())
	r.tick(otherAddr)
	calls := r.calls()
	if len(calls) != 3 || calls[2] != (recipeCall{IPv4: verifiedAddr, Previous: closedAddr}) {
		t.Fatalf("the records stayed on another server's address: %v", calls)
	}
	st := r.store.Snapshot()
	c := r.u.Connectivity()
	if st.LastProbe != verifiedAddr || st.AddressRefusedAt == 0 || !hasEvent(c, "address-refused") ||
		!hasEvent(c, "address-rolled-back") || !c.Alert {
		t.Fatalf("rollback state: LastProbe %q, refusedAt %d, alert %v, events %+v", st.LastProbe, st.AddressRefusedAt, c.Alert, c.Events)
	}
}

func TestARefusedReportKeepsAPublishedAddressWhereNothingAnswers(t *testing.T) {
	r := newPinRig(t)
	r.verified()
	r.tick(closedAddr)
	r.tick(otherAddr)
	if calls := r.calls(); len(calls) != 2 {
		t.Fatalf("the records moved for an address that proves nothing: %v", calls)
	}
	st := r.store.Snapshot()
	if st.LastProbe != closedAddr || hasEvent(r.u.Connectivity(), "address-rolled-back") {
		t.Fatalf("LastProbe %q, events %+v", st.LastProbe, r.u.Connectivity().Events)
	}
}

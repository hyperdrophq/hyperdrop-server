package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestDDNSReportsNothingConfiguredOnAFreshServer(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "GET", "/api/ddns", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var out struct {
		Configured bool   `json:"configured"`
		Name       string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Configured || out.Name != "" {
		t.Fatalf("fresh server reports %+v", out)
	}
}

func TestPutDDNSRefusesANameTheServiceWouldNotIssue(t *testing.T) {
	h := newTestAPI(t)
	for _, name := range []string{"bob", "", "Alice", "al_ice", "-alice", "alice-",
		"al--ice", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		body := `{"name":"` + name + `"}`
		rec := doReq(t, h, "PUT", "/api/ddns", testToken, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("name %q gave %d, want 400", name, rec.Code)
		}
	}
}

// The 3-30 middle run in the route's regex makes 5 and 32 the shortest and
// longest names the service accepts; either bound off by one would refuse
// a name the service itself would issue.
func TestPutDDNSAcceptsBoundaryLengthNames(t *testing.T) {
	for _, name := range []string{"aaaaa", strings.Repeat("a", 32)} {
		h := newTestAPI(t)
		body := `{"name":"` + name + `"}`
		rec := doReq(t, h, "PUT", "/api/ddns", testToken, body)
		if rec.Code != http.StatusOK {
			t.Errorf("name of length %d (%q) gave %d, want 200 (%s)", len(name), name, rec.Code, rec.Body)
		}
	}
}

// A name with no token means claim it for this install: the Synology path
// has no app in front of the server to hold a token, only DSM's own
// install wizard, so the server has to be able to ask for itself.
func TestPutDDNSWithNoTokenClaimsTheName(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"alice"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Configured bool   `json:"configured"`
		Name       string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Configured || out.Name != "alice" {
		t.Fatalf("got %+v", out)
	}
}

// A malformed name must never reach the claim service at all: name
// validation is the front gate, so the hit count pins that the service was
// never asked rather than only that the response happened to be 400.
func TestPutDDNSStillRefusesAMalformedNameWithNoToken(t *testing.T) {
	upd, hits := testDDNS(t)
	h := New(testBackend(t), "2.0.0", testDomain(t), upd)
	for _, name := range []string{"bob", "Alice", "al--ice", ""} {
		rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"`+name+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("name %q gave %d, want 400", name, rec.Code)
		}
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("the names service was hit %d times for names that never should have reached it", got)
	}
}

// A refusal from the service is the user's to read, so it reaches them
// rather than becoming an opaque 502. The reason is one the wrapping error
// text ("ddns: that name is taken") does not itself contain, so this fails
// if the service's own words were ever dropped in favor of the generic one.
func TestARefusedClaimIsReportedWithItsReason(t *testing.T) {
	h := newTestAPIRefusingClaims(t, http.StatusConflict, "already assigned to another install")
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"alice"}`)
	if rec.Code == http.StatusOK {
		t.Fatal("a refused claim reported success")
	}
	if !strings.Contains(rec.Body.String(), "already assigned to another install") {
		t.Fatalf("body %q does not carry the reason", rec.Body)
	}
}

// Each of the three refusals the names service can give a claim carries its
// own status code, which is what a client uses to decide whether asking
// again could ever work; the reason alone does not say that.
func TestPutDDNSMapsClaimRefusalsToStatusCodes(t *testing.T) {
	cases := []struct {
		status int
		reason string
	}{
		{http.StatusConflict, "already assigned to another install"},
		{http.StatusUnprocessableEntity, "reserved and not issued to installs"},
		{http.StatusTooManyRequests, "too many claims from this address today"},
	}
	for _, c := range cases {
		h := newTestAPIRefusingClaims(t, c.status, c.reason)
		rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"alice"}`)
		if rec.Code != c.status {
			t.Errorf("service %d %q gave %d, want %d", c.status, c.reason, rec.Code, c.status)
		}
		if !strings.Contains(rec.Body.String(), c.reason) {
			t.Errorf("service %d %q: body %q does not carry the reason", c.status, c.reason, rec.Body)
		}
	}
}

// The same no-token operation changes an existing managed name atomically;
// the customer server owns the recovery token and the app never needs it.
func TestPutDDNSRefusesChangingTheNameAlreadyHeld(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"alice"}`); rec.Code != http.StatusOK {
		t.Fatalf("claiming alice = %d: %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"bobbie"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("replacing alice with bobbie = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "name-permanent") {
		t.Fatalf("body %q does not carry the refusal", rec.Body)
	}
	domAfter := doReq(t, h, "GET", "/api/domain", testToken, "")
	if !strings.Contains(domAfter.Body.String(), "alice.hyperdrop.link") {
		t.Fatalf("domain was not adopted: %s", domAfter.Body)
	}
}

// The reason a claim was refused is otherwise invisible: Store.Record never
// runs with no name held, so GET /api/ddns is the only place a Synology
// user, who has no app to read a PUT's response, can ever see it.
func TestGetDDNSReportsWhyTheLastClaimWasRefused(t *testing.T) {
	h := newTestAPIRefusingClaims(t, http.StatusConflict, "that name is reserved")
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"alice"}`); rec.Code == http.StatusOK {
		t.Fatalf("a refused claim reported success: %s", rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/ddns", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status %d", rec.Code)
	}
	var out struct {
		Configured     bool   `json:"configured"`
		LastClaimError string `json:"lastClaimError"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Configured {
		t.Fatal("a refused claim reports configured")
	}
	if !strings.Contains(out.LastClaimError, "that name is reserved") {
		t.Fatalf("lastClaimError = %q, want it to carry the service's reason", out.LastClaimError)
	}
}

// Deleting twice must succeed both times, and the name must actually be
// gone afterwards: a no-op Clear would also pass a test that never checks.
func TestDeleteDDNSIsIdempotent(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"alice"}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d body %s", rec.Code, rec.Body)
	}
	for i := 0; i < 2; i++ {
		rec := doReq(t, h, "DELETE", "/api/ddns", testToken, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("delete %d gave %d", i, rec.Code)
		}
	}
	rec := doReq(t, h, "GET", "/api/ddns", testToken, "")
	var out struct {
		Configured bool `json:"configured"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Configured {
		t.Fatal("GET after DELETE still reports configured")
	}
}

// The routes are the owner's own surface: they must refuse an
// unauthenticated caller AND a signed-in caller who is not the admin.
func TestDDNSRoutesAreAdminOnly(t *testing.T) {
	h := newTestAPI(t)
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		rec := doReq(t, h, m, "/api/ddns", "", `{"name":"alice","token":"t"}`)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Errorf("%s unauthenticated gave %d", m, rec.Code)
		}
	}

	h2, um := newTestAPIWithUsers(t)
	nonAdmin := seedUser(t, um, "bob")
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		rec := doReq(t, h2, m, "/api/ddns", nonAdmin, `{"name":"alice","token":"t"}`)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s as a non-admin gave %d, want 403", m, rec.Code)
		}
	}
}

// Ordinary status must remain safe to poll and log. The recovery token only
// ever appears on the separately authenticated export route.
func TestGetDDNSNeverLeaksTheMachineCredential(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken,
		`{"name":"alice"}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "GET", "/api/ddns", testToken, "")
	if strings.Contains(rec.Body.String(), "tok-recovery") || strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("GET leaked token: %s", rec.Body)
	}
}

// putDDNS must post the update FIRST, THEN persist the name, THEN adopt the
// domain: persisting before the service confirms the token would leave the
// server reporting a name it does not actually hold whenever the token
// turns out to be wrong, and adopting before the post would put a name that
// has not been confirmed with the service in front of ACME. The stub names
// service reads the domain manager and the ddns store AT THE MOMENT it is
// called, which is the only way to observe an ordering bug rather than just
// an end state a reordering would also reach.

// A token the service refuses must leave nothing on disk: without this, GET
// /api/ddns would report a name the server does not actually hold until
// someone notices and clears it by hand.

// Giving up a name must not touch the domain the server currently serves:
// links issued under it keep working until it lapses on its own.
func TestDeleteDDNSDoesNotChangeTheDomain(t *testing.T) {
	_, dom := newDomainAPI(t, "203.0.113.7")
	upd, _ := testDDNS(t)
	h := New(testBackend(t), "2.0.0", dom, upd)

	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"alice"}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d body %s", rec.Code, rec.Body)
	}
	before := dom.Current()
	if before == "" {
		t.Fatal("PUT did not adopt a domain")
	}

	if rec := doReq(t, h, "DELETE", "/api/ddns", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("DELETE = %d body %s", rec.Code, rec.Body)
	}
	if dom.Current() != before {
		t.Fatalf("DELETE changed the domain from %q to %q", before, dom.Current())
	}
}

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/metadb"
)

// claimCountingDDNS is testDDNS counting only the claims that reach the
// names service.
func claimCountingDDNS(t *testing.T) (*ddns.Updater, *atomic.Int32) {
	t.Helper()
	var claims atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/v1/claim") {
			claims.Add(1)
			var in struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"` + in.Name + `","fqdn":"` + ddns.FQDN(in.Name) +
				`","token":"claimed-tok","expiresAt":9000}`))
			return
		}
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":0}`))
	}))
	t.Cleanup(srv.Close)
	s, err := ddns.Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	addr := func(context.Context) (string, bool) { return "203.0.113.7", true }
	upd := ddns.NewUpdater(s, &ddns.Client{BaseURL: srv.URL}, addr)
	t.Cleanup(upd.Stop)
	return upd, &claims
}

// restrictedSecondAdmin adds an admin with no second factor beside the
// seeded admin and returns its bearer token.
func restrictedSecondAdmin(t *testing.T, db *metadb.DB) string {
	t.Helper()
	if _, err := db.CreateUser("bob", "bob-pw", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	tok, err := db.MintToken("bob", "test")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Releasing the served free name leaves the domain reading that name and
// the store holding none. Once an admin with a second factor exists, first
// setup is over, so a second admin owing one cannot claim a new free name
// with the password alone.
func TestAReleasedFreeNameIsNoFirstSetupOnceAnAdminHasASecondFactor(t *testing.T) {
	upd, claims := claimCountingDDNS(t)
	b := testBackend(t)
	h := New(b, "2.0.0", testDomain(t), upd)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"mynas"}`); rec.Code != http.StatusOK {
		t.Fatalf("the enrolled admin's claim = %d %s, want 200", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "DELETE", "/api/ddns", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("the enrolled admin's release = %d %s, want 200", rec.Code, rec.Body)
	}
	if upd.Store().Snapshot().Name != "" {
		t.Fatal("the release left a name held")
	}
	bob := restrictedSecondAdmin(t, b.DB)
	before := claims.Load()
	rec := doReq(t, h, "PUT", "/api/ddns", bob, `{"name":"othername","currentPassword":"bob-pw"}`)
	wantSetupRequired(t, "a restricted admin's claim after the release", rec)
	if n := claims.Load() - before; n != 0 {
		t.Fatalf("the refused claim reached the names service %d times, want none", n)
	}
	if st := upd.Store().Snapshot(); st.Name != "" {
		t.Fatalf("the refused claim left %q held", st.Name)
	}
}

// First setup keeps the cancel-and-rechoose Server Management offers: the
// lone admin, owing a second factor, cancels its pending name and chooses
// another with the password alone.
func TestFirstSetupCancelsAPendingNameAndChoosesAnother(t *testing.T) {
	upd, claims := claimCountingDDNS(t)
	b := testBackend(t)
	clearSeededAdminTOTP(t, b.DB)
	h := New(b, "2.0.0", testDomain(t), upd)
	if err := upd.Store().BeginClaim("mynas", "token", "server"); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "DELETE", "/api/ddns?pendingName=mynas", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("cancelling the pending name = %d %s, want 200", rec.Code, rec.Body)
	}
	if !upd.Store().Snapshot().Disconnected {
		t.Fatal("the cancel did not end in a disconnected store")
	}
	body := fmt.Sprintf(`{"name":"othername","currentPassword":%q}`, testAdminPassword)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("choosing another name after the cancel = %d %s, want 200", rec.Code, rec.Body)
	}
	if n := claims.Load(); n != 1 {
		t.Fatalf("claims = %d, want 1", n)
	}
	if st := upd.Store().Snapshot(); st.Name != "othername" {
		t.Fatalf("held name = %q, want othername", st.Name)
	}
}

// Outside first setup a pending name belongs to an admin with a second
// factor, so an admin owing one cannot cancel it.
func TestAPendingNameIsCancelledOnlyDuringFirstSetup(t *testing.T) {
	upd, _ := claimCountingDDNS(t)
	b := testBackend(t)
	h := New(b, "2.0.0", testDomain(t), upd)
	if err := upd.Store().BeginClaim("mynas", "token", "server"); err != nil {
		t.Fatal(err)
	}
	bob := restrictedSecondAdmin(t, b.DB)
	rec := doReq(t, h, "DELETE", "/api/ddns?pendingName=mynas", bob, "")
	wantSetupRequired(t, "a restricted admin's cancel after first setup", rec)
	if st := upd.Store().Snapshot(); st.Name != "mynas" || !st.Pending {
		t.Fatalf("the refused cancel left %+v, want mynas still pending", st)
	}
}

// The retry of the held confirmed name changes nothing, so it stays a 200
// confirmation for an admin owing a second factor after first setup.
func TestTheHeldNameRetryIsAConfirmationAfterFirstSetup(t *testing.T) {
	upd, claims := claimCountingDDNS(t)
	b := testBackend(t)
	h := New(b, "2.0.0", testDomain(t), upd)
	if rec := doReq(t, h, "PUT", "/api/ddns", testToken, `{"name":"mynas"}`); rec.Code != http.StatusOK {
		t.Fatalf("the enrolled admin's claim = %d %s, want 200", rec.Code, rec.Body)
	}
	bob := restrictedSecondAdmin(t, b.DB)
	before := claims.Load()
	rec := doReq(t, h, "PUT", "/api/ddns", bob, `{"name":"mynas","currentPassword":"bob-pw"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"mynas"`) {
		t.Fatalf("the held name's retry = %d %s, want 200 with the held name", rec.Code, rec.Body)
	}
	for _, c := range []struct{ what, body string }{
		{"othername", `{"name":"othername","currentPassword":"bob-pw"}`},
		{"mynas replace", `{"name":"mynas","replace":true,"currentPassword":"bob-pw"}`},
	} {
		wantSetupRequired(t, "PUT /api/ddns "+c.what, doReq(t, h, "PUT", "/api/ddns", bob, c.body))
	}
	if n := claims.Load() - before; n != 0 {
		t.Fatalf("the restricted admin's requests reached the names service %d times, want none", n)
	}
}

// An admin that cannot sign in does not end first setup: its second factor
// protects nothing.
func TestASuspendedOrExpiredEnrolledAdminLeavesFirstSetupOpen(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	off := true
	for _, c := range []struct {
		what string
		s    metadb.Settings
	}{
		{"suspended", metadb.Settings{Disabled: &off}},
		{"expired", metadb.Settings{AccountExpiresAt: &past}},
	} {
		t.Run(c.what, func(t *testing.T) {
			upd, claims := claimCountingDDNS(t)
			b := testBackend(t)
			bob := restrictedSecondAdmin(t, b.DB)
			if _, err := b.DB.UpdateUser(metadb.DefaultAdminName, c.s); err != nil {
				t.Fatal(err)
			}
			h := New(b, "2.0.0", testDomain(t), upd)
			rec := doReq(t, h, "PUT", "/api/ddns", bob, `{"name":"mynas","currentPassword":"bob-pw"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("claim beside a %s enrolled admin = %d %s, want 200", c.what, rec.Code, rec.Body)
			}
			if n := claims.Load(); n != 1 {
				t.Fatalf("claims = %d, want 1", n)
			}
		})
	}
}

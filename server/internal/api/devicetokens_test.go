package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// Device tokens never expire and accumulate for the account's lifetime, so
// "sign out the lost laptop" must exist as a first-class surface: list what
// holds a token, revoke one by id. Self-scope only: a token can only see and
// revoke its own user's tokens.

func loginWithLabel(t *testing.T, h http.Handler, label string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/auth/login", "",
		`{"username":"admin","password":"`+testAdminPassword+`","label":"`+label+`"}`)
	if rec.Code != 200 {
		t.Fatalf("login status = %d body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.Token
}

type tokenRow struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Current bool   `json:"current"`
}

func listTokens(t *testing.T, h http.Handler, token string) []tokenRow {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/me/tokens", token, "")
	if rec.Code != 200 {
		t.Fatalf("list status = %d body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Tokens []tokenRow `json:"tokens"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.Tokens
}

func TestDeviceTokensListMarksTheCaller(t *testing.T) {
	h := newTestAPI(t)
	_ = loginWithLabel(t, h, "mac-a")
	tokB := loginWithLabel(t, h, "mac-b")

	rows := listTokens(t, h, tokB)
	// testToken (the seeded one) + mac-a + mac-b.
	var current, labels int
	for _, r := range rows {
		if r.Current {
			current++
			if r.Label != "mac-b" {
				t.Errorf("current row is %q, want the caller's own (mac-b)", r.Label)
			}
		}
		if r.Label == "mac-a" || r.Label == "mac-b" {
			labels++
		}
		if r.ID == "" {
			t.Error("a row without an id cannot be revoked")
		}
	}
	if current != 1 {
		t.Errorf("current rows = %d, want exactly 1", current)
	}
	if labels != 2 {
		t.Errorf("labelled rows = %d, want both logins visible", labels)
	}
}

func TestRevokeDeviceTokenSignsThatDeviceOut(t *testing.T) {
	h := newTestAPI(t)
	tokA := loginWithLabel(t, h, "mac-a")
	tokB := loginWithLabel(t, h, "mac-b")

	var idA string
	for _, r := range listTokens(t, h, tokB) {
		if r.Label == "mac-a" {
			idA = r.ID
		}
	}
	if idA == "" {
		t.Fatal("mac-a's token not listed")
	}
	if rec := doReq(t, h, "DELETE", "/api/me/tokens/"+idA, tokB, ""); rec.Code != 204 {
		t.Fatalf("revoke status = %d body %s", rec.Code, rec.Body)
	}
	// The revoked device is signed out; the revoker keeps working.
	if rec := doReq(t, h, "GET", "/api/me", tokA, ""); rec.Code != 401 {
		t.Errorf("revoked token still answers %d, want 401", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/api/me", tokB, ""); rec.Code != 200 {
		t.Errorf("revoker's own token broke: %d", rec.Code)
	}
}

func TestRevokeUnknownDeviceTokenIs404(t *testing.T) {
	h := newTestAPI(t)
	if rec := doReq(t, h, "DELETE", "/api/me/tokens/ffffffff", testToken, ""); rec.Code != 404 {
		t.Errorf("unknown id status = %d, want 404", rec.Code)
	}
}

func TestPasswordChangeKeepsTheDeviceLabel(t *testing.T) {
	// passwd revokes everything and mints the caller a replacement; the
	// replacement should keep naming the device, not become an anonymous row.
	h := newTestAPI(t)
	tok := loginWithLabel(t, h, "mac-a")
	rec := doReq(t, h, "PATCH", "/api/me/password", tok, `{"currentPassword":"`+testAdminPassword+`","password":"brand-new-pass"}`)
	if rec.Code != 200 {
		t.Fatalf("passwd status = %d body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	rows := listTokens(t, h, resp.Token)
	if len(rows) != 1 || rows[0].Label != "mac-a" || !rows[0].Current {
		t.Fatalf("rows after passwd = %+v, want one current row still labelled mac-a", rows)
	}
}

// withFreshDeviceRule turns the 24 h fresh-device rule on for one test.
func withFreshDeviceRule(t *testing.T) {
	t.Helper()
	freshDeviceAge = 24 * time.Hour
	t.Cleanup(func() { freshDeviceAge = 0 })
}

func tokenID(t *testing.T, h http.Handler, caller, label string) string {
	t.Helper()
	for _, r := range listTokens(t, h, caller) {
		if r.Label == label {
			return r.ID
		}
	}
	t.Fatalf("no token labelled %q", label)
	return ""
}

func TestAFreshDeviceCannotSignOthersOut(t *testing.T) {
	withFreshDeviceRule(t)
	h := newTestAPI(t)
	tokA := loginWithLabel(t, h, "mac-a")
	tokB := loginWithLabel(t, h, "mac-b")
	idA, idB := tokenID(t, h, tokB, "mac-a"), tokenID(t, h, tokB, "mac-b")

	rec := doReq(t, h, "DELETE", "/api/me/tokens/"+idA, tokB, "")
	if rec.Code != 403 || errCode(t, rec.Body.String()) != "device-too-new" {
		t.Fatalf("a fresh device revoking another: %d %s, want 403 device-too-new", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/me", tokA, ""); rec.Code != 200 {
		t.Fatalf("the refused revoke signed mac-a out: %d", rec.Code)
	}
	if rec := doReq(t, h, "DELETE", "/api/me/tokens/"+idB, tokB, ""); rec.Code != 204 {
		t.Fatalf("a fresh device revoking itself: %d %s, want 204", rec.Code, rec.Body)
	}
}

func TestTheTokenListNamesTheApprover(t *testing.T) {
	h, hd := newTestAPIParts(t)
	link := mintDeviceLink(t, h, testToken, testAdminPassword)
	claim, err := hd.db.ClaimDeviceLink(link.Secret, "Pixel 9", "android", "192.0.2.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := doReq(t, h, "POST", "/api/me/device-links/"+link.ID+"/approve", testToken,
		`{"number":`+strconv.Itoa(claim.Number)+`}`); rec.Code != 204 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if _, _, _, err := hd.db.SpendDeviceLink(claim.ClaimID, claim.PollSecret, time.Now()); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, h, "GET", "/api/me/tokens", testToken, "")
	var resp struct {
		Tokens []struct {
			ID, Label, ViaToken string
		} `json:"tokens"`
	}
	unmarshal(t, rec, &resp)
	found := false
	for _, r := range resp.Tokens {
		switch r.Label {
		case "Pixel 9":
			found = true
			if r.ViaToken != "seeded" {
				t.Errorf("the phone's viaToken = %q, want the desktop's id", r.ViaToken)
			}
		default:
			if r.ViaToken != "" {
				t.Errorf("%q carries viaToken %q, want none", r.Label, r.ViaToken)
			}
		}
	}
	if !found {
		t.Fatalf("no phone row in %s", rec.Body)
	}
}

// backdateTokens moves every token's sign-in time in the database under dir
// back by age.
func backdateTokens(t *testing.T, dir string, age time.Duration) {
	t.Helper()
	execRaw(t, dir, `UPDATE tokens SET created_at = created_at - ?`, age.Nanoseconds())
}

// changePassword changes the admin's password, signing other devices out,
// and answers the replacement token.
func changePassword(t *testing.T, h http.Handler, token, from, to string) string {
	t.Helper()
	rec := doReq(t, h, "PATCH", "/api/me/password", token, `{"currentPassword":"`+from+`","password":"`+to+`"}`)
	if rec.Code != 200 {
		t.Fatalf("passwd: %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		Token string `json:"token"`
	}
	unmarshal(t, rec, &resp)
	return resp.Token
}

func TestAPasswordChangeKeepsTheDevicesAge(t *testing.T) {
	withFreshDeviceRule(t)
	dir := t.TempDir()
	hd := newHandler(testBackendAt(t, dir), "2.0.0", testDomain(t), nil, Deployment{})
	h := hd.routes()
	backdateTokens(t, dir, 48*time.Hour)
	before, err := hd.db.User("admin")
	if err != nil {
		t.Fatal(err)
	}
	signedIn := before.Tokens[0].CreatedAt

	tok := changePassword(t, h, testToken, testAdminPassword, "brand-new-pass")
	after, err := hd.db.User("admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Tokens) != 1 || after.Tokens[0].SHA256 != metadb.TokenHash(tok) || !after.Tokens[0].CreatedAt.Equal(signedIn) {
		t.Fatalf("tokens after passwd = %+v, want the replacement created at %v", after.Tokens, signedIn)
	}
	mintDeviceLink(t, h, tok, "brand-new-pass")
	fresh := loginWithPassword(t, h, "mac-b", "brand-new-pass")
	if rec := doReq(t, h, "DELETE", "/api/me/tokens/"+tokenID(t, h, tok, "mac-b"), tok, ""); rec.Code != 204 {
		t.Fatalf("the replacement revoking a fresh device: %d %s, want 204", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/api/me", fresh, ""); rec.Code != 401 {
		t.Fatalf("the revoked device still answers %d", rec.Code)
	}
}

func TestAPasswordChangeLeavesAFreshDeviceFresh(t *testing.T) {
	withFreshDeviceRule(t)
	h := newTestAPI(t)
	tok := changePassword(t, h, testToken, testAdminPassword, "brand-new-pass")
	rec := doReq(t, h, "POST", "/api/me/device-links", tok, `{"currentPassword":"brand-new-pass"}`)
	if rec.Code != 403 || errCode(t, rec.Body.String()) != "device-too-new" {
		t.Fatalf("a fresh device's replacement minting: %d %s, want 403 device-too-new", rec.Code, rec.Body)
	}
}

func loginWithPassword(t *testing.T, h http.Handler, label, password string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/auth/login", "",
		`{"username":"admin","password":"`+password+`","label":"`+label+`"}`)
	if rec.Code != 200 {
		t.Fatalf("login status = %d body %s", rec.Code, rec.Body)
	}
	var resp struct {
		Token string `json:"token"`
	}
	unmarshal(t, rec, &resp)
	return resp.Token
}

package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/domain"
)

func newDomainAPI(t *testing.T, ip string) (http.Handler, *domain.Manager) {
	t.Helper()
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), ip)
	if err != nil {
		t.Fatal(err)
	}
	dom.Lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP(ip)}, nil
	}
	return New(testBackend(t), "2.0.0", dom, nil), dom
}

func TestDomainRequiresAuth(t *testing.T) {
	h, _ := newDomainAPI(t, "203.0.113.7")
	for _, method := range []string{"GET", "PUT"} {
		if rec := doReq(t, h, method, "/api/domain", "", ""); rec.Code != 401 {
			t.Errorf("%s /api/domain without token = %d, want 401", method, rec.Code)
		}
	}
}

// The route is gone: a server cannot lose its domain. ServeMux answers 405
// because GET and PUT for the path still exist.
func TestDomainDeleteGone(t *testing.T) {
	h, _ := newDomainAPI(t, "203.0.113.7")
	for _, tok := range []string{"", testToken} {
		if rec := doReq(t, h, "DELETE", "/api/domain", tok, ""); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE /api/domain (token=%q) = %d, want 405", tok, rec.Code)
		}
	}
}

func TestDomainGetEmpty(t *testing.T) {
	h, _ := newDomainAPI(t, "203.0.113.7")
	rec := doReq(t, h, "GET", "/api/domain", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("GET = %d body %s", rec.Code, rec.Body)
	}
	var out struct{ Domain, IP string }
	unmarshal(t, rec, &out)
	if out.Domain != "" || out.IP != "203.0.113.7" {
		t.Fatalf("got %+v", out)
	}
}

func TestDomainPutThenGet(t *testing.T) {
	h, _ := newDomainAPI(t, "203.0.113.7")
	rec := doReq(t, h, "PUT", "/api/domain", testToken, `{"domain":"Share.Example.com"}`)
	if rec.Code != 200 {
		t.Fatalf("PUT = %d body %s", rec.Code, rec.Body)
	}
	var out struct{ Domain, IP string }
	unmarshal(t, rec, &out)
	if out.Domain != "share.example.com" || out.IP != "203.0.113.7" {
		t.Fatalf("PUT response %+v", out)
	}

	rec = doReq(t, h, "GET", "/api/domain", testToken, "")
	unmarshal(t, rec, &out)
	if out.Domain != "share.example.com" {
		t.Fatalf("GET after PUT %+v", out)
	}
}

func TestDomainPutBadRequests(t *testing.T) {
	h, _ := newDomainAPI(t, "203.0.113.7")
	for _, body := range []string{"", "{", `{"domain":""}`, `{"domain":"nodots"}`} {
		if rec := doReq(t, h, "PUT", "/api/domain", testToken, body); rec.Code != 400 {
			t.Errorf("PUT %q = %d, want 400", body, rec.Code)
		}
	}
}

func TestDomainPutPlainHTTPMode(t *testing.T) {
	h, _ := newDomainAPI(t, "")
	rec := doReq(t, h, "PUT", "/api/domain", testToken, `{"domain":"share.example.com"}`)
	if rec.Code != 409 {
		t.Fatalf("PUT in plain mode = %d, want 409", rec.Code)
	}
	var out struct{ Error string }
	unmarshal(t, rec, &out)
	if out.Error == "" {
		t.Fatal("want an error message about public IP")
	}
}

func TestDomainPutNotPointing(t *testing.T) {
	h, dom := newDomainAPI(t, "203.0.113.7")
	dom.Lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("198.51.100.9")}, nil
	}
	rec := doReq(t, h, "PUT", "/api/domain", testToken, `{"domain":"share.example.com"}`)
	if rec.Code != 409 {
		t.Fatalf("PUT not-pointing = %d, want 409", rec.Code)
	}
	var out struct{ Error string }
	unmarshal(t, rec, &out)
	if !strings.Contains(out.Error, "203.0.113.7") {
		t.Fatalf("409 error should name the expected IP, got %q", out.Error)
	}
}

// A NAS behind a router resolves its domain to the WAN IP while HYPERDROP_IP is
// the LAN address, so the points-here check refuses a correct setup. adopt:true
// skips that check and lets ACME be the arbiter.
func TestPutDomainAdoptSkipsThePointsHereCheck(t *testing.T) {
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	// Resolves somewhere other than this server: the NAT case.
	dom.Lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("198.51.100.1")}, nil
	}
	dom.Manage = func(string) error { return nil }
	h := New(testBackend(t), "2.0.0", dom, nil)

	if rec := doReq(t, h, "PUT", "/api/domain", testToken,
		`{"domain":"share.example.com"}`); rec.Code == http.StatusOK {
		t.Fatal("the normal path accepted a domain pointing elsewhere: " +
			"there is nothing for adopt to fix")
	}
	rec := doReq(t, h, "PUT", "/api/domain", testToken,
		`{"domain":"share.example.com","adopt":true,"currentPassword":"`+testAdminPassword+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("adopt = %d, want 200 (%s)", rec.Code, rec.Body)
	}
	if dom.Current() != "share.example.com" {
		t.Fatalf("Current() = %q after adopt", dom.Current())
	}
}

// Adopting points the server at a name nothing has shown resolves here, so a
// bearer token alone is not enough: it takes the caller's password, and the
// code when the account has a second factor, as PUT /api/connectivity does.
func TestAdoptingADomainNeedsTheCallersStepUp(t *testing.T) {
	h, dom := newDomainAPI(t, "203.0.113.7")
	dom.Lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("198.51.100.1")}, nil
	}
	dom.Manage = func(string) error { return nil }
	adopt := `{"domain":"share.example.com","adopt":true`
	wantStepUpRequired(t, "adopt with no password", doReq(t, h, "PUT", "/api/domain", testToken, adopt+`}`))
	if rec := doReq(t, h, "PUT", "/api/domain", testToken, adopt+`,"currentPassword":"wrong"}`); rec.Code != 401 ||
		errCode(t, rec.Body.String()) != "wrong-password" {
		t.Fatalf("wrong password: %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	withPassword := adopt + `,"currentPassword":"` + testAdminPassword + `"`
	if rec := doReq(t, h, "PUT", "/api/domain", testToken, withPassword+`}`); rec.Code != 401 ||
		errCode(t, rec.Body.String()) != "totp-required" {
		t.Fatalf("no code: %d %s, want 401 totp-required", rec.Code, rec.Body)
	}
	if dom.Current() != "" {
		t.Fatalf("a refused step-up adopted %q", dom.Current())
	}
	if rec := doReq(t, h, "PUT", "/api/domain", testToken, withPassword+`,"totp":"`+nextCode(t, secret)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("password and code: %d %s, want 200", rec.Code, rec.Body)
	}
	if dom.Current() != "share.example.com" {
		t.Fatalf("Current() = %q after a confirmed adopt", dom.Current())
	}
}

func TestDomainStatusCarriesCertAndNAT(t *testing.T) {
	h, dom := newDomainAPI(t, "")
	dom.BehindNAT = true
	dom.RecordCertEvent("cert_failed", map[string]any{
		"identifier": "files.share.example.com", "error": errors.New("dial tcp: i/o timeout")})
	dom.SetNAT("cgnat")
	rec := doReq(t, h, "GET", "/api/domain", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("GET = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		NAT        string `json:"nat"`
		CertStatus map[string]struct {
			State     string `json:"state"`
			LastError string `json:"lastError"`
		} `json:"certStatus"`
	}
	unmarshal(t, rec, &out)
	if out.NAT != "cgnat" {
		t.Fatalf("nat = %q", out.NAT)
	}
	st := out.CertStatus["files.share.example.com"]
	if st.State != "failed" || !strings.Contains(st.LastError, "timeout") {
		t.Fatalf("certStatus = %+v", out.CertStatus)
	}
}

func TestDomainStatusOmitsEmptyDiagnostics(t *testing.T) {
	h, _ := newDomainAPI(t, "203.0.113.7")
	rec := doReq(t, h, "GET", "/api/domain", testToken, "")
	var raw map[string]any
	unmarshal(t, rec, &raw)
	if _, ok := raw["certStatus"]; ok {
		t.Fatal("certStatus must be omitted when nothing was recorded")
	}
	if _, ok := raw["nat"]; ok {
		t.Fatal("nat must be omitted when never probed")
	}
	if _, ok := raw["ports"]; ok {
		t.Fatal("ports must be omitted when never probed")
	}
}

func TestDomainStatusCarriesPorts(t *testing.T) {
	h, dom := newDomainAPI(t, "")
	dom.BehindNAT = true
	dom.SetPorts(domain.Ports{HTTPS: "taken", HTTP: "ok"})
	rec := doReq(t, h, "GET", "/api/domain", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("GET = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Ports map[string]string `json:"ports"`
	}
	unmarshal(t, rec, &out)
	if len(out.Ports) != 2 || out.Ports["https"] != "taken" || out.Ports["http"] != "ok" {
		t.Fatalf("ports = %v (%s)", out.Ports, rec.Body)
	}
}

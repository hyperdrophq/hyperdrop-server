package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// domainPutAPI is a handler whose domain manager resolves every name to the
// server's own address (or to nowhere, while pointsHere is false) and
// manages nothing.
func domainPutAPI(t *testing.T) (http.Handler, *handler, *atomic.Bool) {
	t.Helper()
	h, hd := newTestAPIParts(t)
	var pointsHere atomic.Bool
	pointsHere.Store(true)
	hd.dom.Lookup = func(context.Context, string) ([]net.IP, error) {
		if pointsHere.Load() {
			return []net.IP{net.ParseIP("203.0.113.7")}, nil
		}
		return nil, nil
	}
	hd.dom.Manage = func(string) error { return nil }
	return h, hd, &pointsHere
}

func domainPutBody(extra string) string {
	return `{"domain":"share.example.com"` + extra + `}`
}

func TestABareDomainPutStillWorks(t *testing.T) {
	h, hd, _ := domainPutAPI(t)
	if rec := doReq(t, h, "PUT", "/api/domain", testToken, domainPutBody("")); rec.Code != http.StatusOK {
		t.Fatalf("bare PUT = %d %s, want 200", rec.Code, rec.Body)
	}
	if got := hd.dom.Current(); got != "share.example.com" {
		t.Fatalf("Current = %q", got)
	}
}

func TestADomainPutVerifiesTheStepUpItCarries(t *testing.T) {
	h, hd, _ := domainPutAPI(t)
	body := domainPutBody(fmt.Sprintf(`,"currentPassword":%q`, testAdminPassword))
	if rec := doReq(t, h, "PUT", "/api/domain", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT with the right password = %d %s, want 200", rec.Code, rec.Body)
	}
	if got := hd.dom.Current(); got != "share.example.com" {
		t.Fatalf("Current = %q", got)
	}
}

func TestAWrongDomainStepUpChangesNothing(t *testing.T) {
	h, hd, _ := domainPutAPI(t)
	rec := doReq(t, h, "PUT", "/api/domain", testToken, domainPutBody(`,"currentPassword":"wrong"`))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"wrong-password"`) {
		t.Fatalf("PUT with a wrong password = %d %s, want 401 wrong-password", rec.Code, rec.Body)
	}
	if got := hd.dom.Current(); got != "" {
		t.Fatalf("Current = %q, want unchanged", got)
	}
}

func TestAWrongDomainStepUpCountsOnTheLoginLockout(t *testing.T) {
	h, _, _ := domainPutAPI(t)
	const addr = "203.0.113.9:4321"
	body := domainPutBody(`,"currentPassword":"wrong"`)
	for i := range pwFailLimit - 1 {
		rec := doReqFrom(t, h, "PUT", "/api/domain", testToken, body, addr)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d %s, want 401", i+1, rec.Code, rec.Body)
		}
	}
	if rec := doReqFrom(t, h, "PUT", "/api/domain", testToken, body, addr); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429", pwFailLimit, rec.Code)
	}
}

func TestACodeWithoutAPasswordIsStepUpRequired(t *testing.T) {
	h, hd, _ := domainPutAPI(t)
	rec := doReq(t, h, "PUT", "/api/domain", testToken, domainPutBody(`,"totp":"123456"`))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"step-up-required"`) {
		t.Fatalf("code only = %d %s, want 403 step-up-required", rec.Code, rec.Body)
	}
	if hd.dom.Current() != "" {
		t.Fatalf("Current = %q, want unchanged", hd.dom.Current())
	}
}

func TestAPasswordWithoutTheCodeIsTotpRequiredAndCountsNothing(t *testing.T) {
	h, _, _ := domainPutAPI(t)
	enableTOTP(t, h, testToken, testAdminPassword)
	const addr = "203.0.113.9:4321"
	body := domainPutBody(fmt.Sprintf(`,"currentPassword":%q`, testAdminPassword))
	for i := range pwFailLimit + 2 {
		rec := doReqFrom(t, h, "PUT", "/api/domain", testToken, body, addr)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"code":"totp-required"`) {
			t.Fatalf("attempt %d = %d %s, want 401 totp-required", i+1, rec.Code, rec.Body)
		}
	}
}

func TestAStepUpIsNotSpentOnADomainThatDoesNotPointHereYet(t *testing.T) {
	h, hd, pointsHere := domainPutAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	body := domainPutBody(fmt.Sprintf(`,"currentPassword":%q,"totp":%q`, testAdminPassword, nextCode(t, secret)))
	pointsHere.Store(false)
	if rec := doReq(t, h, "PUT", "/api/domain", testToken, body); rec.Code != http.StatusConflict {
		t.Fatalf("PUT to a domain not pointing here = %d %s, want 409", rec.Code, rec.Body)
	}
	pointsHere.Store(true)
	if rec := doReq(t, h, "PUT", "/api/domain", testToken, body); rec.Code != http.StatusOK {
		t.Fatalf("same code once it points here = %d %s, want 200", rec.Code, rec.Body)
	}
	if hd.dom.Current() != "share.example.com" {
		t.Fatalf("Current = %q", hd.dom.Current())
	}
}

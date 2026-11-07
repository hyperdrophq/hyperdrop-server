package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hyperdrop/server/internal/domain"
)

// domainAPI is a handler whose server has a real domain, so the origin split
// is live and /view is served from files.<domain>.
func domainAPI(t *testing.T, name string) http.Handler {
	t.Helper()
	dom, err := domain.Load(t.TempDir()+"/domain", "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Adopt(name); err != nil {
		t.Fatal(err)
	}
	return New(testBackend(t), "9.9.9", dom, nil)
}

// The password form is rendered IN PLACE on whichever origin the visitor
// reached, and a single-file share's links are /view and /download, both on the FILE
// origin. A relative action resolved there, where /unlock is pinned away and
// Misrouted 404s anything that is not a GET, so the correct password answered
// 404. Reported live on 2026-08-08.
func TestThePasswordFormPostsToTheAppOrigin(t *testing.T) {
	h := domainAPI(t, "share.example.com")
	id := createProtectedShare(t, h, "s3cret")

	req := httptest.NewRequest("GET", "/view/"+id+"/whatever", nil)
	req.Host = "files.share.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Password required") {
		t.Fatalf("expected the password form, got %d: %.200s", rec.Code, body)
	}
	want := `action="https://share.example.com/unlock/` + id + `"`
	if !strings.Contains(body, want) {
		t.Fatalf("form does not post to the app origin.\nwant %s\ngot: %s",
			want, formAction(body))
	}
}

// On the APP origin a relative action is already right, and an absolute one
// would only be noise.
func TestOnTheAppOriginTheFormStaysRelative(t *testing.T) {
	h := domainAPI(t, "share.example.com")
	id := createProtectedShare(t, h, "s3cret")

	req := httptest.NewRequest("GET", "/share/"+id, nil)
	req.Host = "share.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := formAction(rec.Body.String()); got != `action="/unlock/`+id+`"` {
		t.Fatalf("app-origin form action = %s, want the relative form", got)
	}
}

// A server with no domain has no split and no absolute host to name.
func TestWithoutADomainTheFormStaysRelative(t *testing.T) {
	h := newTestAPI(t)
	id := createProtectedShare(t, h, "s3cret")
	rec := doReq(t, h, "GET", "/share/"+id, "", "")
	if got := formAction(rec.Body.String()); got != `action="/unlock/`+id+`"` {
		t.Fatalf("no-domain form action = %s, want the relative form", got)
	}
}

func formAction(body string) string {
	i := strings.Index(body, `action="`)
	if i < 0 {
		return "(no form)"
	}
	rest := body[i:]
	j := strings.Index(rest[8:], `"`)
	return rest[:8+j+1]
}

// createProtectedShare makes a password-protected share and returns its id.
func createProtectedShare(t *testing.T, h http.Handler, pw string) string {
	t.Helper()
	rec := doReq(t, h, "POST", "/api/shares", testToken,
		`{"name":"secret","password":"`+pw+`"}`)
	if rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("create share: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	unmarshal(t, rec, &out)
	return out.ID
}

// A server with a domain sends every visitor to https://, so its cookies are
// Secure even when TLS ends at a proxy in front of a plain-HTTP listener and
// the request reaches this server without r.TLS. Without a domain there is no
// such promise, and a LAN install over plain HTTP must still be able to set
// them.
func TestCookiesAreSecureWheneverTheServerHasADomain(t *testing.T) {
	for _, tc := range []struct {
		h      http.Handler
		host   string
		secure bool
	}{
		{domainAPI(t, "share.example.com"), "share.example.com", true},
		{newTestAPI(t), "192.168.1.5", false},
	} {
		id := createProtectedShare(t, tc.h, "hunter2")
		r := httptest.NewRequest("POST", "/unlock/"+id, strings.NewReader("password=hunter2"))
		r.Host = tc.host
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		tc.h.ServeHTTP(rec, r)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: unlock = %d", tc.host, rec.Code)
		}
		cookies := rec.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatalf("%s: no cookie set", tc.host)
		}
		for _, c := range cookies {
			if c.Secure != tc.secure {
				t.Errorf("%s: cookie %s Secure = %v, want %v", tc.host, c.Name, c.Secure, tc.secure)
			}
		}
	}
}

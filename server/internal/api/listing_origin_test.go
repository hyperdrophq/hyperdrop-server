package api

import (
	"net/http"
	"strings"
	"testing"
)

// With a domain, a one-file share's View lands on the file origin in one
// redirect, and the listing's View, Download, Download all and folder zips
// name the file origin outright: a click costs no 308 on the way.
func TestRecipientLinksNameTheFileOrigin(t *testing.T) {
	hd := withDomain(t, "share.example.com")
	one := createShare(t, hd, "One")
	doReq(t, hd, "PUT", "/api/shares/"+one+"/files/a.pdf", testToken, "x")
	rec := req(t, hd, "GET", "share.example.com", "/share/"+one)
	if rec.Code != http.StatusFound ||
		!strings.HasPrefix(rec.Header().Get("Location"), "https://files.share.example.com/view/"+one+"/") {
		t.Fatalf("one-file share: %d Location %q, want the file origin's /view", rec.Code, rec.Header().Get("Location"))
	}

	two := createShare(t, hd, "Two")
	doReq(t, hd, "PUT", "/api/shares/"+two+"/files/a.pdf", testToken, "x")
	doReq(t, hd, "PUT", "/api/shares/"+two+"/files/sub/b.pdf", testToken, "y")
	body := req(t, hd, "GET", "share.example.com", "/share/"+two).Body.String()
	for _, want := range []string{
		`href="https://files.share.example.com/view/` + two + `/`,
		`href="https://files.share.example.com/download/` + two + `/`,
		`href="https://files.share.example.com/zip/` + two + `"`,
		`href="https://files.share.example.com/zip/` + two + `?dir=sub"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}
	for _, rel := range []string{`href="/view/`, `href="/download/`, `href="/zip/`, `href="/site/`} {
		if strings.Contains(body, rel) {
			t.Errorf("listing still links %s… relative", rel)
		}
	}
	folder := req(t, hd, "GET", "share.example.com", "/share/"+two+"?dir=sub").Body.String()
	if !strings.Contains(folder, `href="https://files.share.example.com/zip/`+two+`?dir=sub"`) {
		t.Error("a folder page's Download this folder is not on the file origin")
	}
}

// With no domain there is no file origin: everything stays root-relative.
func TestRecipientLinksStayRelativeWithoutADomain(t *testing.T) {
	h := newTestAPI(t)
	one := createShare(t, h, "One")
	doReq(t, h, "PUT", "/api/shares/"+one+"/files/a.pdf", testToken, "x")
	if loc := doReq(t, h, "GET", "/share/"+one, "", "").Header().Get("Location"); !strings.HasPrefix(loc, "/view/"+one+"/") {
		t.Fatalf("Location %q, want root-relative /view", loc)
	}
	two := createShare(t, h, "Two")
	doReq(t, h, "PUT", "/api/shares/"+two+"/files/a.pdf", testToken, "x")
	doReq(t, h, "PUT", "/api/shares/"+two+"/files/b.pdf", testToken, "y")
	body := doReq(t, h, "GET", "/share/"+two, "", "").Body.String()
	if !strings.Contains(body, `href="/zip/`+two+`"`) || !strings.Contains(body, `href="/download/`+two+`/`) {
		t.Fatal("a domain-less listing lost its relative links")
	}
}

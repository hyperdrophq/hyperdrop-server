package api

import (
	"net/http"
	"net/url"
	"testing"
)

// uploadPath uploads one file under a relpath that needs escaping to survive a
// URL: uploadGetSlug takes the path raw, and a name holding #, a space or a %
// cannot be spelled that way.
func uploadPath(t *testing.T, h http.Handler, id, rel string) {
	t.Helper()
	u := url.URL{Path: "/api/shares/" + id + "/files/" + rel}
	rec := doReq(t, h, "PUT", u.String(), testToken, "body of "+rel)
	if rec.Code != 201 {
		t.Fatalf("upload %q: %d %s", rel, rec.Code, rec.Body)
	}
}

// rescueShare holds one file of every shape the rescue has to cover: a
// pre-encoded reserved character next to Cyrillic, a space, a #, a name that
// literally contains %24, and a directory whose own name holds a #.
func rescueShare(t *testing.T, h http.Handler) string {
	t.Helper()
	id := createShare(t, h, "site")
	for _, rel := range []string{
		"posts/до-$10k.html",
		"sp ace.html",
		"q#1.html",
		"lit%24.html",
		"docs/index.html",
		"d#ir/index.html",
	} {
		uploadPath(t, h, id, rel)
	}
	return id
}

// Chrome keeps spaces and pre-encoded reserved characters percent-encoded in
// the address bar while showing Cyrillic decoded, and a chat client pasting
// that mixed address encodes the % again: %24 arrives as %2524. Decoding once
// names no file, so the request is rescued by decoding once more and answered
// with a redirect to the canonical address.
func TestSiteRescuesADoubleEncodedAddress(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := rescueShare(t, h)

	for _, tc := range []struct{ req, rel string }{
		{"/site/" + id + "/posts/%D0%B4%D0%BE-%252410k.html", "posts/до-$10k.html"},
		{"/site/" + id + "/sp%2520ace.html", "sp ace.html"},
		{"/site/" + id + "/q%2523%31.html", "q#1.html"},
	} {
		rec := fileGet(t, h, tc.req)
		if rec.Code != http.StatusMovedPermanently {
			t.Fatalf("GET %s = %d, want 301", tc.req, rec.Code)
		}
		loc := rec.Header().Get("Location")
		if want := sitePath(id, tc.rel); loc != want {
			t.Fatalf("GET %s -> %q, want %q", tc.req, loc, want)
		}
		// The canonical address is one a browser can follow back here.
		got := fileGet(t, h, loc)
		if got.Code != 200 {
			t.Fatalf("GET %s (the rescued address) = %d, want 200", loc, got.Code)
		}
		if body, want := got.Body.String(), "body of "+tc.rel; body != want {
			t.Errorf("GET %s served %q, want %q", loc, body, want)
		}
	}

	// The Cyrillic name's canonical form carries a RAW $: it is a path
	// sub-delimiter, so re-encoding it is what started this.
	if loc := sitePath(id, "posts/до-$10k.html"); loc != "/site/"+id+"/posts/%D0%B4%D0%BE-$10k.html" {
		t.Errorf("canonical address = %q", loc)
	}
}

// A file whose NAME contains a literal %24 is found by exact match, because
// the exact lookup runs before any rescue. The single-encoded spelling of the
// same address decodes to lit$.html, which the share does not hold and which a
// second decoding cannot change, so it is a plain 404.
func TestSiteExactMatchBeatsTheRescue(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := rescueShare(t, h)

	rec := fileGet(t, h, "/site/"+id+"/lit%2524.html")
	if rec.Code != 200 {
		t.Fatalf("GET the literal %%24 name = %d, want 200", rec.Code)
	}
	if got, want := rec.Body.String(), "body of lit%24.html"; got != want {
		t.Errorf("served %q, want %q", got, want)
	}
	if rec := fileGet(t, h, "/site/"+id+"/lit%24.html"); rec.Code != 404 {
		t.Errorf("GET lit$.html = %d, want 404", rec.Code)
	}
}

// A rescued directory lands on the trailing-slash form, like the directory
// branch it borrows: without the slash a relative href inside the index would
// resolve against the parent.
func TestSiteRescuesADirectory(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := rescueShare(t, h)

	want := sitePath(id, "d#ir/")
	for _, from := range []string{"/site/" + id + "/d%2523ir/", "/site/" + id + "/d%2523ir"} {
		rec := fileGet(t, h, from)
		if rec.Code != http.StatusMovedPermanently {
			t.Fatalf("GET %s = %d, want 301", from, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != want {
			t.Fatalf("GET %s -> %q, want %q", from, got, want)
		}
	}
	if rec := fileGet(t, h, want); rec.Code != 200 {
		t.Errorf("GET %s = %d, want the index", want, rec.Code)
	}
}

// The rescue decodes ONCE. A triply-encoded address, and a path that names
// nothing however it is decoded, both answer the ordinary 404.
func TestSiteRescuesOnlyOnce(t *testing.T) {
	h := withDomain(t, "share.example.com")
	id := rescueShare(t, h)

	for _, p := range []string{
		"/site/" + id + "/posts/%2525%2524.html",
		"/site/" + id + "/nope%2520.html",
		"/site/" + id + "/%2523missing/",
	} {
		if rec := fileGet(t, h, p); rec.Code != 404 {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
}

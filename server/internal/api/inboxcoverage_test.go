package api

import (
	"net/http"
	"strings"
	"testing"

	"hyperdrop/server/internal/linked"
)

// What an INBOX owes each public route. An inbox collects files
// strangers upload INTO it, so its content is never served publicly: that is
// the containment rule, and it is the one invariant here whose failure hands
// somebody else's private uploads to anyone holding the link.
//
// The rule lives in `visibleShareVia`, which every public read is supposed to
// resolve through. Nothing but this file forces a NEW public route to resolve
// through it: a route that reaches for `visibleShareAny` (or reads the share
// directly) still answers, it just answers with content that was never meant
// to be public. That is the same open-and-silent shape the origin split has,
// and it is answered the same way: by walking the mux rather than by keeping
// a hand-written list of paths in step with it.
type inboxExposure int

const (
	// hidden: an anonymous request must answer 404 for an inbox.
	hidden inboxExposure = iota
	// inboxOwn: the link's own public surface. The upload page, the
	// anonymous PUT that feeds it, and the unlock that a password-protected
	// upload page needs are exactly the three carve-outs from "an inbox is
	// never served publicly", and they are the reason `visibleShareAny`
	// exists at all.
	inboxOwn
	// notShareScoped: the route takes no share id, so containment cannot
	// apply to it.
	notShareScoped
	// beforeLookup: the route answers without resolving the share at all, so
	// it says the same thing for every well-formed id and can leak nothing by
	// saying it. Asserted rather than waived: the answer must MATCH what an id
	// that never existed gets, so a route that starts resolving the share
	// stops qualifying.
	beforeLookup
)

func (e inboxExposure) String() string {
	switch e {
	case hidden:
		return "hidden from the public"
	case inboxOwn:
		return "the link's own surface"
	case beforeLookup:
		return "answered before any lookup"
	default:
		return "not share-scoped"
	}
}

// routeExposure names every public route registered in api.go and what an
// inbox owes it. Every entry is a decision: `inboxOwn` is as
// deliberate as `hidden`, and adding a route means making one.
var routeExposure = map[string]inboxExposure{
	"GET /.well-known/hyperdrop-names": notShareScoped,
	"GET /":                            notShareScoped,
	"GET /{$}":                         notShareScoped,
	"GET /join":                        notShareScoped,
	"GET /card-video.png":              notShareScoped,
	"GET /card.png":                    notShareScoped,
	"GET /favicon.ico":                 notShareScoped,
	"GET /icon.svg":                    notShareScoped,
	"GET /card/{id}/poster.jpg":        hidden,
	"GET /download/{id}/{path...}":     hidden,
	"GET /share/{id}":                  hidden,
	"GET /share/{id}/status":           hidden,
	// Redirects to /site/{id}/ on the id's SHAPE alone (relative references in
	// an index need the trailing slash), without resolving the share.
	"GET /site/{id}":                 beforeLookup,
	"GET /site/{id}/{path...}":       hidden,
	"GET /thumb/{id}/{slug}":         hidden,
	"GET /view/{id}/{path...}":       hidden,
	"GET /zip/{id}":                  hidden,
	"GET /receive/{id}":              inboxOwn,
	"PUT /receive/{id}/files/{name}": inboxOwn,
	"POST /unlock/{id}":              inboxOwn,
}

// Every registered public route is classified, and every classification is a
// route that exists. Without the second half a renamed route leaves a stale
// entry behind that keeps asserting about a path nothing serves.
func TestEveryPublicRouteIsClassifiedForContainment(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range registeredRoutes(t) {
		if strings.HasPrefix(r.Pattern, "/api/") {
			continue // Bearer-authenticated: the owner's own surface.
		}
		key := r.Method + " " + r.Pattern
		seen[key] = true
		if _, ok := routeExposure[key]; !ok {
			t.Errorf("route %q is registered but not in routeExposure: decide whether a "+
				"inbox is hidden from it or serves it", key)
		}
	}
	for key := range routeExposure {
		if !seen[key] {
			t.Errorf("routeExposure names %q, which api.go does not register", key)
		}
	}
}

// The rule itself, driven through every route the table calls hidden.
//
// TWO shares, identical in content, differing only in `receive`. Each hidden
// route must SERVE the ordinary one and refuse the inbox one, and the first
// half is what keeps the second from passing for the wrong reason: a probe
// that 404s because the share holds no such thing proves nothing about the
// gate, and a mutation putting the thumbnail route on the unrefusing gate went
// undetected until the ordinary share was there to show the route can answer
// at all.
func TestAnInboxIsHiddenOnEveryPublicReadRoute(t *testing.T) {
	// The fixture volume is scanned in before the handler is built: the
	// server roots gate every serve, so a linked probe cannot be added to a
	// running handler.
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := New(testBackendWithRoots(t, roots), "2.0.0", testDomain(t), nil)
	ordinary, ordinarySlug := publicProbeShare(t, h, false)
	link, linkSlug := publicProbeShare(t, h, true)
	linkedID, linkedSlug := publicProbeLinkedShare(t, h)

	// A well-formed id that names nothing, for the routes that answer before
	// they look anything up.
	const stranger = "Qx7mK2pR9v"

	tested := 0
	for key, exposure := range routeExposure {
		method, pattern, _ := strings.Cut(key, " ")
		switch exposure {
		case hidden:
			// The ordinary share proves the route can answer at all.
			served := doReq(t, h, method, inboxPath(pattern, ordinary, ordinarySlug), "", "")
			if served.Code == 404 {
				t.Errorf("%s %s = 404 for an ORDINARY share: this probe cannot tell a "+
					"refused inbox from a route with nothing to serve", method, pattern)
				continue
			}
			path := inboxPath(pattern, link, linkSlug)
			if rec := doReq(t, h, method, path, "", ""); rec.Code != 404 {
				t.Errorf("%s %s = %d, want 404: this route serves an inbox's content "+
					"to anyone holding the link", method, path, rec.Code)
			}
			tested++
		case beforeLookup:
			mine := doReq(t, h, method, inboxPath(pattern, link, linkSlug), "", "")
			none := doReq(t, h, method, inboxPath(pattern, stranger, linkSlug), "", "")
			wantLocation := strings.Replace(none.Header().Get("Location"), stranger, link, 1)
			if mine.Code != none.Code || mine.Header().Get("Location") != wantLocation {
				t.Errorf("%s %s answers %d for an inbox and %d for an id that never "+
					"existed: it is resolving the share, so it owes the containment rule",
					method, pattern, mine.Code, none.Code)
			}
			tested++
		}
	}
	if tested == 0 {
		t.Fatal("no routes were exercised: the table has drifted from the mux")
	}

	// A linked share is a third kind alongside the ordinary and the inbox
	// probe above: its content lives under a server folder rather than
	// uploaded bytes, and every hidden route must serve it exactly like an
	// ordinary share.
	for key, exposure := range routeExposure {
		if exposure != hidden {
			continue
		}
		method, pattern, _ := strings.Cut(key, " ")
		path := inboxPath(pattern, linkedID, linkedSlug)
		if rec := doReq(t, h, method, path, "", ""); rec.Code == 404 {
			t.Errorf("%s %s = 404 for a LINKED share: this route should serve its content "+
				"like an ordinary share", method, path)
		}
	}

	// A REVOKED linked share is the fourth kind: its owner's allowlist no
	// longer covers its source, so every hidden route must serve none of
	// its bytes, whether it answers 404, the unavailable page, or (the
	// status route alone) its own JSON unavailable body. The probe holds a
	// tile and a poster, and every route serves it before the revoke, so a
	// sidecar route cannot pass here for having nothing to serve.
	editedID, editedSlug := publicProbeRevokedShare(t, h, func(id, slug string) {
		for key, exposure := range routeExposure {
			if exposure != hidden {
				continue
			}
			method, pattern, _ := strings.Cut(key, " ")
			path := inboxPath(pattern, id, slug)
			if rec := doReq(t, h, method, path, "", ""); rec.Code == 404 {
				t.Errorf("%s %s = 404 BEFORE the revoke: this probe cannot tell a "+
					"refused revoked source from a route with nothing to serve", method, path)
			}
		}
	})
	for _, probe := range []struct{ id, slug string }{{editedID, editedSlug}} {
		for key, exposure := range routeExposure {
			if exposure != hidden {
				continue
			}
			method, pattern, _ := strings.Cut(key, " ")
			path := inboxPath(pattern, probe.id, probe.slug)
			rec := doReq(t, h, method, path, "", "")
			if strings.Contains(rec.Body.String(), "<h1>hi</h1>") {
				t.Errorf("%s %s served a revoked source's bytes", method, path)
			}
			if rec.Header().Get("Content-Type") == "image/jpeg" {
				t.Errorf("%s %s served a revoked source's picture", method, path)
			}
			if rec.Code != 404 && !strings.Contains(rec.Body.String(), "not available on this server") &&
				!strings.Contains(rec.Body.String(), `"unavailable":true`) {
				t.Errorf("%s %s = %d for a REVOKED share: neither 404, the unavailable page, nor a JSON unavailable body", method, path, rec.Code)
			}
		}
	}

	// A HIDDEN entry is the fifth: the share stays published and the hidden
	// entry's link and tile are dead, so every route addressing it by slug
	// or relpath must refuse it.
	hiddenID, hiddenSlug := publicProbeHiddenEntry(t, h)
	for key, exposure := range routeExposure {
		if exposure != hidden {
			continue
		}
		method, pattern, _ := strings.Cut(key, " ")
		if !strings.Contains(pattern, "{slug}") && !strings.Contains(pattern, "{path...}") {
			continue // a share-wide route: the share itself is still published
		}
		path := inboxPath(pattern, hiddenID, hiddenSlug)
		rec := doReq(t, h, method, path, "", "")
		if strings.Contains(rec.Body.String(), "<h1>hi</h1>") || rec.Header().Get("Content-Type") == "image/jpeg" {
			t.Errorf("%s %s served a hidden entry", method, path)
		}
		if rec.Code != 404 {
			t.Errorf("%s %s = %d for a HIDDEN entry, want 404", method, path, rec.Code)
		}
	}
}

// probeFileName is a PAGE, because /site and /view answer for one; naming the
// probe's file anything else makes those routes 404 for a reason that has
// nothing to do with containment.
const probeFileName = "index.html"

// publicProbeShare builds a share that every hidden route has something to
// serve from: a page to render, a poster to unfurl and a tile to draw. It
// returns the share id and its file's slug.
//
// The file is `index.html` because /site and /view answer for a PAGE; naming
// it anything else makes those two routes 404 for a reason that has nothing to
// do with containment.
func publicProbeShare(t *testing.T, h http.Handler, inbox bool) (string, string) {
	t.Helper()
	body := `{"name":"probe","files":[{"path":"` + probeFileName + `","size":15}]}`
	if inbox {
		body = `{"name":"probe","receive":true}`
	}
	id := createInbox(t, h, body)
	if inbox {
		// An inbox takes its files through the anonymous PUT.
		if rec := doReq(t, h, "PUT", "/receive/"+id+"/files/"+probeFileName, "", "<html>hi</html>"); rec.Code != 201 {
			t.Fatalf("inbox upload = %d %s", rec.Code, rec.Body)
		}
	} else if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+probeFileName, testToken,
		"<html>hi</html>"); rec.Code != 201 {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body)
	}
	var sh struct {
		Files []struct {
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &sh)
	if len(sh.Files) != 1 {
		t.Fatalf("probe share holds %d files, want one", len(sh.Files))
	}
	slug := sh.Files[0].Slug
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/poster", testToken,
		string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("poster = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken,
		string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("thumb = %d %s", rec.Code, rec.Body)
	}
	return id, slug
}

// publicProbeLinkedShare is publicProbeShare for a share whose content lives
// under a server folder rather than uploaded bytes: it points the share at
// public-share/index.html on a fixture volume (the same fixture
// linkedserve_test.go seeds), which plays probeFileName's role for a linked
// share the way the ordinary and inbox probes' own upload does for theirs.
// It returns the share id and its file's slug.
func publicProbeLinkedShare(t *testing.T, h http.Handler) (string, string) {
	t.Helper()
	id := createInbox(t, h, `{"source":"public-share"}`)
	var sh struct {
		Files []struct {
			Slug string `json:"slug"`
		} `json:"files"`
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+id, testToken, ""), &sh)
	if len(sh.Files) != 1 {
		t.Fatalf("linked probe share holds %d files, want one", len(sh.Files))
	}
	slug := sh.Files[0].Slug
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/poster", testToken,
		string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("poster = %d %s", rec.Code, rec.Body)
	}
	// A linked entry's slug is minted beside the walk rather than stored as a
	// file row, and the thumbnail route reads both, so /thumb serves a linked
	// share exactly like an ordinary one and the loop below proves it.
	if rec := doReq(t, h, "PUT", "/api/shares/"+id+"/thumbs/"+slug, testToken,
		string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("linked thumbnail write = %d %s", rec.Code, rec.Body)
	}
	return id, slug
}

// publicProbeRevokedShare builds a linked share owned by a granted user,
// gives it a poster and its one entry a tile, hands both to live (which
// asserts the share serves on every route while granted), then takes the
// grant away with the confirmed users PATCH. Answers the share id and the
// slug its one entry had while it was live.
func publicProbeRevokedShare(t *testing.T, h http.Handler, live func(id, slug string)) (string, string) {
	t.Helper()
	token := grantedUser(t, h, "revokee", "public-share")
	rec := doReq(t, h, "POST", "/api/shares", token, `{"source":"public-share"}`)
	if rec.Code != 201 {
		t.Fatalf("revoked probe create = %d %s", rec.Code, rec.Body)
	}
	var made revokedView
	unmarshal(t, rec, &made)
	slug := slugOf(t, made, "index.html")
	if rec := doReq(t, h, "PUT", "/api/shares/"+made.ID+"/poster", token,
		string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("revoked probe poster = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+made.ID+"/thumbs/"+slug, token,
		string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("revoked probe thumbnail = %d %s", rec.Code, rec.Body)
	}
	live(made.ID, slug)
	if rec := doReq(t, h, "PATCH", "/api/users/revokee", testToken, `{"sourceRoots":[],"confirmRevoke":true}`); rec.Code != 200 {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	return made.ID, slug
}

// publicProbeHiddenEntry builds a linked share of the fixture's
// public-share folder, gives index.html a tile, proves the tile and the
// entry serve, then hides the entry with the owner's PATCH. Answers the
// share id and the hidden entry's slug.
func publicProbeHiddenEntry(t *testing.T, h http.Handler) (string, string) {
	t.Helper()
	id, slug := publicProbeLinkedShare(t, h)
	for _, path := range []string{"/thumb/" + id + "/" + slug, "/download/" + id + "/" + slug} {
		if rec := doReq(t, h, "GET", path, "", ""); rec.Code != 200 {
			t.Fatalf("%s = %d before the hide, want 200", path, rec.Code)
		}
	}
	if rec := doReq(t, h, "PATCH", "/api/shares/"+id, testToken,
		`{"linked":{"public-share":{"hide":["`+probeFileName+`"]}}}`); rec.Code != 200 {
		t.Fatalf("hide = %d %s", rec.Code, rec.Body)
	}
	return id, slug
}

// inboxPath fills a mux pattern with this share's own id, slug and relpath.
//
// Distinct from samplePath, which uses fixed stand-ins: containment can only
// be tested against content that really exists, since a made-up id answers 404
// whatever the gate does.
//
// `{path...}` is not one thing. /view and /download take the public SLUG,
// while /site takes the file's RELPATH, because a site's pages reference each
// other by name. Feeding one to the other 404s for a reason that has nothing
// to do with the gate.
func inboxPath(pattern, id, slug string) string {
	wildcard := slug
	if strings.HasPrefix(pattern, "/site/") {
		wildcard = probeFileName
	}
	return strings.NewReplacer(
		"{id}", id,
		"{slug}", slug,
		"{path...}", wildcard,
		"{name}", probeFileName,
	).Replace(pattern)
}

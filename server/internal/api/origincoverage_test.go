package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Which origin a route must answer on. The split is a security boundary, not
// tidiness: a payload route that answers on the APP origin serves uploaded
// HTML first-party, able to ride the hd_ access cookie of any share the
// viewer has unlocked and to repaint the password form under the real domain
// and the real certificate.
//
// isPayloadPath and isPagePath are maintained SEPARATELY from the mux
// registrations, so nothing but this file forces the two to agree. A route
// that is registered and unclassified still serves; it just serves from the
// wrong origin, silently.
type originClass int

const (
	onFile  originClass = iota // uploaded bytes: files.<domain> only
	onApp                      // our own pages: <domain> only
	anyHost                    // deliberately unpinned
)

func (c originClass) String() string {
	switch c {
	case onFile:
		return "file origin"
	case onApp:
		return "app origin"
	default:
		return "any host"
	}
}

// routeOrigins names every route registered in api.go and the origin it must
// be pinned to. Every entry is a decision: anyHost is as deliberate as the
// other two.
//
// The /api surface is unpinned because it is Bearer-authenticated and reads
// no cookie, so an uploaded page calling it has no more power than curl,
// while pinning it WOULD break the client dialling the bare IP before DNS
// resolves (post-install login, the LAN shortcut).
//
// The card images are unpinned because an anonymous unfurler bot fetches them
// from whichever host it saw in the tag.
//
// The status poll is the one page sub-route carved out of the app pin: the
// waiting page for a pending payload link renders on the FILE origin and
// polls it with a relative fetch(), which cannot follow a 308 cross-origin.
var routeOrigins = map[string]originClass{
	"/.well-known/hyperdrop-names": anyHost,
	"/":                            anyHost,
	"/{$}":                         onApp,
	"/join":                        onApp,
	"/app":                         onApp,
	"/app/{path...}":               onApp,
	"/favicon.ico":                 anyHost,
	"/icon.svg":                    anyHost,
	"/card.png":                    anyHost,
	"/card-video.png":              anyHost,
	"/card/{id}/poster.jpg":        anyHost,
	"/share/{id}":                  onApp,
	"/share/{id}/status":           anyHost,
	"/unlock/{id}":                 onApp,
	"/access/{id}":                 onFile,
	"/reaccess/{id}":               onApp,
	"/access/clear":                onFile,
	"/thumb/{id}/{slug}":           onFile,
	"/view/{id}/{path...}":         onFile,
	"/site/{id}":                   onFile,
	"/site/{id}/{path...}":         onFile,
	"/download/{id}/{path...}":     onFile,
	"/zip/{id}":                    onFile,
	"/f/{fileKey}":                 onFile,
	"/f/{fileKey}/download":        onFile,
	"/f/{fileKey}/status":          onFile,
	"/f/{fileKey}/unlock":          onFile,
	"/receive/{id}":                onApp,
	"/receive/{id}/files/{name}":   onApp,
}

// muxPatternRE pulls the method and the path out of every mux registration in
// api.go. http.ServeMux exposes no way to enumerate what was registered, so
// the source is read the same way TestExpectedServerVersionMatchesServerSource
// and TestFileOriginLabelMatchesServerSource read theirs.
//
// ONE reader, because two coverage rules now hang off it (the origin split
// here and the inbox containment in inboxcoverage_test.go), and a
// second regex is a second thing to drift from the source.
var muxPatternRE = regexp.MustCompile(`mux\.(?:Handle|HandleFunc)\("([A-Z]+) (/[^"]*)"`)

// registeredRoute is one mux registration.
type registeredRoute struct {
	Method  string
	Pattern string
}

func registeredRoutes(t *testing.T) []registeredRoute {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("api.go"))
	if err != nil {
		t.Fatalf("read api.go: %v", err)
	}
	m := muxPatternRE.FindAllSubmatch(src, -1)
	if len(m) == 0 {
		t.Fatal("found no mux registrations in api.go: the regex has drifted from the source")
	}
	out := make([]registeredRoute, 0, len(m))
	for _, g := range m {
		out = append(out, registeredRoute{Method: string(g[1]), Pattern: string(g[2])})
	}
	return out
}

func registeredPatterns(t *testing.T) []string {
	t.Helper()
	routes := registeredRoutes(t)
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.Pattern)
	}
	return out
}

// samplePath turns a mux pattern into a concrete request path. The bare "/"
// pattern is the fallback for every path nothing else registered, so its
// sample is such a path; the root itself is the "/{$}" pattern.
func samplePath(pattern string) string {
	if pattern == "/" {
		return "/unregistered-path"
	}
	r := strings.NewReplacer(
		"{$}", "",
		"{id}", "Qx7mK2pR9v",
		"{fileKey}", "3mJr7AoUXx2Wqd4p8bPZtK",
		"{path...}", "dir/file.txt",
		"{slug}", "0192b3c4-5678-4abc-8def-0123456789ab",
		"{name}", "alice",
		"{hash}", "0f1e2d3c",
		"{job}", "job-1",
	)
	return r.Replace(pattern)
}

const (
	guardApp  = "share.example.com"
	guardFile = "files.share.example.com"
)

// Every registered route is classified, and every classification is a route
// that exists. Without the second half a renamed route leaves a stale entry
// behind that keeps asserting about a path nothing serves.
func TestEveryRegisteredRouteIsClassified(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range registeredPatterns(t) {
		seen[p] = true
		if strings.HasPrefix(p, "/api/") {
			continue
		}
		if _, ok := routeOrigins[p]; !ok {
			t.Errorf("route %q is registered but not in routeOrigins: decide which origin it belongs to", p)
		}
	}
	for p := range routeOrigins {
		if !seen[p] {
			t.Errorf("routeOrigins names %q, which api.go does not register", p)
		}
	}
}

// Each classified route actually resolves to the origin it claims, through
// the same Misrouted the router uses.
func TestClassifiedRoutesResolveToTheirOrigin(t *testing.T) {
	o := OriginsFor(guardApp)
	if !o.Split() {
		t.Fatal("OriginsFor did not produce a split pair")
	}
	for pattern, want := range routeOrigins {
		path := samplePath(pattern)
		fromApp, appMis := o.Misrouted(path, guardApp)
		fromFile, fileMis := o.Misrouted(path, guardFile)

		switch want {
		case onFile:
			if !appMis || fromApp != guardFile {
				t.Errorf("%s on the app origin: got (%q,%v), want a redirect to %s",
					pattern, fromApp, appMis, guardFile)
			}
			if fileMis {
				t.Errorf("%s on the file origin: redirected to %q, want served", pattern, fromFile)
			}
		case onApp:
			if !fileMis || fromFile != guardApp {
				t.Errorf("%s on the file origin: got (%q,%v), want a redirect to %s",
					pattern, fromFile, fileMis, guardApp)
			}
			if appMis {
				t.Errorf("%s on the app origin: redirected to %q, want served", pattern, fromApp)
			}
		case anyHost:
			if appMis || fileMis {
				t.Errorf("%s is meant to answer anywhere, but Misrouted said app=%v file=%v",
					pattern, appMis, fileMis)
			}
		}
	}
}

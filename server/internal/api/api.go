// Package api wires the HyperDrop server's HTTP routes: the /api surface
// used by client apps (login-minted per-user bearer tokens) and the public
// share routes. Self-hosted VPS only: the rows live in a local database and
// the bytes on the local filesystem.
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"hyperdrop/core/domainconn"
	"hyperdrop/core/inboxannounce"
	"hyperdrop/core/updatenotice"
	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/mimetype"
	"hyperdrop/server/internal/pushrelay"
	"hyperdrop/server/internal/selfupdate"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
	"hyperdrop/server/internal/updatesig"
	"hyperdrop/server/internal/volsecret"
	"hyperdrop/server/internal/webapp"
)

type handler struct {
	// linkAddrs holds the address each claimed device link was claimed
	// from, in memory only, for the minting desktop to show.
	linkAddrs linkAddrBook
	// tickets holds the download tickets the web client trades its session
	// for, in memory only.
	tickets ticketBook
	// signIns holds the browsers' phone sign-in requests, in memory only.
	signIns webSignIns
	// desktopSignIns holds the computers' phone sign-in requests
	// (desktopsignin.go), a book of their own, in memory only.
	desktopSignIns webSignIns
	// db holds the rows, fs the bytes, roots the server folders a linked
	// share may point at (nil disables linked shares).
	db      *metadb.DB
	fs      *sharefs.FS
	roots   *linked.Roots
	version string
	dom     *domain.Manager
	// ddns drives the free-name heartbeat; nil on a server built without it.
	ddns *ddns.Updater
	// pushRelay is the relay this server sends through; "" = push off.
	pushRelay string
	// push announces to registered phones (pusher.go); nil when push is off.
	push *pusher
	// updates is the daily self-update check and what an admin is told
	// about this server's updates (GET /api/server/settings); never nil.
	updates *selfupdate.Checker
	// stageMu serializes staging: the update route and the self-updater
	// write the same part file.
	stageMu sync.Mutex
	// limits are the throttles. Grouped because they are one concern read from
	// three different files, and because keeping them adjacent is what makes
	// the separate-instances rule visible.
	limits rateLimits
	// dep is where this server is installed: the paths and names that come
	// from the box. Held as the struct it arrived in, so the fields cannot
	// drift apart from Deployment's.
	dep Deployment
	// dl counts the byte-serving requests in flight per share, so an owner
	// about to change a share can be told someone is pulling it right now.
	dl *downloads
	// speedTestBusy holds the one upload-probe slot (speedtest.go): two
	// probes at once would measure each other. speedTestTimeout overrides
	// how long one probe may hold it, in tests.
	speedTestBusy    atomic.Bool
	speedTestTimeout time.Duration
	// watch is the long-poll surface behind the app's live share list: what
	// woke, what changed, and how many connections one account may park. Four
	// fields that only ever move together, and only watch.go and
	// shareschanges.go read them.
	watch watchState
	// liveShareReg holds relay-only shares (server/internal/liveshare): visibleShareVia
	// falls back to it, so a live share answers every public route with no
	// second implementation. liveSharePollPark overrides the 20 s job-poll park
	// in tests.
	liveShareReg      *liveshare.Registry
	liveSharePollPark time.Duration
	// hevc remembers where each movie's `hev1` sample entries are, so the
	// public view route scans a header once rather than per visitor.
	hevc hevcCache
	// walks holds each linked share's composed walk for the public reads
	// (linkedwalk.go).
	walks linkedWalks
	// claims holds the inbox uploads in flight, so a second sender's
	// colliding name is renamed rather than overwriting the first
	// (inboxclaims.go).
	claims *inboxClaims
	// inboxSlots bounds the anonymous uploads in flight (inboxslots.go).
	inboxSlots *inboxSlots
	// visits holds the public reads not yet written as visitor rows (visits.go).
	visits *visitTracker
	// committing holds the ranged commits between their rename and their
	// row (ranged.go).
	committing rangedCommits
	// prep holds the senders' preparing reports on pending files (preparing.go).
	prep *prepTracker
	// webSwitchUnread is true while the web client's switch cannot be read
	// (webOn), so the log says so once.
	webSwitchUnread atomic.Bool
	// desktopSwitchUnread is the same for the desktop sign-in's switch
	// (desktopSignInOn).
	desktopSwitchUnread atomic.Bool
	// knownKey is the known-browser cookie's MAC key (knownbrowser.go), the
	// volume secret's subkey for knownKeyInfo; empty only when the handler
	// has no file store, which mints no cookie and holds none.
	knownKey []byte
}

// Server is the api surface plus Drain, the shutdown hook: main calls it on
// SIGTERM so parked long-polls release before the graceful Shutdown starts,
// instead of holding the old process open for the watch timeout.
type Server struct {
	http.Handler
	h *handler
	// drainOnce keeps Drain idempotent: the drain channel is closed once,
	// and a second SIGTERM must not panic on a closed channel.
	drainOnce sync.Once
}

// Drain releases every parked long-poll (the share watch and the stream job
// polls) and makes later ones answer immediately. It also stops the pusher,
// after any send in flight, and writes every visit still pending, so a
// shutdown loses none.
func (s *Server) Drain() {
	if s.h.push != nil {
		s.h.push.stop()
	}
	s.drainOnce.Do(func() { close(s.h.watch.drain) })
	s.h.liveShareReg.Drain()
	s.h.visits.close()
	s.h.updates.Stop()
}

// RereadSelfUpdate checks for a release and for the web client now when
// automatic updates are on: the operator's auto-update command turned the
// switch in the database.
func (s *Server) RereadSelfUpdate() {
	s.h.updates.Reread()
	if auto, err := selfupdate.AutoIn(s.h.db); err == nil && auto {
		s.h.nudgeWebFetch()
	}
}

// Deployment is where this server is INSTALLED, as distinct from what it
// serves: the paths and names that come from the box rather than from a
// request.
//
// A struct rather than four adjacent string parameters. A signature ending
// in `dataDir, updateDir, channel, localPort` accepts any permutation of the
// four, and a transposed pair is a server that stages its update in the wrong
// place and reports the wrong install manager, with nothing anywhere to say
// so. Named fields cannot be swapped silently.
type Deployment struct {
	// DataDir is the root of the data volume: the rows, the bytes, the
	// cookie secret and the CertMagic storage all live under it.
	DataDir string
	// MissingFiles, when set, holds the housekeeping pass's latest count of
	// stored files missing from disk; /api/health reports it.
	MissingFiles *atomic.Int64
	// ProxyHeaders, when set, answers the HTTPS listener's current record of
	// connections failing on the PROXY header: the private sources, most
	// recently seen first, and how many came from public addresses. The
	// health verdict reports it.
	ProxyHeaders func() (private []ProxyHeaderSource, publicCount int)
	// AddressPending, when set, answers the address change requested from
	// DSM that waits until the new address is proven, and why; both empty
	// when none is pending. The health verdict reports it.
	AddressPending func() (address, reason string)
	// AddressChange, when set, runs every address change the app makes
	// (PUT /api/domain, PUT and DELETE /api/ddns): change applies it and
	// reports whether it was accepted, and an accepted one replaces an
	// address change still waiting from DSM.
	AddressChange func(change func() (accepted bool))
	// UpdateDir is where POST /api/server/update writes the binary a
	// root-owned systemd path unit then installs. Empty disables the route and
	// makes /api/health report no updateOverAPI, which is what a server
	// installed before that unit existed must say.
	UpdateDir string
	// Channel names the install manager that owns the binary ("synology" =
	// Package Center). Clients read it from /api/health to route "update this
	// server" at the manager instead of the API self-update. Empty on a normal
	// VPS install.
	Channel string
	// LocalPort is the HTTPS listen port /api/local-addresses joins onto the
	// server's private addresses; empty in plain-HTTP mode, which reports no
	// candidates.
	LocalPort string
	// Platform names the package family that must receive an update. The DSM
	// package exports dsm7 or dsm6, its DSM generation; ordinary VPS installs
	// leave it empty.
	// Non-secret and public beside arch: together they select the exact SPK.
	Platform string
	// Releases is the directory of the website's server manifest the
	// self-updater reads daily (HYPERDROP_SERVER_RELEASES, already parsed);
	// "" never checks.
	Releases string
	// Official is true in a binary HyperDrop's build scripts made. Only an
	// official build installs a newer release on its own; any build reads
	// the manifest and reminds its admins, and any build takes Update Server.
	Official bool
	// LiveShareGrace is how long a live share outlives its sharer's
	// connection; 0 means defaultLiveShareGrace.
	LiveShareGrace time.Duration
	// PushRelay is the relay notifications go through (ParsePushRelay's
	// answer for HYPERDROP_PUSH_RELAY); "" turns push off.
	PushRelay string
	// Web is the web client's installs under DataDir, which /app serves;
	// nil serves nothing and installs nothing.
	Web *webapp.Store
	// WebFailed is why Web could not be opened ("" when it was), which
	// GET /api/server/settings reports as webApp.failed.
	WebFailed string
	// WebFetcher fetches the web client's bundle into Web from the web
	// release manifest; nil when nothing fetches. The handler sets its
	// policy (webFetchPolicy), and an administrator's act nudges it.
	WebFetcher *webapp.Fetcher
}

// NewServer is New plus the install-side settings dep carries. It starts the
// visit-flusher goroutine and, with push on, the pusher, so it is the
// constructor for a server a client actually reaches.
func NewServer(b Backend, version string, dom *domain.Manager, upd *ddns.Updater, dep Deployment) *Server {
	h := newHandler(b, version, dom, upd, dep)
	go h.visits.run(visitFlushInterval)
	h.updates.Start()
	if h.push != nil {
		h.push.start()
	}
	return &Server{Handler: h.routes(), h: h}
}

func newHandler(b Backend, version string, dom *domain.Manager, upd *ddns.Updater, dep Deployment) *handler {
	if upd != nil && dom != nil {
		upd.Connected = dom.Adopt
	}
	// A live share and a stored share mint IDs from the same shareid.NewID
	// keyspace. A collision (astronomically unlikely at ~58 bits of entropy,
	// but not impossible) would make the live share unreachable forever:
	// visibleShareVia checks the database FIRST, so the id would always resolve
	// to the pre-existing stored share and the relay registry's own copy would
	// never be consulted. newLiveShareID loops past any id the database
	// already holds; see its doc comment (liveshareapi.go) for the testable
	// shape.
	liveShareIDExists := func(id string) bool {
		_, err := b.DB.ShareCapped(id, 1)
		return err == nil
	}
	grace := dep.LiveShareGrace
	if grace <= 0 {
		grace = defaultLiveShareGrace
	}
	h := &handler{db: b.DB, fs: b.FS, roots: b.Roots,
		version: version, dom: dom, ddns: upd, dep: dep, pushRelay: dep.PushRelay,
		limits: rateLimits{
			pw: newPWLimiter(), login: newPWLimiter(), create: newCreateLimiter(),
		},
		dl: newDownloads(),
		watch: watchState{
			watchSem: newFairSem(watchMaxTotal, watchMaxPerOwner),
			drain:    make(chan struct{}),
		},
		claims:     newInboxClaims(),
		inboxSlots: newInboxSlots(),
		liveShareReg: liveshare.NewRegistry(liveshare.Config{
			Grace: grace, NewID: newLiveShareID(shareid.NewID, liveShareIDExists),
			NewSlug: shareid.NewSlug, MaxVisitors: metadb.MaxVisitorsPerShare,
			MaxFiles: liveShareManifestMaxFiles,
		}),
		visits: newVisitTracker(b.DB),
		prep:   newPrepTracker(),
	}
	if upd != nil {
		upd.ServerID = b.FS.ServerID
	}
	if b.FS != nil {
		if key, err := volsecret.Subkey(b.FS.Secret(), knownKeyInfo); err == nil {
			h.knownKey = key
		}
	}
	// Bytes are stored by name, so on a data volume that folds case every
	// name decision folds with it: the database's spelling of a path, which
	// asks the volume before it spells one name as another, and the inbox's
	// claims in flight, as the file layer's path locks do.
	if b.FS != nil && b.FS.FoldsCase() {
		b.DB.SetFoldCase(b.FS.SamePath)
		h.claims.fold = true
	}
	h.updates = selfupdate.New(selfupdate.Config{
		Base: dep.Releases, Version: version, Arch: runtime.GOARCH, Channel: dep.Channel,
		Official: dep.Official,
		CanStage: func() bool { return h.dep.UpdateDir != "" },
		Store:    b.DB,
		Stage:    h.stageRelease,
		Keys:     updatesig.TrustedKeys,
	})
	if dep.WebFetcher != nil {
		dep.WebFetcher.SetPolicy(webFetchPolicy{h})
	}
	if dep.PushRelay != "" {
		h.push = newPusher(b.DB, pushrelay.New(dep.PushRelay, "hyperdrop-server/"+version), dep.PushRelay)
		h.push.incoming = func(id string) []inboxannounce.Claim {
			var out []inboxannounce.Claim
			for _, c := range h.claims.incoming(id) {
				out = append(out, inboxannounce.Claim{Name: c.Name, By: c.By})
			}
			return out
		}
		if upd != nil {
			h.push.domain = func() (domainconn.Facts, string) { return ddnsFacts(upd) }
		}
		h.push.updates = func() []updatenotice.Notice { return h.updates.Facts().Notices }
	}
	return h
}

func (h *handler) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", h.health)
	mux.HandleFunc("GET /.well-known/hyperdrop-names", h.namesEnrollmentChallenge)
	mux.HandleFunc("POST /api/auth/login", h.login)
	mux.HandleFunc("POST /api/auth/invite", h.spendInvite)
	// A phone signing in through a desktop's link: unauthenticated, the
	// scanned secret and then the claim's poll secret being the credentials.
	mux.HandleFunc("POST /api/auth/device-link/claim", h.claimDeviceLink)
	mux.HandleFunc("POST /api/auth/device-link/poll", h.pollDeviceLink)
	mux.Handle("DELETE /api/auth/token", h.auth(h.logout))
	// The web client's session (websession.go): the sign-in sets the
	// session cookie, and the other three are for that session alone.
	// Literal /elevate segment, no wildcard.
	// Signing out answers whatever the switch and the bundle say, so a
	// session can always end; the others refuse while the web client is
	// not served (webServed).
	mux.HandleFunc("POST /api/web/session", h.webServed(h.webSignIn))
	mux.Handle("GET /api/web/session", h.webAuth(h.webServed(h.webSessionInfo)))
	mux.HandleFunc("DELETE /api/web/session", h.webSignOut)
	mux.Handle("POST /api/web/session/elevate", h.webAuth(h.webServed(h.webElevate)))
	// Signing a browser in with a phone (phonesignin.go): the browser's two
	// routes are unauthenticated and refuse while the web client is not
	// served; the phone claims, approves and denies with its device token.
	mux.HandleFunc("POST /api/web/phone-sign-in", h.webServed(h.createWebSignIn))
	mux.HandleFunc("POST /api/web/phone-sign-in/poll", h.webServed(h.pollWebSignIn))
	mux.Handle("POST /api/me/web-sign-ins/claim", h.auth(h.claimWebSignIn))
	mux.Handle("POST /api/me/web-sign-ins/{id}/approve", h.auth(h.approveWebSignIn))
	mux.Handle("POST /api/me/web-sign-ins/{id}/deny", h.auth(h.denyWebSignIn))
	// Signing a computer in with a phone (desktopsignin.go): the computer's
	// two routes are unauthenticated and answer installed apps alone; the
	// phone claims, approves and denies with its device token.
	mux.HandleFunc("POST /api/auth/desktop-sign-in", h.createDesktopSignIn)
	mux.HandleFunc("POST /api/auth/desktop-sign-in/poll", h.pollDesktopSignIn)
	mux.Handle("POST /api/me/desktop-sign-ins/claim", h.auth(h.claimDesktopSignIn))
	mux.Handle("POST /api/me/desktop-sign-ins/{id}/approve", h.auth(h.approveDesktopSignIn))
	mux.Handle("POST /api/me/desktop-sign-ins/{id}/deny", h.auth(h.denyDesktopSignIn))
	mux.Handle("GET /api/me", h.read(h.me))
	// Device-token management, self-scope only: tokens never expire, so
	// "sign out the lost laptop" must exist without nuking every device the
	// way a password change does. Literal segment before the {id} wildcard,
	// same ServeMux rule as /api/shares/watch.
	// The LAN-shortcut discovery source: any signed-in account (guests
	// upload too), never the open health route (LAN topology stays off the
	// unauthenticated surface).
	mux.Handle("GET /api/local-addresses", h.auth(h.localAddresses))
	mux.Handle("GET /api/me/tokens", h.read(h.listMyTokens))
	mux.Handle("DELETE /api/me/tokens/{id}", h.auth(h.revokeMyToken))
	// Signing a phone in from this device, scoped to the calling token. Each
	// {id} follows the literal device-links segment, so the /renew, /approve
	// and /deny segments never meet the wildcard.
	mux.Handle("POST /api/me/device-links", h.auth(h.mintDeviceLink))
	mux.Handle("GET /api/me/device-links/{id}", h.read(h.deviceLinkStatus))
	mux.Handle("POST /api/me/device-links/{id}/renew", h.auth(h.renewDeviceLink))
	mux.Handle("POST /api/me/device-links/{id}/approve", h.auth(h.approveDeviceLink))
	mux.Handle("POST /api/me/device-links/{id}/deny", h.auth(h.denyDeviceLink))
	mux.Handle("PATCH /api/me/password", h.auth(h.changeOwnPassword))
	// A device's push registration and a computer's console activity sit on
	// the calling token's row.
	mux.Handle("GET /api/me/push", h.read(h.getPush))
	mux.Handle("PUT /api/me/push", h.auth(h.putPush))
	mux.Handle("DELETE /api/me/push", h.auth(h.deletePush))
	mux.Handle("PUT /api/me/activity", h.auth(h.putActivity))
	// Optional TOTP second factor, self-scope. The literal /confirm and
	// /recovery segments sit under the same /api/me/totp path with distinct
	// methods, so no wildcard is involved.
	mux.Handle("GET /api/me/totp", h.read(h.totpStatus))
	mux.Handle("POST /api/me/totp", h.auth(h.totpStart))
	mux.Handle("POST /api/me/totp/confirm", h.auth(h.totpConfirm))
	mux.Handle("DELETE /api/me/totp", h.auth(h.totpDisable))
	mux.Handle("POST /api/me/totp/recovery", h.auth(h.totpRecovery))
	mux.Handle("DELETE /api/users/{name}/totp", h.admin(h.adminResetTOTP))
	// Replacing the server's own binary. Admin, and step-up authenticated
	// inside the handler (password + a second factor), because it grants root
	// on the box and a bearer token alone must not.
	mux.Handle("POST /api/server/update", h.admin(h.updateServer))
	// The server fetches and stages its newest release itself (the web
	// client has no binary to upload); the same step-up, in the body.
	mux.Handle("POST /api/server/update/latest", h.admin(h.updateLatest))
	// Whether the server updates itself, and the switch. The switch is a
	// bearer-only admin write: the box only ever installs a release its own
	// binary verifies.
	mux.Handle("GET /api/server/settings", h.admin(h.serverSettings))
	mux.Handle("PATCH /api/server/settings", h.admin(h.patchServerSettings))
	// Installing the web client's bundle by hand (webswitch.go), for a box
	// that cannot reach the web manifest: the archive is the body, verified
	// against the web release keys like a fetched one.
	mux.Handle("PUT /api/server/web", h.admin(h.installWebBundle))
	mux.Handle("POST /api/shares", h.auth(h.createShare))
	mux.Handle("GET /api/shares", h.read(h.listShares))
	// A literal segment, so ServeMux prefers it over the {id} wildcard below
	// regardless of registration order (pinned by a test).
	mux.Handle("GET /api/shares/watch", h.auth(h.watchShares))
	mux.Handle("GET /api/shares/changes", h.read(h.shareChanges))
	// Literal segments, same ServeMux rule as /watch: POST /api/shares/{id}
	// does not exist, but a future one must not swallow these.
	mux.Handle("POST /api/shares/delete", h.auth(h.deleteShares))
	mux.Handle("POST /api/shares/edit", h.auth(h.editShares))
	mux.Handle("GET /api/shares/{id}", h.read(h.getShare))
	mux.Handle("GET /api/sources", h.read(h.listSources))
	mux.Handle("GET /api/sources/browse", h.read(h.browseSource))
	mux.Handle("GET /api/sources/file", h.read(h.serveSource))
	mux.Handle("PUT /api/shares/{id}/files/{path...}", h.auth(h.uploadFile))
	mux.Handle("DELETE /api/shares/{id}/files/{path...}", h.auth(h.deleteFile))
	mux.Handle("POST /api/shares/{id}/move", h.auth(h.moveFile))
	mux.Handle("POST /api/shares/{id}/folders", h.auth(h.createFolder))
	mux.Handle("DELETE /api/shares/{id}/folders/{path...}", h.auth(h.deleteFolder))
	mux.Handle("POST /api/shares/{id}/batch", h.auth(h.uploadBatch))
	mux.Handle("PUT /api/shares/{id}/poster", h.auth(h.setPoster))
	mux.Handle("DELETE /api/shares/{id}/poster", h.auth(h.clearPoster))
	// A media share's gallery sidecars. Neither is a file entry, so both
	// carry their own size cap and neither touches the quota.
	mux.Handle("POST /api/shares/{id}/thumbs", h.auth(h.setThumbBatch))
	mux.Handle("PUT /api/shares/{id}/thumbs/{slug}", h.auth(h.setThumb))
	mux.Handle("PUT /api/shares/{id}/gallery", h.auth(h.setGallery))
	mux.Handle("GET /api/downloads", h.auth(h.shareDownloads))
	mux.Handle("GET /api/shares/{id}/poster", h.auth(h.posterForOwner))
	mux.Handle("GET /api/shares/{id}/thumbs/{slug}", h.auth(h.thumbForOwner))
	mux.Handle("GET /api/shares/{id}/text", h.read(h.shareText))
	mux.Handle("GET /api/shares/{id}/uploads/{path...}", h.auth(h.uploadStatus))
	mux.Handle("PUT /api/shares/{id}/preparing/{path...}", h.auth(h.reportPreparing))
	mux.Handle("PATCH /api/shares/{id}", h.auth(h.updateShare))
	mux.Handle("POST /api/shares/{id}/download-ticket", h.auth(h.downloadTicket))
	mux.Handle("DELETE /api/shares/{id}", h.auth(h.deleteShare))
	// Live Shares (server/internal/liveshare): relay-only, nothing lands on disk.
	mux.Handle("POST /api/live-share", h.auth(h.createLiveShare))
	mux.Handle("GET /api/live-share/{id}/jobs", h.auth(h.liveSharePollJobs))
	mux.Handle("POST /api/live-share/jobs/{job}", h.auth(h.liveShareSendJob))
	mux.Handle("POST /api/live-share/jobs/{job}/error", h.auth(h.liveShareFailJob))
	mux.Handle("PATCH /api/live-share/{id}", h.auth(h.patchLiveShare))
	mux.Handle("DELETE /api/live-share/{id}", h.auth(h.deleteLiveShare))
	mux.Handle("GET /api/users", h.adminRead(h.listUsers))
	mux.Handle("POST /api/users", h.admin(h.createUser))
	mux.Handle("GET /api/users/{name}", h.admin(h.getUser))
	mux.Handle("PATCH /api/users/{name}", h.admin(h.updateUser))
	mux.Handle("DELETE /api/users/{name}", h.admin(h.deleteUser))
	mux.Handle("GET /api/usage", h.admin(h.usage))
	mux.Handle("GET /api/admin/log", h.admin(h.adminLog))
	// The upload speed probe counts and discards its body; it is not
	// admin-only, since guests upload too.
	mux.Handle("POST /api/speedtest", h.auth(h.speedTest))
	mux.Handle("GET /api/domain", h.admin(h.getDomain))
	mux.Handle("PUT /api/domain", h.admin(h.putDomain))
	mux.Handle("GET /api/ddns", h.admin(h.getDDNS))
	mux.Handle("GET /api/connectivity", h.admin(h.ddnsOnly(h.getConnectivity)))
	mux.Handle("PUT /api/connectivity", h.admin(h.ddnsOnly(h.putConnectivity)))
	mux.Handle("POST /api/connectivity/check", h.admin(h.ddnsOnly(h.checkConnectivity)))
	mux.Handle("GET /api/ddns/available", h.admin(h.ddnsOnly(h.availableDDNS)))
	mux.Handle("PUT /api/ddns", h.admin(h.putDDNS))
	mux.Handle("DELETE /api/ddns", h.admin(h.deleteDDNS))
	// Public routes are spelled as words. The prefix is a couple of characters
	// against a link whose UUIDv4 slug is 36, so the abbreviation bought
	// nothing and cost every recipient a guess. Every one of these is
	// classified in origincoverage_test.go: adding one here owes an entry
	// there, or it serves from whichever origin the prefix happens to match.
	mux.HandleFunc("GET /favicon.ico", serveIcon(iconICO, "image/x-icon"))
	mux.HandleFunc("GET /icon.svg", serveIcon(iconSVG, "image/svg+xml"))
	mux.HandleFunc("GET /card.png", h.ogImage)
	mux.HandleFunc("GET /card-video.png", h.ogVideoImage)
	mux.HandleFunc("GET /card/{id}/poster.jpg", h.posterImage)
	mux.HandleFunc("GET /share/{id}", compressText(h.brandedNotFound(h.sharePage)))
	mux.HandleFunc("GET /share/{id}/status", compressText(h.shareStatus))
	mux.HandleFunc("GET /thumb/{id}/{slug}", h.thumbImage)
	mux.HandleFunc("GET /view/{id}/{path...}", h.brandedNotFound(h.viewFile))
	mux.HandleFunc("GET /site/{id}", h.brandedNotFound(h.siteRoot))
	mux.HandleFunc("GET /site/{id}/{path...}", h.brandedNotFound(h.siteFile))
	mux.HandleFunc("GET /download/{id}/{path...}", h.downloadRefusals(h.downloadFile))
	mux.HandleFunc("GET /zip/{id}", h.brandedNotFound(h.zipShare))
	mux.HandleFunc("POST /unlock/{id}", h.brandedNotFound(h.passwordSubmit))
	// The access hop: an app-origin unlock passes through it so the file
	// origin sets its own host-only access cookie (accesshop.go).
	mux.HandleFunc("GET /access/{id}", h.brandedNotFound(h.accessHop))
	// Its clear: the web sign-out's file-origin half. The literal segment
	// takes precedence over {id}, and "clear" is never a share id.
	mux.HandleFunc("GET /access/clear", h.accessClear)
	// The inbox surface: the upload page and the one ANONYMOUS
	// write path the server has. Its auth is the request id plus the
	// password cookie when the request is protected, checked inside the
	// handler.
	mux.HandleFunc("GET /receive/{id}", compressText(h.brandedNotFound(h.inboxPage)))
	mux.HandleFunc("PUT /receive/{id}/files/{name}", h.inboxUpload)
	// The front page: how to join this server (join.go). The root pattern
	// with {$} matches "/" alone, so the fallback below keeps every other
	// unknown path.
	mux.HandleFunc("GET /{$}", compressText(h.joinPage))
	mux.HandleFunc("GET /join", compressText(h.joinPage))
	// The web client (internal/webapp): its installed bundle while the
	// switch is on, and the server's own page saying why not otherwise.
	// Pinned to the app origin with the other pages (isPagePath).
	app := webapp.Handler(h.dep.Web, h.webState, h.webCSP)
	mux.Handle("GET /app", app)
	mux.Handle("GET /app/{path...}", app)
	// The browser-facing fallback. The root pattern is least specific, so every
	// route above keeps precedence while an unknown GET on either the free or
	// custom domain gets a real page instead of net/http's plain-text default.
	mux.HandleFunc("GET /", compressText(h.notFoundPage))
	// Payload bytes answer only on files.<domain>; pages and the API only on
	// <domain>. See origins.go for why that boundary is the fix and no
	// response header is. noSniff is outermost so every response carries
	// it, the origin router's own redirect and refusal included.
	return noSniff(hsts(h.origins, originRouter(h.origins, logResponses(recoverPanics(mux)))))
}

// origins is the hostname pair for the CURRENTLY configured domain.
func (h *handler) origins() Origins {
	return OriginsFor(h.dom.Current())
}

// noSniff stops a browser second-guessing a Content-Type. Without it a
// file uploaded as .txt (or a mislabelled .png) can be sniffed into HTML and
// executed, which routes around every decision made from the declared type.
func noSniff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// userKey carries the authenticated user through the request context,
// tokenKey the caller's own token row (its device token, or its web
// session), and adminRouteKey marks a request h.admin let through.
type ctxKey int

const (
	userKey ctxKey = iota
	tokenKey
	adminRouteKey
)

// reqUser returns the authenticated user an auth-wrapped handler runs as.
func reqUser(r *http.Request) metadb.User {
	u, _ := r.Context().Value(userKey).(metadb.User)
	return u
}

// auth refuses a client outside this server's version window (409, before
// the token is looked up), resolves the caller to its user (401 unknown,
// 403 inactive, a 500 when the database cannot answer, which a client must
// not read as a revoked token) and stores the user and the caller's own
// token row in the request context. A request with an Authorization header
// is judged by its bearer token alone; one without is judged by its web
// session cookie, when webCookieAccepted accepts the request, and is
// otherwise unknown. A cookie caller is refused 401 web-session-refused,
// before its session is looked up, on a route cookieRoutes does not class
// cookieJSON, and every answer to it carries Cache-Control: no-store. While
// the web client's switch is off every cookie caller is unknown. A
// request the user made moves the session's idle limit; one marked
// X-HyperDrop-Background: 1 (the change-feed watch, a poll) does not. When
// that move slides a kept session (at most once a minute), the answer sets
// the cookie again with a fresh 30-day Max-Age.
func (h *handler) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := metadb.ParseClientHeader(r.Header.Get("X-HyperDrop-Client"))
		if h.refuseClientOutsideWindow(w, r, client.Version) {
			return
		}
		var u metadb.User
		var tok metadb.Token
		var err error
		cookie, cookieErr := r.Cookie(webCookie)
		switch {
		case r.Header.Get("Authorization") != "":
			raw := bearerToken(r)
			if u, err = h.db.UserByToken(raw, client); err == nil {
				tok = tokenNamed(u, metadb.TokenHash(raw))
			}
		case cookieErr == nil && h.webCookieAccepted(r):
			w.Header().Set("Cache-Control", "no-store")
			if cookieRoutes[r.Pattern] != cookieJSON {
				writeErrorCode(w, http.StatusUnauthorized, "web-session-refused", "this route does not take the web client's session")
				return
			}
			if !h.webOn() {
				// Turning the switch off revokes every session, and one a
				// sign-in minted after that revoke is refused here.
				err = metadb.ErrBadCredentials
				break
			}
			u, tok, err = h.db.UserByWebSession(cookie.Value, client, time.Now(), r.Header.Get("X-HyperDrop-Background") != "1")
			if err == nil && tok.Slid {
				// A kept session's cookie slides with its row.
				setWebCookie(w, cookie.Value, true)
			}
		default:
			err = metadb.ErrBadCredentials
		}
		switch {
		case errors.Is(err, metadb.ErrBadCredentials):
			writeError(w, http.StatusUnauthorized, "invalid or missing token")
			return
		case err != nil:
			writeRefusal(w, err)
			return
		}
		ctx := context.WithValue(context.WithValue(r.Context(), userKey, u), tokenKey, tok)
		next(w, r.WithContext(ctx))
	})
}

// tokenNamed is u's token row whose hash is hash, zero when none is.
func tokenNamed(u metadb.User, hash string) metadb.Token {
	for _, tok := range u.Tokens {
		if tok.SHA256 == hash {
			return tok
		}
	}
	return metadb.Token{}
}

// admin guards an /api route for the admin role. A write (any method but
// GET and HEAD) from a web session also needs the session elevated
// (POST /api/web/session/elevate): 403 web-elevation-required otherwise,
// a code of its own so a client tells it from a route's step-up
// (step-up-required). A device token needs no elevation. The request goes
// on marked adminRouteKey, so the route's own step-up asks an elevated
// session the password alone (webElevated), unless the route names the
// caller's own account ({name}): a change to the caller's own account asks
// the code from every caller, as PATCH /api/me/password does. Account
// names compare exactly, as the users table's key does.
func (h *handler) admin(next http.HandlerFunc) http.Handler {
	return h.auth(func(w http.ResponseWriter, r *http.Request) {
		u := reqUser(r)
		if !u.IsAdmin() {
			writeError(w, http.StatusForbidden, "admin only")
			return
		}
		if tok := h.callerToken(r); r.Method != http.MethodGet && r.Method != http.MethodHead &&
			tok.Kind == metadb.TokenKindWeb && !tok.ElevatedUntil.After(time.Now()) {
			writeErrorCode(w, http.StatusForbidden, "web-elevation-required",
				"confirm your password to make admin changes from the web")
			return
		}
		if r.PathValue("name") == u.Username {
			next(w, r)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), adminRouteKey, true)))
	})
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if len(got) > len(prefix) && got[:len(prefix)] == prefix {
		return got[len(prefix):]
	}
	return ""
}

func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"status": "ok", "version": h.version, "serverID": h.fs.ServerID(),
		// The architecture this binary was built for, so a client updating the
		// server over the API sends the matching build. It is on the OPEN
		// health route because a client reads it before it has authenticated.
		// Non-secret: it is inferable from the binary anyone could fetch.
		"arch": runtime.GOARCH,
	}
	// Whether this server can be updated over its own API, which needs the
	// root-owned installer unit that provisioning installs. A server without
	// that unit reports false, and the client refuses `server update` rather
	// than staging a binary nothing will ever pick up: the fix is a fresh
	// install with HyperDrop Server Management.
	if h.dep.UpdateDir != "" {
		out["updateOverAPI"] = true
	}
	// Who manages the installed binary. A Synology install is updated in
	// Package Center, so the client must not offer the API update even
	// though the version differs.
	if h.dep.Channel != "" {
		out["channel"] = h.dep.Channel
	}
	if h.dep.Platform == "dsm7" || h.dep.Platform == "dsm6" {
		out["platform"] = h.dep.Platform
	}
	// Whether this server has at least one folder a linked share may point
	// at. The app shows its server picker only when this is true.
	if h.roots.Enabled() {
		out["sources"] = true
	}
	// The domain this server serves, so a client whose registry entry holds a
	// bare IP can move its LINKS onto the name. Links are composed CLIENT-side
	// from that entry, so an entry created by joining over an IP hands out IP
	// links forever unless it can learn this.
	//
	// On the UNAUTHENTICATED route deliberately, unlike GET /api/domain, which
	// is admin-only: a guest who joined over an IP is exactly the client that
	// cannot read that route and most needs this. It discloses nothing, the TLS
	// certificate presents the same name to anyone who connects on 443, and
	// og:url embeds it in every unfurl.
	if d := h.advertisedDomain(); d != "" {
		out["domain"] = d
	}
	// Whether /app serves the web client, so an app can offer to open it.
	if h.webState() == webapp.StateOn {
		out["web"] = true
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) usage(w http.ResponseWriter, r *http.Request) {
	sp, err := h.fs.Space()
	if err != nil {
		writeRefusal(w, err)
		return
	}
	shares, bytes, err := h.db.Totals()
	if err != nil {
		writeRefusal(w, err)
		return
	}
	out := map[string]any{
		"mode": "vps", "totalBytes": sp.Total, "usedBytes": sp.Used,
		"freeBytes": sp.Free, "hyperdropBytes": bytes,
		"reservePercent": max(h.fs.ReservePercent, 0), "reserveBytes": sp.Reserve,
	}
	// Server health beyond disk: clients turn these into "your server
	// needs attention" warnings instead of looking broken.
	memTotal, memAvail, load1 := readSysinfo()
	if memTotal > 0 {
		out["memTotalBytes"] = memTotal
		out["memAvailableBytes"] = memAvail
		out["load1"] = load1
	}
	// The verdict is computed HERE, not in each client: the thresholds are a
	// property of the server's own limits (its disk reserve, the host's
	// memory), and three clients deriving them separately would drift.
	// Admin-only, like the rest of /api/usage - a guest reading how close the
	// box is to failing is a disclosure, not a feature.
	out["health"] = h.healthVerdict(sp, memTotal, memAvail)
	out["shares"] = map[string]any{"count": shares}
	writeJSON(w, http.StatusOK, out)
}

// shareOut is the sanitized share view for API responses: passwordHash
// never appears here. hasPassword is the signal every response carries;
// password itself is set by getShare alone, for the share's owner.
type shareOut struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Folder      bool       `json:"folder,omitempty"`
	Entry       string     `json:"entry,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	ModifiedAt  *time.Time `json:"modifiedAt,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	HasPassword bool       `json:"hasPassword,omitempty"`
	// Password is the share's password, set by getShare alone for the
	// owner's bearer: never in a listing, the change feed, the watch, a
	// bulk edit or a public route.
	Password string `json:"password,omitempty"`
	// HasPoster reports a stored preview sidecar, so a client can fetch the
	// thumbnail without probing and 404ing per share.
	HasPoster bool `json:"hasPoster,omitempty"`
	// Media marks a GALLERY: its public link opens the pictures instead of
	// the file listing. Unlike an inbox it is NOT excluded from the
	// default listing, being an ordinary share you hand out.
	Media bool `json:"media,omitempty"`
	// Listing forces the file listing on a share of ONE file, which
	// /share/{id} otherwise redirects straight to.
	Listing bool `json:"listing,omitempty"`
	// Inbox marks an INBOX (a container strangers fill through the public
	// /receive/{id} page); Note, Closed and the caps travel with it. The default
	// listing excludes inboxes: clients ask for them with ?kind=receive.
	Inbox bool `json:"receive,omitempty"`
	// Text marks a TEXT share: one text file the link opens as that file. It
	// takes no other View answer, no second file and no delete (409 text-share).
	Text     bool   `json:"text,omitempty"`
	Note     string `json:"note,omitempty"`
	Closed   bool   `json:"closed,omitempty"`
	MaxBytes int64  `json:"maxBytes,omitempty"`
	MaxFiles int    `json:"maxFiles,omitempty"`
	// Source names the server folder a LINKED share serves live; SourceMissing
	// says that folder cannot be read right now.
	Source        string `json:"source,omitempty"`
	SourceMissing bool   `json:"sourceMissing,omitempty"`
	// Sources is every source of a linked share (one entry for a
	// one-source share); with several, each file lists under its
	// source's base name.
	Sources []string `json:"sources,omitempty"`
	// Linked is what each source's filter does, keyed by source: whether
	// it is fixed to what it held when it was picked, and how many paths
	// it hides. Present only for sources that have a filter; the lists
	// themselves never travel.
	Linked map[string]linked.SourceState `json:"linked,omitempty"`
	// Notify says whether arrivals announce themselves on the owner's
	// clients. A POINTER because it is present on inboxes only and
	// ALWAYS present there: a client must read a definite value rather than
	// infer one from an absent omitempty field.
	Notify *bool `json:"notify,omitempty"`
	// SeenAt is the owner's read watermark; absent until first set.
	SeenAt *time.Time `json:"seenAt,omitempty"`
	// PinnedAt is when the owner pinned the share to the top of their list;
	// absent when it is not pinned. Clients order pinned shares first, the
	// most recent pin on top.
	PinnedAt *time.Time `json:"pinnedAt,omitempty"`
	// Incoming lists a request's uploads IN FLIGHT (claimed name, bytes
	// received, sender's declared total), so the owner watches an upload
	// happen rather than only its result. Authed reads fill it (getShare,
	// the inbox listing, the change feed), and the owner's watch answers it
	// as it moves (inboxprogress.go); it is never on any public surface.
	Incoming []incomingOut `json:"incoming,omitempty"`
	// Pending mirrors scheduled password/expiry changes: hashes stay
	// server-only, clients see only kind/when/set-vs-clear.
	Pending []pendingOut `json:"pending,omitempty"`
	Files   []fileOut    `json:"files"`
	// Folders are the share's EXPLICIT folder records (an empty folder is
	// one); folders a file path implies are read off Files. Never
	// windowed: the database caps the list.
	Folders []string `json:"folders,omitempty"`
	// FileCount and TotalSize describe the WHOLE share, always. Files may be
	// a window onto it in a listing, and then FilesTruncated says so: a
	// client showing "20,000 files" reads it from here, and one that needs
	// the paths fetches GET /api/shares/{id}, which is never capped.
	FileCount      int   `json:"fileCount"`
	FilesTruncated bool  `json:"filesTruncated,omitempty"`
	TotalSize      int64 `json:"totalSize"`
	// Visitors is how many distinct visitors have read the share: one per
	// hd_visitor cookie, or per address and User-Agent for a request without
	// one. Never windowed and never the owner's own bearer reads.
	Visitors int `json:"visitors"`
}

type pendingOut struct {
	Kind    string    `json:"kind"`
	ApplyAt time.Time `json:"applyAt"`
	Clear   bool      `json:"clear,omitempty"`
}

type incomingOut struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	Total int64  `json:"total"`
	// By groups this upload with the rest of one sender's share, so a client
	// can say "2 senders" and announce each one's share once. Empty for a
	// sender that carried no visitor cookie.
	By string `json:"by,omitempty"`
}

// incomingFor maps an inbox's in-flight uploads for the authed DTOs: the
// claimed names with the bytes each has received; nil for an ordinary
// share, and for an inbox nobody is uploading into, so the field stays
// absent.
func (h *handler) incomingFor(v shareView) []incomingOut {
	if !v.Inbox {
		return nil
	}
	out := h.claims.incoming(v.ID)
	if len(out) == 0 {
		return nil
	}
	return out
}

// fileOut is a file row as API responses show it: the stored mime stays
// internal; clients get the derived viewable verdict instead.
type fileOut struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Slug     string `json:"slug"`
	SHA256   string `json:"sha256,omitempty"`
	Viewable bool   `json:"viewable"`
	// Pending: declared in the creation manifest, bytes not yet uploaded.
	// (Distinct from the share-level pending scheduled-actions array.)
	Pending bool `json:"pending,omitempty"`
	// Linked: comes from the live walk of one of the share's sources; no
	// upload, no quota, no delete.
	Linked bool `json:"linked,omitempty"`
	// CommittedAt is when the bytes landed, which clients show as the file's
	// date modified. Absent on a pending entry and on a row that has no
	// commit time.
	CommittedAt *time.Time `json:"committedAt,omitempty"`
	AddedAt     *time.Time `json:"addedAt,omitempty"`
	// UploadedBy groups a received file with the rest of one sender's upload.
	// Filled on INBOXES only, by toShareOut: an owner's own upload
	// session is theirs and has no business on the wire.
	UploadedBy string `json:"uploadedBy,omitempty"`
	// HasThumb says a gallery tile (thumbs/<slug>.jpg) stands for this file
	// and is at least as new as the file: the client derives tiles and
	// needs to know which files still want one, without reading the share
	// back. Filled by resolvedRow on a MEDIA share's owner view only; public
	// pages read the tiles themselves.
	HasThumb bool `json:"hasThumb,omitempty"`
}

func toFileOut(f fileView) fileOut {
	// A file gets its type when its bytes land, so an entry still waiting
	// for them is judged by its name: a client laying out a share mid-upload
	// needs to know which entries it will be able to open.
	return fileOut{Path: f.Path, Size: f.Size, Slug: f.Slug, SHA256: f.SHA256,
		Viewable: mimetype.Viewable(f.MimeOrGuess()), Pending: f.Pending, Linked: f.Linked,
		CommittedAt: f.CommittedAt, AddedAt: f.AddedAt}
}

// resolvedRow is a share as the authed read routes answer it: the sanitized
// DTO plus the two per-row file-layer lookups toShareOut deliberately leaves
// out so it stays a pure mapper. HasPoster costs one os.Stat per row,
// bounded by the caller's page limit.
func (h *handler) resolvedRow(v shareView) shareOut {
	so := toShareOut(v)
	so.HasPoster = h.fs.HasPoster(v.ID)
	so.Incoming = h.incomingFor(v)
	if v.Media {
		// One directory read per share view, never per file, the way the
		// gallery page reads its tiles.
		if tiles, err := h.fs.ThumbTimes(v.ID); err == nil {
			for i := range so.Files {
				so.Files[i].HasThumb = thumbCurrent(v.Files[i], tiles)
			}
		}
	}
	return so
}

// thumbCurrent answers whether the tile written for f still stands for it.
// A stored file's bytes never change under its slug (a replace prunes the
// tile with the row it hands on), so any tile is current; a linked file is
// the NAS's own file and can be overwritten in place, so its tile counts
// only while it is no older than the file's modification time, which the
// walk reports as CommittedAt.
func thumbCurrent(f fileView, tiles map[string]time.Time) bool {
	at, ok := tiles[f.Slug]
	if !ok {
		return false
	}
	if f.Linked && f.CommittedAt != nil && at.Before(*f.CommittedAt) {
		return false
	}
	return true
}

func toShareOut(v shareView) shareOut {
	files := make([]fileOut, 0, len(v.Files))
	for _, f := range v.Files {
		out := toFileOut(f)
		if v.Inbox {
			out.UploadedBy = f.UploadSession
		}
		files = append(files, out)
	}
	var pending []pendingOut
	for _, p := range v.Scheduled {
		pending = append(pending, pendingOut{Kind: p.Kind, ApplyAt: p.ApplyAt, Clear: p.Clear})
	}
	// Totals describes the whole share whether or not Files is a window, so
	// a truncated listing row still reports real figures.
	count, total := v.Totals()
	out := shareOut{
		ID: v.ID, Name: v.Name, Folder: v.Folder, Entry: v.Entry,
		CreatedAt: v.CreatedAt, ModifiedAt: v.ModifiedAt,
		ExpiresAt: v.ExpiresAt, HasPassword: v.PasswordHash != "",
		Media:   v.Media,
		Listing: v.Listing,
		Inbox:   v.Inbox, Text: v.Text, Note: v.Note, Closed: v.Closed,
		MaxBytes: v.MaxBytes, MaxFiles: v.MaxFiles,
		Source: v.Source(), SourceMissing: v.SourceMissing, Sources: v.SourceList(),
		Linked:  v.LinkedState,
		Pending: pending, Files: files, Folders: v.Folders,
		FileCount: count, FilesTruncated: v.Truncated, TotalSize: total,
		Visitors: v.Visitors, PinnedAt: v.PinnedAt,
	}
	if v.Inbox {
		notify := !v.NotifyOff
		out.Notify = &notify
		out.SeenAt = v.SeenAt
		out.MaxFiles = inboxFileLimit(v.MaxFiles, v.Committed)
	}
	return out
}

// updateShare edits an existing share's password/expiry, immediately or
// scheduled via applyInSeconds (the server applies it later; the client can
// be offline). Editing an already-expired-but-unswept share is allowed and
// can rescue it by setting a new expiry.
// shareUpdate is the PATCH /api/shares/{id} body. A named type rather than an
// anonymous struct so the questions asked of it (is anything set? which fields
// belong to an inbox?) can be methods beside the fields they read,
// instead of three long conjunctions inside the handler.
type shareUpdate struct {
	// Pointer semantics: absent = leave unchanged. "" removes the
	// password; expiresInSeconds 0 removes the expiry.
	Password         *string `json:"password"`
	ExpiresInSeconds *int64  `json:"expiresInSeconds"`
	// ApplyInSeconds > 0 schedules the change(s) instead of applying now.
	ApplyInSeconds int64 `json:"applyInSeconds"`
	// CancelPending: "password" | "expiry" | "all".
	CancelPending string `json:"cancelPending"`
	// Name: absent = unchanged. Unlike Password, "" is NOT "remove": a
	// share has to have a name, so an empty one is a 400.
	Name *string `json:"name"`
	// Entry: absent = unchanged, "" = back to the file listing, a relpath
	// = the page /share opens. Not checked against the file list, which may
	// legitimately be empty when this is set: /share resolves it at serve time.
	Entry *string `json:"entry"`
	// Closed/Note mutate an inbox (refused on ordinary shares):
	// closed stops the /receive page accepting uploads, note is its message.
	Closed *bool   `json:"closed"`
	Note   *string `json:"note"`
	// Notify/SeenAt are inbox fields like Closed and Note.
	Notify *bool      `json:"notify"`
	SeenAt *time.Time `json:"seenAt"`
	// MaxBytes/MaxFiles set an inbox's own caps: absent = unchanged, 0 = no
	// cap of its own, negative = refused. A file cap above the server's bound
	// is stored as the bound. Lowering a cap below what the inbox holds
	// deletes nothing; the inbox reads full.
	MaxBytes *int64 `json:"maxBytes"`
	MaxFiles *int   `json:"maxFiles"`
	// Sources replaces the share's sources, validated exactly like create.
	// Refused on an inbox. An empty list is a share with no sources.
	Sources *[]string `json:"sources"`
	// Linked edits what each named source SHOWS of what its walk finds,
	// applied per source and merged with what the share holds: a client that
	// knows one source's change need not know the others'. Applied after
	// Sources, so a source added in the same request can be fixed in it.
	// Refused on an inbox, like Sources.
	Linked map[string]linkedSourceEdit `json:"linked"`
	// Media turns the share into a GALLERY, or back into a file listing.
	// Asymmetric on purpose: false is always allowed, because a listing
	// renders anything, while true is gated on every file that would be
	// TILED being one a browser plays (see galleryRefusal).
	Media *bool `json:"media"`
	// Listing makes a one-file share open its file listing rather than
	// the file. Symmetric, unlike Media: a listing renders anything, so
	// both directions are always allowed.
	Listing *bool `json:"listing"`
	// Pinned pins the share to the top of the owner's list, or unpins it.
	// Pinning an already pinned share keeps its pin time. Refused on an
	// inbox, and never moves modifiedAt: the order of the owner's own list
	// is not a change to the share.
	Pinned *bool `json:"pinned"`
	// pinAt is the pin time a new pin takes, set by a batch so every share
	// it pins shares one time and keeps its place among the others; zero
	// takes the edit's own time.
	pinAt time.Time
}

// linkedSourceEdit is one source's instruction under shareUpdate.Linked.
// Fixed true snapshots the source now (the server walks it and records what
// it found), false returns it to live, absent leaves that alone. Hide takes
// relpaths (source-relative) out of what the source shows; Show is the undo.
type linkedSourceEdit struct {
	Fixed *bool    `json:"fixed"`
	Hide  []string `json:"hide"`
	Show  []string `json:"show"`
}

func (e linkedSourceEdit) edit(source string) metadb.FilterEdit {
	out := metadb.FilterEdit{Source: source, Hide: relPaths(e.Hide), Show: relPaths(e.Show)}
	if e.Fixed != nil {
		out.SetFixed, out.Fixed = true, *e.Fixed
	}
	return out
}

// any reports whether the request asks for anything at all. Every field is a
// pointer or a zero-meaning-absent scalar, so "nothing to change" is a real
// state a client can send by accident.
func (u shareUpdate) any() bool {
	return u.Password != nil || u.ExpiresInSeconds != nil || u.CancelPending != "" ||
		u.Name != nil || u.Entry != nil || u.Closed != nil || u.Note != nil ||
		u.Notify != nil || u.SeenAt != nil || u.Media != nil || u.Listing != nil ||
		u.Sources != nil || len(u.Linked) > 0 || u.Pinned != nil ||
		u.MaxBytes != nil || u.MaxFiles != nil
}

// inboxOnly reports whether the request touches a field that exists only on
// an inbox.
func (u shareUpdate) inboxOnly() bool {
	return u.Closed != nil || u.Note != nil || u.Notify != nil || u.SeenAt != nil ||
		u.MaxBytes != nil || u.MaxFiles != nil
}

// publishOnly reports whether the request touches a field that only a
// PUBLISHED share has. An inbox's content is never served, so none of
// these can apply to one.
func (u shareUpdate) publishOnly() bool {
	return u.Entry != nil || u.Media != nil || u.Listing != nil ||
		u.ExpiresInSeconds != nil || u.ApplyInSeconds > 0 || u.Pinned != nil
}

// options turns the request into the row edit, plus the changes it asks to
// be applied later.
//
// A name ALWAYS applies immediately, even beside a scheduled password or
// expiry change: scheduling exists because an access decision has a "let it
// lapse later" story, and a name has none. The same goes for what the link
// opens. Only the password and the expiry are schedulable, which is why they
// are the only two read under ApplyInSeconds == 0 here and answered as
// scheduled changes when it is not.
func (u shareUpdate) options(name, passwordHash string,
	now time.Time) (metadb.UpdateOptions, []metadb.Scheduled) {
	var o metadb.UpdateOptions
	if u.Name != nil {
		o.SetName, o.Name = true, name
	}
	if u.Entry != nil {
		o.SetEntry, o.Entry = true, *u.Entry
	}
	if u.Media != nil {
		o.SetMedia, o.Media = true, *u.Media
	}
	if u.Listing != nil {
		o.SetListing, o.Listing = true, *u.Listing
	}
	if u.Closed != nil {
		o.SetClosed, o.Closed = true, *u.Closed
	}
	if u.Note != nil {
		o.SetNote, o.Note = true, strings.TrimSpace(*u.Note)
	}
	if u.Notify != nil {
		o.SetNotify, o.Notify = true, *u.Notify
	}
	if u.SeenAt != nil {
		o.SeenAt = u.SeenAt
	}
	if u.MaxBytes != nil {
		o.SetMaxBytes, o.MaxBytes = true, *u.MaxBytes
	}
	if u.MaxFiles != nil {
		o.SetMaxFiles, o.MaxFiles = true, min(*u.MaxFiles, metadb.InboxMaxFiles)
	}
	if u.Pinned != nil {
		o.SetPinned, o.Pinned, o.PinnedAt = true, *u.Pinned, u.pinAt
	}
	if u.ApplyInSeconds <= 0 {
		if u.Password != nil {
			o.SetPassword, o.PasswordHash = true, passwordHash
		}
		if u.ExpiresInSeconds != nil {
			o.SetExpiry, o.ExpiresAt = true, expiryAt(now, *u.ExpiresInSeconds)
		}
		return o, nil
	}
	applyAt := afterSeconds(now, u.ApplyInSeconds)
	var actions []metadb.Scheduled
	if u.Password != nil {
		actions = append(actions, metadb.Scheduled{Kind: metadb.ScheduledPassword,
			ApplyAt: applyAt, Clear: *u.Password == "", PasswordHash: passwordHash})
	}
	if u.ExpiresInSeconds != nil {
		actions = append(actions, metadb.Scheduled{Kind: metadb.ScheduledExpiry, ApplyAt: applyAt,
			Clear: *u.ExpiresInSeconds == 0, ExpiresAt: expiryAt(applyAt, *u.ExpiresInSeconds)})
	}
	return o, actions
}

func (h *handler) updateShare(w http.ResponseWriter, r *http.Request) {
	v, caller, ok := h.ownedShare(w, r)
	if !ok {
		return
	}
	var req shareUpdate
	if !decodeJSONBody(w, r, 1<<20, &req) {
		return
	}
	var hash string
	if req.Password != nil {
		if hash, ok = hashPassword(w, *req.Password); !ok {
			return
		}
	}
	edited, err := h.applyEdit(v, caller, req, hash)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// The full resolved row, not the bare DTO: clients persist this response
	// into their replicas as a whole-row overwrite, so a missing hasPoster or
	// incoming here would erase state the listing had already delivered.
	writeJSON(w, http.StatusOK, h.resolvedRow(edited))
}

// Manifest bounds for share creation. maxManifestFiles is how many entries
// one create request may declare, and createBodyLimit is the budget it is
// sized against: an entry costs about 90 bytes on the wire, so 10,000 of
// them is under a megabyte and the 4 MB body holds a full manifest with
// room for the rest of the request. Past that count a create stops
// describing a share anybody is going to watch land.
const (
	maxManifestFiles = 10000
	createBodyLimit  = 4 << 20
)

// kindInbox is the ?kind= value that scopes a listing to inboxes.
const kindInbox = "receive"

// Bounds for a STREAM share's manifest, which is the whole share: every file
// the relay will ever serve is described in the create (or addFiles) request,
// with mime and mtime beside path and size, and nothing arrives later. The
// stored caps above size an OPTIONAL early-links manifest a client skips for
// a big folder; a stream client cannot skip it, and an ordinary project
// folder (node_modules, .git) runs to tens of thousands of files. What bounds
// a stream manifest is the registry's memory (about 250 B an entry for the
// life of the relay, so ~25 MB at the cap, times the per-owner share cap) and
// the listing page rendered from it (about 330 B a row); the byte bound
// leaves room for the long paths a dependency tree has.
const (
	liveShareManifestMaxFiles = 100000
	liveShareBodyLimit        = 64 << 20
)

func (h *handler) createShare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Folder bool   `json:"folder"`
		// Entry: the relpath /share/{id} opens instead of the listing. Set at
		// creation, when the manifest's files are all still pending, so it
		// is validated as a path and resolved against the files at serve
		// time.
		Entry            string `json:"entry"`
		Password         string `json:"password"`
		ExpiresInSeconds int64  `json:"expiresInSeconds"`
		// ReserveBytes: the client's total upload size, admission-checked
		// against free space minus other uploads' live reservations, so two
		// clients can't both start into space that fits only one.
		ReserveBytes int64 `json:"reserveBytes"`
		// Files: optional manifest. Each entry becomes a pending file row
		// with a pre-minted slug, so links exist before the upload starts.
		Files []struct {
			Path string `json:"path"`
			Size int64  `json:"size"`
		} `json:"files"`
		// Media creates a GALLERY: /share/{id} renders the pictures instead
		// of the file listing. Declared here and nowhere else, because the
		// client acts on it before the first byte is uploaded.
		Media bool `json:"media"`
		// Listing forces the file listing on a share of ONE file, which
		// /share/{id} otherwise redirects straight to.
		Listing bool `json:"listing"`
		// Inbox creates an INBOX: a container strangers fill through the
		// public /receive/{id} page. Note is the page's message; the caps bound
		// what the request accepts in total (defaults when 0).
		Inbox bool `json:"receive"`
		// Text creates a TEXT share: one text file, opened as that file.
		Text     bool   `json:"text"`
		Note     string `json:"note"`
		MaxBytes int64  `json:"maxBytes"`
		MaxFiles int    `json:"maxFiles"`
		// Source creates a LINKED share of a folder or file already on the
		// server's disk: no manifest, no receive flag and no reservation,
		// because there is nothing to upload.
		Source string `json:"source"`
		// Sources makes ONE linked share of several picks at once; each
		// lists under its own name. Exclusive with Source.
		Sources []string `json:"sources"`
	}
	// A LimitReader would truncate an oversized manifest into invalid JSON and
	// report it as a syntax error, which is exactly how a 765k-file folder
	// share fails to explain itself. MaxBytesReader makes the size the error.
	if body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, createBodyLimit)); err != nil {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "body-too-large",
			fmt.Sprintf("share request too large (limit %d bytes): send at most %d files in the manifest",
				createBodyLimit, maxManifestFiles))
		return
	} else if len(body) > 0 {
		if err := decodeRequest(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, badJSONMessage(err))
			return
		}
	}
	req.Entry = relPath(req.Entry)
	for i := range req.Files {
		req.Files[i].Path = relPath(req.Files[i].Path)
	}
	if len(req.Files) > maxManifestFiles {
		writeErrorCode(w, http.StatusRequestEntityTooLarge, "manifest-too-big",
			fmt.Sprintf("manifest has %d files, the limit is %d: create the share without a manifest and upload into it",
				len(req.Files), maxManifestFiles))
		return
	}
	if req.Entry != "" && !shareid.ValidRelPath(req.Entry) {
		writeError(w, http.StatusBadRequest, "entry must be a relative path inside the share")
		return
	}
	// A name is optional at creation (a client may simply not send one), but
	// one that arrives must be usable: the same rule the rename path applies.
	if req.Name != "" {
		clean, err := cleanShareName(req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Name = clean
	}
	// A gallery is a published page, and both of these answer the same
	// question it does: an inbox is never served publicly at all, and
	// an entry names some other page as the landing one.
	if err := (linkOpens{Listing: req.Listing, Entry: req.Entry != "",
		Gallery: req.Media, Inbox: req.Inbox, Text: req.Text}).refuse(); err != nil {
		writeRefusal(w, err)
		return
	}
	if req.Source != "" && len(req.Sources) > 0 {
		writeErrorCode(w, http.StatusBadRequest, "bad-source", "give source or sources, not both")
		return
	}
	sources := req.Sources
	if req.Source != "" {
		sources = []string{req.Source}
	}
	if len(sources) > 0 {
		if req.Inbox {
			writeErrorCode(w, http.StatusBadRequest, "source-exclusive",
				"an inbox takes no sources")
			return
		}
		anyDir, err := h.sourceListRefusal(reqUser(r), sources)
		if err != nil {
			writeRefusal(w, err)
			return
		}
		// A share of several sources, or of a source beside uploads, is a
		// folder: it lists more than one thing.
		req.Folder = req.Folder || anyDir || len(sources) > 1 || len(req.Files) > 0
		specs := make([]linked.SourceSpec, 0, len(sources))
		for _, src := range sources {
			specs = append(specs, linked.SourceSpec{Path: src})
		}
		for _, f := range req.Files {
			if err := h.sourceSpecNameRefusal(specs, len(sources) > 1, f.Path); err != nil {
				writeRefusal(w, err)
				return
			}
		}
	}
	if req.Inbox {
		// A request carries none of a share's publish-side machinery: no
		// manifest (nothing is known up front), no entry page (its content
		// is never served publicly), no expiry (close is the off switch),
		// and no reservation (the owner is not about to upload).
		if len(req.Files) > 0 || req.Entry != "" || req.ExpiresInSeconds != 0 || req.ReserveBytes != 0 {
			writeError(w, http.StatusBadRequest, "an inbox takes no manifest, entry, expiry or reservation")
			return
		}
		// The name titles the upload page, so unlike a share there is no
		// filename to fall back on.
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "an inbox needs a name")
			return
		}
		req.Note = strings.TrimSpace(req.Note)
		if err := inboxNoteRefusal(req.Note); err != nil {
			writeRefusal(w, err)
			return
		}
		// The caps are opt-in: 0 stays 0 (unlimited), the owner's quota
		// being the standing bound. A file cap above the server's bound is
		// stored as that bound, the most any inbox takes.
		if req.MaxBytes < 0 || req.MaxFiles < 0 {
			writeError(w, http.StatusBadRequest, "negative cap")
			return
		}
		req.MaxFiles = min(req.MaxFiles, metadb.InboxMaxFiles)
	} else if req.Note != "" || req.MaxBytes != 0 || req.MaxFiles != 0 {
		writeError(w, http.StatusBadRequest, "note and caps apply to Receive Inboxes only")
		return
	}
	u := reqUser(r)
	// Quotas cap how much a guest can STORE; this caps how fast they can
	// create.
	if !h.allowCreate(w, u) {
		return
	}
	opts := metadb.CreateOptions{Name: req.Name, Owner: u.Username, Folder: req.Folder,
		Entry:   req.Entry,
		Media:   req.Media,
		Listing: req.Listing,
		Inbox:   req.Inbox, Text: req.Text, Note: req.Note,
		MaxBytes: req.MaxBytes, MaxFiles: req.MaxFiles,
		Sources: sources}
	for _, f := range req.Files {
		opts.Files = append(opts.Files, metadb.PendingFile{Path: f.Path, Size: f.Size})
	}
	hash, ok := hashPassword(w, req.Password)
	if !ok {
		return
	}
	opts.PasswordHash = hash
	if req.Password != "" {
		plain := req.Password
		opts.SealPassword = func(id string) ([]byte, error) { return h.sealPassword(id, hash, plain) }
	}
	opts.ExpiresAt = expiryAt(time.Now(), req.ExpiresInSeconds)
	d, err := h.db.CreateShare(opts)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	// The sources were admitted against the allowlist this request carried;
	// asked again now the share exists, a narrowing that committed in
	// between refuses the create as the admission would have (ungranted).
	if lost, err := h.ungranted(u.Username, sources); err != nil || len(lost) > 0 {
		_ = h.db.DeleteShare(d.ID)
		if err == nil {
			err = refuse(http.StatusForbidden, "source-forbidden", "this account may not share from "+lost[0])
		}
		writeRefusal(w, err)
		return
	}
	v := h.viewFrom(d)
	if d.Linked() {
		// The create response carries the first walk of the source, the
		// same as any later read: a client that lists what it just made
		// must see the files without a second round trip. A share the
		// server just created but cannot read back is an error: a later
		// GET would 500 the same way.
		if v.SourceMissing {
			_ = h.db.DeleteShare(d.ID)
			writeError(w, http.StatusInternalServerError, "source is unreadable")
			return
		}
		// linkOpens.refuse only checks the exclusivity of Entry/Listing/
		// Gallery/Inbox; a linked share's files are only known after this walk,
		// so gallery playability is gated here instead, exactly as PATCH
		// gates it against an ordinary share's already-uploaded files.
		if req.Media {
			if err := galleryRefusal(v); err != nil {
				_ = h.db.DeleteShare(d.ID)
				writeRefusal(w, err)
				return
			}
		}
	}
	if req.ReserveBytes > 0 {
		err := h.ownerRoom(u, d.ID, "", req.ReserveBytes)
		if err == nil {
			err = h.fs.Reserve(d.ID, u.Username, req.ReserveBytes)
		}
		if err != nil {
			_ = h.db.DeleteShare(d.ID)
			switch {
			case errors.Is(err, metadb.ErrQuota):
				writeErrorCode(w, http.StatusInsufficientStorage, "quota", err.Error())
			default:
				// The one upload failure a server OWNER can act on, so it
				// carries a code the app can name a remedy for.
				writeErrorCode(w, http.StatusInsufficientStorage, "no-space",
					spaceMessage(err, u.IsAdmin()))
			}
			return
		}
	}
	writeJSON(w, http.StatusCreated, h.resolvedRow(v))
}

// getShare returns one share by ID, the single-share read the client uses
// after a replace/edit, so it doesn't fetch the whole listing for one entry.
// It is the one route that answers `password`, to the owner's bearer only
// (ownedShare refuses anyone else, an admin included) and under no-store; a
// copy that does not open leaves it out and the share reads as set.
func (h *handler) getShare(w http.ResponseWriter, r *http.Request) {
	v, _, ok := h.ownedShare(w, r)
	if !ok {
		return
	}
	out := h.resolvedRow(v)
	if pw := h.readablePassword(v.Share); pw != "" {
		out.Password = pw
		w.Header().Set("Cache-Control", "no-store")
	}
	writeJSON(w, http.StatusOK, out)
}

// Listing page bounds: an absent/invalid limit gets metadb.DefaultListLimit;
// nothing can ask for more than metadb.MaxListLimit rows in one response.
// Clients page with offset until they have total.
//
// File bounds on a listing. Rows bound the page in SHARES; these bound it in
// FILES. Without them, 500 rows over 20,000-file shares would build ten
// million file entries for one response, about 4 GB, reachable from the
// app's ordinary Shares screen.
//
// Two ceilings, because neither covers the other. The per-share cap stops one
// fat share; the page budget stops many medium ones (metadb.MaxListLimit rows
// at the per-share cap is still 200,000 entries). A row past the cap reports
// its true fileCount and totalSize with filesTruncated set, and clients fetch
// the whole record with GET /api/shares/{id}, which is never capped.
//
// Vars, not consts, only so tests can shrink them; nothing on the request path
// writes them.
var (
	listMaxFilesPerShare = metadb.DefaultMaxFilesPerShare
	listMaxFilesPerPage  = metadb.DefaultMaxFilesPerPage
)

// listShares returns one page of the caller's own shares, newest first, every
// role scoped the same way, an admin included. Response: {shares, total,
// offset, totalBytes} - total counts everything the query matches (so
// clients know how far the pages go), and totalBytes is the committed bytes
// of those same matches.
func (h *handler) listShares(w http.ResponseWriter, r *http.Request) {
	u := reqUser(r)
	q := metadb.ListQuery{Name: r.URL.Query().Get("q"), Limit: metadb.DefaultListLimit,
		MaxFiles: listMaxFilesPerShare, MaxPageFiles: listMaxFilesPerPage,
		After: r.URL.Query().Get("after")}
	// The default listing is ordinary shares only; inboxes are their own
	// scope (?kind=receive), so no existing consumer ever sees them.
	switch kind := r.URL.Query().Get("kind"); kind {
	case "", kindInbox:
		q.Kind = kind
	default:
		writeError(w, http.StatusBadRequest, "kind takes receive")
		return
	}
	q.Owner = u.Username
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v > 0 {
		q.Offset = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		q.Limit = min(v, metadb.MaxListLimit)
	}
	page, err := h.db.List(q)
	if errors.Is(err, metadb.ErrBadRequest) {
		writeError(w, http.StatusBadRequest, "invalid cursor")
		return
	}
	if err != nil {
		writeRefusal(w, err)
		return
	}
	out := make([]shareOut, 0, len(page.Shares))
	for _, d := range page.Shares {
		out = append(out, h.resolvedRow(h.viewFrom(d)))
	}
	resp := map[string]any{
		"shares": out, "total": page.Total, "offset": q.Offset, "totalBytes": page.TotalBytes,
	}
	if page.NextCursor != "" {
		resp["nextCursor"] = page.NextCursor
	}
	writeJSON(w, http.StatusOK, resp)
}

// commitUpload commits a part Write staged whole, of size bytes (see
// commitWith): a batch entry's or an inbox upload's.
func (h *handler) commitUpload(in metadb.CommitInput, size int64) (metadb.File, error) {
	var check func() error
	if in.Anonymous {
		// A stranger's upload never replaces a file, whoever committed it.
		// Every commit writes its row under the path's lock, which check runs
		// under, so a committed row it does not see cannot land before this
		// commit's own; refusing here leaves the owner's bytes untouched.
		// On a volume that folds case the row it must not replace is the
		// one its name folds onto (metadb.Spelling).
		check = func() error {
			p, err := h.db.Spelling(in.ShareID, in.Path, "")
			if err != nil {
				return err
			}
			if f, err := h.db.File(in.ShareID, p); err == nil && !f.Pending {
				return metadb.PathTaken(in.Path)
			} else if err != nil && !errors.Is(err, metadb.ErrNotFound) {
				return err
			}
			return nil
		}
	}
	return h.commitWith(in, func(record sharefs.Record) (sharefs.Committed, error) {
		return h.fs.CommitChecked(in.ShareID, in.Path, size, check, record)
	})
}

// commitWith is the second half of every upload whose bytes are staged:
// commit renames the staged part into files/ (Commit for a part Write
// staged, CommitRanged for a ranged one) and writes the row through record, under
// the path's lock. The rename comes first because a crash between leaves a
// pending row and a file nothing serves, which the client's retry
// overwrites and the stalled sweep removes; the other order would leave a
// committed row naming bytes that are not there. A row the database refuses
// (quota, cap, a closed inbox) takes its bytes with it, and the file layer
// puts back what the path held, so a refused overwrite leaves the previous
// version served as it was. in names the path and who is committing; the
// staged part fills in what the bytes are.
func (h *handler) commitWith(in metadb.CommitInput, commit func(sharefs.Record) (sharefs.Committed, error)) (metadb.File, error) {
	id, rel := in.ShareID, in.Path
	var f metadb.File
	refused := false
	_, err := commit(func(c sharefs.Committed) error {
		in.Size, in.SHA256, in.Mime = c.Size, c.SHA256, c.Mime
		var err error
		f, err = h.db.CommitFile(in)
		refused = err != nil
		return err
	})
	switch {
	case refused:
		// When the previous bytes could not be put back they went with the
		// refused ones, and a link must never serve a path whose file is
		// gone, so a committed row for it goes too.
		if before, err := h.db.File(id, rel); err == nil && !before.Pending {
			if _, err := h.fs.Stat(id, rel); errors.Is(err, sharefs.ErrNotFound) {
				_, _, _ = h.db.RemoveFiles(id, []string{rel})
			}
		}
		return metadb.File{}, err
	case err != nil:
		// A path the filesystem refuses can never commit, so its part is
		// not resume state.
		if errors.Is(err, sharefs.ErrBadPath) {
			h.fs.Discard(id, rel)
		}
		return metadb.File{}, err
	}
	h.prep.forgetFile(id, rel)
	return f, nil
}

// declareOwn declares rel's pending row before a batch entry's first byte
// and answers the func that withdraws it when the entry fails, so a lost
// connection leaves no entry nothing will ever fill. Only a row this request
// created is withdrawn: one the creation manifest declared keeps its slug
// for the retry.
func (h *handler) declareOwn(id, rel string, size int64) (withdraw func(), err error) {
	_, heldErr := h.db.File(id, rel)
	ours := errors.Is(heldErr, metadb.ErrNotFound)
	if _, err := h.db.DeclareFile(id, rel, size); err != nil {
		return nil, err
	}
	return func() {
		if ours {
			_ = h.db.RemovePending(id, rel)
		}
	}, nil
}

func (h *handler) uploadFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rel := relPathParam(r)
	v, u, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	rel = h.spelled(id, rel, "")
	// The one refusal a linked source imposes on an upload's name.
	if err := h.sourceNameRefusal(v, rel); err != nil {
		writeRefusal(w, err)
		return
	}
	// ?replaces=<oldpath>: once this upload commits, the new file inherits
	// oldpath's public slug and oldpath is removed, so links keep working.
	// ?replaceAll=1: on commit the new file becomes the share's ONLY file
	// (slug inheritance per metadb.ReplaceAll): whole-share replacement.
	replaces := relPath(r.URL.Query().Get("replaces"))
	replaceAll := r.URL.Query().Get("replaceAll") == "1"
	if replaces != "" && replaceAll {
		writeError(w, http.StatusBadRequest, "replaces and replaceAll are mutually exclusive")
		return
	}
	if err := textShareRefusal(v, rel, textShareReplacing(v, replaces, replaceAll)); err != nil {
		writeRefusal(w, err)
		return
	}

	// Optional transport compression: the body is decompressed while being
	// received, so everything downstream (ranges, sizes, hashes, and the
	// Upload-Total a decoded body is checked against) stays in original bytes.
	body, cleanup, _, err := decodeBody(w, r)
	if err != nil {
		return // decodeBody has already answered
	}
	defer cleanup()

	session := r.Header.Get("Upload-Session")
	if !validUploadSession(session) {
		writeError(w, http.StatusBadRequest, "invalid Upload-Session")
		return
	}

	if r.Header.Get("Upload-Range") == "" {
		writeError(w, http.StatusBadRequest, "Upload-Range and Upload-Total are required")
		return
	}
	h.uploadRanged(w, r, uploadPut{id: id, rel: rel, session: session, replaces: replaces,
		replaceAll: replaceAll, u: u, body: body})
}

// applyReplaces runs the ?replaces= slug transfer (or the ?replaceAll=1
// whole-share collapse) after a committed upload, returning the entry with
// its final (inherited) slug and removing the bytes and tiles of what it
// replaced.
func (h *handler) applyReplaces(id, rel, replaces string, replaceAll bool, entry metadb.File) (metadb.File, error) {
	if replaces == "" && !replaceAll {
		return entry, nil
	}
	// The paths and slugs the rows are about to lose, read before the write:
	// afterwards there is nothing left to name the bytes and the tiles. A
	// whole-share replace loses every other file; ?replaces= loses one row
	// at most, so that row alone is read.
	var before []metadb.File
	if replaceAll {
		all, err := h.db.Share(id)
		if err != nil {
			return entry, err
		}
		before = all.Files
	} else {
		old, err := h.db.File(id, replaces)
		switch {
		case err == nil:
			before = []metadb.File{old}
		case !errors.Is(err, metadb.ErrNotFound):
			return entry, err
		}
	}
	var d metadb.Share
	var err error
	if replaceAll {
		d, err = h.db.ReplaceAll(id, rel)
	} else {
		d, err = h.db.ReplaceEntry(id, rel, replaces)
	}
	// A replace naming nothing the share holds is the request's mistake,
	// not a missing share: the upload itself has committed.
	if errors.Is(err, metadb.ErrNotFound) {
		return entry, refuse(http.StatusBadRequest, "", err.Error())
	}
	if err != nil {
		return entry, err
	}
	for _, f := range before {
		if f.Path == rel || (!replaceAll && f.Path != replaces) {
			continue
		}
		_ = h.fs.RemoveFile(id, f.Path)
		h.fs.RemoveThumb(id, f.Slug)
	}
	for _, f := range d.Files {
		if f.Path == rel {
			entry = f
			break
		}
	}
	return entry, nil
}

// spaceMessage keeps the server-wide detail (how much room is left, how much
// other uploads have promised) for the admin and gives a guest the bare fact.
// /api/usage is admin-only for the same reason: a 507 a guest can trigger at
// will must not become a side channel for it. Quota messages are NOT routed
// through here: those describe the caller's own account.
func spaceMessage(err error, isAdmin bool) string {
	if isAdmin {
		return err.Error()
	}
	return "not enough space on the server right now, ask whoever runs it"
}

// writeUploadDone sends the 201 upload response, echoing the stored size (the
// client hard-fails on mismatch) and the file's public slug.
func (h *handler) writeUploadDone(w http.ResponseWriter, f metadb.File) {
	writeJSON(w, http.StatusCreated, map[string]any{
		"path": f.Path, "size": f.Size, "slug": f.Slug,
		"sha256": f.SHA256, "viewable": mimetype.Viewable(f.Mime)})
}

// uploadStatus tells a resuming client where an upload stands for its
// session. The session's own ranged part answers first (its missing
// ranges), so a session re-sending a file it committed before reads the new
// bytes, not the old commit; then this session's commit (so a commit whose
// answer was lost is never read as another device's part); then another
// session's part, which is resumed from 0; then any commit; then nothing
// staged.
func (h *handler) uploadStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rel := relPathParam(r)
	v, _, ok := h.ownedShareMeta(w, r)
	if !ok {
		return
	}
	rel = h.spelled(id, rel, "")
	session := r.URL.Query().Get("session")
	if !validUploadSession(session) {
		writeError(w, http.StatusBadRequest, "invalid session")
		return
	}
	if st, ok := h.fs.PartRanges(id, rel, session); ok {
		writeJSON(w, http.StatusOK, map[string]any{"offset": st.Prefix, "complete": false,
			"total": st.Total, "missing": st.Missing})
		return
	}
	pending, err := h.fs.PartSize(id, rel)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	f, held, err := h.statusFile(v, id, rel)
	if err != nil {
		writeRefusal(w, err)
		return
	}
	if held && !f.Pending && f.UploadSession == session {
		writeJSON(w, http.StatusOK, completeStatus(f))
		return
	}
	if pending > 0 {
		// A partial belongs to the session that staged it; anyone else's
		// resume point is 0 (their first chunk starts a fresh part).
		writeJSON(w, http.StatusOK, map[string]any{"offset": 0, "complete": false})
		return
	}
	if held && !f.Pending {
		writeJSON(w, http.StatusOK, completeStatus(f))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"offset": 0, "complete": false})
}

// statusFile is the row the status route answers from: the windowed view's,
// or for a stored path past the window the row itself (a stored file
// outranks a linked entry of the same path).
func (h *handler) statusFile(v shareView, id, rel string) (fileView, bool, error) {
	f, ok := v.FileByPath(rel)
	if v.Truncated {
		stored, err := h.db.File(id, rel)
		switch {
		case err == nil:
			return fileView{File: stored}, true, nil
		case !errors.Is(err, metadb.ErrNotFound):
			return fileView{}, false, err
		}
	}
	return f, ok, nil
}

// completeStatus answers a committed file: its size, slug and hash, and the
// session that committed it, so a client whose commit answer was lost can
// tell its own commit from another device's same-size one.
func completeStatus(f fileView) map[string]any {
	return map[string]any{"offset": f.Size, "complete": true, "size": f.Size, "slug": f.Slug,
		"sha256": f.SHA256, "viewable": mimetype.Viewable(f.Mime), "session": f.UploadSession}
}

// validUploadSession bounds the required client-minted upload-session identity.
func validUploadSession(s string) bool {
	if len(s) < 6 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

func (h *handler) deleteShare(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := h.ownedShareMeta(w, r); !ok {
		return
	}
	if err := h.removeShare(r.PathValue("id")); err != nil {
		writeRefusal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// zstdDecoders pools stream decoders across compressed PUTs: building one
// per request is expensive; klauspost's documented reuse is Reset per stream.
// Pooled decoders are never Closed.
//
// Deliberately UNCAPPED in number, unlike bcryptSem and zipSem: decode
// measures 12 to 15 GB/s per core and scales linearly across them, i.e. ~100×
// what a 1 Gbit/s link can deliver, so it cannot be the CPU that runs out.
// See BenchmarkUploadDecode for the numbers and the reasoning. Memory is
// what a stream could exhaust: a decoder buffers twice the window a frame
// declares, so a 42-byte body declaring zstd's 512 MiB maximum would cost a
// gigabyte. zstdMaxWindow bounds it, for a frame's declared window and, as
// the decoder's memory bound, for a single-segment frame's content size,
// which stands in for its window.
var zstdDecoders = sync.Pool{New: func() any {
	zr, _ := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(zstdMaxWindow), zstd.WithDecoderMaxMemory(zstdMaxWindow))
	return zr
}}

// zstdMaxWindow is the largest window a compressed upload may declare: eight
// times the 8 MiB the reference client's encoder uses at every level
// (core/api compress.go), so a stream past it is refused as a bad request.
const zstdMaxWindow = 64 << 20

// Pending or disconnected managed domains must not pull a direct-IP client
// back onto an unapproved name or a released name still cached in DNS.
func (h *handler) advertisedDomain() string {
	d := h.dom.Current()
	if h.ddns != nil && strings.HasSuffix(d, "."+ddns.Zone) {
		st := h.ddns.Store().Snapshot()
		if !h.ddns.Store().Configured() || ddns.FQDN(st.Name) != d {
			return ""
		}
	}
	return d
}

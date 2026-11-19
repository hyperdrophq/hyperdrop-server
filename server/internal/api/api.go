// Package api wires the HyperDrop server's HTTP routes: the /api surface
// used by client apps (login-minted per-user bearer tokens) and the public
// share routes. Self-hosted VPS only: the rows live in a local database and
// the bytes on the local filesystem.
package api

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/selfupdate"
	"hyperdrop/server/internal/sharefs"
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
	// signInMeter limits the correct passwords one account presents.
	signInMeter *signInMeter
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
	// copies runs the duplicates' copy work (duplicate.go).
	copies copier
	// publishes serializes a commit and an abort of one publish, and
	// publishOpenMu the opens, so two cannot both pass the per-owner cap
	// (publish.go).
	publishes     publishLocks
	publishOpenMu sync.Mutex
	// publishPrepared, when set, runs once a commit's journal is written,
	// before the commit takes the share's swap lock: the tests' seam.
	publishPrepared func(id, pid string)
	// rowsRemoved, when set, runs after a removal's rows are gone and
	// before its bytes go: the tests' seam.
	rowsRemoved func(id string, paths []string)
	// prep holds the senders' preparing reports on pending files (preparing.go).
	prep *prepTracker
	// webSwitchUnread is true while the web client's switch cannot be read
	// (webOn), so the log says so once.
	webSwitchUnread atomic.Bool
	// desktopSwitchUnread is the same for the desktop sign-in's switch
	// (desktopSignInOn).
	desktopSwitchUnread atomic.Bool
	// requireTwoFactorUnread is the same for the require-two-factor switch
	// (requireTwoFactorSince).
	requireTwoFactorUnread atomic.Bool
	// requireTwoFactorUnparsed is true while the require-two-factor switch
	// holds a value that is no time, so the log says so once.
	requireTwoFactorUnparsed atomic.Bool
	// knownKey is the known-browser cookie's MAC key (knownbrowser.go), the
	// volume secret's subkey for knownKeyInfo; empty only when the handler
	// has no file store, which mints no cookie and holds none.
	knownKey []byte
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
	// Phone first (desktopexpect.go): the phone expects a computer's key,
	// the computer arrives and proves it, and the arrival joins the routes
	// above.
	mux.Handle("POST /api/me/desktop-sign-ins/expect", h.auth(h.expectDesktopSignIn))
	mux.Handle("GET /api/me/desktop-sign-ins/{id}", h.auth(h.desktopSignInArrival))
	mux.HandleFunc("POST /api/auth/desktop-sign-in/arrive", h.arriveDesktopSignIn)
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
	// the calling token's row; the presence read answers from the account's
	// activity spans.
	mux.Handle("GET /api/me/push", h.read(h.getPush))
	mux.Handle("PUT /api/me/push", h.auth(h.putPush))
	mux.Handle("DELETE /api/me/push", h.auth(h.deletePush))
	mux.Handle("PUT /api/me/activity", h.auth(h.putActivity))
	mux.Handle("GET /api/me/presence", h.read(h.getPresence))
	// Optional TOTP second factor, self-scope. The literal /confirm,
	// /recovery and /replace segments sit under the same /api/me/totp path
	// with distinct methods, so no wildcard is involved.
	mux.Handle("GET /api/me/totp", h.read(h.totpStatus))
	mux.Handle("POST /api/me/totp", h.auth(h.totpStart))
	mux.Handle("POST /api/me/totp/confirm", h.auth(h.totpConfirm))
	mux.Handle("DELETE /api/me/totp", h.auth(h.totpDisable))
	mux.Handle("POST /api/me/totp/recovery", h.auth(h.totpRecovery))
	mux.Handle("POST /api/me/totp/replace", h.auth(h.totpReplaceStart))
	mux.Handle("POST /api/me/totp/replace/confirm", h.auth(h.totpReplaceConfirm))
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
	mux.Handle("POST /api/shares/{id}/duplicate", h.auth(h.duplicateShare))
	mux.Handle("POST /api/shares/{id}/file-links", h.auth(h.mintFileLinks))
	mux.Handle("DELETE /api/shares/{id}/file-links/{slug}", h.auth(h.stopFileLink))
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
	// An atomic publish (publish.go): open one, commit it, or abort it.
	mux.Handle("POST /api/shares/{id}/publishes", h.auth(h.publishOpen))
	mux.Handle("POST /api/shares/{id}/publishes/{pid}/commit", h.auth(h.publishCommit))
	mux.Handle("DELETE /api/shares/{id}/publishes/{pid}", h.auth(h.publishAbort))
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
	mux.HandleFunc("GET /apple-touch-icon.png", serveIcon(iconTouch, "image/png"))
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
	// The re-access route: a file-origin navigation without a valid copy of
	// the access cookie passes through it on the app origin (accesshop.go).
	mux.HandleFunc("GET /reaccess/{id}", h.brandedNotFound(h.reaccess))
	// Its clear: the web sign-out's file-origin half. The literal segment
	// takes precedence over {id}, and "clear" is never a share id.
	mux.HandleFunc("GET /access/clear", h.accessClear)
	// A file link: one file of one share, addressed by a key that names
	// neither (filelink.go). Its status poll answers JSON, so its 404 stays
	// JSON.
	mux.HandleFunc("GET /f/{fileKey}", h.brandedNotFound(h.fileLinkView))
	mux.HandleFunc("GET /f/{fileKey}/download", h.brandedNotFound(h.fileLinkDownload))
	mux.HandleFunc("GET /f/{fileKey}/status", h.fileLinkStatus)
	mux.HandleFunc("POST /f/{fileKey}/unlock", h.brandedNotFound(h.fileLinkUnlock))
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

package api

import (
	"hyperdrop/core/domainconn"
	"hyperdrop/core/inboxannounce"
	"hyperdrop/core/updatenotice"
	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/liveshare"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/pushrelay"
	"hyperdrop/server/internal/selfupdate"
	"hyperdrop/server/internal/shareid"
	"hyperdrop/server/internal/updatesig"
	"hyperdrop/server/internal/volsecret"
	"hyperdrop/server/internal/webapp"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

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
// after any send in flight, writes every visit still pending, so a
// shutdown loses none, and stops the duplicates' copies (duplicate.go).
func (s *Server) Drain() {
	if s.h.push != nil {
		s.h.push.stop()
	}
	s.drainOnce.Do(func() { close(s.h.watch.drain) })
	s.h.liveShareReg.Drain()
	s.h.visits.close()
	s.h.updates.Stop()
	s.h.copies.stop(copyStopWait)
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
	// CertificatePending, when set, answers the served domain that has no
	// certificate in storage yet ("" when it has one or none is served). The
	// health verdict reports it, since every handshake is refused until then.
	CertificatePending func() string
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
	// keyspace. A collision (astronomically unlikely at ~94 bits of entropy,
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
		signInMeter: newSignInMeter(),
		limits: rateLimits{
			pw: newPWLimiter(), login: newPWLimiter(), create: newCreateLimiter(),
			inboxFail: newTokenLimiter(inboxFailBurst, inboxFailPerHour),
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
			NewSlug: shareid.NewSlug, NewFileKey: shareid.NewFileKey, MaxVisitors: metadb.MaxVisitorsPerShare,
			MaxFiles: liveShareManifestMaxFiles, MaxJobs: liveShareMaxJobs(ReadMemory().Limit),
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
		h.push.domainChanges = func() []domainconn.ChangeNotice {
			list, err := h.db.DomainChanges(time.Now())
			if err != nil {
				return nil
			}
			out := make([]domainconn.ChangeNotice, 0, len(list))
			for _, c := range list {
				out = append(out, domainconn.NoticeOf(c))
			}
			return out
		}
	}
	b.FS.SidecarRoom = h.sidecarRoom
	return h
}

// origins is the hostname pair for the CURRENTLY configured domain.
func (h *handler) origins() Origins {
	return OriginsFor(h.dom.Current())
}

// Pending or disconnected managed domains must not pull a direct-IP client
// back onto an unapproved name or a released name still cached in DNS.
func (h *handler) advertisedDomain() string {
	d := h.dom.Current()
	if h.ddns != nil && ddns.InFreeZone(d) {
		st := h.ddns.Store().Snapshot()
		if !h.ddns.Store().Configured() || ddns.FQDN(st.Name) != d {
			return ""
		}
	}
	return d
}

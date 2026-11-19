package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"

	"hyperdrop/core/domainconn"
	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/bytefmt"
	"hyperdrop/server/internal/certpair"
	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/housekeep"
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/netprobe"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/webapp"
)

// The serving process's phases, which main runs in this file's order. Each
// takes what it needs and answers what a later phase uses; a fatal inside one
// stops the boot at that point, as main's own would.

// openServingVolume opens the database and the share store under bc.DataDir,
// builds the linked roots, seeds the first administrator and runs the boot
// pass's scan, so the volume is settled before anything else reads it; the
// answer's bootSweep is the rest of the pass, which the API phase starts
// once the API exists (startBootSweep). main closes the answer's database
// when it returns (closeVolume).
func openServingVolume(bc bootConfig) (api.Backend, bootSweep) {
	volumeStart := time.Now()
	dataDir := bc.DataDir
	db, err := metadb.Open(dataDir)
	if err != nil {
		log.Fatalf("opening the database at %s: %v", dataDir, err)
	}
	logDatabaseOpen(db.OpenStats(), time.Since(volumeStart))
	storeStart := time.Now()
	store, err := sharefs.Open(dataDir)
	if err != nil {
		log.Fatalf("opening the data directory at %s: %v", dataDir, err)
	}
	log.Printf("boot: store: %s (folds case: %t)", bootDuration(time.Since(storeStart)), store.FoldsCase())
	store.AbandonedWindow = bc.AbandonedWindow
	roots, err := linked.NewRoots(bc.LinkedRoots, bc.LinkedScan, []string{dataDir})
	if err != nil {
		log.Fatalf("linked roots: %v", err)
	}
	if roots.Enabled() {
		names := []string{}
		for _, r := range roots.List() {
			names = append(names, r.Name)
		}
		log.Printf("linked roots: %s", strings.Join(names, ", "))
	}
	// Accounts live on the data volume beside the shares they own. The first
	// administrator is bootstrapped from HYPERDROP_ADMIN_USER (empty: "admin")
	// and HYPERDROP_ADMIN_PASSWORD on first boot; once any admin exists both
	// env values are ignored (renames and password changes win), and so is
	// HYPERDROP_AUTO_UPDATE, the new volume's automatic-update choice.
	if bc.AutoUpdateErr != nil {
		log.Fatalf("HYPERDROP_AUTO_UPDATE: %v", bc.AutoUpdateErr)
	}
	if err := seedAdmin(db, bc.AutoUpdate); err != nil {
		log.Fatalf("admin bootstrap: %v", err)
	}
	if bc.DiskReserveErr != nil {
		log.Fatalf("HYPERDROP_DISK_RESERVE: %v", bc.DiskReserveErr)
	}
	store.ReservePercent = bc.DiskReserve
	sweep := bootPass(db, store)
	log.Printf("boot: volume ready: %s", bootDuration(time.Since(volumeStart)))
	return api.Backend{DB: db, FS: store, Roots: roots}, sweep
}

// bootDuration is d as the boot lines state it: to the millisecond.
func bootDuration(d time.Duration) string { return d.Round(time.Millisecond).String() }

// logDatabaseOpen logs the two lines the database's open accounts for: the
// integrity check on the file as it was (its size, then that the check was
// skipped for a clean close's record, or its verdict, the backup it was
// replaced by when it failed, and why the record was not trusted), and the
// rest of the open, which is the schema steps a serving open runs. opened
// is the whole open's duration.
func logDatabaseOpen(st metadb.OpenStats, opened time.Duration) {
	if st.Trusted {
		log.Printf("boot: database check: %s (%s, skipped: closed cleanly)", bootDuration(st.Check), bytefmt.Binary(st.Size))
	} else {
		outcome := "ok"
		if st.Recovered != "" {
			outcome = "restored from " + st.Recovered
		}
		log.Printf("boot: database check: %s (%s, %s, checked: %s)", bootDuration(st.Check), bytefmt.Binary(st.Size), outcome, st.Distrust)
	}
	log.Printf("boot: schema: %s (additive %s, names %s, fold keys %s, second factors %s)",
		bootDuration(opened-st.Check), bootDuration(st.Additive), bootDuration(st.Names),
		bootDuration(st.Folds), bootDuration(st.Seal))
}

// bootSweep is what the boot pass leaves for after the listener starts: the
// scan's work (sharefs.BootWork) and when the scan began, before which every
// file it finds was written by an earlier process.
type bootSweep struct {
	work    sharefs.BootWork
	started time.Time
}

// bootPass lists shares/ once (sharefs.BootScan), recording every open
// publish and removing the stages a crash left without an owner, then
// settles the publishes a crash or a failed rename stopped, and answers the
// sweep of stale parts and rowless directories that runs once the listener
// has started. Rows are the truth; a directory without one is a delete that
// crashed between its two halves. It logs how long the share ids, the scan
// of shares/ (with a progress line every 100,000 entries) and the publishes
// took.
func bootPass(db *metadb.DB, store *sharefs.FS) bootSweep {
	// A duplicate still copying when the last process stopped will never
	// fill: it goes first, rows then directory (duplicate.go), on every
	// boot, a trusted one included.
	if n, err := api.RemoveUnfinishedCopies(db, store); err != nil {
		log.Printf("boot pass: unfinished duplicates: %v", err)
	} else if n > 0 {
		log.Printf("boot pass: unfinished duplicates removed: %d", n)
	}
	idsStart := time.Now()
	ids, err := db.ShareIDs()
	if err != nil {
		log.Fatalf("listing shares: %v", err)
	}
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	log.Printf("boot: share ids: %s (%d shares)", bootDuration(time.Since(idsStart)), len(ids))
	passStart := time.Now()
	st, work, err := store.BootScan(func(id string) bool { return known[id] }, func(visited, entries int) {
		log.Printf("boot pass progress: %d of %d entries after %s", visited, entries, bootDuration(time.Since(passStart)))
	})
	if err != nil {
		log.Printf("boot pass: %v", err)
	} else {
		log.Printf("boot pass: %s (%d entries, %d share directories, %d without a row)",
			bootDuration(st.Took), st.Entries, st.Shares, st.Rowless)
	}
	// A publish whose commit journal remains is a commit a crash or a failed
	// rename stopped: settled here, before the listener starts, so no
	// visitor reads rows naming bytes still in stage/.
	publishStart := time.Now()
	finished, reopened, err := bootPublishes(db, store)
	if err != nil {
		log.Printf("boot pass: publishes left for the next boot: %v", err)
	}
	log.Printf("boot: publishes: %s (%d finished, %d reopened)", bootDuration(time.Since(publishStart)), finished, reopened)
	return bootSweep{work: work, started: passStart}
}

// upkeep is the status writer, the HTTPS listener's PROXY header record,
// the housekeeping pass, which startUpkeep builds and the API phase starts
// (startHousekeeping, and the integrity scan's own loop, startIntegrity),
// what a damaged daily copy does (owed), and the count of the background
// work that holds a database connection (background), which closeVolume
// waits for.
type upkeep struct {
	status       *statusWriter
	proxyHeaders *proxyWatch
	pass         *housekeep.Pass
	missingFiles *atomic.Int64
	owed         *owedCheck
	bg           *sync.WaitGroup
}

// owedCheck decides what a damaged daily copy (metadb.ErrCopyDamaged, which
// leaves metadb.CheckOwedFile) does to the process. A server nothing
// restarts keeps serving, and its next start checks the file and restores
// the newest good backup. A supervised one exits so that start comes now,
// with one exception that bounds the restarts: while this process's own
// boot ran the full check and no copy has passed since, the check and the
// copy disagree about one file, and a start after an exit would check the
// same file and meet the same copy, so it keeps serving and its next start
// checks again. A copy that passes ends the exception: damage after it is
// new, and is worth a start that checks it.
type owedCheck struct {
	supervised bool
	checked    bool // the boot ran the full check (metadb.OpenStats.Checked)
	copyPassed bool // a daily copy has passed its check since the boot
}

// exits records r and answers whether its damaged copy stops the process.
func (o *owedCheck) exits(r housekeep.Result) bool {
	if r.BackedUp {
		o.copyPassed = true
	}
	return errors.Is(r.BackupErr, metadb.ErrCopyDamaged) && o.supervised && (!o.checked || o.copyPassed)
}

// housekeepStopLimit is how long closeVolume waits for the background work
// once the listeners have shut down: it starts after shutdownGrace, and both
// together stay inside the 30 s the load rig and the 90 s systemd give a
// stopping server before they kill it. A variable so a test can shorten it.
var housekeepStopLimit = 10 * time.Second

// background runs fn in a goroutine that wait counts. The goroutines the
// boot starts that query the database or walk the volume for longer than a
// request does (the boot sweep, housekeeping, the integrity scan and the
// sealed-password sweep) run here and return once the context they were
// handed ends; the retired objects' drop runs here too and takes no context,
// one statement that cannot be interrupted. The API's own background work is
// joined by its Drain, which serveUntilShutdown calls.
func (u upkeep) background(fn func()) {
	u.bg.Add(1)
	go func() {
		defer u.bg.Done()
		fn()
	}()
}

// wait answers once every goroutine background started has returned, true,
// or once limit has passed with one still running, false.
func (u upkeep) wait(limit time.Duration) bool {
	done := make(chan struct{})
	go func() {
		u.bg.Wait()
		close(done)
	}()
	t := time.NewTimer(limit)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// closeVolume waits for the background work (housekeepStopLimit), then
// closes the database and records the clean close (metadb.CloseClean). A
// goroutine still running after the wait, or a request handler still
// running past the listeners' grace, meets a closed database at its next
// query; the connection it holds keeps the write-ahead log, so no record is
// written and the next boot replays the log and checks the file.
func closeVolume(db *metadb.DB, u upkeep) {
	if !u.wait(housekeepStopLimit) {
		log.Printf("shutdown: background work still running after %s; closing the database under it", bootDuration(housekeepStopLimit))
	}
	switch recorded, err := db.CloseClean(); {
	case err != nil:
		log.Printf("closing the database: %v", err)
	case recorded:
		log.Print("database: closed cleanly; the next start skips its check")
	default:
		log.Print("database: closed with its write-ahead log still open; the next start checks it")
	}
}

// startUpkeep records this process in the status file, starts the PROXY
// header record's minute tick and builds the housekeeping pass over vol,
// which it leaves unstarted, with the last integrity scan's count loaded.
func startUpkeep(bc bootConfig, vol api.Backend) upkeep {
	missingFiles := new(atomic.Int64)
	status := newStatusWriter(bc.StatusFile)
	status.Set(Status{Version: version, StartedAt: time.Now().Unix()})
	// The HTTPS listener's record of connections failing on the PROXY
	// header, kept in the status file and the health verdict.
	proxyHeaders := newProxyWatch(func(private []ProxySource, public int) {
		status.Update(func(s *Status) { s.ProxySources, s.PublicProxy = private, public })
	})
	go func() {
		for range time.Tick(time.Minute) {
			proxyHeaders.Tick()
		}
	}()
	pass := &housekeep.Pass{DB: vol.DB, FS: vol.FS, DataDir: bc.DataDir, MissingFiles: missingFiles}
	// The last integrity scan's count reaches the health verdict and the
	// status file before the listener opens, so a restart does not hide a
	// warning until the next scan.
	if err := pass.LoadIntegrity(); err != nil {
		log.Printf("integrity scan record: %v", err)
	}
	if n := int(missingFiles.Load()); n > 0 {
		status.Update(func(s *Status) { s.MissingFiles = n })
	}
	owed := &owedCheck{supervised: bc.Supervised, checked: vol.DB.OpenStats().Checked}
	return upkeep{status: status, proxyHeaders: proxyHeaders, pass: pass, missingFiles: missingFiles, owed: owed, bg: new(sync.WaitGroup)}
}

// beforeBootSweep runs as the boot sweep starts. A variable so a test can
// hold the sweep back.
var beforeBootSweep = func() {}

// startBootSweep runs the boot pass's sweep in the background: the stale
// parts the scan found (sharefs.BootSweepParts), then its rowless
// directories (sharefs.BootSweepOrphans), which no request reads (a stale
// part is what SweepStaleParts reclaims on a running server, and every
// route reads a share's row before its directory), so the listener does not
// wait for them. The answer closes once the parts are done, or the sweep
// stopped: the first housekeeping pass waits for it (startHousekeeping), so
// its stalled step finds a pending row whose part the boot found stale
// with neither part nor file, and keeps the row and its slug for
// housekeep.DeclaredLifetime, whichever goroutine runs first. It logs what
// it did and how long it took, or that it stopped for shutdown.
func (u upkeep) startBootSweep(ctx context.Context, store *sharefs.FS, s bootSweep) <-chan struct{} {
	partsDone := make(chan struct{})
	u.background(func() {
		start := time.Now()
		beforeBootSweep()
		cleaned := store.BootSweepParts(ctx, s.work, s.started)
		close(partsDone)
		removed := store.BootSweepOrphans(ctx, s.work)
		took := bootDuration(time.Since(start))
		if ctx.Err() != nil {
			log.Printf("boot sweep: stopped for shutdown after %s (%d shares' parts cleaned, %d orphans removed)", took, cleaned, removed)
			return
		}
		log.Printf("boot sweep: %s (%d shares' parts cleaned, %d orphans removed)", took, cleaned, removed)
	})
	return partsDone
}

// dropRetired drops the objects metadb retires (metadb.DropRetired) in the
// background once the listener is open, so the updater's health wait never
// includes it, and logs what it dropped and how long it took. A shutdown
// waits housekeepStopLimit for it as for the rest of the background work
// (closeVolume). A drop still running then is cut off with the process: the
// volume stays as it was, no clean-close record is written, so the next boot
// takes the full check and drops it again.
func (u upkeep) dropRetired(db *metadb.DB) {
	u.background(func() {
		start := time.Now()
		n, err := db.DropRetired()
		if err != nil {
			log.Printf("retired objects: %v", err)
			return
		}
		if n > 0 {
			log.Printf("retired objects: dropped %d in %s", n, bootDuration(time.Since(start)))
		}
	})
}

// startHousekeeping runs the pass in the background, every
// housekeep.Interval, rather than ahead of the listener: every step is
// advisory cleanup that takes the same locks as a scheduled pass, and
// blocking the listener on it costs a minute of downtime per restart on a big
// volume. A pass logs a line for each thing it did or failed, and its timing
// only on the process's first pass or when it took a second or longer, so an
// idle server's later passes stay silent in the journal. A damaged daily
// copy exits a supervised server (owedCheck) with no clean-close record, so
// the start systemd makes next checks the file. The first pass waits for
// after to close (the boot sweep's parts, startBootSweep). When ctx ends the
// pass under way stops at its next check and the loop returns.
func (u upkeep) startHousekeeping(ctx context.Context, after <-chan struct{}) {
	u.background(func() {
		select {
		case <-after:
		case <-ctx.Done():
			return
		}
		for {
			res := u.pass.Run(ctx)
			for _, line := range res.Lines() {
				log.Print(line)
			}
			if t := res.Timing(); t != "" {
				log.Print(t)
			}
			exit := u.owed.exits(res)
			if errors.Is(res.BackupErr, metadb.ErrCopyDamaged) {
				if exit {
					log.Fatalf("database: %v; exiting so the next start checks it and restores the newest good backup", res.BackupErr)
				}
				log.Printf("database: %v; the next start checks it and restores the newest good backup", res.BackupErr)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(housekeep.Interval):
			}
		}
	})
}

// startIntegrity runs the integrity scan in its own background loop, apart
// from the housekeeping pass, whose five-minute steps it would otherwise hold
// up for as long as it reads the volume. It first recounts what every share's
// tiles and poster occupy (housekeep.Pass.RecountSidecars), which the quota
// counts from memory, then every housekeep.Interval asks the database
// whether a scan is due (housekeep.Pass.IntegrityDue) and, when one is,
// scans, logs its line (at its first check, when none is owed, it logs when the last one finished instead), publishes the count to the health verdict and the
// status file, and recounts again unless it recounted at this start: the
// disk is awake for the scan, and the recount corrects any drift. When ctx
// ends the recount or the scan under way stops at its next check, records
// nothing, and the loop returns.
func (u upkeep) startIntegrity(ctx context.Context) {
	u.background(func() {
		u.pass.RecountSidecars(ctx)
		recounted := true
		first := true
		for ctx.Err() == nil {
			due, err := u.pass.IntegrityDue(time.Now())
			if err != nil {
				log.Printf("integrity scan record: %v", err)
			}
			if first && !due {
				if line, ok, err := u.pass.NotDueLine(time.Now()); err == nil && ok {
					log.Print(line)
				}
			}
			first = false
			if due {
				res := u.pass.Integrity(ctx)
				if res.Cancelled {
					log.Printf("integrity scan stopped for shutdown after %s (%d files checked)", bootDuration(res.Took), res.Files)
					return
				}
				log.Print(res.Line())
				u.status.Update(func(s *Status) { s.MissingFiles = res.Missing })
				if !recounted {
					u.pass.RecountSidecars(ctx)
				}
			}
			recounted = false
			select {
			case <-ctx.Done():
				return
			case <-time.After(housekeep.Interval):
			}
		}
	})
}

// addressing is how the server is reached: the domain manager, the DDNS
// state, the names-service client and the updater, DSM's address requests,
// and the domain this boot serves.
type addressing struct {
	dom      *domain.Manager
	dstore   *ddns.Store
	names    *ddns.Client
	updater  *ddns.Updater
	requests *addressRequests // nil unless HYPERDROP_ADDRESS_REQUEST is set
	// domainName is the domain this boot serves: the persisted one, else
	// bc.Domain; "" on a development server.
	domainName string
}

// openAddressing loads the domain and the DDNS state, claims a desired free
// name and adopts the boot domain, so the A pair exists by the time ACME
// goes looking for it.
func openAddressing(ctx context.Context, bc bootConfig, vol api.Backend, status *statusWriter) addressing {
	db, store := vol.DB, vol.FS
	domainName := bc.Domain
	// The domain is persisted in the data volume and can be CHANGED at
	// runtime via PUT /api/domain, but it cannot be absent: see main's
	// HYPERDROP_DOMAIN check.
	dom, err := domain.Load(filepath.Join(bc.DataDir, "domain"), bc.PublicIP)
	if err != nil {
		log.Fatalf("reading domain state: %v", err)
	}
	// The Synology package's conf names the current address, whichever path
	// changes it.
	conf := &confAddress{path: bc.ConfFile}
	dom.Changed = conf.Sync
	dom.Moved = func(from, to string) {
		now := time.Now()
		if err := db.RecordDomainChange(domainconn.Change{From: from, To: to, At: now}, now); err != nil {
			log.Printf("domain change %s → %s not recorded: %v", from, to, err)
		}
	}
	// Installation environment is a seed. Runtime domain changes must
	// survive a restart, including switching a managed name to custom DDNS.
	if persisted := dom.Current(); persisted != "" {
		domainName = persisted
	}
	// The free-name address and a DDNS recipe. Both are absent on a server
	// with a domain of its own, the ordinary case: its updater's ticks then
	// send nothing anywhere, and the address and hostnames are checked only
	// when an administrator asks (POST /api/connectivity/check).
	dstore, err := ddns.Load(filepath.Join(bc.DataDir, "ddns"))
	if err != nil {
		log.Fatalf("reading ddns state: %v", err)
	}
	namesClient := &ddns.Client{BaseURL: bc.NamesURL}
	updater := ddns.NewUpdater(dstore, namesClient, func(ctx context.Context) (string, bool) {
		ip, err := namesClient.PublicIPv4(ctx)
		return ip, err == nil
	})
	dom.BehindNAT = bc.BehindNAT
	// A claim the updater completes cannot adopt its domain until
	// setupCertificates replaces this with dom.Adopt, once certificate
	// management exists.
	updater.Connected = func(string) error { return errors.New("certificate management is starting") }
	updater.Domain = dom.Current
	updater.PrivateRecipes = bc.DDNSAllowPrivate
	updater.ServerID = store.ServerID
	// A desired free name is claimed before the domain is adopted, so the A
	// pair exists by the time ACME goes looking for it. A refusal is logged
	// and carried in GET /api/ddns: the server still boots and serves over
	// its IP, it simply does not hold the name it was asked to.
	if bc.DDNSName != "" && (dom.Current() == "" || domainName == ddns.FQDN(bc.DDNSName)) {
		if err := bootTake(ctx, updater, bc.DDNSName, store.ServerID(), bootTakeLimit); err != nil {
			log.Printf("ddns: taking %s: %v", ddns.FQDN(bc.DDNSName), err)
		}
	}
	// A stored domain wins over HYPERDROP_DOMAIN; the variable seeds a server
	// that has none. Adopt rather than Set: Set verifies the domain already
	// resolves HERE, which cannot be true yet on a server that has not
	// started serving.
	if domainName != "" && dom.Current() != domainName {
		if err := dom.Adopt(domainName); err != nil {
			// A free name that could not be claimed must not stop the
			// server from booting: it serves over its IP and GET
			// /api/ddns explains why. An explicitly configured
			// HYPERDROP_DOMAIN is an operator error and stays fatal.
			if bc.DDNSName != "" {
				log.Printf("ddns: configuring domain %s: %v", domainName, err)
			} else {
				log.Fatalf("configuring domain %s: %v", domainName, err)
			}
		}
	}

	// The persisted domain wins over the conf's seed, so the conf may name an
	// older address until now.
	conf.Sync(dom.Current())
	// An address change asked for on DSM; unset, as on every server but the
	// Synology package, nothing is asked.
	var addressReqs *addressRequests
	if path := bc.AddressRequest; path != "" {
		addressReqs = &addressRequests{path: path, dom: dom, up: updater, st: status}
	}
	return addressing{dom: dom, dstore: dstore, names: namesClient, updater: updater,
		requests: addressReqs, domainName: domainName}
}

// webClient is the web client's install store, why it could not be opened
// ("" when it could), and the fetch that keeps it current; store and fetcher
// are nil when the store could not be opened.
type webClient struct {
	store   *webapp.Store
	failed  string
	fetcher *webapp.Fetcher
}

// prepareServices logs the push relay and the self-updater's release
// directory when either is malformed, and opens the web client's store.
func prepareServices(bc bootConfig) webClient {
	// Unset is the HyperDrop relay; set and empty turns push off. A malformed
	// value turns push off with a log line rather than refusing to boot: a
	// typo must not take the shares offline.
	if bc.PushRelayErr != nil {
		log.Printf("push notifications are off: %v", bc.PushRelayErr)
	}
	// The website directory the self-updater reads once a day. Unset: the
	// HyperDrop site; empty: never check (the box then gets no reminders
	// and installs nothing on its own); malformed: logged, never check.
	if bc.ReleasesErr != nil {
		log.Printf("HYPERDROP_SERVER_RELEASES: %v; this server will not check for updates", bc.ReleasesErr)
	}
	// The web client's installs under the data directory, and the fetch that
	// keeps them current from the web release manifest. A store that cannot
	// be opened leaves /app saying the web version is not installed rather
	// than keeping the shares offline, and the settings say why.
	wc := bc.Web
	if wc.BaseErr != nil {
		log.Printf("%v; this server will not fetch the web version", wc.BaseErr)
	}
	web, err := webapp.Open(bc.DataDir, wc.Keys, version)
	if err != nil {
		log.Printf("the web version is unavailable: %v", err)
		return webClient{failed: err.Error()}
	}
	if wc.DevDir != "" {
		log.Printf("serving the web version unsigned from %s (HYPERDROP_WEB_DEV_DIR)", wc.DevDir)
		web.UseDevDir(wc.DevDir)
	}
	return webClient{store: web, fetcher: webapp.NewFetcher(web, wc.Base, nil)}
}

// startAPI builds the API handler, then starts the web client's fetch, the
// self-update switch's watch, the boot sweep, housekeeping, the integrity
// scan and the sealed-password sweep, in that order.
func startAPI(ctx context.Context, bc bootConfig, vol api.Backend, up upkeep, addr addressing, web webClient, sweep bootSweep) *api.Server {
	// The port /api/local-addresses joins onto the server's private
	// addresses. bc.HTTPSAddr is always host:port shaped (":443" default),
	// so the split cannot fail; plain-HTTP mode reports no candidates.
	_, localPort, _ := net.SplitHostPort(bc.HTTPSAddr)
	if addr.domainName == "" {
		localPort = ""
	}
	mux := api.NewServer(vol, version, addr.dom, addr.updater, api.Deployment{
		DataDir:      bc.DataDir,
		MissingFiles: up.missingFiles,
		ProxyHeaders: func() ([]api.ProxyHeaderSource, int) {
			private, public := up.proxyHeaders.Snapshot()
			out := make([]api.ProxyHeaderSource, len(private))
			for i, s := range private {
				out[i] = api.ProxyHeaderSource{Addr: s.Addr, Kind: s.Kind}
			}
			return out, public
		},
		AddressPending: func() (string, string) {
			if p := up.status.Current().AddressPending; p != nil {
				return p.Address, p.Reason
			}
			return "", ""
		},
		CertificatePending: certificatePending(addr.dom),
		AddressChange:      addr.requests.AppChange,
		// Set by the systemd unit provisioning writes, beside the root-owned
		// installer unit that watches it. Without it the binary belongs to a
		// container image or a package manager, so the update route stays off
		// and /api/health says so rather than accepting a binary nothing would
		// ever install.
		UpdateDir: bc.UpdateDir,
		Channel:   bc.Channel,
		LocalPort: localPort,
		Platform:  bc.Platform,

		LiveShareGrace: bc.LiveShareGrace,
		PushRelay:      bc.PushRelay,
		Releases:       bc.Releases,
		Official:       official == "true",
		Web:            web.store,
		WebFailed:      web.failed,
		WebFetcher:     web.fetcher,
	})
	if web.fetcher != nil {
		web.fetcher.Start(ctx)
	}
	up.pass.Alive = mux.PreparingReportedSince
	watchSelfUpdateSwitch(ctx, mux.RereadSelfUpdate)
	partsSwept := up.startBootSweep(ctx, vol.FS, sweep)
	up.dropRetired(vol.DB)
	// The pass starts once the API exists, because its empty sweep asks the
	// API's preparing tracker whether a sender is still making a share's
	// bytes.
	up.startHousekeeping(ctx, partsSwept)
	up.startIntegrity(ctx)
	// A readable password copy that no longer opens beside its row's hash
	// (the previous release changed or removed the hash, or the copy came
	// from another server's volume) is cleared once per boot, in the
	// background so it never delays the listener or the updater's health
	// wait: every read already treats such a copy as absent. It stops
	// between batches at shutdown, and closeVolume waits for it. A boot that
	// trusted a clean close's record skips it: no other release and no
	// other volume's file wrote the database since a build of the same
	// metadb.RepairGeneration closed it, and that generation names this
	// sweep, so a change to the sealed-password scheme raises it.
	if vol.DB.OpenStats().Trusted {
		return mux
	}
	up.background(func() {
		cleared, err := api.SweepSealed(ctx, vol.DB, vol.FS.Secret())
		if cleared > 0 {
			log.Printf("sealed passwords: cleared %d stale", cleared)
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("sealed passwords: %v", err)
		}
	})
	return mux
}

// certificatePending answers a function naming dom's served domain while no
// certificate for it is in storage: the health verdict and the DSM page both
// say so, since every handshake is refused until Let's Encrypt issues one.
func certificatePending(dom *domain.Manager) func() string {
	return func() string {
		d := dom.Current()
		if d == "" {
			return ""
		}
		if _, _, ok := storedCertificate(context.Background(), certmagic.Default.Storage, d); ok {
			return ""
		}
		return d
	}
}

// certificates is what the listeners need from certificate management: the
// CertMagic config whose TLS configuration the HTTPS listener serves, the
// domain's ACME issuer, whose challenge handler port 80 serves, the selector
// that picks the certificate for a handshake on the bare public IP, and the
// flag that lets the NAT probe run once both listeners are bound.
type certificates struct {
	magic      *certmagic.Config
	domainACME *certmagic.ACMEIssuer
	selector   *bootstrapCertificateSelector
	listening  *atomic.Bool
}

// setupCertificates runs in HTTPS mode only, after the API exists and before
// either listener binds. It configures CertMagic, puts the boot domain (and
// the public IP) under certificate management, routes every later domain
// change through that management, starts the DDNS update loop and keeps a
// free name's certificate. Its order is load-bearing:
//
//   - every certmagic.Default field the certificate pair depends on (storage,
//     key source, subject transformer, event hook, fallback name) is set
//     before the cache and the config are built from it, and the issuers,
//     which need that config, go on both afterwards;
//   - the ACME CA and trusted-root hooks are applied before the IP issuer's
//     template is copied from certmagic.DefaultACME;
//   - dom.ReprobeNAT is assigned before the event hook and before any domain
//     enters management;
//   - updater.LocalLeaf is set before the update loop starts and before the
//     listeners serve the connectivity check;
//   - the boot subjects enter management here, because the boot adoption
//     (openAddressing) runs while dom.Manage is unset and updater.Connected
//     still refuses; dom.Manage and updater.Connected are wired after them,
//     the update loop starts after both, and the free name's certificate is
//     kept last, through dom.Manage.
func setupCertificates(ctx context.Context, bc bootConfig, addr addressing, store *sharefs.FS, status *statusWriter) certificates {
	dom, dstore, namesClient, updater := addr.dom, addr.dstore, addr.names, addr.updater
	subject := addr.domainName
	publicIP := bc.PublicIP
	certificatePending := certificatePending(dom)

	// managed is the live set of domains under certificate management, which
	// both the storage alias and the subject transformer below consult. It is
	// filled by the manage closure, the one way a domain enters management.
	managed := certpair.NewSubjects(api.ShareHost)
	certPath := filepath.Join(bc.DataDir, "certmagic")
	certmagic.Default.Storage = certpair.NewFileOriginAlias(
		&certmagic.FileStorage{Path: certPath}, managed)
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = bc.ACMEEmail
	certmagic.DefaultACME.Profile = certpair.DomainProfile
	// Test hook: point ACME at a private CA (e.g. Pebble) instead of Let's
	// Encrypt. Both CA and TestCA are set to the override: certmagic retries
	// a failed order against TestCA, so leaving it at its Let's Encrypt
	// staging default would send a test server's ACME traffic to a public
	// CA on the open internet on the very first retry.
	if ca := bc.ACMECA; ca != "" {
		certmagic.DefaultACME.CA = ca
		certmagic.DefaultACME.TestCA = ca
	}
	// Test hook: trust a private ACME CA's TLS cert (e.g. Pebble).
	if bc.ACMETrustedRootsErr != nil {
		log.Fatal(bc.ACMETrustedRootsErr)
	}
	if bc.ACMETrustedRoots != nil {
		certmagic.DefaultACME.TrustedRoots = bc.ACMETrustedRoots
	}
	keys := certpair.NewKeyRecorder(certmagic.DefaultKeyGenerator)
	// Every field the certificate pair depends on is set on certmagic.Default
	// rather than on the config below, because background certificate
	// maintenance does not use that config: it asks the certificate cache for
	// one, and the cache builds a fresh config out of certmagic.Default. A
	// renewal that ran with the stock key generator and the bare ACME issuer
	// would replace the certificate with one covering the app domain alone
	// and take the file origin down.
	certmagic.Default.KeySource = keys
	// CertMagic renews a cached certificate under its FIRST name, which for a
	// paired certificate is whichever of the two origins sorts first (see
	// certpair.FileOriginAlias). Mapping a file origin back to its app domain
	// here is what keeps the ACME order, the storage lock and every
	// certificate event naming the domain an operator can act on.
	certmagic.Default.SubjectTransformer = managed.Subject
	// Behind NAT the router is the only thing that knows whether inbound
	// traffic can ever arrive, so classify the NAT above it and ask the
	// names service to dial our public 443 and 80 (probeNetwork). Async and
	// advisory. Assigned before CertMagic's event hook is installed and before
	// any domain enters management, so nothing that fires it (Adopt, a
	// freshly issued certificate, a manual connectivity check) can race the
	// assignment; a probe does nothing until both listeners are bound: a dial
	// back that lands first would read "closed" and raise a false alarm.
	// Probes run one at a time, so a slow one can never overwrite a newer
	// verdict.
	netListening := new(atomic.Bool)
	if bc.BehindNAT {
		var probeMu sync.Mutex
		dom.ReprobeNAT = func() {
			if !netListening.Load() {
				return
			}
			probeMu.Lock()
			defer probeMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			probeNetwork(ctx, netprobe.RouterExternalIP, namesClient, store.ServerID(), dom)
			reachable := reachableFromManager(dom)
			pending := certificatePending()
			status.Update(func(s *Status) { s.Reachable, s.CertificatePending = reachable, pending })
		}
	}

	// One certificate covers both origins, so a lifecycle event for a
	// managed domain is its file origin's event too: /api/domain reports a
	// state for each name an operator can point DNS at, for every domain
	// this process manages, not only the one it booted with.
	certmagic.Default.OnEvent = func(_ context.Context, event string, data map[string]any) error {
		dom.RecordCertEvent(event, data)
		if paired, ok := certpair.PairedCertEvent(api.ShareHost, data); ok {
			dom.RecordCertEvent(event, paired)
		}
		updater.CertificateEvent(event, data)
		return nil
	}
	// Keep the ordinary fallback stable. The selector below handles direct-IP
	// NAT connections separately, without mutating live CertMagic configuration.
	certmagic.Default.DefaultServerName = subject
	// The cache is this process's own rather than CertMagic's default, which
	// is unreachable, so a subject can be removed from maintenance: the IP
	// certificate of an address the box no longer has. Like the default
	// cache, it builds each certificate's config fresh out of
	// certmagic.Default.
	var certCache *certmagic.Cache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.New(certCache, certmagic.Default), nil
		},
		Logger: certmagic.Default.Logger,
	})
	magic := certmagic.New(certCache, certmagic.Default)
	bootstrapTLS := &bootstrapCertificateSelector{getCertificate: magic.GetCertificate}
	// Custom DDNS pins its HTTPS checks to the leaf this process serves.
	// Set before the update loop starts and before the API serves the
	// connectivity check, the two callers that read it concurrently.
	updater.LocalLeaf = func(host string) []byte { return localLeaf(magic.GetCertificateWithContext, host) }
	bootstrapTLS.observe(publicIP)
	domainACME := certmagic.NewACMEIssuer(magic, certmagic.DefaultACME)
	ipTemplate := certmagic.DefaultACME
	ipTemplate.Profile = certpair.IPProfile
	ipACME := certmagic.NewACMEIssuer(magic, ipTemplate)
	// One PairIssuer instance serves every domain this process ever manages:
	// the boot domain, a free name claimed at runtime and a domain set through
	// the API all widen through it, and it sends the IP certificate to the one
	// issuer ordering the profile Let's Encrypt issues an IP address under.
	certmagic.Default.Issuers = []certmagic.Issuer{certpair.NewPairIssuer(domainACME, ipACME, keys, api.ShareHost)}
	magic.Issuers = certmagic.Default.Issuers

	// manage is the one way a domain enters certificate management, so it is
	// where the alias, the subject transformer and the paired-certificate
	// check all see it. Recording precedes the request: certificate work
	// begins immediately and resolves names through that set.
	manage := func(ctx context.Context, names []string) error {
		managed.Add(names...)
		if err := magic.ManageAsync(ctx, names); err != nil {
			return err
		}
		// Async for the same reason management is: a transient ACME outage
		// must not crash-loop the service. The carry-over runs first and in
		// the same goroutine, so the file origin has a certificate to serve
		// before the ACME round trip the check below can start.
		go func() {
			carryOverFileOriginCertificates(ctx, magic, certPath, names)
			ensurePairedCertificates(ctx, magic, names)
		}()
		return nil
	}

	// The app domain alone: files.<domain> is a real origin serving real
	// bytes and still needs its own DNS A record, which is why `domain set`
	// creates two, but its certificate rides the app domain's order through
	// the paired issuer above instead of being requested here.
	//
	// The bare IP is kept as an ADDITIONAL subject, never as the identity: a
	// server has to be reachable before its DNS points here at all, the
	// client logs in right after installing. It does not reopen the
	// origin split, which is enforced by the Host header (origins.go): a
	// payload request arriving on the IP is redirected to the file origin.
	//
	// Async so a transient ACME/network outage doesn't crash-loop the
	// service; issuance retries while :80 stays up.
	subjects := initialCertSubjects(subject, publicIP, !dstore.Configured())
	if err := manage(context.Background(), subjects); err != nil {
		log.Fatalf("certmagic manage %v: %v", subjects, err)
	}
	// Every domain change after boot, a free name claimed at runtime or an
	// operator-set domain, runs certificate management through this
	// closure. It manages the domain alone: the PairIssuer constructed above
	// widens whichever domain CertMagic orders a certificate for, so the file
	// origin never needs its own subject here.
	dom.Manage = func(d string) error {
		return manage(context.Background(), []string{d})
	}

	updater.Connected = dom.Adopt
	if bc.BehindNAT && bc.DDNSName != "" && publicIP == "" {
		go bootstrapIPCertificate(ctx, 30*time.Second, ddns.TickInterval, namesClient.PublicIPv4, func(ip string) error {
			if err := manage(ctx, []string{ip}); err != nil {
				return err
			}
			bootstrapTLS.observe(ip)
			return nil
		}, func(ip string) {
			certCache.RemoveManaged([]certmagic.SubjectIssuer{{Subject: ip}})
			log.Printf("tls: the public IP changed; stopped managing the certificate for %s", ip)
		})
	}

	// A server that already holds a name or a DDNS recipe resumes its
	// heartbeat on boot, the same way it resumes after any PUT /api/ddns: a
	// restart must not leave the address unpublished until the next config
	// change. On a server holding neither, the loop's ticks send nothing.
	updater.Start(context.Background())

	// A free name outlives a domain change made before this boot: links
	// already issued under it must keep answering, so a certificate for it
	// stays managed even when it is not the server's current domain.
	// Without this a server that changed domain would lose the free name's
	// certificate at its next restart, and every link issued under that name
	// would start failing a TLS handshake instead of just going unused.
	if st := dstore.Snapshot(); !st.Pending && st.Name != "" && ddns.FQDN(st.Name) != dom.Current() {
		if err := dom.Manage(ddns.FQDN(st.Name)); err != nil {
			log.Printf("ddns: keeping a certificate for %s: %v", ddns.FQDN(st.Name), err)
		}
	}

	return certificates{magic: magic, domainACME: domainACME, selector: bootstrapTLS, listening: netListening}
}

// serveHTTP serves a development server, plain HTTP on addr with both
// origins on one, until ctx ends.
func serveHTTP(ctx context.Context, addr string, mux *api.Server) {
	log.Printf("hyperdrop-server %s serving HTTP on %s (no domain, development mode)",
		version, addr)
	// Not proxy-wrapped: the boot self-check dials this one listener
	// over loopback with no header, and a development server has no
	// HTTPS listener for a proxy to sit in front of.
	srv := newServer(addr, mux)
	go bootSelfCheck(addr)
	serveUntilShutdown(ctx, mux.Drain, serverRun{srv, srv.ListenAndServe})
}

// serveHTTPS binds the HTTPS listener and then port 80, starts the boot
// self-check, the NAT probe once both are bound and DSM's address requests,
// and serves both ports until ctx ends.
func serveHTTPS(ctx context.Context, bc bootConfig, addr addressing, up upkeep, mux *api.Server, certs certificates) {
	dom, subject := addr.dom, addr.domainName
	status := up.status

	// :80 serves the ACME challenge, health and the redirect to https.
	httpMux := http.NewServeMux()
	httpMux.Handle("GET /api/health", mux) // the api handler's open health route
	httpMux.Handle("GET /.well-known/hyperdrop-names", mux)
	httpMux.Handle("/", redirectToHTTPS(dom, subject))
	// CertMagic keeps every pending challenge in one process-wide table read
	// through the shared config, so the domain issuer's handler answers the
	// IP issuer's challenges as well.
	httpSrv := newServer(bc.HTTPAddr, certs.domainACME.HTTPChallengeHandler(httpMux))

	tlsConfig := httpsTLSConfig(certs.magic.TLSConfig(), certs.selector.GetCertificate)
	// The PROXY header precedes the TLS ClientHello, so the proxy listener
	// sits BELOW TLS: TCP, then PROXY, then TLS. Port 80 stays unwrapped
	// (proxyproto.go says why).
	tcpLn, err := listenRecording(status, bc.HTTPSAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", bc.HTTPSAddr, err)
	}
	ln := tls.NewListener(wrapProxyListener(tcpLn, bc.TrustedProxies, up.proxyHeaders), tlsConfig)
	log.Printf("hyperdrop-server %s serving HTTPS for %s", version, subject)
	// Bound here rather than by ListenAndServe so both ports accept before
	// the first port check asks the names service to dial them.
	httpLn, err := listenRecording(status, bc.HTTPAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", bc.HTTPAddr, err)
	}
	tlsSrv := newServer("", mux)
	go bootSelfCheck(bc.HTTPAddr)
	if dom.ReprobeNAT != nil {
		certs.listening.Store(true)
		go func() {
			dom.ReprobeNAT()
			// A user who fixes the router sees the warning go away without
			// a restart; a check is one small request to the registry.
			t := time.NewTicker(30 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					dom.ReprobeNAT()
				}
			}
		}()
	}
	// An address change asked for on DSM waits for certificate management
	// and the updater's adoption hook (setupCertificates), and runs beside
	// the listeners: it may wait for DNS or approval for as long as it
	// takes, and the old address serves meanwhile.
	if addr.requests != nil {
		go addr.requests.watch(ctx, addressRetry, addressRefresh)
	}
	serveUntilShutdown(ctx, mux.Drain,
		serverRun{httpSrv, func() error { return httpSrv.Serve(httpLn) }},
		serverRun{tlsSrv, func() error { return tlsSrv.Serve(ln) }})
}

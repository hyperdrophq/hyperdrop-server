// hyperdrop-server: minimal self-hosted file share server.
//
// A server has a domain (HYPERDROP_DOMAIN, or a free name from
// HYPERDROP_DDNS_NAME) and serves it over HTTPS on HYPERDROP_HTTPS_ADDR
// (default :443) with automatic Let's Encrypt certificates, one covering the
// domain and its files.<domain> origin. HYPERDROP_HTTP_ADDR (default :80)
// serves the ACME HTTP-01 challenge, /api/health and a redirect to https. Its
// three modes (resolveBoot):
//   - public IP: HYPERDROP_IP is this box's public IPv4, which also gets a
//     certificate of its own (160 h, the only lifetime Let's Encrypt issues
//     an IP address under; the domain's is 45 days);
//   - behind NAT: HYPERDROP_BEHIND_NAT=1 and no HYPERDROP_IP, a router
//     forwarding 443 (and 80) here, as on a NAS;
//   - development: HYPERDROP_ALLOW_PRIVATE=1 and no domain, plain HTTP on
//     HYPERDROP_HTTP_ADDR with both origins collapsed onto one.
//
// Storage: a SQLite database of rows beside the bytes on the local
// filesystem (HYPERDROP_DATA). Accounts are rows too (login-minted bearer
// tokens; the first admin bootstrapped from HYPERDROP_ADMIN_USER and
// HYPERDROP_ADMIN_PASSWORD).
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"

	"hyperdrop/server/internal/api"
	"hyperdrop/server/internal/conffile"
	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/housekeep"
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/logfile"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/selfupdate"
	"hyperdrop/server/internal/sharefs"
)

const version = "1.8.3"

// official is "true" in the binaries HyperDrop's own build scripts make
// (-ldflags "-X main.official=true"). A build without it, such as a fork or
// a plain `go build`, still checks for newer releases and reminds its admins,
// but never replaces itself with one on its own.
var official string

// isPublicIPv4 reports whether s is an IPv4 literal the domain can be
// expected to resolve to. Certificates are issued for the DOMAIN, never for
// the address, so this is only the "does your DNS point here" reference
// point. IPv6 is deliberately not accepted; an IPv4-mapped IPv6 literal
// counts as its IPv4 address.
func isPublicIPv4(s string) bool {
	v4 := net.ParseIP(s).To4()
	if v4 == nil {
		return false
	}
	return ddns.IsPublicIPv4(netip.AddrFrom4([4]byte(v4)))
}

// bootConfig is what main derives from the environment before it can listen.
// PublicIP is empty in behind-NAT mode: the router holds the public address
// and forwards 443 (and optionally 80) to the addrs below, so there is no IP
// to certify and no "does DNS point here" reference; ACME arbitrates
// reachability instead (the boot-time twin of `domain set --behind-nat`).
// The Synology package is what sets HYPERDROP_BEHIND_NAT and the alternate
// addrs: DSM's own nginx owns :80/:443 on a NAS.
type bootConfig struct {
	HTTPAddr     string
	HTTPSAddr    string
	Domain       string
	PublicIP     string
	AllowPrivate bool
	// BehindNAT: HTTPS mode with no local public IP; the domain manager
	// needs to know, or boot-time adoption refuses its own domain.
	BehindNAT bool
	// DDNSName is the free name this server should hold. When set it is the
	// source of Domain, so nothing downstream needs to know the difference.
	DDNSName string
	// Platform is the package family (HYPERDROP_PLATFORM; the DSM package
	// sets dsm7 or dsm6), reported by /api/health.
	Platform string
	// LiveShareGrace (HYPERDROP_LIVE_SHARE_GRACE) and AbandonedWindow
	// (HYPERDROP_ABANDONED_UPLOAD_TTL) override the live-share grace and the
	// abandoned-upload window; 0 keeps each package's default.
	LiveShareGrace  time.Duration
	AbandonedWindow time.Duration
	// TrustedProxies (HYPERDROP_TRUSTED_PROXIES, comma-separated addresses
	// and CIDR prefixes) are the peers whose PROXY header the HTTPS listener
	// requires and believes; empty lists none, so every peer's header is
	// refused. Nothing is trusted implicitly, loopback included. See
	// proxyproto.go.
	TrustedProxies []netip.Prefix
	// NamesURL (HYPERDROP_NAMES_URL) is the free-name service this server
	// talks to; unset is the HyperDrop service (ddns.ParseBaseURL).
	NamesURL string

	// DataDir (HYPERDROP_DATA, default /data) holds the database, the shares
	// and the log directory; the operator subcommands read it too.
	DataDir string
	// Channel (HYPERDROP_CHANNEL) is the package channel; "synology" keeps
	// the log off stderr (logSink), and /api/health reports it.
	Channel string
	// Supervised is INVOCATION_ID set: systemd started the process and
	// restarts it when it exits (Restart=always), so a damaged daily copy
	// exits it into a start that checks the file (owedCheck). The Synology
	// package is never supervised: DSM starts its script under a unit of
	// its own, which is not relied on to restart the server.
	Supervised bool
	// LinkedRoots (HYPERDROP_LINKED_ROOTS) and LinkedScan
	// (HYPERDROP_LINKED_SCAN) are the colon-separated fixed roots and scanned
	// volumes of linked shares (linked.SplitList); main builds the root set
	// from them once the store is open.
	LinkedRoots []string
	LinkedScan  []string
	// AutoUpdate (HYPERDROP_AUTO_UPDATE, selfupdate.ParseChoice) is a new
	// volume's automatic-update choice.
	AutoUpdate bool
	// DiskReserve (HYPERDROP_DISK_RESERVE) is the upload reserve
	// (diskReservePercent).
	DiskReserve int
	// StatusFile (HYPERDROP_STATUS_FILE) is where the status writer records
	// this process's state; "" writes none.
	StatusFile string
	// ConfFile (HYPERDROP_CONF) is the Synology package's conf, which names
	// the current address; "" on every other server.
	ConfFile string
	// DDNSAllowPrivate (HYPERDROP_DDNS_ALLOW_PRIVATE=1) lets a DDNS recipe
	// name a private address.
	DDNSAllowPrivate bool
	// AddressRequest (HYPERDROP_ADDRESS_REQUEST) is the file through which
	// DSM asks for an address change; "" asks nothing.
	AddressRequest string
	// UpdateDir (HYPERDROP_UPDATE_DIR) is the directory the root-owned
	// installer watches; "" keeps the update route off.
	UpdateDir string
	// PushRelay (HYPERDROP_PUSH_RELAY, api.ParsePushRelay) is the push relay:
	// api.DefaultPushRelay when unset, "" when set empty or malformed.
	PushRelay string
	// Releases (HYPERDROP_SERVER_RELEASES, selfupdate.ParseBase) is the
	// website directory the self-updater reads: selfupdate.DefaultBase when
	// unset, "" when set empty or malformed.
	Releases string
	// ACMEEmail (HYPERDROP_ACME_EMAIL) is the ACME account's address, and
	// ACMECA (HYPERDROP_ACME_CA) a private CA's directory URL in place of
	// Let's Encrypt; both are read in HTTPS mode only.
	ACMEEmail string
	ACMECA    string
	// ACMETrustedRoots (HYPERDROP_ACME_CA_CERT, PEM) are the roots a private
	// ACME CA's TLS certificate is checked against; nil when unset.
	ACMETrustedRoots *x509.CertPool
	// Web is the web client's configuration (resolveWeb).
	Web webConfig

	// The fields below each hold the error of a value resolveBoot could not
	// parse, which a later boot phase refuses or logs where it first uses the
	// value rather than with resolveBoot's own error: a malformed
	// HYPERDROP_AUTO_UPDATE or HYPERDROP_DISK_RESERVE is fatal in
	// openServingVolume, a malformed HYPERDROP_ACME_CA_CERT is fatal in
	// setupCertificates (HTTPS mode only), and a malformed HYPERDROP_PUSH_RELAY
	// or HYPERDROP_SERVER_RELEASES turns its feature off with a log line in
	// prepareServices.
	AutoUpdateErr       error
	DiskReserveErr      error
	ACMETrustedRootsErr error
	PushRelayErr        error
	ReleasesErr         error
}

// positiveDuration parses a Go duration override ("45m", "12h"), answering 0
// (the default) for an empty, unparseable or non-positive value: a typo must
// not disable a sweep or a grace period, so it is ignored rather than obeyed.
func positiveDuration(v string) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// resolveBoot reads the whole serving environment, through lookup, in one
// place. It only reads (the environment, and the directory
// HYPERDROP_WEB_DEV_DIR names), so main calls it before the operator
// subcommands and refuses its error once the log is open. A custom domain is
// REQUIRED (two structural reasons: the files.<domain> origin split, and
// links that survive a move, see the comment at the call site), and with a
// domain there must be either a public HYPERDROP_IP or HYPERDROP_BEHIND_NAT=1.
// The web client's variables are judged last (resolveWeb), so a server with
// both kinds of error reports the domain's first. DataDir and Channel are set
// even when it answers an error.
func resolveBoot(lookup func(string) (string, bool)) (bootConfig, error) {
	getenv := func(k string) string {
		v, _ := lookup(k)
		return v
	}
	bc := bootConfig{
		HTTPAddr:     cmp.Or(getenv("HYPERDROP_HTTP_ADDR"), ":80"),
		HTTPSAddr:    cmp.Or(getenv("HYPERDROP_HTTPS_ADDR"), ":443"),
		Domain:       getenv("HYPERDROP_DOMAIN"),
		PublicIP:     getenv("HYPERDROP_IP"),
		AllowPrivate: getenv("HYPERDROP_ALLOW_PRIVATE") == "1",
		Platform:     getenv("HYPERDROP_PLATFORM"),

		LiveShareGrace:  positiveDuration(getenv("HYPERDROP_LIVE_SHARE_GRACE")),
		AbandonedWindow: positiveDuration(getenv("HYPERDROP_ABANDONED_UPLOAD_TTL")),

		DataDir:          cmp.Or(getenv("HYPERDROP_DATA"), "/data"),
		Channel:          getenv("HYPERDROP_CHANNEL"),
		LinkedRoots:      linked.SplitList(getenv("HYPERDROP_LINKED_ROOTS")),
		LinkedScan:       linked.SplitList(getenv("HYPERDROP_LINKED_SCAN")),
		StatusFile:       getenv("HYPERDROP_STATUS_FILE"),
		ConfFile:         getenv("HYPERDROP_CONF"),
		DDNSAllowPrivate: getenv("HYPERDROP_DDNS_ALLOW_PRIVATE") == "1",
		AddressRequest:   getenv("HYPERDROP_ADDRESS_REQUEST"),
		UpdateDir:        getenv("HYPERDROP_UPDATE_DIR"),
		ACMEEmail:        getenv("HYPERDROP_ACME_EMAIL"),
		ACMECA:           getenv("HYPERDROP_ACME_CA"),
	}
	bc.Supervised = getenv("INVOCATION_ID") != "" && bc.Channel != "synology"
	bc.AutoUpdate, bc.AutoUpdateErr = selfupdate.ParseChoice(getenv("HYPERDROP_AUTO_UPDATE"))
	bc.DiskReserve, bc.DiskReserveErr = diskReservePercent(getenv("HYPERDROP_DISK_RESERVE"))
	// Unset is the HyperDrop relay; set and empty turns push off.
	bc.PushRelay = api.DefaultPushRelay
	if v, set := lookup("HYPERDROP_PUSH_RELAY"); set {
		bc.PushRelay = v
	}
	if bc.PushRelay, bc.PushRelayErr = api.ParsePushRelay(bc.PushRelay, bc.AllowPrivate); bc.PushRelayErr != nil {
		bc.PushRelay = ""
	}
	// Unset is the HyperDrop site; set and empty never checks.
	bc.Releases = selfupdate.DefaultBase
	if raw, set := lookup("HYPERDROP_SERVER_RELEASES"); set {
		bc.Releases, bc.ReleasesErr = selfupdate.ParseBase(raw)
	}
	// A test hook: a private ACME CA's TLS certificate (e.g. Pebble's), PEM.
	if pem := getenv("HYPERDROP_ACME_CA_CERT"); pem != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(pem)) {
			bc.ACMETrustedRoots = pool
		} else {
			bc.ACMETrustedRootsErr = errors.New("HYPERDROP_ACME_CA_CERT: invalid PEM")
		}
	}
	behindNAT := getenv("HYPERDROP_BEHIND_NAT") == "1"
	bc.BehindNAT = behindNAT
	trusted, err := conffile.ParseTrustedProxies(getenv("HYPERDROP_TRUSTED_PROXIES"))
	if err != nil {
		return bc, err
	}
	bc.TrustedProxies = trusted
	if bc.NamesURL, err = ddns.ParseBaseURL(getenv("HYPERDROP_NAMES_URL"), bc.AllowPrivate); err != nil {
		return bc, err
	}
	// A free name IS the domain: <name>.hyperdrop.link. Deriving it here
	// means origins, certificate subjects and adoption all read one field.
	if name := getenv("HYPERDROP_DDNS_NAME"); name != "" {
		if bc.Domain != "" {
			return bc, errors.New("HYPERDROP_DDNS_NAME and HYPERDROP_DOMAIN are both set: " +
				"a free name supplies the domain, so set one or the other")
		}
		if !ddns.ValidName(name) {
			return bc, fmt.Errorf("HYPERDROP_DDNS_NAME=%q is not a name this service issues: "+
				"use 5 to 32 characters of lowercase letters, digits and hyphens", name)
		}
		bc.DDNSName = name
		bc.Domain = ddns.FQDN(name)
	}
	if bc.Domain == "" && !bc.AllowPrivate {
		return bc, errors.New("HYPERDROP_DOMAIN is required: HyperDrop serves share pages on it and " +
			"uploaded files on files.<domain>, which is what keeps an uploaded page off " +
			"the origin that holds your listings and password form. " +
			"Set HYPERDROP_ALLOW_PRIVATE=1 for a development server with neither")
	}
	if bc.Domain != "" && !domain.Valid(bc.Domain) {
		return bc, fmt.Errorf("HYPERDROP_DOMAIN=%q is not a valid domain name", bc.Domain)
	}
	if bc.Domain != "" && !isPublicIPv4(bc.PublicIP) {
		if !behindNAT {
			// A free name is the variable the operator actually set, so it
			// is named here instead of the derived HYPERDROP_DOMAIN: naming
			// the wrong one sends them looking for a variable they never
			// touched.
			domainVar, domainVal := "HYPERDROP_DOMAIN", bc.Domain
			if bc.DDNSName != "" {
				domainVar, domainVal = "HYPERDROP_DDNS_NAME", bc.DDNSName
			}
			return bc, fmt.Errorf("%s=%s needs HYPERDROP_IP set to this server's public IPv4 "+
				"(got %q): the certificate is only issued once %s resolves here. "+
				"Behind a router that forwards 443 here, set HYPERDROP_BEHIND_NAT=1 instead",
				domainVar, domainVal, bc.PublicIP, bc.Domain)
		}
		if bc.PublicIP != "" {
			return bc, fmt.Errorf("HYPERDROP_IP=%q is not a public IPv4; behind NAT leave it unset", bc.PublicIP)
		}
	}
	if bc.Web, err = resolveWeb(lookup, bc.AllowPrivate); err != nil {
		return bc, err
	}
	return bc, nil
}

func main() {
	// Read before the operator subcommands, which need only DataDir; the
	// error is refused below, once the log is open, so it lands there.
	bc, bootErr := resolveBoot(os.LookupEnv)
	dataDir := bc.DataDir
	if exit, serve := operatorCommand(dataDir, os.Args[1:]); !serve {
		os.Exit(exit)
	}

	if err := checkDataWritable(dataDir); err != nil {
		log.Fatal(err)
	}

	// Everything the serving process logs, CertMagic included, lands in its
	// own rotating file beside the data, and on stderr too except on a NAS
	// (logSink). Opened after the operator subcommands above, which run while
	// another server process still owns the file.
	logs, err := logfile.Open(filepath.Join(dataDir, "logs"))
	if err != nil {
		log.Fatalf("opening the log directory: %v", err)
	}
	defer logs.Close()
	sink := logSink(bc.Channel, logs)
	log.SetFlags(log.LUTC | log.Ldate | log.Ltime)
	log.SetOutput(sink)
	certmagic.Default.Logger = certLogger(sink)
	certmagic.DefaultACME.Logger = certmagic.Default.Logger

	// SIGINT/SIGTERM (docker stop) trigger a graceful shutdown instead of
	// truncating in-flight transfers.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go serverGuard.Run(ctx)
	defer stop()

	// A custom domain is REQUIRED. Two reasons, both structural:
	//
	//   1. Uploaded bytes are served from files.<domain>, a separate origin,
	//      so an uploaded .html cannot run as first-party script on the page
	//      origin. An IP address cannot be split that way, and a second PORT
	//      cannot either (cookies ignore ports).
	//   2. A domain is what makes links survive. Every link embeds the host;
	//      with a domain the server can move and the links keep working.
	//
	// HYPERDROP_ALLOW_PRIVATE=1 is the development escape hatch (matching the
	// client-side flag of the same name): plain HTTP, one origin, no domain.
	// An env var rather than a flag, so it stays out of --help and cannot be
	// reached by accident. The rest of the rules live in resolveBoot.
	if bootErr != nil {
		log.Fatal(bootErr)
	}
	if len(bc.TrustedProxies) > 0 {
		log.Printf("HTTPS requires a PROXY header from %s and refuses one from anyone else",
			joinPrefixes(bc.TrustedProxies))
	}

	// The phases (boot.go), in the order they run.
	vol, sweep := openServingVolume(bc)
	up := startUpkeep(bc, vol)
	// Deferred after stop and logs.Close, so it runs before them: the
	// background work stops and is waited for, and the database closes and
	// records a clean close, while the log still takes lines. A log.Fatal
	// exits without running it, so a fatal stop leaves no record.
	defer closeVolume(vol.DB, up)
	addr := openAddressing(ctx, bc, vol, up.status)
	web := prepareServices(bc)
	mux := startAPI(ctx, bc, vol, up, addr, web, sweep)
	if addr.domainName == "" {
		serveHTTP(ctx, bc.HTTPAddr, mux)
		return
	}
	certs := setupCertificates(ctx, bc, addr, vol.FS, up.status)
	serveHTTPS(ctx, bc, addr, up, mux, certs)
}

// bootTakeLimit bounds the free-name claim that runs before the listeners
// bind, well inside the 90 s health windows of the updater and the
// provisioner.
const bootTakeLimit = 30 * time.Second

// bootTake is the boot's attempt at the free name: Take under ctx (the signal
// context, so a stop during boot is not held up by the names service) and at
// most limit. A claim cut short stays pending in the store, and the update
// loop finishes it like any other pending claim.
func bootTake(ctx context.Context, updater *ddns.Updater, name, serverID string, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	return updater.Take(ctx, name, serverID)
}

// seedAdmin bootstraps the first administrator from HYPERDROP_ADMIN_USER and
// the password (EnsureAdmin ignores both once any admin exists), then lets
// the password go. A volume with no administrator is a new one, so it first
// records autoUpdate, the volume's automatic-update choice, before the
// administrator exists: a boot that stops between the two records it again,
// and a volume that already has an administrator keeps the switch it has. It is read once, from the file HYPERDROP_ADMIN_PASSWORD_FILE
// names when that is set and the file exists, else from
// HYPERDROP_ADMIN_PASSWORD.
//
// A seed file is removed once EnsureAdmin succeeds, so the password never
// enters this process's environment and does not outlive the first boot on
// disk. A volume that already has an administrator never reads the seed: it
// says so in the log, because a password typed into a reinstall over kept
// data changes nothing, and removes it, so a seed it cannot read (a
// directory, a file another user owns) never stops a boot that does not
// need it. Only a volume with no administrator yet fails on a seed it cannot
// read, since that password is the one it would be created with.
// The variable is unset either way, which keeps it out of every later
// os.Getenv and of anything this process starts; the copy the kernel shows in
// /proc/<pid>/environ is the one passed at exec, and it stays.
func seedAdmin(db *metadb.DB, autoUpdate bool) error {
	defer os.Unsetenv("HYPERDROP_ADMIN_PASSWORD")
	password := os.Getenv("HYPERDROP_ADMIN_PASSWORD")
	seed := os.Getenv("HYPERDROP_ADMIN_PASSWORD_FILE")
	admins, err := db.AdminNames()
	if err != nil {
		return err
	}
	if len(admins) > 0 {
		if seed != "" {
			if _, err := os.Lstat(seed); err == nil {
				log.Printf("admin bootstrap: %s is ignored: this volume already has an administrator, whose password is unchanged", seed)
				if err := os.Remove(seed); err != nil && !errors.Is(err, fs.ErrNotExist) {
					log.Printf("admin bootstrap: removing %s: %v", seed, err)
				}
			}
		}
		return nil
	}
	fromFile := false
	if seed != "" {
		b, err := os.ReadFile(seed)
		switch {
		case err == nil:
			password, fromFile = string(b), true
		case !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("reading the admin password seed: %w", err)
		}
	}
	if err := selfupdate.StartWith(db, autoUpdate); err != nil {
		return fmt.Errorf("recording the automatic-update choice: %w", err)
	}
	if err := db.EnsureAdmin(os.Getenv("HYPERDROP_ADMIN_USER"), password); err != nil {
		return err
	}
	if fromFile {
		if err := os.Remove(seed); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("admin bootstrap: removing %s: %v", seed, err)
		}
	}
	return nil
}

// redirectToHTTPS is port 80's answer to everything but health, the
// names-service probe and ACME. It is host-aware: a request already addressed
// to the current domain or its file origin keeps that name (so an http://
// link to a file lands on the file origin); anything else, a bare IP or a
// domain the server does not hold, goes to the current domain's page
// origin. fallback (the boot domain) stands in only while no domain is
// current. Only those names are ever a redirect target, so it is not an open
// redirect.
func redirectToHTTPS(dom *domain.Manager, fallback string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		target := dom.Current()
		switch {
		case target == "":
			target = fallback
		case dom.IsCurrent(host) || host == api.ShareHost(target):
			target = host
		}
		http.Redirect(w, r, "https://"+target+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}

// httpsTLSConfig is the HTTPS listener's TLS configuration: CertMagic's
// (which carries the TLS-ALPN challenge protocol), with certificates chosen
// by getCertificate, HTTP/2 offered ahead of HTTP/1.1, and TLS 1.2 the
// oldest version accepted.
func httpsTLSConfig(base *tls.Config, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	base.GetCertificate = getCertificate
	base.NextProtos = append([]string{"h2", "http/1.1"}, base.NextProtos...)
	base.MinVersion = tls.VersionTLS12
	return base
}

// bootSelfCheck probes this process's own plain-HTTP health route (served
// unredirected on :80 in both modes) and exits nonzero when it cannot answer
// within the window. `systemctl is-active` cannot tell serving from wedged,
// so a process that binds and then cannot serve would otherwise sit
// active-but-broken past the updater's rollback watch; exiting turns that
// state into a visible unit failure instead. The window is generous because
// a big store's startup scan is real work, not a wedge.
func bootSelfCheck(addr string) {
	urls, ok := selfCheckURLs(addr)
	if !ok {
		return
	}
	if !waitServing(time.Minute, time.Second, urls...) {
		log.Fatal("boot self-check: /api/health never answered; exiting so systemd (and the updater's rollback) can see the failure")
	}
}

// The HTTP/2 receive windows: how many body bytes a connection, and one
// stream on it, may have in flight before the handler reads them. Go's
// default of 1 MiB for both caps every upload on a connection at 1 MiB per
// round trip (about 80 Mbit/s at 100 ms), and a client carries all of a
// share's parallel chunks, and every other command, on one connection. The
// upload handlers stream to disk, so these are ceilings, not steady memory.
const (
	h2ConnWindow   = 16 << 20
	h2StreamWindow = 8 << 20
)

// h2MaxStreams is how many requests one HTTP/2 connection may have open, each of
// which holds a goroutine: the lowest RFC 9113 recommends, well above what a browser
// or a client's parallel chunks use, and well below Go's default of 250.
const h2MaxStreams = 100

// serverErrorLog is every HTTP server's error log: abandoned TLS handshakes
// are counted per address and hour (handshakeLog), the rest logged as is.
var serverErrorLog = log.New(newHandshakeLog(time.Now), "", 0)

// newServer applies header timeouts and no whole-request timeout: uploads and
// downloads can legitimately run for many minutes. A request body is read
// under serverBodyDeadline instead (bodydeadline.go), which fails a body that
// stalls or trickles and never one that keeps arriving. IdleTimeout only reaps
// keep-alive connections between requests, so it is safe to set. The HTTP/2
// windows apply where HTTP/2 is negotiated (the HTTPS server).
func newServer(addr string, h http.Handler) *http.Server {
	srv := &http.Server{Addr: addr, Handler: serverGuard.Wrap(serverBodyDeadline.wrap(h)),
		ErrorLog:          serverErrorLog,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          h2MaxStreams,
			MaxReceiveBufferPerConnection: h2ConnWindow,
			MaxReceiveBufferPerStream:     h2StreamWindow,
		}}
	serverGuard.AddServer(srv)
	return srv
}

// serverGuard refuses new requests on every server this binary starts while the
// machine cannot afford them (api.LoadGuard).
var serverGuard = api.NewLoadGuard(api.ReadMemory)

// serverRun pairs a server with its (blocking) serve call.
type serverRun struct {
	srv   *http.Server
	serve func() error
}

// shutdownGrace is how long each server's graceful Shutdown may wait for
// the requests still running.
const shutdownGrace = 5 * time.Second

// serveUntilShutdown runs the servers and, when ctx is canceled (SIGINT/
// SIGTERM), drains the parked long-polls and gives each server a short
// graceful Shutdown. The grace (shutdownGrace) is not the watch timeout:
// long-polls are woken by drain, resumable uploads pick up where they were
// cut, and holding the listener longer is downtime for everyone during an
// update. A serve error before that is fatal.
func serveUntilShutdown(ctx context.Context, drain func(), servers ...serverRun) {
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func() { errc <- s.serve() }()
	}
	select {
	case err := <-errc:
		log.Fatal(err)
	case <-ctx.Done():
	}
	log.Print("shutting down")
	drain()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.srv.Shutdown(shutdownCtx)
		}()
	}
	wg.Wait()
}

// diskReservePercent reads HYPERDROP_DISK_RESERVE: unset, the flat 1 GiB
// reserve (sharefs.FlatReserve); otherwise a percentage of the disk from 0
// (no reserve, uploads still admitted against the free space) to 90.
func diskReservePercent(v string) (int, error) {
	if v == "" {
		return sharefs.FlatReserve, nil
	}
	pct, err := strconv.Atoi(v)
	if err != nil || pct < 0 || pct > 90 {
		return 0, fmt.Errorf("invalid value %q (want 0-90)", v)
	}
	return pct, nil
}

// bootPublishes settles the commit journals the boot pass found. The
// database spells paths as the volume does before the first journal is
// judged: a commit's rows and a later upload's are spelled that way, so on
// a volume that folds case only a spelled lookup finds them. api.NewServer
// sets the same answer (b.FS.SamePath) when it builds the handler.
func bootPublishes(db *metadb.DB, store *sharefs.FS) (finished, reopened int, err error) {
	if store.FoldsCase() {
		db.SetFoldCase(store.SamePath)
	}
	return housekeep.FinishPublishes(db, store)
}

package api

// The server's own verdict on whether it is in trouble, so a self-hosted box
// can say so before it is too late. This product has no console: if the
// server runs out of disk or of memory, the owner's only chance of hearing
// about it is the app, and the app can only report what the server tells it.
//
// Thresholds, deliberately, not trends: a projection needs a history file and
// a rate, and the failure it would catch (a slow fill) is caught by the warn
// level anyway, just with less notice.

import (
	"fmt"
	"net/http"
	"runtime"
	"slices"

	"hyperdrop/server/internal/bytefmt"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/webapp"
)

// Health levels, ordered: a verdict takes the worst of its signals.
const (
	healthOK       = "ok"
	healthWarn     = "warn"
	healthCritical = "critical"
)

// Reason codes. Stable strings: clients word them for the user, so renaming
// one silently downgrades a warning to "something is wrong".
const (
	reasonDiskLow      = "disk-low"
	reasonMemoryLow    = "memory-low"
	reasonDBRecovered  = "db-recovered"
	reasonFilesMissing = "files-missing"
	reasonProxyHeader  = "proxy-header"
	// reasonAddressPending is an address change requested from DSM that
	// waits until the new address is proven.
	reasonAddressPending = "address-pending"
	// reasonCertificatePending is a served domain with no certificate in
	// storage yet, so every HTTPS handshake is refused until Let's Encrypt
	// issues one.
	reasonCertificatePending = "certificate-pending"
)

// The two ways a connection's PROXY header can be wrong, as the HTTPS
// listener reports them.
const (
	// ProxyKindUntrustedHeader is a header from a peer that is not a listed
	// proxy.
	ProxyKindUntrustedHeader = "untrusted-header"
	// ProxyKindTrustedNoHeader is a listed proxy whose connection sent bytes
	// that are not a header.
	ProxyKindTrustedNoHeader = "trusted-no-header"
)

// ProxyHeaderSource is a private address whose secure connections fail on
// the PROXY header.
type ProxyHeaderSource struct {
	Addr string
	Kind string
}

// Signal thresholds. Disk is measured as the room left for new shares, the
// free space above the file layer's own system reserve, which is the number
// the apps show as available. It warns when that room is under
// diskWarnRoomBytes, whatever the disk's size.
const diskWarnRoomBytes int64 = 100_000_000

const (
	memWarnFraction     = 0.15
	memCriticalFraction = 0.08
)

type healthReason struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

type healthVerdict struct {
	Level   string         `json:"level"`
	Reasons []healthReason `json:"reasons,omitempty"`
}

// healthInputs is everything the verdict is computed from, so the rule is a
// pure function of numbers and can be table-tested without a server.
type healthInputs struct {
	FreeBytes    int64
	TotalBytes   int64
	ReserveBytes int64
	MemTotal     int64
	MemAvailable int64
	// Recovered is the marker a boot left after restoring the database
	// from a backup; nil when none.
	Recovered *metadb.Recovered
	// MissingFiles is how many stored files the last integrity scan found
	// absent from disk.
	MissingFiles int
	// ProxyPrivate are the private addresses whose secure connections fail
	// on the PROXY header, most recently seen first; ProxyPublic counts the
	// recent headers from public addresses, which are never named.
	ProxyPrivate []ProxyHeaderSource
	ProxyPublic  int
	// Synology is true on the DSM package, where the proxy address is set on
	// HyperDrop's DSM page rather than in the environment.
	Synology bool
	// PendingAddress is an address change requested from DSM that is not
	// carried out yet, and PendingReason the sentence saying what it waits
	// for; both empty when none is pending.
	PendingAddress string
	PendingReason  string
	// CertificatePending is the served domain that has no certificate in
	// storage yet; "" when it has one or no domain is served.
	CertificatePending string
}

// healthLevels are the verdict's levels, least severe first.
var healthLevels = []string{healthOK, healthWarn, healthCritical}

// worse answers the more severe of two levels.
func worse(a, b string) string {
	if slices.Index(healthLevels, b) > slices.Index(healthLevels, a) {
		return b
	}
	return a
}

// evaluateHealth is the whole rule. Each signal contributes at most one
// reason, and the level is the worst of them.
func evaluateHealth(in healthInputs) healthVerdict {
	v := healthVerdict{Level: healthOK}
	add := func(level, code, text string) {
		v.Level = worse(v.Level, level)
		v.Reasons = append(v.Reasons, healthReason{Code: code, Text: text})
	}

	// Disk. Below the reserve, uploads are already failing.
	room := in.FreeBytes - in.ReserveBytes
	switch {
	case in.ReserveBytes > 0 && room < 0:
		add(healthCritical, reasonDiskLow, fmt.Sprintf(
			"No room left for new shares: %s of disk free, below the %s this server keeps free. New shares are being refused",
			byteText(in.FreeBytes), byteText(in.ReserveBytes)))
	case room < diskWarnRoomBytes:
		add(healthWarn, reasonDiskLow, fmt.Sprintf("Only %s left for new shares", byteText(room)))
	}

	// A restored database: the shares made after the backup are gone, and
	// the owner is the only one who can tell whether that matters.
	if in.Recovered != nil {
		add(healthWarn, reasonDBRecovered, fmt.Sprintf(
			"the database was restored from the backup of %s; shares made after it may be missing",
			in.Recovered.BackupAt.UTC().Format("2006-01-02")))
	}

	// Rows that name bytes the disk no longer holds: only a backup of the
	// folder can bring them back.
	if in.MissingFiles == 1 {
		add(healthWarn, reasonFilesMissing,
			"1 file is missing from HyperDrop's data folder. Restore it from a backup of the folder.")
	} else if in.MissingFiles > 1 {
		add(healthWarn, reasonFilesMissing, fmt.Sprintf(
			"%d files are missing from HyperDrop's data folder. Restore them from a backup of the folder.", in.MissingFiles))
	}

	// A PROXY header the listener refuses fails every secure connection
	// from that source before the server can say why anywhere else.
	if len(in.ProxyPrivate) > 0 {
		src := in.ProxyPrivate[0]
		switch src.Kind {
		case ProxyKindTrustedNoHeader:
			add(healthCritical, reasonProxyHeader, fmt.Sprintf(
				"%s is set as the proxy address but sends no PROXY header, so its connections fail. "+
					"Turn on send-proxy-v2 in the proxy, or clear the proxy address.", src.Addr))
		default:
			fix := "in HYPERDROP_TRUSTED_PROXIES."
			if in.Synology {
				fix = "as the proxy address on HyperDrop's DSM page."
			}
			add(healthCritical, reasonProxyHeader, fmt.Sprintf(
				"Connections from %s start with a PROXY header, but %s is not set as a proxy address, "+
					"so every secure connection fails. Set %s %s", src.Addr, src.Addr, src.Addr, fix))
		}
	} else if in.ProxyPublic > 0 {
		// Anyone on the internet can send a header, and the listener
		// reports public ones only once several arrive within an hour.
		add(healthWarn, reasonProxyHeader,
			"Connections from the internet start with a PROXY header. A proxy in front of HyperDrop must be on this network.")
	}

	// A domain with no certificate refuses every handshake: the cause is
	// almost always the name not pointing here yet or port 443 not reaching
	// this server, which only the person at the router can fix.
	if in.CertificatePending != "" {
		add(healthWarn, reasonCertificatePending, fmt.Sprintf(
			"No certificate for %s yet, so nothing can connect over HTTPS. Let's Encrypt issues one once %s points at this server's public address and port 443 reaches it (port 80 too for a free name): check the router's forwards; the first certificate can take a few minutes after that.",
			in.CertificatePending, in.CertificatePending))
	}

	// The old address keeps serving until the requested one is proven.
	if in.PendingAddress != "" {
		add(healthWarn, reasonAddressPending, fmt.Sprintf(
			"Waiting to switch to %s: %s", in.PendingAddress, in.PendingReason))
	}

	// Memory. Host-wide, which is what the server competes for.
	if in.MemTotal > 0 {
		frac := float64(in.MemAvailable) / float64(in.MemTotal)
		switch {
		case frac < memCriticalFraction:
			add(healthCritical, reasonMemoryLow, fmt.Sprintf(
				"only %s of memory available out of %s: the server is close to being killed by the system",
				byteText(in.MemAvailable), byteText(in.MemTotal)))
		case frac < memWarnFraction:
			add(healthWarn, reasonMemoryLow, fmt.Sprintf(
				"%s of memory available out of %s", byteText(in.MemAvailable), byteText(in.MemTotal)))
		}
	}
	return v
}

// byteText renders a size the way a person reads one: decimal units (1000).
// Kept here rather than borrowed from the client so a server message never
// depends on which client is asking. humanSize (listing.go) is the binary
// twin; both go through package bytefmt.
func byteText(n int64) string { return bytefmt.Decimal(n) }

// healthVerdict gathers the live numbers and evaluates them.
func (h *handler) healthVerdict(sp sharefs.Space, memTotal, memAvail int64) healthVerdict {
	in := healthInputs{
		FreeBytes: sp.Free, TotalBytes: sp.Total, ReserveBytes: sp.Reserve,
		MemTotal: memTotal, MemAvailable: memAvail,
	}
	if h.dep.MissingFiles != nil {
		in.MissingFiles = int(h.dep.MissingFiles.Load())
	}
	if h.dep.ProxyHeaders != nil {
		in.ProxyPrivate, in.ProxyPublic = h.dep.ProxyHeaders()
	}
	in.Synology = h.dep.Channel == "synology"
	if h.dep.AddressPending != nil {
		in.PendingAddress, in.PendingReason = h.dep.AddressPending()
	}
	if h.dep.CertificatePending != nil {
		in.CertificatePending = h.dep.CertificatePending()
	}
	if h.dep.DataDir != "" {
		if rec, ok := metadb.ReadRecovered(h.dep.DataDir); ok {
			in.Recovered = &rec
		}
	}
	return evaluateHealth(in)
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

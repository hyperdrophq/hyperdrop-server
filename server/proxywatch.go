package main

import (
	"errors"
	"log"
	"net/netip"
	"slices"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"hyperdrop/server/internal/api"
)

// A wrong proxy setting fails every TLS handshake before the server can say
// anything over HTTPS: a proxy sending PROXY headers that is not listed, or
// a listed one sending none. proxyWatch records the sources of those
// failures so the health verdict and the status file can name the fix.
//
// Only a private source (RFC 1918 and IPv6 ULA, loopback, link-local) is
// ever named: anyone on the internet can send a header, so a public source
// is counted without its address and its address reaches the server log
// alone. The set holds at most proxyWatchMax private sources; a new one
// evicts the least recently seen, and public ones never take a place, so a
// stranger cannot push the real proxy out. Public headers are counted over
// the last hour and reported only from proxyPublicMin of them, so one stray
// packet from the internet reports nothing.

const (
	// proxyWatchMax bounds the private sources kept.
	proxyWatchMax = 8
	// proxyLogMax bounds the record of when each source was last logged.
	proxyLogMax = 64
	// proxyLogEvery is how often one source is logged at most.
	proxyLogEvery = time.Hour
	// proxyWatchForget is how long a private source stays reported after
	// its last failed connection.
	proxyWatchForget = 24 * time.Hour
	// proxyPublicWindow is how far back public headers are counted, in
	// one-minute buckets.
	proxyPublicWindow = 60
	// proxyPublicMin is how many public headers within the window are
	// reported; fewer report none.
	proxyPublicMin = 3
)

// proxyWatch is the HTTPS listener's record of connections failing on the
// PROXY header. A nil watch records nothing.
type proxyWatch struct {
	now  func() time.Time
	logf func(format string, args ...any)
	// changed receives the snapshot when a source is added, evicted,
	// changes kind or is forgotten, and when the reported public count
	// appears; on Tick it also receives moved counts, so a flood of
	// connections does not write the status file per connection. It is
	// called outside mu, in the order the snapshots were taken.
	changed func(private []ProxySource, publicCount int)

	mu      sync.Mutex
	private []ProxySource // at most proxyWatchMax, least recently seen first
	// publicN[i] counts the public headers of minute publicAt[i], the
	// bucket being that minute modulo proxyPublicWindow.
	publicN  [proxyPublicWindow]int
	publicAt [proxyPublicWindow]int64
	logged   map[netip.Addr]time.Time // at most proxyLogMax
	dirty    bool                     // counts moved since the last report
	reported int                      // the public count last reported
	seq      uint64                   // snapshots taken for changed

	deliverMu sync.Mutex
	delivered uint64 // the newest snapshot handed to changed
}

// proxyReport is a snapshot taken under mu for changed; seq 0 is none.
type proxyReport struct {
	seq     uint64
	private []ProxySource
	public  int
}

// newProxyWatch returns a watch reporting changes to changed (nil: none).
func newProxyWatch(changed func(private []ProxySource, publicCount int)) *proxyWatch {
	return &proxyWatch{now: time.Now, logf: log.Printf, changed: changed, logged: map[netip.Addr]time.Time{}}
}

// privateSource reports whether an address may be named: RFC 1918 and IPv6
// ULA, loopback or link-local.
func privateSource(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

// Observe records a connection from peer whose first Read failed with err:
// proxyproto.ErrSuperfluousProxyHeader (a header from a peer that is not
// listed) or proxyproto.ErrNoProxyProtocol (a listed peer that sent no
// header). Any other error is ignored.
func (p *proxyWatch) Observe(peer netip.Addr, err error) {
	if p == nil || !peer.IsValid() {
		return
	}
	var kind string
	switch {
	case errors.Is(err, proxyproto.ErrSuperfluousProxyHeader):
		kind = api.ProxyKindUntrustedHeader
	case errors.Is(err, proxyproto.ErrNoProxyProtocol):
		kind = api.ProxyKindTrustedNoHeader
	default:
		return
	}
	peer = peer.Unmap()
	now := p.now()

	p.mu.Lock()
	r := p.observe(peer, kind, now)
	p.mu.Unlock()
	p.deliver(r)
}

// observe is Observe under mu.
func (p *proxyWatch) observe(peer netip.Addr, kind string, now time.Time) proxyReport {
	p.logOnce(peer, kind, now)
	if !privateSource(peer) {
		// A public listed proxy without a header is the operator's own
		// address, not a stranger's header: the log line is its report.
		if kind != api.ProxyKindUntrustedHeader {
			return proxyReport{}
		}
		minute := now.Unix() / 60
		i := minute % proxyPublicWindow
		if p.publicAt[i] != minute {
			p.publicAt[i], p.publicN[i] = minute, 0
		}
		p.publicN[i]++
		switch n := p.publicCount(now); {
		case n == p.reported:
		case p.reported == 0:
			return p.report()
		default:
			p.dirty = true
		}
		return proxyReport{}
	}
	addr := peer.String()
	if i := slices.IndexFunc(p.private, func(s ProxySource) bool { return s.Addr == addr }); i >= 0 {
		s := p.private[i]
		moved := s.Kind != kind
		s.Count++
		s.LastSeen = now.Unix()
		s.Kind = kind
		p.private = append(slices.Delete(p.private, i, i+1), s)
		if moved {
			return p.report()
		}
		p.dirty = true
		return proxyReport{}
	}
	if len(p.private) == proxyWatchMax {
		p.private = slices.Delete(p.private, 0, 1)
	}
	p.private = append(p.private, ProxySource{Addr: addr, Count: 1, LastSeen: now.Unix(), Kind: kind})
	return p.report()
}

// publicCount answers the public headers of the last proxyPublicWindow
// minutes, or 0 below proxyPublicMin. Called with mu held.
func (p *proxyWatch) publicCount(now time.Time) int {
	since := now.Unix()/60 - proxyPublicWindow
	n := 0
	for i, at := range p.publicAt {
		if at > since {
			n += p.publicN[i]
		}
	}
	if n < proxyPublicMin {
		return 0
	}
	return n
}

// logOnce logs a source at most once per proxyLogEvery. Called with mu held.
func (p *proxyWatch) logOnce(peer netip.Addr, kind string, now time.Time) {
	if last, ok := p.logged[peer]; ok && now.Sub(last) < proxyLogEvery {
		return
	}
	if len(p.logged) >= proxyLogMax {
		var oldest netip.Addr
		for a, at := range p.logged {
			if now.Sub(at) >= proxyLogEvery {
				delete(p.logged, a)
			} else if !oldest.IsValid() || at.Before(p.logged[oldest]) {
				oldest = a
			}
		}
		if len(p.logged) >= proxyLogMax {
			delete(p.logged, oldest)
		}
	}
	p.logged[peer] = now
	if kind == api.ProxyKindUntrustedHeader {
		p.logf("HTTPS: %s sent a PROXY header but is not a listed proxy (HYPERDROP_TRUSTED_PROXIES), so its secure connections fail", peer)
	} else {
		p.logf("HTTPS: %s is a listed proxy (HYPERDROP_TRUSTED_PROXIES) but sent no PROXY header, so its secure connections fail", peer)
	}
}

// Tick forgets private sources silent for proxyWatchForget and reports
// counts that moved since the last report, the public count leaving its
// window among them. main calls it once a minute.
func (p *proxyWatch) Tick() {
	if p == nil {
		return
	}
	p.mu.Lock()
	now := p.now()
	cutoff := now.Add(-proxyWatchForget).Unix()
	n := len(p.private)
	p.private = slices.DeleteFunc(p.private, func(s ProxySource) bool { return s.LastSeen < cutoff })
	var r proxyReport
	if len(p.private) != n || p.dirty || p.publicCount(now) != p.reported {
		r = p.report()
	}
	p.mu.Unlock()
	p.deliver(r)
}

// report takes the snapshot changed will receive. Called with mu held.
func (p *proxyWatch) report() proxyReport {
	p.dirty = false
	p.seq++
	private, public := p.snapshot()
	p.reported = public
	return proxyReport{seq: p.seq, private: private, public: public}
}

// deliver hands r to changed outside mu, dropping a snapshot older than one
// already delivered, so the last write is always the newest state.
func (p *proxyWatch) deliver(r proxyReport) {
	if r.seq == 0 || p.changed == nil {
		return
	}
	p.deliverMu.Lock()
	defer p.deliverMu.Unlock()
	if r.seq <= p.delivered {
		return
	}
	p.delivered = r.seq
	p.changed(r.private, r.public)
}

// Snapshot answers the private sources, most recently seen first, and how
// many headers came from public addresses in the last hour (0 below
// proxyPublicMin).
func (p *proxyWatch) Snapshot() (private []ProxySource, publicCount int) {
	if p == nil {
		return nil, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshot()
}

func (p *proxyWatch) snapshot() ([]ProxySource, int) {
	public := p.publicCount(p.now())
	if len(p.private) == 0 {
		return nil, public
	}
	out := slices.Clone(p.private)
	slices.Reverse(out)
	return out, public
}

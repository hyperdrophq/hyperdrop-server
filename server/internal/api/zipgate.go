package api

import (
	"container/list"
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// zipFloor is how many zips run whatever the server's load: a brief spike, or
	// a signal that misreads, must never stop every download.
	zipFloor = 4
	// zipListBytesPerFile is what a zip's file list costs for each file it holds,
	// measured over real streams, garbage included.
	zipListBytesPerFile = 1 << 10
	// zipAdmitEvery is how often more zips start past zipFloor, and zipAdmitShare
	// how many: one in eight of those already running, at least one. A stream
	// starting shows in the signals only once it runs, so a burst of waiters must
	// not all read the same calm numbers and start together, and growing with what
	// runs means a strong server takes a crowd in within seconds rather than at a
	// fixed rate.
	zipAdmitEvery = 250 * time.Millisecond
	zipAdmitShare = 8
	// zipUsefulRate is the slowest a download is worth starting more of, in bytes a
	// second. Below it a person is better served by waiting for their turn and then
	// getting the file than by joining a crowd in which nobody finishes.
	zipUsefulRate = 256 << 10
	// zipSpeedWindow is how often the running zips' speed is read, and how old a
	// stream must be to count.
	zipSpeedWindow = 5 * time.Second
	// zipSpeedShare is how many of the running zips must be able to beat
	// zipUsefulRate for the server to take another: 10%. A client on a slow link is
	// slow whatever the server does, so it is the fastest that show whether the
	// server, its disk or its uplink has run out.
	zipSpeedShare = 10
	// zipProbeEvery is how often one more zip starts while the running ones crawl
	// waiting on their clients, when something says one more is worth it: a stream
	// running fast shows the server has speed to give and those crawling are slow
	// clients, and a share with nothing running has no other way in.
	zipProbeEvery = 30 * time.Second
	// zipFullLineProbeEvery is the same with nothing to say so: every stream crawling
	// on its client is most likely an uplink out of speed, where each one let in
	// shrinks everyone's share. It stays above zero because clients trickling just
	// above zipMinRate look exactly the same: one fast download let in shows it, and the
	// quick probes take over.
	zipFullLineProbeEvery = 5 * time.Minute
	// zipDiskProbeEvery is how often one more zip starts while the running ones crawl
	// with their writes returning at once. That crowd is held by the disk, where one
	// more reader slows them all, but the reading could be wrong, and only a zip that
	// runs well can say so.
	zipDiskProbeEvery = 2 * time.Minute
	// zipMemoryShare is how much of the memory the server may use it lets its heap
	// and file lists reach before a new zip waits.
	zipMemoryShare = 0.8
	// zipStreamBytes is what a stream takes once it runs, beyond its file list: its
	// copy buffer, its goroutines and its connection's buffers in the program and the
	// kernel, measured on a 0.5 GB server with clients that stop reading. A stream
	// started within zipStreamFreshFor counts as this much, since a memory reading does
	// not show it yet and a burst would otherwise all read the same calm number.
	zipStreamBytes    = 1 << 20
	zipStreamFreshFor = 2 * time.Second
)

// The line is what waits for zipGate, and it holds memory while nothing runs: a
// waiting request costs 30 to 60 KiB (its goroutines, its connection's buffers and
// TLS state, measured on a 0.5 GB server), so it is bounded by what the server can
// pay for. One address can hold only a few places in it, and one share only a part of
// it, so a flood on one link leaves room for the visitors of every other share.
const (
	// zipLineBytesPerWaiter is the most a waiting request was measured to cost.
	zipLineBytesPerWaiter = 64 << 10
	// zipLineShare is the part of the server's memory the line may hold: one tenth.
	zipLineShare = 10
	// zipLineFloor is the shortest the line gets, on the smallest server or one
	// whose memory cannot be read.
	zipLineFloor = 64
	// zipLinePerAddress is how many places one address may hold, enough for a
	// household behind one address to queue its downloads.
	zipLinePerAddress = 8
	// zipLineShareParts is what one share's part of the line is: a quarter, so it takes
	// floods on four links to fill it. A visitor past it gets the page that retries.
	zipLineShareParts = 4
)

// zipFreshWait is how long a person who clicked Download waits for a place, behind
// their own address's streams and for the gate together, before a page tells them why
// nothing is happening and keeps trying for them. A place that is free is taken at once,
// so only a server that is really full shows the page.
var zipFreshWait = 15 * time.Second

// zipWaitLimit is the same wait for a client no page can reach: a browser resuming a
// download, or a program that would save the page as the zip it asked for. Past it they
// are told the server is busy, so that a place in line is never held for good.
var zipWaitLimit = 5 * time.Minute

// zipLineLimit is how many waiting requests limit bytes of memory pay for.
func zipLineLimit(limit int64) int {
	return max(zipLineFloor, int(limit/zipLineShare/zipLineBytesPerWaiter))
}

// zipLine counts who is waiting for a zip, behind their own address's stream or for
// the gate, and refuses anyone past its size, their address's places or their share's
// part of it.
type zipLine struct {
	size func() int

	mu      sync.Mutex
	waiting int
	byAddr  map[string]int
	byShare map[string]int
}

func newZipLine(size func() int) *zipLine {
	return &zipLine{size: size, byAddr: map[string]int{}, byShare: map[string]int{}}
}

// enter takes a place in line for addr asking for share, answering the call that gives
// it up, which runs once, and false when there is no place. A line too short to divide
// still gives a share one place.
func (l *zipLine) enter(addr, share string) (leave func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := l.size()
	if l.waiting >= size || l.byAddr[addr] >= zipLinePerAddress || l.byShare[share] >= max(1, size/zipLineShareParts) {
		return nil, false
	}
	l.waiting++
	l.byAddr[addr]++
	l.byShare[share]++
	return sync.OnceFunc(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.waiting--
		if l.byAddr[addr]--; l.byAddr[addr] == 0 {
			delete(l.byAddr, addr)
		}
		if l.byShare[share]--; l.byShare[share] == 0 {
			delete(l.byShare, share)
		}
	}), true
}

// zipLoad answers whether the server has room for one more zip whose file list
// needs bytes more memory. It reads the machine as it is now, because the same
// number of zips is nothing on one server and too many on another.
type zipLoad func(bytes int64) bool

// zipTurn is whose zip is asking: the share's owner, and the share.
type zipTurn struct {
	owner, share string
}

// zipWaiter is one request waiting for its turn.
type zipWaiter struct {
	turn  zipTurn
	bytes int64
	ready chan struct{}
	seq   uint64
	place *list.Element
}

// zipGate decides when a zip starts. There is no cap on how many run: past zipFloor
// one starts whenever the server's load allows and the running zips still move at
// a useful speed, so a stronger server serves more, and a crowd too big for the
// disk or the uplink waits its turn rather than everyone crawling.
// A request waits holding nothing but its goroutine, in a line that serves the
// owner with the fewest zips running first, then that owner's share with the fewest,
// oldest first among equals, so a popular or flooded share cannot keep another share
// waiting, of another account or the same one. One timer moves the line whatever its
// length, and it reads the machine once a tick.
type zipGate struct {
	load zipLoad
	now  func() time.Time

	mu      sync.Mutex
	running map[string]int
	// runningShares is the same count by share.
	runningShares map[string]int
	total         int
	reserved      int64
	lines         map[zipTurn]*list.List
	seq           uint64
	ticking       bool
	window        time.Time
	windowFor     int
	streams       map[*zipTracked]struct{}
	readAt        time.Time
	crawling      bool
	// heldByClients says the crawl waits on its clients rather than the disk, and
	// someFast that a stream still beat zipUsefulRate: both read with crawling.
	heldByClients bool
	someFast      bool
	probedAt      time.Time
	fresh         []time.Time

	// waiting is how many are in line, read on every chunk of every stream.
	waiting atomic.Int64
}

// zipStreamCounts is what a running stream's writes add to: its bytes, and the
// nanoseconds it spent in them, waiting on its client.
type zipStreamCounts struct {
	sent, inClientWrites atomic.Int64
}

// zipTracked is one running stream, read for its speed.
type zipTracked struct {
	zipStreamCounts
	began      time.Time
	seen       int64
	seenWrites int64
	seenAt     time.Time
}

func newZipGate(load zipLoad) *zipGate {
	return &zipGate{load: load, now: time.Now, running: map[string]int{}, runningShares: map[string]int{}, lines: map[zipTurn]*list.List{},
		streams: map[*zipTracked]struct{}{}}
}

// acquire waits for owner's turn to start a zip whose file list needs bytes,
// reporting false when ctx ends first, in which case nothing is held.
func (g *zipGate) acquire(ctx context.Context, turn zipTurn, bytes int64) bool {
	w := &zipWaiter{turn: turn, bytes: bytes, ready: make(chan struct{})}
	g.mu.Lock()
	moves := g.waiting.Load() == 0 || g.total < zipFloor
	g.pushLocked(w)
	if moves {
		g.pumpLocked()
	}
	if g.waiting.Load() > 0 && !g.ticking {
		g.ticking = true
		go g.tick()
	}
	g.mu.Unlock()
	select {
	case <-w.ready:
		return true
	case <-ctx.Done():
		g.mu.Lock()
		defer g.mu.Unlock()
		select {
		case <-w.ready:
			g.releaseLocked(turn, bytes)
		default:
			g.dropLocked(w)
		}
		return false
	}
}

// tick moves the line for as long as anyone is in it.
func (g *zipGate) tick() {
	t := time.NewTicker(zipAdmitEvery)
	defer t.Stop()
	for range t.C {
		g.mu.Lock()
		g.pumpLocked()
		done := g.waiting.Load() == 0
		if done {
			g.ticking = false
		}
		g.mu.Unlock()
		if done {
			return
		}
	}
}

// release ends a zip acquire admitted.
func (g *zipGate) release(turn zipTurn, bytes int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.releaseLocked(turn, bytes)
}

func (g *zipGate) releaseLocked(turn zipTurn, bytes int64) {
	g.total--
	g.reserved -= bytes
	if g.running[turn.owner]--; g.running[turn.owner] == 0 {
		delete(g.running, turn.owner)
	}
	if g.runningShares[turn.share]--; g.runningShares[turn.share] == 0 {
		delete(g.runningShares, turn.share)
	}
	g.pumpLocked()
}

func (g *zipGate) pushLocked(w *zipWaiter) {
	line := g.lines[w.turn]
	if line == nil {
		line = list.New()
		g.lines[w.turn] = line
	}
	g.seq++
	w.seq = g.seq
	w.place = line.PushBack(w)
	g.waiting.Add(1)
}

func (g *zipGate) dropLocked(w *zipWaiter) {
	line := g.lines[w.turn]
	line.Remove(w.place)
	if line.Len() == 0 {
		delete(g.lines, w.turn)
	}
	g.waiting.Add(-1)
}

// pumpLocked starts every waiter the floor covers, and past it as many as this
// window's share while the load allows and the running zips still move, or one each
// zipProbeEvery while they crawl on their clients.
func (g *zipGate) pumpLocked() {
	for g.waiting.Load() > 0 {
		next := g.nextLocked()
		if g.total >= zipFloor {
			now := g.now()
			if now.Sub(g.window) >= zipAdmitEvery {
				g.window, g.windowFor = now, max(1, g.total/zipAdmitShare)
			}
			if g.windowFor == 0 {
				return
			}
			crawling := g.crawlingLocked()
			if crawling && now.Sub(g.probedAt) < g.probeEveryLocked(next) {
				return
			}
			if !g.load(g.reserved + next.bytes + g.freshBytesLocked(now)) {
				return
			}
			if crawling {
				g.probedAt = now
			}
			g.windowFor--
		}
		g.startLocked(next)
	}
}

// probeEveryLocked is how long the line waits between probes for w while the running
// zips crawl.
func (g *zipGate) probeEveryLocked(w *zipWaiter) time.Duration {
	switch {
	case !g.heldByClients:
		return zipDiskProbeEvery
	case g.someFast || g.runningShares[w.turn.share] == 0:
		return zipProbeEvery
	}
	return zipFullLineProbeEvery
}

// startLocked takes w out of the line and lets it run.
func (g *zipGate) startLocked(w *zipWaiter) {
	g.dropLocked(w)
	g.total++
	g.reserved += w.bytes
	g.running[w.turn.owner]++
	g.runningShares[w.turn.share]++
	now := g.now()
	g.freshBytesLocked(now)
	g.fresh = append(g.fresh, now)
	close(w.ready)
}

// freshBytesLocked is what the streams started within zipStreamFreshFor are about to
// take, and forgets the older ones.
func (g *zipGate) freshBytesLocked(now time.Time) int64 {
	old := 0
	for old < len(g.fresh) && now.Sub(g.fresh[old]) >= zipStreamFreshFor {
		old++
	}
	g.fresh = g.fresh[old:]
	return int64(len(g.fresh)) * zipStreamBytes
}

// track registers a running stream, answering the counts its writes add to and the
// call that ends it.
func (g *zipGate) track() (*zipStreamCounts, func()) {
	t := &zipTracked{began: g.now(), seenAt: g.now()}
	g.mu.Lock()
	g.streams[t] = struct{}{}
	g.mu.Unlock()
	return &t.zipStreamCounts, func() {
		g.mu.Lock()
		delete(g.streams, t)
		g.mu.Unlock()
	}
}

// crawlingLocked reports whether the running zips have run out of speed: too few of
// them beat zipUsefulRate. It rereads them every zipSpeedWindow, and counts only
// streams that have run for a whole window and moved a byte in it: a client taking
// nothing at all says nothing about the server, whose disk and uplink would still
// move something for everyone else. Most of them spending at least half the window
// waiting on their clients means the crawl is on the clients' side: the same speed with
// writes returning at once is the disk's. The probes' clock starts when the crawl does.
func (g *zipGate) crawlingLocked() bool {
	now := g.now()
	if now.Sub(g.readAt) < zipSpeedWindow {
		return g.crawling
	}
	g.readAt = now
	counted, fast, heldByClient := 0, 0, 0
	for t := range g.streams {
		sent, writes, elapsed := t.sent.Load(), t.inClientWrites.Load(), now.Sub(t.seenAt)
		if elapsed > 0 && now.Sub(t.began) >= zipSpeedWindow && sent > t.seen {
			counted++
			if float64(sent-t.seen)/elapsed.Seconds() >= zipUsefulRate {
				fast++
			}
			if (writes-t.seenWrites)*2 >= int64(elapsed) {
				heldByClient++
			}
		}
		t.seen, t.seenWrites, t.seenAt = sent, writes, now
	}
	crawling := counted >= zipFloor && fast*100 < counted*zipSpeedShare
	if crawling && !g.crawling {
		g.probedAt = now
	}
	g.crawling = crawling
	g.heldByClients = heldByClient*2 >= counted
	g.someFast = fast > 0
	return g.crawling
}

// nextLocked is the waiter whose owner has the fewest zips running, then whose share
// has the fewest, the oldest of those. It looks at one waiter per share, whatever the
// line's length.
func (g *zipGate) nextLocked() *zipWaiter {
	var best *zipWaiter
	for _, line := range g.lines {
		w := line.Front().Value.(*zipWaiter)
		if best == nil || g.before(w, best) {
			best = w
		}
	}
	return best
}

// before reports whether a goes ahead of b.
func (g *zipGate) before(a, b *zipWaiter) bool {
	if ao, bo := g.running[a.turn.owner], g.running[b.turn.owner]; ao != bo {
		return ao < bo
	}
	if as, bs := g.runningShares[a.turn.share], g.runningShares[b.turn.share]; as != bs {
		return as < bs
	}
	return a.seq < b.seq
}

// hasWaiter reports whether a request is waiting for a zip to end.
func (g *zipGate) hasWaiter() bool {
	return g.waiting.Load() > 0
}

// handOver starts the next in line in the place of a stream holding bytes, which
// then ends, and reports whether it did: so a stream ends only for a waiter that
// moves because of it, and one waiter costs one stream. It happens only when the machine
// is what refuses the waiter. A line waiting on the crowd's speed takes nobody's place:
// the waiter would take the ended stream's exact share of the uplink, so the bytes sent
// would be thrown away for nothing. A waiter whose file list is larger than what the
// stream frees still needs the memory for the difference.
func (g *zipGate) handOver(bytes int64) bool {
	if !g.hasWaiter() {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.waiting.Load() == 0 {
		return false
	}
	next := g.nextLocked()
	fresh := g.freshBytesLocked(g.now())
	if g.load(g.reserved + next.bytes + fresh) {
		return false
	}
	if next.bytes > bytes && !g.load(g.reserved-bytes+next.bytes+fresh) {
		return false
	}
	g.startLocked(next)
	return true
}

// MemoryReading is how much memory the server and its machine have left. A field
// the system cannot report is 0.
type MemoryReading struct {
	// Used is what the Go runtime holds from the system beyond the heap it has freed
	// and could reuse at once, and Limit what it may hold: GOMEMLIMIT, or else the
	// machine's memory.
	Used, Limit int64
	// Total is the machine's memory (a container's limit, inside one), and Available
	// what the kernel could give to a process without swapping.
	Total, Available int64
}

// ReadMemory reads the server's memory now. It opens files, so it runs a few times a
// second at most, never once a request.
func ReadMemory() MemoryReading {
	sample := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"},
		{Name: "/memory/classes/heap/free:bytes"}}
	metrics.Read(sample)
	r := MemoryReading{Used: int64(sample[0].Value.Uint64()) - int64(sample[1].Value.Uint64()) - int64(sample[2].Value.Uint64())}
	r.Total, r.Available = machineMemory()
	r.Limit = debug.SetMemoryLimit(-1)
	if r.Limit <= 0 || r.Limit == math.MaxInt64 {
		r.Limit = r.Total
	}
	return r
}

// cgroupMemory reads a cgroup directory's memory limit, and what is left of it once
// the file cache and slab the kernel could take back are set aside, as /proc/meminfo's
// MemAvailable sets them aside. A limit of 0 means none is set or none can be read.
func cgroupMemory(dir string) (limit, available int64) {
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return ""
		}
		return string(b)
	}
	limit, err := strconv.ParseInt(strings.TrimSpace(read("memory.max")), 10, 64)
	if err != nil || limit <= 0 {
		return 0, 0
	}
	current, _ := strconv.ParseInt(strings.TrimSpace(read("memory.current")), 10, 64)
	var reclaimable int64
	for line := range strings.Lines(read("memory.stat")) {
		name, value, _ := strings.Cut(line, " ")
		switch name {
		case "active_file", "inactive_file", "slab_reclaimable":
			n, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			reclaimable += n
		}
	}
	return limit, max(0, limit-(current-reclaimable))
}

// zipSchedWindow is how long a reading of the CPU covers. The delay is only
// meaningful over a stretch of work: every waiting request asks for room, and a
// reading of the last few milliseconds holds too little to show anything.
const zipSchedWindow = time.Second

// zipSchedLimit is how long the slowest 1% of the server's work may wait for a
// core before a new zip waits. Past it the machine's CPU is what is holding work
// back, and every request is paying for it. Measured on one core of a real server:
// held here, sixty fast downloads settled at twenty running with pages under half a
// second and the total throughput unchanged; let through, pages took over two.
var zipSchedLimit = 100 * time.Millisecond

// zipMachineReadEvery is how often memory and open files are read: each reading opens
// files, and hasRoom runs under the gate's lock.
const zipMachineReadEvery = 250 * time.Millisecond

// zipMachine reads the running server's load for a zipGate.
type zipMachine struct {
	mu         sync.Mutex
	now        func() time.Time
	readMemory func() MemoryReading
	sample     []metrics.Sample
	last       []uint64
	// delay is the last reading of the CPU, taken at readAt.
	delay  time.Duration
	readAt time.Time
	// memory and files are the last reading of each, taken at memoryAt.
	memory   MemoryReading
	files    bool
	memoryAt time.Time
}

func newZipMachine() *zipMachine {
	return &zipMachine{now: time.Now, readMemory: ReadMemory, sample: []metrics.Sample{{Name: "/sched/latencies:seconds"}}}
}

// hasRoom is the zipLoad of the running server: CPU, memory and open files.
func (m *zipMachine) hasRoom(bytes int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if now.Sub(m.readAt) >= zipSchedWindow {
		metrics.Read(m.sample)
		m.delay, m.readAt = m.schedDelayLocked(), now
	}
	if m.delay > zipSchedLimit {
		return false
	}
	if now.Sub(m.memoryAt) >= zipMachineReadEvery {
		m.memory, m.files, m.memoryAt = m.readMemory(), filesToSpare(), now
	}
	r := m.memory
	if r.Limit > 0 && float64(r.Used+bytes) > float64(r.Limit)*zipMemoryShare {
		return false
	}
	if r.Total > 0 && r.Available-bytes < availableClear(r.Total) {
		return false
	}
	return m.files
}

// schedDelayLocked is the 99th percentile of the time work waited for a core since
// the last reading.
func (m *zipMachine) schedDelayLocked() time.Duration {
	h := m.sample[0].Value.Float64Histogram()
	delta := make([]uint64, len(h.Counts))
	var total uint64
	for i, c := range h.Counts {
		delta[i] = c
		if len(m.last) == len(h.Counts) {
			delta[i] = c - m.last[i]
		}
		total += delta[i]
	}
	m.last = append(m.last[:0], h.Counts...)
	var seen uint64
	for i, c := range delta {
		seen += c
		if total > 0 && seen*100 >= total*99 {
			return time.Duration(h.Buckets[i+1] * float64(time.Second))
		}
	}
	return 0
}

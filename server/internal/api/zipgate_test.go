package api

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// gateClock is a clock a test steps while the gate's waiters read it.
type gateClock struct{ ns atomic.Int64 }

func (c *gateClock) step(d time.Duration) { c.ns.Add(int64(d)) }

// testGate is a gate on a clock of its own.
func testGate(room func(int64) bool) (*zipGate, *gateClock) {
	start := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	clock := &gateClock{}
	g := newZipGate(room)
	g.now = func() time.Time { return start.Add(time.Duration(clock.ns.Load())) }
	return g, clock
}

// oneShare is the turn of an owner with a single share.
func oneShare(owner string) zipTurn { return zipTurn{owner: owner, share: "share-of-" + owner} }

func TestTheFloorRunsWhateverTheLoad(t *testing.T) {
	g, _ := testGate(func(int64) bool { return false })
	for i := range zipFloor {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if !g.acquire(ctx, oneShare("a"), 0) {
			t.Fatalf("zip %d waited under a full load", i)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if g.acquire(ctx, oneShare("a"), 0) {
		t.Fatal("past the floor under a full load")
	}
	if g.hasWaiter() {
		t.Fatal("the gave-up waiter is still in line")
	}
}

// There is no number a strong server stops at: while the load allows, zips start.
func TestNoCapStopsAServerWithRoom(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	for i := range 1000 {
		clock.step(zipAdmitEvery)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if !g.acquire(ctx, oneShare("a"), 0) {
			t.Fatalf("zip %d waited with room to spare", i)
		}
		cancel()
	}
}

// Past the floor a burst starts one at a time, since a stream shows in the signals
// only once it runs.
func TestAdmissionsPastTheFloorAreSpaced(t *testing.T) {
	var asked atomic.Int32
	g, clock := testGate(func(int64) bool { asked.Add(1); return true })
	for range zipFloor {
		g.acquire(context.Background(), oneShare("a"), 0)
	}
	clock.step(zipAdmitEvery)
	g.acquire(context.Background(), oneShare("a"), 0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if g.acquire(ctx, oneShare("a"), 0) {
		t.Fatal("a second zip in the same instant")
	}
}

// The waiting owner with the fewest zips goes first, so a popular share cannot
// keep another account's first zip waiting behind its own queue.
func TestTheOwnerWithFewestZipsGoesFirst(t *testing.T) {
	room := atomic.Bool{}
	g, clock := testGate(func(int64) bool { return room.Load() })
	for range zipFloor {
		g.acquire(context.Background(), oneShare("popular"), 0)
	}
	order := make(chan string, 2)
	start := func(owner string) {
		go func() {
			if g.acquire(context.Background(), oneShare(owner), 0) {
				order <- owner
			}
		}()
	}
	start("popular")
	waitUntilBlocked(t, g.hasWaiter)
	time.Sleep(10 * time.Millisecond)
	start("quiet")
	time.Sleep(10 * time.Millisecond)
	room.Store(true)
	clock.step(zipAdmitEvery)
	if first := <-order; first != "quiet" {
		t.Fatalf("%s started first", first)
	}
}

// A strong server takes a crowd in fast: the share of each window grows with what
// already runs, so no fixed rate holds it back.
func TestTheAdmissionRateGrowsWithWhatRuns(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	g.total = 800
	waiters := make([]*zipWaiter, 150)
	for i := range waiters {
		waiters[i] = &zipWaiter{turn: oneShare("a"), ready: make(chan struct{})}
		g.pushLocked(waiters[i])
	}
	clock.step(zipAdmitEvery)
	g.mu.Lock()
	g.pumpLocked()
	g.mu.Unlock()
	started := 0
	for _, w := range waiters {
		select {
		case <-w.ready:
			started++
		default:
		}
	}
	if started != 800/zipAdmitShare {
		t.Fatalf("started %d in one window, want %d", started, 800/zipAdmitShare)
	}
}

// A crowd too big for the disk or the uplink stops growing, with no number saying
// how big that is: when even the fastest have fallen below a useful speed, the next
// person waits and those running finish.
func TestAnotherZipWaitsWhenEveryoneIsCrawling(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	var counters []*zipStreamCounts
	for range zipFloor {
		g.acquire(context.Background(), oneShare("a"), 0)
		counts, _ := g.track()
		counters = append(counters, counts)
	}
	step := func(perStream int64) {
		clock.step(zipSpeedWindow)
		for _, c := range counters {
			c.sent.Add(perStream * int64(zipSpeedWindow/time.Second))
		}
	}
	step(zipUsefulRate / 4)
	step(zipUsefulRate / 4)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if g.acquire(ctx, oneShare("b"), 0) {
		t.Fatal("started another while everyone crawled")
	}
	step(zipUsefulRate * 4)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if !g.acquire(ctx2, oneShare("b"), 0) {
		t.Fatal("waited with the running zips moving well")
	}
}

// One fast zip among slow ones shows the server still has speed to give: those
// others are slow because of their own links, which no amount of waiting fixes.
func TestSlowClientsAloneDoNotStopTheLine(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	var counters []*zipStreamCounts
	for range 8 {
		clock.step(zipAdmitEvery)
		g.acquire(context.Background(), oneShare("a"), 0)
		counts, _ := g.track()
		counters = append(counters, counts)
	}
	for range 2 {
		clock.step(zipSpeedWindow)
		counters[0].sent.Add(zipUsefulRate * 10 * int64(zipSpeedWindow/time.Second))
		for _, c := range counters[1:] {
			c.sent.Add(1024)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !g.acquire(ctx, oneShare("b"), 0) {
		t.Fatal("slow clients held the line")
	}
}

// A zip ending lets the next one start.
func TestReleaseMovesTheLine(t *testing.T) {
	g, clock := testGate(func(int64) bool { return false })
	for range zipFloor {
		g.acquire(context.Background(), oneShare("a"), 0)
	}
	done := make(chan bool, 1)
	go func() { done <- g.acquire(context.Background(), oneShare("b"), 0) }()
	waitUntilBlocked(t, g.hasWaiter)
	clock.step(zipAdmitEvery)
	g.release(oneShare("a"), 0)
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("refused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the line did not move")
	}
}

// What a file list needs is reserved until the zip ends, so the memory check sees
// the lists of streams still starting.
func TestAListsMemoryIsReservedUntilItsZipEnds(t *testing.T) {
	var seen []int64
	g, clock := testGate(func(b int64) bool { seen = append(seen, b); return true })
	for range zipFloor {
		g.acquire(context.Background(), oneShare("a"), 100)
	}
	clock.step(zipStreamFreshFor)
	g.acquire(context.Background(), oneShare("a"), 100)
	if len(seen) != 1 || seen[0] != 500 {
		t.Fatalf("asked %v, want the 4 running and this one", seen)
	}
	g.release(oneShare("a"), 100)
	if g.reserved != 400 {
		t.Fatalf("reserved %d", g.reserved)
	}
}

// A client that takes its bytes at once is not slow, however long the disk took to
// find them: only the time spent waiting on the client counts against it.
func TestASlowDiskIsNotASlowClient(t *testing.T) {
	waiting := true
	s, clock := yieldingWriter(&waiting, 0)
	s.minRate = zipMinRate
	for range 60 {
		*clock = clock.Add(time.Minute) // the disk: nothing is being written
		if _, err := s.Write(make([]byte, 1<<10)); err != nil {
			t.Fatalf("a client waiting on a slow disk was dropped: %v", err)
		}
	}
}

// The real load reader answers, and on an idle process it finds room.
func TestTheMachineReadsAndFindsRoom(t *testing.T) {
	if !newZipMachine().hasRoom(1 << 10) {
		t.Skip("this machine is busy right now")
	}
}

// The CPU's reading covers a whole window, however often room is asked for: a line
// of waiters each asking many times a second must not read a calm few milliseconds
// out of a machine that is falling behind.
func TestTheCPUReadingHoldsForItsWindow(t *testing.T) {
	clock := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	m := newZipMachine()
	m.now = func() time.Time { return clock }
	m.delay, m.readAt = zipSchedLimit*2, clock
	for range 100 {
		if m.hasRoom(0) {
			t.Fatal("a reading from this window was dropped for a newer, emptier one")
		}
		clock = clock.Add(time.Millisecond)
	}
	clock = m.readAt.Add(zipSchedWindow)
	m.hasRoom(0)
	if !m.readAt.Equal(clock) {
		t.Fatal("the window ended and nothing was reread")
	}
}

// A line of thousands costs one reading of the machine per tick, not one per person
// waiting: each reading opens files, and a line that read for every waiter would
// spend the server's whole core on asking whether it has room.
func TestALongLineReadsTheMachineOnlyOnItsTimer(t *testing.T) {
	var asked atomic.Int32
	g, _ := testGate(func(int64) bool { asked.Add(1); return false })
	for range zipFloor {
		g.acquire(context.Background(), oneShare("a"), 0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const waiters = 2000
	for range waiters {
		go g.acquire(ctx, oneShare("a"), 0)
	}
	for !lineHolds(g, waiters) {
		time.Sleep(time.Millisecond)
	}
	if n := asked.Load(); n > 50 {
		t.Errorf("joining the line read the machine %d times", n)
	}
	asked.Store(0)
	time.Sleep(3 * zipAdmitEvery)
	if n := asked.Load(); n > 8 {
		t.Errorf("three ticks read the machine %d times with %d waiting", n, waiters)
	}
}

func lineHolds(g *zipGate, n int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.waiting.Load() == int64(n)
}

// The timer stops with the line, so an idle server runs nothing for it.
func TestTheLinesTimerEndsWithTheLine(t *testing.T) {
	g, _ := testGate(func(int64) bool { return false })
	for range zipFloor {
		g.acquire(context.Background(), oneShare("a"), 0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	g.acquire(ctx, oneShare("a"), 0)
	deadline := time.Now().Add(5 * zipAdmitEvery)
	for {
		g.mu.Lock()
		ticking := g.ticking
		g.mu.Unlock()
		if !ticking {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the timer outlived the line")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A client that takes nothing at all says nothing about the server: four of them
// must not stop everyone else's downloads.
func TestStreamsThatTakeNothingDoNotHoldTheLine(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	for range zipFloor {
		g.acquire(context.Background(), oneShare("a"), 0)
		g.track()
	}
	clock.step(zipSpeedWindow)
	clock.step(zipSpeedWindow)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !g.acquire(ctx, oneShare("b"), 0) {
		t.Fatal("clients that read nothing held the line")
	}
}

// Clients trickling just above the minimum rate look exactly like a server out of
// speed, so the line keeps moving at a walk: one fast download let in shows the
// server has speed to give, and a server really out of it gains one stream a probe.
// Here the waiter's owner has nothing running, which takes the quick interval.
func TestACrawlingCrowdStillLetsOneInEveryProbe(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	var counters []*zipStreamCounts
	for range zipFloor {
		g.acquire(context.Background(), oneShare("a"), 0)
		counts, _ := g.track()
		counters = append(counters, counts)
	}
	trickle := func(d time.Duration) {
		clock.step(d)
		for _, c := range counters {
			c.sent.Add(int64(zipMinRate) * int64(d/time.Second))
			c.inClientWrites.Add(int64(d))
		}
	}
	trickle(zipSpeedWindow)
	trickle(zipSpeedWindow)
	first, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if g.acquire(first, oneShare("b"), 0) {
		t.Fatal("started another the moment the crowd crawled")
	}
	for elapsed := time.Duration(0); elapsed < zipProbeEvery; elapsed += zipSpeedWindow {
		trickle(zipSpeedWindow)
	}
	second, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if !g.acquire(second, oneShare("b"), 0) {
		t.Fatal("the probe never came")
	}
	third, cancel3 := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel3()
	if g.acquire(third, oneShare("b"), 0) {
		t.Fatal("two probes in one period")
	}
}

// The line is as long as a share of the server's memory pays for, so a stronger
// server keeps more people waiting and no fixed number decides it.
func TestTheLineIsAsLongAsMemoryPays(t *testing.T) {
	small, big := zipLineLimit(270<<20), zipLineLimit(4<<30)
	if want := (270 << 20) / zipLineShare / zipLineBytesPerWaiter; small != want {
		t.Errorf("270 MiB pays for %d, want %d", small, want)
	}
	if big <= small {
		t.Errorf("4 GiB pays for %d, 270 MiB for %d", big, small)
	}
	if got := zipLineLimit(0); got != zipLineFloor {
		t.Errorf("an unknown memory size gives %d, want the floor %d", got, zipLineFloor)
	}
}

func TestOneAddressHoldsOnlyAFewPlacesInLine(t *testing.T) {
	l := newZipLine(func() int { return 1000 })
	var leaves []func()
	for range zipLinePerAddress {
		leave, ok := l.enter("203.0.113.5", "one-share")
		if !ok {
			t.Fatal("refused inside the address's places")
		}
		leaves = append(leaves, leave)
	}
	if _, ok := l.enter("203.0.113.5", "one-share"); ok {
		t.Fatal("one address took more than its places")
	}
	if leave, ok := l.enter("198.51.100.7", "one-share"); !ok {
		t.Fatal("another address was refused")
	} else {
		leave()
	}
	leaves[0]()
	if leave, ok := l.enter("203.0.113.5", "one-share"); !ok {
		t.Fatal("a place freed was not offered again")
	} else {
		leave()
	}
	for _, leave := range leaves[1:] {
		leave()
	}
	if len(l.byAddr) != 0 {
		t.Errorf("addresses left in the line's map: %v", l.byAddr)
	}
}

func TestAFullLineRefusesTheNextAddress(t *testing.T) {
	l := newZipLine(func() int { return 2 })
	a, ok := l.enter("203.0.113.5", "share-1")
	if !ok {
		t.Fatal("refused with room")
	}
	if _, ok := l.enter("203.0.113.6", "share-2"); !ok {
		t.Fatal("refused with room")
	}
	if _, ok := l.enter("203.0.113.7", "share-3"); ok {
		t.Fatal("the line grew past its size")
	}
	a()
	if _, ok := l.enter("203.0.113.7", "share-3"); !ok {
		t.Fatal("a place freed was not offered again")
	}
}

// A container's limit is the machine: its memory.max, and what the kernel could not
// take back from memory.current.
func TestACgroupLimitIsTheMachinesMemory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if limit, _ := cgroupMemory(dir); limit != 0 {
		t.Fatalf("no cgroup files read as %d", limit)
	}
	write("memory.max", "max\n")
	if limit, _ := cgroupMemory(dir); limit != 0 {
		t.Fatalf("an unlimited cgroup read as %d", limit)
	}
	write("memory.max", "1000000\n")
	write("memory.current", "700000\n")
	write("memory.stat", "anon 500000\ninactive_file 200000\n")
	limit, avail := cgroupMemory(dir)
	if limit != 1000000 || avail != 500000 {
		t.Errorf("limit %d, available %d, want 1000000 and 500000", limit, avail)
	}
}

// A stream's buffers show in a memory reading only once it has run a moment, so a burst
// starting together would all read the same calm number: until then each counts as the
// memory it is about to take.
func TestStreamsJustStartedCountTowardMemory(t *testing.T) {
	var last atomic.Int64
	g, clock := testGate(func(bytes int64) bool { last.Store(bytes); return true })
	g.total = 800
	clock.step(zipAdmitEvery)
	for range 3 {
		w := &zipWaiter{turn: oneShare("a"), ready: make(chan struct{})}
		g.pushLocked(w)
	}
	g.mu.Lock()
	g.pumpLocked()
	g.mu.Unlock()
	if got := last.Load(); got != 2*zipStreamBytes {
		t.Errorf("the third asked for %d bytes, want the two before it, %d", got, 2*zipStreamBytes)
	}
	clock.step(zipStreamFreshFor + zipAdmitEvery)
	g.pushLocked(&zipWaiter{turn: oneShare("a"), ready: make(chan struct{})})
	g.mu.Lock()
	g.pumpLocked()
	g.mu.Unlock()
	if got := last.Load(); got != 0 {
		t.Errorf("streams long started still count for %d bytes", got)
	}
}

// A zip stream holds one chunk's buffer however large its files: a client that stops
// reading pins it until the stall cuts it off.
func TestAZipStreamCopiesAChunkAtATime(t *testing.T) {
	src := strings.NewReader(strings.Repeat("x", 3*zipStallChunk))
	var biggest int
	dst := writerFunc(func(p []byte) (int, error) {
		biggest = max(biggest, len(p))
		return len(p), nil
	})
	if n, err := zipCopy(dst, src); err != nil || n != 3*zipStallChunk {
		t.Fatalf("copied %d: %v", n, err)
	}
	if biggest != zipStallChunk {
		t.Errorf("wrote %d bytes at once, want %d", biggest, zipStallChunk)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// Each chunk of each stream asks whether someone waits, so asking must not queue behind
// the gate's lock.
func TestAskingWhetherSomeoneWaitsTakesNoLock(t *testing.T) {
	g, _ := testGate(func(int64) bool { return true })
	g.mu.Lock()
	defer g.mu.Unlock()
	done := make(chan bool)
	go func() { done <- g.hasWaiter() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("hasWaiter waited on the gate's lock")
	}
}

// The machine is read a few times a second however many are asked about: each reading
// opens files, under the gate's lock.
func TestTheMachineIsReadAFewTimesASecond(t *testing.T) {
	reads := 0
	m := newZipMachine()
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	m.readMemory = func() MemoryReading {
		reads++
		return MemoryReading{Limit: 1 << 30, Total: 1 << 30, Available: 1 << 30}
	}
	for range 100 {
		m.hasRoom(0)
	}
	if reads != 1 {
		t.Fatalf("%d readings in one moment", reads)
	}
	now = now.Add(zipMachineReadEvery)
	m.hasRoom(0)
	if reads != 2 {
		t.Fatalf("%d readings after a period", reads)
	}
}

// What one request costs is compared afresh each time, against one reading.
func TestTheMachineStillWeighsEachRequest(t *testing.T) {
	m := newZipMachine()
	m.now = func() time.Time { return time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) }
	m.readMemory = func() MemoryReading { return MemoryReading{Limit: 100 << 20} }
	if !m.hasRoom(1 << 20) {
		t.Error("a small request found no room")
	}
	if m.hasRoom(90 << 20) {
		t.Error("a large request found room")
	}
}

// The memory a stream is about to take counts for a moment after it starts, so a
// server that never reaches the floor keeps no record of the zips it served long ago.
func TestAQuietServerForgetsTheZipsItStarted(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	for range 100 {
		g.acquire(context.Background(), oneShare("a"), 0)
		g.release(oneShare("a"), 0)
		clock.step(zipStreamFreshFor)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.fresh) > 1 {
		t.Fatalf("holds %d starts older than %v", len(g.fresh), zipStreamFreshFor)
	}
}

// The kernel takes back all of a cgroup's file cache and reclaimable slab under
// pressure, whichever list it sits on, as /proc/meminfo's MemAvailable counts it. A
// container that serves the same files holds most of its cache on the active list.
func TestACgroupsReclaimableMemoryCountsAsAvailable(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"memory.max":     "1000000\n",
		"memory.current": "950000\n",
		"memory.stat":    "anon 100000\nfile 800000\nactive_file 600000\ninactive_file 200000\nslab_reclaimable 50000\nslab_unreclaimable 1000\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, avail := cgroupMemory(dir); avail != 900000 {
		t.Errorf("available %d, want 900000", avail)
	}
}

// Streams that crawl with their writes returning at once are held by the disk, not by
// their clients, and one more reader slows them all. The line still takes one zip a
// zipDiskProbeEvery, in case the reading was wrong; a test zip that runs well opens it.
func TestACrowdHeldByTheDiskTakesOneTestZipEveryFewMinutes(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	var counters []*zipStreamCounts
	for range zipFloor {
		g.acquire(context.Background(), oneShare("a"), 0)
		counts, _ := g.track()
		counters = append(counters, counts)
	}
	crawl := func() {
		clock.step(zipSpeedWindow)
		for _, c := range counters {
			c.sent.Add(int64(zipMinRate) * int64(zipSpeedWindow/time.Second))
			c.inClientWrites.Add(int64(zipSpeedWindow / 100))
		}
	}
	tryOnce := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		return g.acquire(ctx, oneShare("b"), 0)
	}
	crawl()
	crawl()
	for elapsed := time.Duration(0); elapsed < zipDiskProbeEvery-2*zipSpeedWindow; elapsed += zipSpeedWindow {
		crawl()
		if tryOnce() {
			t.Fatalf("a zip joined a crowd the disk holds after %v", elapsed)
		}
	}
	crawl()
	crawl()
	crawl() // the interval runs from when a waiter first read the crawl
	if !tryOnce() {
		t.Fatal("no test zip after the disk's interval")
	}
	if tryOnce() {
		t.Fatal("a second test zip at once")
	}
	for _, c := range counters {
		c.sent.Add(zipUsefulRate * 4 * int64(zipSpeedWindow/time.Second))
	}
	clock.step(zipSpeedWindow)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !g.acquire(ctx, oneShare("b"), 0) {
		t.Fatal("the line stayed shut once the streams moved well")
	}
}

// crawlingOnClients starts running zips of owner "a" and answers the call that passes
// d of everyone reading slowly, their writes held by their clients.
func crawlingOnClients(g *zipGate, clock *gateClock, running int) (trickle func(time.Duration), counters []*zipStreamCounts) {
	for range running {
		clock.step(zipAdmitEvery)
		g.acquire(context.Background(), oneShare("a"), 0)
		counts, _ := g.track()
		counters = append(counters, counts)
	}
	return func(d time.Duration) {
		clock.step(d)
		for _, c := range counters {
			c.sent.Add(int64(zipMinRate) * int64(d/time.Second))
			c.inClientWrites.Add(int64(d))
		}
	}, counters
}

// A line whose every stream crawls on its clients has probably run out of uplink, and
// each stream let in only shrinks everyone's share, so the owner already running waits
// long between probes.
func TestAFullLineTakesASameOwnerZipOnlyEveryFewMinutes(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	trickle, _ := crawlingOnClients(g, clock, zipFloor)
	tryOnce := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		return g.acquire(ctx, oneShare("a"), 0)
	}
	trickle(zipSpeedWindow)
	trickle(zipSpeedWindow)
	for elapsed := time.Duration(0); elapsed < zipFullLineProbeEvery-2*zipSpeedWindow; elapsed += zipSpeedWindow {
		trickle(zipSpeedWindow)
		if tryOnce() {
			t.Fatalf("another zip on a full line after %v", elapsed)
		}
	}
	trickle(zipSpeedWindow)
	trickle(zipSpeedWindow)
	trickle(zipSpeedWindow) // the interval runs from when a waiter first read the crawl
	if !tryOnce() {
		t.Fatal("no probe after the full line's interval")
	}
}

// One stream beating the useful speed shows the server still has speed to give: the
// slow ones are slow clients, so the line keeps its quick probes until the crowd moves.
func TestAFastStreamKeepsTheProbesQuick(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	trickle, counters := crawlingOnClients(g, clock, 12)
	fast := counters[0]
	step := func(d time.Duration) {
		trickle(d)
		fast.sent.Add(zipUsefulRate * 2 * int64(d/time.Second))
	}
	step(zipSpeedWindow)
	step(zipSpeedWindow)
	tryOnce := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		return g.acquire(ctx, oneShare("a"), 0)
	}
	if tryOnce() {
		t.Fatal("started another the moment the crowd crawled")
	}
	for elapsed := time.Duration(0); elapsed < zipProbeEvery; elapsed += zipSpeedWindow {
		step(zipSpeedWindow)
	}
	if !tryOnce() {
		t.Fatal("no quick probe with a fast stream running")
	}
}

// A waiter whose owner has nothing running gets a quick probe on a full line: one more
// stream costs the others little, and it is the only way the other account's visitor
// gets a download at all. It stops being quick once that owner has one.
func TestAnOwnerWithNothingRunningGetsAQuickProbeOnAFullLine(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	trickle, _ := crawlingOnClients(g, clock, zipFloor)
	trickle(zipSpeedWindow)
	trickle(zipSpeedWindow)
	first, cancelFirst := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancelFirst()
	if g.acquire(first, oneShare("b"), 0) {
		t.Fatal("started another the moment the crowd crawled")
	}
	for elapsed := time.Duration(0); elapsed < zipProbeEvery; elapsed += zipSpeedWindow {
		trickle(zipSpeedWindow)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !g.acquire(ctx, oneShare("b"), 0) {
		t.Fatal("the other account's visitor got no probe")
	}
	for elapsed := time.Duration(0); elapsed < 2*zipProbeEvery; elapsed += zipSpeedWindow {
		trickle(zipSpeedWindow)
	}
	soon, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if g.acquire(soon, oneShare("b"), 0) {
		t.Fatal("an owner already running kept the quick probes")
	}
}

// The quick probe is still within what the machine can pay for.
func TestAQuickProbeNeedsTheMachine(t *testing.T) {
	room := &atomic.Bool{}
	room.Store(true)
	g, clock := testGate(func(int64) bool { return room.Load() })
	trickle, _ := crawlingOnClients(g, clock, zipFloor)
	for elapsed := time.Duration(0); elapsed < 2*zipProbeEvery; elapsed += zipSpeedWindow {
		trickle(zipSpeedWindow)
	}
	room.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if g.acquire(ctx, oneShare("b"), 0) {
		t.Fatal("a probe the machine refuses went in")
	}
}

// On a full line a waiter would take the cut stream's exact share, so a cut only throws
// away what that stream sent: while the machine has room, nobody's stream ends for it.
func TestAFullLineCutsNobody(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	trickle, _ := crawlingOnClients(g, clock, zipFloor)
	trickle(zipSpeedWindow)
	trickle(zipSpeedWindow)
	go g.acquire(t.Context(), oneShare("a"), 0)
	waitUntilBlocked(t, g.hasWaiter)
	if g.handOver(0) {
		t.Fatal("a stream ended for a line only the uplink is holding")
	}
}

// fillPastFloor starts running zips of owner "a" while the load allows, and
// answers the switch that makes it refuse.
func fillPastFloor(t *testing.T, running int) (*zipGate, *atomic.Bool) {
	t.Helper()
	room := &atomic.Bool{}
	room.Store(true)
	g, clock := testGate(func(int64) bool { return room.Load() })
	for i := range running {
		clock.step(zipAdmitEvery)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if !g.acquire(ctx, oneShare("a"), 0) {
			t.Fatalf("zip %d did not start", i)
		}
	}
	room.Store(false)
	return g, room
}

// A stream that ends for someone in line is what starts them, whatever the load
// says, and one waiter costs one stream however many are old and slow.
func TestOneWaiterTakesOneStreamsPlace(t *testing.T) {
	g, _ := fillPastFloor(t, 20)
	started := make(chan struct{})
	go func() {
		if g.acquire(context.Background(), oneShare("b"), 0) {
			close(started)
		}
	}()
	waitUntilBlocked(t, g.hasWaiter)
	yields := 0
	for range 19 {
		if g.handOver(0) {
			yields++
			g.release(oneShare("a"), 0)
		}
	}
	if yields != 1 {
		t.Fatalf("%d streams ended for one waiter", yields)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("the waiter did not start in the place given up")
	}
}

// A line the load is not holding moves by itself, so nobody's stream ends for it.
func TestNoStreamEndsForALineThatMoves(t *testing.T) {
	g, _ := testGate(func(int64) bool { return true })
	for range zipFloor + 1 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if !g.acquire(ctx, oneShare("a"), 0) {
			t.Fatal("a zip with room did not start")
		}
	}
	go g.acquire(t.Context(), oneShare("b"), 0)
	waitUntilBlocked(t, g.hasWaiter)
	if g.handOver(0) {
		t.Fatal("a stream ended for a waiter waiting only for the next window")
	}
}

// Taking a place must not let in a file list the memory cannot pay for: the stream
// keeps running when what it would free does not cover the waiter's list.
func TestAWaitersLargerListNeedsRoom(t *testing.T) {
	g, _ := fillPastFloor(t, zipFloor+1)
	go g.acquire(t.Context(), oneShare("b"), 1<<20)
	waitUntilBlocked(t, g.hasWaiter)
	if g.handOver(1 << 10) {
		t.Fatal("gave way to a list the load refuses")
	}
	if !g.handOver(1 << 20) {
		t.Fatal("did not give way to a list its own frees")
	}
}

// One share can fill only its part of the line, so a flood on one link leaves places
// for every other share. The count follows the line's size, and a place freed is offered
// again.
func TestOneShareHoldsOnlyItsPartOfTheLine(t *testing.T) {
	l := newZipLine(func() int { return 8 * zipLineShareParts })
	var leaves []func()
	for i := range 8 {
		leave, ok := l.enter("203.0.113."+strconv.Itoa(i), "flooded")
		if !ok {
			t.Fatalf("refused inside the share's part, after %d", i)
		}
		leaves = append(leaves, leave)
	}
	if _, ok := l.enter("203.0.113.100", "flooded"); ok {
		t.Fatal("one share took more than its part of the line")
	}
	other, ok := l.enter("203.0.113.100", "another")
	if !ok {
		t.Fatal("another share was refused while the line had room")
	}
	other()
	leaves[0]()
	again, ok := l.enter("203.0.113.100", "flooded")
	if !ok {
		t.Fatal("a place freed was not offered again")
	}
	again()
	for _, leave := range leaves[1:] {
		leave()
	}
	if len(l.byShare) != 0 {
		t.Errorf("shares left in the line's map: %v", l.byShare)
	}
}

// On a line too short to divide, a share still has a place.
func TestAShortLineStillGivesAShareAPlace(t *testing.T) {
	l := newZipLine(func() int { return 1 })
	if _, ok := l.enter("203.0.113.5", "only"); !ok {
		t.Fatal("no place on a line of one")
	}
}

// Within one account the share with the fewest zips running goes first, oldest first
// among equals, so a server with a single account is as fair as one with many.
func TestTheShareWithFewestZipsGoesFirstWithinAnAccount(t *testing.T) {
	room := atomic.Bool{}
	g, clock := testGate(func(int64) bool { return room.Load() })
	flooded, quiet := zipTurn{owner: "me", share: "flooded"}, zipTurn{owner: "me", share: "quiet"}
	for range zipFloor {
		g.acquire(context.Background(), flooded, 0)
	}
	order := make(chan zipTurn, 2)
	start := func(turn zipTurn) {
		go func() {
			if g.acquire(context.Background(), turn, 0) {
				order <- turn
			}
		}()
	}
	start(flooded)
	waitUntilBlocked(t, g.hasWaiter)
	time.Sleep(10 * time.Millisecond)
	start(quiet)
	time.Sleep(10 * time.Millisecond)
	room.Store(true)
	clock.step(zipAdmitEvery)
	if first := <-order; first != quiet {
		t.Fatalf("%v started first", first)
	}
}

// The owner comes first and the share second: a quiet share of a busy account does not
// overtake an account with less running.
func TestTheOwnerWithFewestZipsComesBeforeAQuietShare(t *testing.T) {
	g, _ := testGate(func(int64) bool { return true })
	g.running["busy"], g.running["calm"] = 5, 1
	g.runningShares["calm-share"] = 1
	quiet := &zipWaiter{turn: zipTurn{owner: "busy", share: "quiet"}, ready: make(chan struct{})}
	calm := &zipWaiter{turn: zipTurn{owner: "calm", share: "calm-share"}, ready: make(chan struct{})}
	g.pushLocked(quiet)
	g.pushLocked(calm)
	if next := g.nextLocked(); next != calm {
		t.Fatalf("%v goes first", next.turn)
	}
}

// A share with nothing running gets a quick probe on a full line even when its owner
// has zips running elsewhere, and stops being quick once it has one of its own.
func TestAShareWithNothingRunningGetsAQuickProbeOnAFullLine(t *testing.T) {
	g, clock := testGate(func(int64) bool { return true })
	trickle, _ := crawlingOnClients(g, clock, zipFloor)
	quiet := zipTurn{owner: "a", share: "quiet"}
	trickle(zipSpeedWindow)
	trickle(zipSpeedWindow)
	first, cancelFirst := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancelFirst()
	if g.acquire(first, quiet, 0) {
		t.Fatal("started another the moment the crowd crawled")
	}
	for elapsed := time.Duration(0); elapsed < zipProbeEvery; elapsed += zipSpeedWindow {
		trickle(zipSpeedWindow)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !g.acquire(ctx, quiet, 0) {
		t.Fatal("the quiet share got no probe")
	}
	for elapsed := time.Duration(0); elapsed < 2*zipProbeEvery; elapsed += zipSpeedWindow {
		trickle(zipSpeedWindow)
	}
	soon, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if g.acquire(soon, quiet, 0) {
		t.Fatal("a share already running kept the quick probes")
	}
}

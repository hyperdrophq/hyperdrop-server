package liveshare

import (
	"sync/atomic"
	"time"
)

// How many transfers a live share holds at once adapts to the sharer's uplink.
// Every byte a visitor receives crosses the sharer's own connection, so one
// more transfer is worth starting only while it adds speed: past the point
// the uplink is full it only splits the same speed more ways, and a video
// stops playing for everyone. The relay reads every byte, so the share's
// total speed is measured exactly, and a share learns its limit by trying.
const (
	// MinJobsPerShare is the limit every share starts at and never drops
	// below: what any sharer's connection carries.
	MinJobsPerShare = 8
	// MinJobsPerAddress is the fewest transfers one visitor address may hold
	// of a share, however low its limit. An address holds a quarter of the
	// share's limit past that (addrLimitLocked), so a household or an office
	// behind one address shares a fast uplink while one address never fills
	// the share.
	MinJobsPerAddress = 2
	// MinQueuedPerShare is the shortest a share's line of visitors waiting for
	// a place gets; a line holds twice the share's limit past that.
	MinQueuedPerShare = 16
	// adaptGrowShare is how much a try adds: an eighth of the limit, at least
	// one, so a fast uplink is found in a few tries rather than one place at a
	// time.
	adaptGrowShare = 8
	// adaptHoldMin and adaptHoldMax bound how long a share waits before trying
	// again after a try that added no speed. Each failure doubles the wait, so
	// a full uplink is asked rarely, and a success resets it.
	adaptHoldMin = 30 * time.Second
	adaptHoldMax = 5 * time.Minute
)

// gauge is a share's adaptive limit and what it measures. Every field but
// sent is guarded by the jobSet's mu.
type gauge struct {
	limit   int
	ceiling int
	window  time.Duration
	// sent counts the bytes relayed to the share's visitors; a body's Read
	// adds to it without taking a lock.
	sent atomic.Int64
	// streaming is how many jobs hold a place and are claimed by the sharer.
	streaming int
	// The current measurement: since when, the bytes sent then, and the
	// fewest jobs streaming at any moment since.
	windowStart  time.Time
	windowSent   int64
	minStreaming int

	state    adaptState
	baseline float64 // bytes a second before the try
	added    int
	fillBy   time.Time
	hold     time.Duration
	holdTill time.Time
	timer    *time.Timer
}

type adaptState int

const (
	adaptIdle    adaptState = iota // measuring at the current limit
	adaptFilling                   // a try's places are being taken and claimed
	adaptTrying                    // measuring with the try's places streaming
)

// addrLimitLocked is how many places, in line or holding a job, one address
// may have.
func (js *jobSet) addrLimitLocked() int {
	return max(MinJobsPerAddress, js.g.limit/4)
}

// lineLimitLocked is how long the share's line may grow.
func (js *jobSet) lineLimitLocked() int {
	return max(MinQueuedPerShare, 2*js.g.limit)
}

// armLocked starts measuring when visitors are waiting and nothing measures
// yet. The caller holds js.mu.
func (js *jobSet) armLocked() {
	if js.g.timer != nil || isEnded(js) {
		return
	}
	js.restartWindowLocked(time.Now())
	js.g.timer = time.AfterFunc(js.g.window, js.tick)
}

func (js *jobSet) restartWindowLocked(now time.Time) {
	js.g.windowStart = now
	js.g.windowSent = js.g.sent.Load()
	js.g.minStreaming = js.g.streaming
}

// streamedLocked records that a job's sharer started sending or a streaming
// job ended. The caller holds js.mu.
func (js *jobSet) streamedLocked(delta int) {
	js.g.streaming += delta
	js.g.minStreaming = min(js.g.minStreaming, js.g.streaming)
}

func (js *jobSet) tick() {
	js.mu.Lock()
	defer js.mu.Unlock()
	if isEnded(js) || js.g.timer == nil {
		return
	}
	js.adaptLocked(time.Now())
	if js.line.Len() == 0 && js.g.state == adaptIdle {
		js.g.timer = nil
		return
	}
	js.g.timer.Reset(js.g.window)
}

// adaptLocked reads the window that ended at now and moves the limit. While
// visitors wait and every place streamed the whole window, it adds places and
// keeps them only when, once they all stream, the share's speed grows by at
// least half of what that many more streams would add to an uplink with room.
// A try that does not, or whose places are not all streaming in time, gives
// the places back, and the share waits before it tries again. The caller holds
// js.mu.
func (js *jobSet) adaptLocked(now time.Time) {
	g := &js.g
	elapsed := now.Sub(g.windowStart).Seconds()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(g.sent.Load()-g.windowSent) / elapsed
	}
	steady := g.minStreaming >= g.limit
	switch g.state {
	case adaptIdle:
		if steady && js.line.Len() > 0 && !now.Before(g.holdTill) && g.limit < g.ceiling {
			g.baseline = rate
			g.added = min(max(1, g.limit/adaptGrowShare), g.ceiling-g.limit)
			g.limit += g.added
			g.state = adaptFilling
			g.fillBy = now.Add(2 * g.window)
			js.grantLocked()
			js.wakeAddressesLocked()
		}
	case adaptFilling:
		if g.streaming >= g.limit {
			g.state = adaptTrying
		} else if now.After(g.fillBy) {
			js.giveBackLocked(now, false)
		}
	case adaptTrying:
		before := g.limit - g.added
		if steady && rate >= g.baseline*(1+0.5*float64(g.added)/float64(before)) {
			g.state = adaptIdle
			g.hold = 0
		} else {
			js.giveBackLocked(now, steady)
		}
	}
	js.restartWindowLocked(now)
}

// giveBackLocked ends a try without keeping its places. A try that measured
// no gain makes the share wait before the next, longer each time; one that
// could not fill its places was not a measurement and waits the least.
func (js *jobSet) giveBackLocked(now time.Time, measured bool) {
	g := &js.g
	g.limit -= g.added
	g.state = adaptIdle
	if measured {
		g.hold = min(max(2*g.hold, adaptHoldMin), adaptHoldMax)
	} else {
		g.hold = adaptHoldMin
	}
	g.holdTill = now.Add(g.hold)
}

// wakeAddressesLocked wakes every request waiting for a place of its address,
// since a higher limit gives each address more.
func (js *jobSet) wakeAddressesLocked() {
	for addr, freed := range js.freed {
		close(freed)
		delete(js.freed, addr)
	}
}

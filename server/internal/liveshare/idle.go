package liveshare

import "time"

// A transfer that holds a place without moving data keeps a waiting visitor
// out for nothing: a video paused in a tab, a connection opened and left. So
// while anyone waits in the share's line, a streaming transfer whose visitor
// takes less than IdleBytesPerSecond over a whole Config.IdleWindow is ended
// and its place goes to the line. Nothing is ended while nobody waits, and
// nothing is measured then either: the check runs on the share's tick, which
// runs only while visitors wait or a try is under way.
//
// Only the visitor's own slowness counts. The relay's time splits in two:
// waiting in a read for the sharer's next bytes, and everything else, which
// is the visitor's connection taking them. A transfer is judged by its bytes
// over the second part alone, and only when that part is at least half the
// window, so a sharer whose uplink trickles or falls silent never costs a
// visitor its transfer, and neither does a job the sharer has not claimed,
// which is not measured at all.
//
// The window with one tick (Config.ProbeWindow) stays under Config.QueueWait,
// so a visitor in line sees the place an idle transfer held before it gives
// up.
const (
	// IdleBytesPerSecond is the least a visitor takes, averaged over the
	// time the relay spent sending to it, to keep its place while others
	// wait: 8 kbit/s, a fifth of what a GPRS connection carries.
	IdleBytesPerSecond = 1 << 10
)

// clock is the time since the set was made, in nanoseconds and never 0.
func (js *jobSet) clock() int64 { return int64(time.Since(js.born)) + 1 }

// sharerWait is how long the job's reads have waited for the sharer, the read
// in progress included. It reads reading before waited, so a read that ends
// between the two is counted twice rather than not at all: an error on the
// side that keeps the transfer.
func (j *Job) sharerWait() int64 {
	began := j.reading.Load()
	waited := j.waited.Load()
	if began != 0 {
		waited += j.set.clock() - began
	}
	return waited
}

// markIdleLocked starts the job's idle measurement at now. The caller holds
// the set's mu.
func (j *Job) markIdleLocked(now time.Time) {
	j.idleAt, j.idleSent, j.idleWaited = now, j.sent.Load(), j.sharerWait()
}

// markStreamsLocked starts every streaming job's idle measurement at now: the
// line stopped being empty, and a transfer answers only for the time someone
// waited. The caller holds js.mu.
func (js *jobSet) markStreamsLocked(now time.Time) {
	for j := range js.streams {
		j.markIdleLocked(now)
	}
}

// idleLocked takes the place back from every streaming job whose measurement
// has run a whole window and found its visitor idle, for as long as visitors
// wait in line, and answers those jobs for the caller to end once it has let
// go of js.mu. A job that kept up starts a new measurement. The caller holds
// js.mu.
func (js *jobSet) idleLocked(now time.Time) []*Job {
	var idle []*Job
	for j := range js.streams {
		if js.line.Len() == 0 {
			break
		}
		elapsed := now.Sub(j.idleAt)
		if elapsed < js.idleWindow {
			continue
		}
		sent, waited := j.sent.Load(), j.sharerWait()
		sending := elapsed - time.Duration(waited-j.idleWaited)
		if sending >= js.idleWindow/2 && float64(sent-j.idleSent) < IdleBytesPerSecond*sending.Seconds() {
			js.releaseLocked(j)
			idle = append(idle, j)
			continue
		}
		j.idleAt, j.idleSent, j.idleWaited = now, sent, waited
	}
	return idle
}

// endIdle ends a job whose place idleLocked took back, the way its visitor
// leaving does: the sharer's next write fails, the visitor's next read of the
// body fails, and the visitor's request is told through OnIdle, since a copy
// blocked writing to a visitor that takes nothing never reads the body again.
func (j *Job) endIdle() {
	j.pr.Close()
	j.mu.Lock()
	defer j.mu.Unlock()
	j.idled = true
	if j.onIdle != nil {
		j.onIdle()
	}
}

// OnIdle has fn run when the job is ended for holding its place idle, at once
// when it already was, and answers a stop after whose return fn is never
// running nor run. fn must not call into the job.
func (j *Job) OnIdle(fn func()) (stop func()) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.idled {
		fn()
		return func() {}
	}
	j.onIdle = fn
	return func() {
		j.mu.Lock()
		j.onIdle = nil
		j.mu.Unlock()
	}
}

// Idled says the job was ended for holding its place idle.
func (j *Job) Idled() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.idled
}

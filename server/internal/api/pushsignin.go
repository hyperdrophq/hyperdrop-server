package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"slices"
	"time"

	"hyperdrop/core/pushseal"
	"hyperdrop/core/signinannounce"
	"hyperdrop/server/internal/metadb"
)

// A computer a phone signed in is announced to every other registered
// device of the account at once, by the request that minted its token: the
// owner of a phone that approved a stranger's code learns of it on every
// device, and any of them signs the computer out. Unlike the pusher's
// passes it never asks quiet: a computer's console activity, the new
// computer's own included, must not silence the alarm about a computer.
// No device can mute it (metadb.PushKinds does not list the kind).
//
// The owner's push_state row (kind signIn, signInMemory) records each
// sign-in as owed before anything is sent, and as announced once the relay
// answered about every device (relayAnswered). A device the relay did not
// answer about (a transport error, a 5xx) leaves the sign-in owed, and the
// sweep sends it again to those devices alone, after signInRetryAfter. A
// send the pusher's stop interrupted is sent by the next pusher when it
// starts (resumeSignIns). Every send stays within signinannounce.Window.

// signInMemory is what the pusher remembers of an owner's phone sign-ins.
type signInMemory struct {
	// Announced are the token ids the relay answered for, newest last, at
	// most metadb.SignInEventsKept.
	Announced []string `json:"announced"`
	// Owed are the sign-ins recorded whose send has not finished.
	Owed []owedSignIn `json:"owed,omitempty"`
}

// owedSignIn is a sign-in recorded and not yet answered about every device.
type owedSignIn struct {
	signinannounce.SignIn
	// Answered are the devices (their token ids) the relay answered about;
	// a later send skips them.
	Answered []string `json:"answered,omitempty"`
	// Tries counts the sends that ended with a device unanswered, and Next
	// is when the sweep sends again; a sign-in no send has ended for yet
	// has neither.
	Tries int       `json:"tries,omitempty"`
	Next  time.Time `json:"next,omitzero"`
}

// The wait before an owed sign-in is sent again: signInRetryFirst after the
// first send that left a device unanswered, doubling with each further one
// up to signInRetryMost, so a relay that is down is not hammered.
const (
	signInRetryFirst = pushSweep
	signInRetryMost  = time.Hour
)

// signInRetryAfter is the wait after the tries-th send that left a device
// unanswered.
func signInRetryAfter(tries int) time.Duration {
	d := signInRetryFirst
	for i := 1; i < tries && d < signInRetryMost; i++ {
		d *= 2
	}
	return min(d, signInRetryMost)
}

// known is every token id the memory holds, announced or owed: a sign-in
// among them is never recorded again.
func (m signInMemory) known() []string {
	out := slices.Clone(m.Announced)
	for _, o := range m.Owed {
		out = append(out, o.TokenID)
	}
	return out
}

// stillDue is owed less what has left signinannounce.Window by now.
func stillDue(owed []owedSignIn, now time.Time) []owedSignIn {
	return slices.DeleteFunc(slices.Clone(owed), func(o owedSignIn) bool {
		return len(signinannounce.Due([]signinannounce.SignIn{o.SignIn}, "", nil, now)) == 0
	})
}

// announceDeviceSignedIn announces s, the sign-in that minted newTokenID
// for u, when push is on. It records the sign-in as owed and then sends it
// on its own goroutine, so the computer's sign-in never waits on the relay
// and no push failure fails it. A stopped pusher sends nothing and leaves
// it owed for the next one.
func (h *handler) announceDeviceSignedIn(u metadb.User, newTokenID string, s signinannounce.SignIn) {
	if h.push == nil || newTokenID == "" {
		return
	}
	s.TokenID, s.Username = newTokenID, u.Username
	if h.push.oweSignIn(u.Username, s) {
		h.push.sendSignIn(u.Username, s.TokenID)
	}
}

// loadSignIns reads the owner's memory; ok is false when it cannot be read.
// A value that does not parse reads as empty.
func (p *pusher) loadSignIns(owner string) (m signInMemory, ok bool) {
	raw, found, err := p.db.PushState(owner, pushStateSignIn)
	if err != nil {
		log.Printf("push: announced sign-ins of %s: %v", owner, err)
		return m, false
	}
	if found && json.Unmarshal([]byte(raw), &m) != nil {
		m = signInMemory{}
	}
	return m, true
}

// oweSignIn records s as owed and reports whether it is due and durably
// recorded: signinannounce.Due decides, so a sign-in already announced or
// owed, or older than signinannounce.Window, is never recorded again.
// Nothing is sent unless the record is durable, as for every kind
// (saveState).
func (p *pusher) oweSignIn(owner string, s signinannounce.SignIn) bool {
	p.signInMu.Lock()
	defer p.signInMu.Unlock()
	m, ok := p.loadSignIns(owner)
	if !ok || len(signinannounce.Due([]signinannounce.SignIn{s}, "", m.known(), p.now())) == 0 {
		return false
	}
	m.Owed = append(stillDue(m.Owed, p.now()), owedSignIn{SignIn: s})
	return p.saveState(owner, pushStateSignIn, m)
}

// settleSignIn records how one send of tokenID ended: the devices the relay
// answered about join Answered; a finished send moves the sign-in to
// announced; an unfinished one schedules the next try, unless the pusher's
// stop interrupted it, which leaves it for the next pusher at once. A
// sign-in past signinannounce.Window is dropped.
func (p *pusher) settleSignIn(owner, tokenID string, answered []string, finished, interrupted bool) {
	p.signInMu.Lock()
	defer p.signInMu.Unlock()
	m, ok := p.loadSignIns(owner)
	if !ok {
		return
	}
	now := p.now()
	m.Owed = stillDue(m.Owed, now)
	i := slices.IndexFunc(m.Owed, func(o owedSignIn) bool { return o.TokenID == tokenID })
	switch {
	case i < 0:
	case finished:
		m.Owed = slices.Delete(m.Owed, i, i+1)
		m.Announced = append(m.Announced, tokenID)
		if over := len(m.Announced) - metadb.SignInEventsKept; over > 0 {
			m.Announced = m.Announced[over:]
		}
	default:
		o := &m.Owed[i]
		o.Answered = append(o.Answered, answered...)
		if !interrupted {
			o.Tries++
			o.Next = now.Add(signInRetryAfter(o.Tries))
		}
	}
	p.saveState(owner, pushStateSignIn, m)
}

// sendSignIn sends the owner's owed sign-in tokenID, when its next try is
// due, to every registration of the owner but the computer's own and those
// the relay already answered about, and records how it ended
// (settleSignIn). A sign-in already being sent is not sent again meanwhile.
func (p *pusher) sendSignIn(owner, tokenID string) {
	p.signInMu.Lock()
	m, ok := p.loadSignIns(owner)
	var o owedSignIn
	if ok {
		if i := slices.IndexFunc(m.Owed, func(o owedSignIn) bool { return o.TokenID == tokenID }); i >= 0 {
			o = m.Owed[i]
		}
	}
	if o.TokenID == "" || o.Next.After(p.now()) || p.signInSending[tokenID] {
		p.signInMu.Unlock()
		return
	}
	if p.signInSending == nil {
		p.signInSending = map[string]bool{}
	}
	p.signInSending[tokenID] = true
	p.signInMu.Unlock()
	done := func() {
		p.signInMu.Lock()
		delete(p.signInSending, o.TokenID)
		p.signInMu.Unlock()
	}
	msg, collapse := signInMessage(o.SignIn), signInCollapse(o.TokenID)
	skip := append([]string{o.TokenID}, o.Answered...)
	if !p.sendSoon(func(ctx context.Context) {
		defer done()
		answered, finished := p.deliverTo(ctx, owner, skip, pushKindDeviceSignedIn, collapse, msg)
		p.settleSignIn(owner, o.TokenID, answered, finished, ctx.Err() != nil)
	}) {
		done()
	}
}

// sendOwedSignIns sends every owner's owed sign-ins whose next try is due,
// and drops those past signinannounce.Window.
func (p *pusher) sendOwedSignIns() {
	owners, err := p.db.PushUsers()
	if err != nil {
		log.Printf("push: owed sign-ins: %v", err)
		return
	}
	for _, owner := range owners {
		p.signInMu.Lock()
		m, ok := p.loadSignIns(owner)
		var due []owedSignIn
		if ok {
			due = stillDue(m.Owed, p.now())
			if len(due) != len(m.Owed) {
				m.Owed = due
				p.saveState(owner, pushStateSignIn, m)
			}
		}
		p.signInMu.Unlock()
		for _, o := range due {
			p.sendSignIn(owner, o.TokenID)
		}
	}
}

// resumeSignIns sends every sign-in a previous process left owed whose
// next try is due, whatever the heartbeat says (resume): an owed sign-in is
// an alarm interrupted, never a replay. It runs when the pusher starts,
// before the server takes a request (NewServer).
func (p *pusher) resumeSignIns() { p.sendOwedSignIns() }

// signInMessage is s worded by signinannounce, with the facts the phone
// needs to word it again and to offer Sign Out on the computer's token.
func signInMessage(s signinannounce.SignIn) pushseal.Message {
	title, body := signinannounce.Words(s)
	return pushseal.Message{Title: title, Body: body, Thread: "device-signed-in",
		TokenID: s.TokenID, Label: s.Label, Platform: s.Platform, ApprovedBy: s.ApprovedBy,
		Username: s.Username, At: s.At.UTC().Format(time.RFC3339)}
}

// signInCollapse is the push's collapse id, si-<24 hex>: a SHA-256 of the
// token id, so the relay never learns which token the computer holds.
func signInCollapse(tokenID string) string {
	sum := sha256.Sum256([]byte("deviceSignedIn\x00" + tokenID))
	return "si-" + hex.EncodeToString(sum[:12])
}

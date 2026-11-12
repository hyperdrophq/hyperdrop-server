package api

import (
	"sync"
	"time"
)

const (
	// signInMeterMax is how many correct passwords one account's sign-ins and
	// step-ups may present in signInMeterWindow. An app signs in once per device
	// and an account with a second factor spends two (the prompt, then the code),
	// so this is far past any person, and it bounds what a script can make the
	// server's bcrypt slots and durable commits do.
	signInMeterMax = 60
	// signInMeterWindow is the window signInMeterMax counts in.
	signInMeterWindow = 10 * time.Minute
)

// signInMeter limits the correct passwords one account presents. Wrong guesses
// have the lockouts and lanes; those see a correct password as the end of a
// problem, so an account holder could otherwise run compares without limit and
// hold every bcrypt slot, which refuses every other account's sign-in. Only a
// correct password spends it: a stranger cannot reach it, so nobody who does not
// hold the password can lock the owner out. An entry is only ever made for an
// account that exists, which bounds the map.
type signInMeter struct {
	mu       sync.Mutex
	now      func() time.Time
	accounts map[string]*signInMeterEntry
}

type signInMeterEntry struct {
	start time.Time
	spent int
}

func newSignInMeter() *signInMeter {
	return &signInMeter{now: time.Now, accounts: map[string]*signInMeterEntry{}}
}

// over reports whether name has spent its window, and when that window ends.
func (m *signInMeter) over(name string) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.accounts[name]
	if e == nil || m.now().Sub(e.start) >= signInMeterWindow {
		return time.Time{}, false
	}
	return e.start.Add(signInMeterWindow), e.spent >= signInMeterMax
}

// spend counts one correct password for name.
func (m *signInMeter) spend(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	e := m.accounts[name]
	if e == nil || now.Sub(e.start) >= signInMeterWindow {
		m.accounts[name] = &signInMeterEntry{start: now, spent: 1}
		return
	}
	e.spent++
}

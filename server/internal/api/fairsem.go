package api

import (
	"context"
	"sync"
)

// fairSem is a global concurrency cap with a per-owner sub-cap on top, so one
// account can never hold every slot while other accounts wait. The shared
// caps (zip streams, bcrypt compares) exist to protect a 1-vCPU box; without
// per-owner fairness a single guest (or a single popular guest share being
// downloaded) starves everyone else on the server.
//
// Slots are taken owner-first, then global. The order is the same for every
// caller, so two waiters can't hold each other's next slot; and a waiter
// parked on the global slot holds only its OWN owner slot, which no other
// owner needs.
type fairSem struct {
	global   chan struct{}
	ownerMax int

	mu     sync.Mutex
	owners map[string]chan struct{}
}

func newFairSem(global, perOwner int) *fairSem {
	return &fairSem{global: make(chan struct{}, global), ownerMax: perOwner,
		owners: make(map[string]chan struct{})}
}

func (s *fairSem) ownerSlots(owner string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.owners[owner]
	if c == nil {
		c = make(chan struct{}, s.ownerMax)
		s.owners[owner] = c
	}
	return c
}

// acquire waits for a slot for owner. It returns false when ctx is done first
// (the client gave up queueing), in which case nothing is held.
//
// owner MUST come from stored data (a share's owner), never from request
// input: the map is keyed by it, so a caller-controlled key would let a
// stranger grow it without bound.
func (s *fairSem) acquire(ctx context.Context, owner string) bool {
	oc := s.ownerSlots(owner)
	select {
	case oc <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	select {
	case s.global <- struct{}{}:
		return true
	case <-ctx.Done():
		<-oc
		return false
	}
}

// tryAcquire takes an owner slot and a global slot, or nothing at all. Unlike
// acquire it never queues, because its caller (the long-poll watch route)
// holds its slots for as long as the client stays connected: a queued caller
// would be waiting for a disconnect that may never come. Refusing lets the
// client fall back to polling instead, which keeps it refreshing rather than
// hung.
func (s *fairSem) tryAcquire(owner string) bool {
	oc := s.ownerSlots(owner)
	select {
	case oc <- struct{}{}:
	default:
		return false
	}
	select {
	case s.global <- struct{}{}:
		return true
	default:
		<-oc
		return false
	}
}

func (s *fairSem) release(owner string) {
	<-s.global
	<-s.ownerSlots(owner)
}

// keyedLock is one slot per key, for a key taken from request input (a
// client address): a key's entry lives only while a caller holds or waits
// for it, so the map holds no more entries than there are callers.
type keyedLock struct {
	mu   sync.Mutex
	keys map[string]*keyedSlot
}

type keyedSlot struct {
	slot  chan struct{}
	users int // holders and waiters
}

func newKeyedLock() *keyedLock {
	return &keyedLock{keys: make(map[string]*keyedSlot)}
}

// acquire waits for key's slot. It returns false when ctx is done first, in
// which case nothing is held.
func (k *keyedLock) acquire(ctx context.Context, key string) bool {
	k.mu.Lock()
	e := k.keys[key]
	if e == nil {
		e = &keyedSlot{slot: make(chan struct{}, 1)}
		k.keys[key] = e
	}
	e.users++
	k.mu.Unlock()
	select {
	case e.slot <- struct{}{}:
		return true
	case <-ctx.Done():
		k.leave(key, e)
		return false
	}
}

func (k *keyedLock) release(key string) {
	k.mu.Lock()
	e := k.keys[key]
	k.mu.Unlock()
	<-e.slot
	k.leave(key, e)
}

// leave forgets one holder or waiter of key, and the entry with its last.
func (k *keyedLock) leave(key string, e *keyedSlot) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if e.users--; e.users == 0 {
		delete(k.keys, key)
	}
}

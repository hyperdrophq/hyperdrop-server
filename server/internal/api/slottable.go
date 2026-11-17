package api

import "sync"

// slotCap is one key a slot is counted under, and how many slots that key may hold.
// A max of zero or below counts the key without capping it.
type slotCap struct {
	key string
	max int
}

// slotTable counts held slots, in all and per key, and never queues: a take either
// holds its slot under every key it names or refuses and holds nothing. A key's entry
// lives only while a slot holds it, so a key taken from request input (a client
// address) never outlives its requests, and the total bounds how many entries exist.
// The zero value is ready.
type slotTable struct {
	mu   sync.Mutex
	n    int
	keys map[string]int
}

// take holds one slot under total and under each of caps, whose keys are distinct.
// The total is checked first and always caps (a total of zero refuses every take),
// then each key in argument order. refused is -1 when the slot is held, 0 when the
// total refused it and i+1 when caps[i] did; a refused take counts nothing. The release
// gives the slot back under every key, and runs once however often it is called.
func (t *slotTable) take(total int, caps ...slotCap) (release func(), refused int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.n >= total {
		return nil, 0
	}
	for i, c := range caps {
		if c.max > 0 && t.keys[c.key] >= c.max {
			return nil, i + 1
		}
	}
	if t.keys == nil {
		t.keys = map[string]int{}
	}
	t.n++
	for _, c := range caps {
		t.keys[c.key]++
	}
	return sync.OnceFunc(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.n--
		for _, c := range caps {
			if t.keys[c.key]--; t.keys[c.key] == 0 {
				delete(t.keys, c.key)
			}
		}
	}), -1
}

// held is how many slots key holds.
func (t *slotTable) held(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.keys[key]
}

// total is how many slots are held in all.
func (t *slotTable) total() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

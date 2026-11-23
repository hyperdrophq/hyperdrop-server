package api

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// The total is checked before any key, and the keys in the order they are named, so a
// take past several caps reports the first of them.
func TestSlotTableRefusesInOrder(t *testing.T) {
	var s slotTable
	release, refused := s.take(2, slotCap{"a", 1}, slotCap{"b", 1})
	if refused != -1 {
		t.Fatalf("an empty table refused with %d", refused)
	}
	defer release()
	for _, tc := range []struct {
		name  string
		total int
		caps  []slotCap
		want  int
	}{
		{"both keys full", 2, []slotCap{{"a", 1}, {"b", 1}}, 1},
		{"both keys full, named the other way", 2, []slotCap{{"b", 1}, {"a", 1}}, 1},
		{"the second key full", 2, []slotCap{{"c", 1}, {"b", 1}}, 2},
		{"the total and both keys full", 1, []slotCap{{"a", 1}, {"b", 1}}, 0},
		{"the total full, the keys free", 1, []slotCap{{"c", 1}, {"d", 1}}, 0},
		{"a total of zero", 0, nil, 0},
	} {
		if r, refused := s.take(tc.total, tc.caps...); refused != tc.want {
			t.Errorf("%s: refused %d, want %d", tc.name, refused, tc.want)
			if r != nil {
				r()
			}
		}
	}
	if s.total() != 1 || s.held("a") != 1 || s.held("b") != 1 || s.held("c") != 0 || s.held("d") != 0 {
		t.Errorf("refused takes were counted: total %d, %v", s.total(), s.keys)
	}
}

// A key whose max is zero or below is counted but never refuses.
func TestSlotTableCountsAnUncappedKey(t *testing.T) {
	var s slotTable
	var held []func()
	for range 5 {
		release, refused := s.take(10, slotCap{"open", 0}, slotCap{"negative", -1})
		if refused != -1 {
			t.Fatalf("an uncapped key refused with %d", refused)
		}
		held = append(held, release)
	}
	if s.held("open") != 5 || s.held("negative") != 5 {
		t.Errorf("held %d and %d, want 5", s.held("open"), s.held("negative"))
	}
	for _, release := range held {
		release()
	}
}

// A release gives back the slot under every key once, however often it runs, and a key
// nothing holds has no entry.
func TestSlotTableReleaseIsIdempotent(t *testing.T) {
	var s slotTable
	first, _ := s.take(10, slotCap{"a", 2}, slotCap{"b", 2})
	second, _ := s.take(10, slotCap{"a", 2}, slotCap{"c", 2})
	first()
	first()
	if s.total() != 1 || s.held("a") != 1 || s.held("b") != 0 || s.held("c") != 1 {
		t.Fatalf("after a double release: total %d, %v", s.total(), s.keys)
	}
	if _, ok := s.keys["b"]; ok {
		t.Error("a key nothing holds kept its entry")
	}
	second()
	if s.total() != 0 || len(s.keys) != 0 {
		t.Errorf("after every release: total %d, %v", s.total(), s.keys)
	}
}

// Concurrent takers never hold more than a cap, and every release brings the table back
// to empty.
func TestSlotTableUnderConcurrentTakers(t *testing.T) {
	const total, perKey, keys, takers = 12, 3, 6, 64
	var s slotTable
	var inKey [keys]atomic.Int64
	var inAll atomic.Int64
	var wg sync.WaitGroup
	for i := range takers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k := i % keys
			for range 200 {
				release, refused := s.take(total, slotCap{fmt.Sprintf("k%d", k), perKey}, slotCap{"all", 0})
				if refused != -1 {
					continue
				}
				if n := inKey[k].Add(1); n > perKey {
					t.Errorf("key %d held %d slots, cap %d", k, n, perKey)
				}
				if n := inAll.Add(1); n > total {
					t.Errorf("%d slots held, cap %d", n, total)
				}
				inAll.Add(-1)
				inKey[k].Add(-1)
				release()
				release()
			}
		}()
	}
	wg.Wait()
	if s.total() != 0 || len(s.keys) != 0 {
		t.Errorf("after the storm: total %d, %v", s.total(), s.keys)
	}
}

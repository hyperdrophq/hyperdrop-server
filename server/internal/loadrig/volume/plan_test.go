package volume

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/text/unicode/norm"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
	"hyperdrop/server/internal/shareid"
)

// fixedEpoch keeps the plans a test compares on one day, whenever it runs.
var fixedEpoch = time.Date(2026, 11, 1, 15, 4, 5, 0, time.UTC)

func TestPlanIsDeterministicPerSeed(t *testing.T) {
	a, b, c := NewPlanAt(100000, 7, fixedEpoch), NewPlanAt(100000, 7, fixedEpoch), NewPlanAt(100000, 8, fixedEpoch)
	differs := 0
	for k := 0; k < 1000; k++ {
		i := k * 97
		if a.Share(i) != b.Share(i) {
			t.Fatalf("share %d differs between two plans of one seed", i)
		}
		first, again := a.Share(i), a.Share(i)
		if first != again {
			t.Fatalf("share %d differs between two calls", i)
		}
		if a.Share(i) != c.Share(i) {
			differs++
		}
	}
	if differs == 0 {
		t.Fatal("another seed produced the same shares")
	}
}

func TestAPlanIsAPureFunctionOfItsInputs(t *testing.T) {
	a := NewPlanAt(5000, 9, fixedEpoch)
	b := NewPlanAt(5000, 9, fixedEpoch.Add(5*time.Hour).In(time.FixedZone("east", 3*3600)))
	if a != b {
		t.Fatalf("two plans of one day differ: %+v and %+v", a, b)
	}
	if want := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC); a.Epoch != want {
		t.Fatalf("Epoch %v, want the day's UTC midnight %v", a.Epoch, want)
	}
	for i := 0; i < a.Shares; i += 37 {
		if a.Share(i) != b.Share(i) {
			t.Fatalf("share %d differs between two plans of the same inputs", i)
		}
	}
	if NewPlanAt(5000, 9, fixedEpoch.Add(24*time.Hour)).Share(0) == a.Share(0) {
		t.Fatal("a plan for the next day dates its shares the same")
	}
}

func TestNewPlanIsPlannedForToday(t *testing.T) {
	before := time.Now().UTC()
	p := NewPlan(300, 1)
	after := time.Now().UTC()
	midnight := func(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC) }
	if p.Epoch != midnight(before) && p.Epoch != midnight(after) {
		t.Fatalf("NewPlan's Epoch %v, want today's UTC midnight %v", p.Epoch, midnight(after))
	}
}

func TestIDsAreValidAndFoldSafe(t *testing.T) {
	for i := 0; i < 2_000_000; i += 7 {
		if id := ID(i); !shareid.ValidID(id) {
			t.Fatalf("ID(%d)=%q is not valid", i, id)
		}
	}
	for _, i := range []int{0, 1, 1_999_999} {
		if !shareid.ValidID(ID(i)) {
			t.Fatalf("ID(%d) is not valid", i)
		}
	}
	seen := make(map[string]int, 200_001)
	for i := 0; i <= 200_000; i++ {
		l := strings.ToLower(ID(i))
		if j, dup := seen[l]; dup {
			t.Fatalf("ID(%d) and ID(%d) collide when lower-cased: %q", i, j, l)
		}
		seen[l] = i
	}
}

func TestCapsComeFromThePackages(t *testing.T) {
	p := NewPlan(10000, 1)
	if p.FileCap != sharefs.DefaultStageMaxFiles || p.InboxCap != metadb.InboxMaxFiles {
		t.Fatalf("caps %d/%d", p.FileCap, p.InboxCap)
	}
}

func TestTotalsAtFullSize(t *testing.T) {
	start := time.Now()
	files, byKind := NewPlan(1_000_000, 1).Totals()
	if files < 45_000_000 || files > 65_000_000 {
		t.Fatalf("%d files at 1,000,000 shares", files)
	}
	if byKind[Expired] != 100_000 {
		t.Fatalf("%d expired shares, want 100000", byKind[Expired])
	}
	nonPlain := 0
	for k, n := range byKind {
		if k != Plain && k != Expired {
			nonPlain += n
		}
	}
	if nonPlain >= 100_000 {
		t.Fatalf("%d shares of the special kinds", nonPlain)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("Totals took %v", d)
	}
}

func TestMixAtTenThousand(t *testing.T) {
	p := NewPlan(10000, 1)
	files, byKind := p.Totals()
	for k := Plain; k <= Inbox; k++ {
		if byKind[k] == 0 {
			t.Errorf("kind %v never appears", k)
		}
	}
	var sum int64
	atCap, owned := 0, map[string]int{}
	for i := 0; i < p.Shares; i++ {
		s := p.Share(i)
		sum += int64(s.Files)
		owned[s.Owner]++
		if s.Files < 1 {
			t.Fatalf("share %d has %d files", i, s.Files)
		}
		cap := p.FileCap
		if s.Kind == Inbox {
			cap = p.InboxCap
		}
		if s.Files > cap {
			t.Fatalf("share %d holds %d files, cap %d", i, s.Files, cap)
		}
		if s.Files == p.FileCap {
			atCap++
			if s.Owner != p.Account(0) && s.Owner != p.Account(1) {
				t.Fatalf("share %d at the cap belongs to %s", i, s.Owner)
			}
		}
		if s.Kind == Inbox && s.Files != p.InboxCap {
			t.Fatalf("inbox %d holds %d files", i, s.Files)
		}
		if s.Kind == Text && s.Files != 1 {
			t.Fatalf("text share %d holds %d files", i, s.Files)
		}
		if s.Kind == Expired && !s.ExpiresAt.Before(p.Epoch) || s.Kind == Expiring && s.ExpiresAt.Before(p.Epoch.Add(400*24*time.Hour)) {
			t.Fatalf("share %d (%v) expires at %v", i, s.Kind, s.ExpiresAt)
		}
		if i > 0 && !s.CreatedAt.After(p.Share(i-1).CreatedAt) {
			t.Fatalf("share %d is not newer than share %d", i, i-1)
		}
	}
	if sum != files {
		t.Fatalf("Totals %d, sum %d", files, sum)
	}
	if atCap < 3 {
		t.Fatalf("%d shares at the cap", atCap)
	}
	owner, n := p.Largest()
	if owner != p.Account(0) || n != owned[owner] || n < 2900 || n > 3300 {
		t.Fatalf("largest %s with %d", owner, n)
	}
	if !metadb.ValidUsername(owner) || p.Accounts != 50 {
		t.Fatalf("owner %q, %d accounts", owner, p.Accounts)
	}
}

func TestFileNames(t *testing.T) {
	p := NewPlan(10000, 3)
	checked := 0
	for i := 0; i < p.Shares; i++ {
		s := p.Share(i)
		if s.Files > 5000 && i%3 != 0 {
			continue
		}
		seen := make(map[string]bool, s.Files)
		for f := 0; f < s.Files; f++ {
			n := p.FileName(s, f)
			if !shareid.ValidRelPath(n) || !norm.NFC.IsNormalString(n) {
				t.Fatalf("share %d file %d: %q is not a valid NFC path", i, f, n)
			}
			l := strings.ToLower(n)
			if seen[l] {
				t.Fatalf("share %d file %d: %q repeats", i, f, n)
			}
			seen[l] = true
			ext := n[strings.LastIndex(n, "."):]
			switch s.Kind {
			case Gallery:
				if ext != ".jpg" && ext != ".png" && ext != ".mp4" {
					t.Fatalf("gallery file %q", n)
				}
			case Text:
				if ext != ".txt" {
					t.Fatalf("text file %q", n)
				}
			}
		}
		if s.Kind == Folders && s.Files > 1 && !strings.Contains(p.FileName(s, s.Files-1), "/") {
			t.Fatalf("folders share %d has a flat file", i)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("nothing checked")
	}
}

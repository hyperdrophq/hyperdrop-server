// Package volume plans a load-test volume: which shares exist, who owns them,
// what each holds. The plan is a pure function of its seed and size, so a
// generator's workers can ask for any share in any order.
package volume

import (
	"fmt"
	"time"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// Kind is what a planned share is for.
type Kind int

const (
	Plain     Kind = iota
	Protected      // password-protected
	Expiring
	Expired
	Gallery
	Text
	Folders
	Inbox
)

func (k Kind) String() string {
	names := [...]string{"plain", "password", "expiring", "expired", "gallery", "text", "folders", "inbox"}
	if k < 0 || int(k) >= len(names) {
		return fmt.Sprintf("kind(%d)", int(k))
	}
	return names[k]
}

// ShareSpec is one planned share. ExpiresAt is zero unless the kind is
// Expired (before the plan's Epoch) or Expiring (at least 400 days after it).
type ShareSpec struct {
	Index     int
	ID        string
	Owner     string
	Name      string
	Kind      Kind
	Files     int
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Plan is the shape of one volume. Epoch is the UTC midnight the volume's
// dates are measured from, the day it is generated: creation times spread
// over the year before it, so a server started on the volume that day finds
// the history a year of use leaves.
type Plan struct {
	Seed     int64
	Shares   int
	Accounts int
	FileCap  int
	InboxCap int
	Epoch    time.Time
}

const (
	day  = 24 * time.Hour
	year = 365 * day

	// idSpace is the number of ids ID can mint: nine base-9 digits.
	idSpace = 387420489
	// idStride is coprime to 9, so i*idStride mod idSpace is a bijection that
	// scatters consecutive indexes across the id space.
	idStride = 196836001
)

// NewPlan plans a volume of the given number of shares whose Epoch is
// today's UTC midnight. The caps are the server's own.
func NewPlan(shares int, seed int64) Plan { return NewPlanAt(shares, seed, time.Now()) }

// NewPlanAt plans a volume whose Epoch is the UTC midnight of the day epoch
// falls on. The plan is a pure function of the three.
func NewPlanAt(shares int, seed int64, epoch time.Time) Plan {
	e := epoch.UTC()
	accounts := shares / 200
	if accounts < 20 {
		accounts = 20
	}
	if accounts > 5000 {
		accounts = 5000
	}
	return Plan{
		Seed:     seed,
		Shares:   shares,
		Accounts: accounts,
		FileCap:  sharefs.DefaultStageMaxFiles,
		InboxCap: metadb.InboxMaxFiles,
		Epoch:    time.Date(e.Year(), e.Month(), e.Day(), 0, 0, 0, 0, time.UTC),
	}
}

// ID is the share id of index i: ten base58 characters, one lower-case
// letter then nine digits 1 to 9, so no two ids differ only by case. It is
// unique for i below 387,420,489.
func ID(i int) string {
	const digits = "123456789"
	j := int(int64(i) * idStride % idSpace)
	b := []byte("a111111111")
	for k := 9; k >= 1; k-- {
		b[k] = digits[j%9]
		j /= 9
	}
	return string(b)
}

// Account is the name of account i.
func (p Plan) Account(i int) string { return fmt.Sprintf("u%06d", i) }

func mix(seed int64, i int, salt uint64) uint64 {
	z := uint64(seed) + (uint64(i)+1)*0x9e3779b97f4a7c15 + salt*0xbf58476d1ce4e5b9
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func unit(h uint64) float64 { return float64(h>>11) / (1 << 53) }

func (p Plan) capCount() int   { return max(3, p.Shares/30000) }
func (p Plan) inboxCount() int { return max(2, p.Shares/200000) }
func specialIndex(k, stride, ending int) int {
	return (k*stride/10)*10 + ending
}

// special reports the k-th planted share at index i: ending 5 is a share at
// the file cap, ending 7 an inbox. Expired shares take every index ending 3,
// so the planted ones never disturb their count.
func (p Plan) special(i, count, ending int) (int, bool) {
	if i%10 != ending {
		return 0, false
	}
	stride := max(1, p.Shares/count)
	k0 := int(int64(i) * int64(count) / int64(max(1, p.Shares)))
	for k := max(0, k0-2); k <= k0+2 && k < count; k++ {
		if specialIndex(k, stride, ending) == i && i < p.Shares {
			return k, true
		}
	}
	return 0, false
}

// slotKinds are the residues of an index modulo 100 that hold a non-plain,
// non-expired kind: 8% of shares in all.
var slotKinds = map[int]Kind{
	1: Protected, 21: Protected,
	2: Expiring,
	4: Gallery, 42: Gallery,
	6: Text,
	8: Folders, 68: Folders,
}

var adjectives = []string{"quiet", "blue", "final", "draft", "old", "shared", "weekly", "urgent", "family", "client"}
var nouns = []string{"report", "photos", "invoice", "backup", "holiday", "notes", "design", "contract", "budget", "recipes"}

// Share is the i-th share of the plan. It reads no other share.
func (p Plan) Share(i int) ShareSpec {
	s := ShareSpec{Index: i, ID: ID(i), Kind: Plain}
	h := func(salt uint64) uint64 { return mix(p.Seed, i, salt) }

	s.Name = fmt.Sprintf("%s %s %d", adjectives[h(1)%uint64(len(adjectives))], nouns[h(2)%uint64(len(nouns))], i)
	step := year / time.Duration(max(1, p.Shares))
	s.CreatedAt = p.Epoch.Add(-time.Hour - time.Duration(p.Shares-1-i)*step)

	// Owner: account 0 holds 30%; the rest follow a cubic long tail.
	owner := 0
	if unit(h(3)) >= 0.3 {
		v := unit(h(4))
		owner = 1 + int(float64(p.Accounts-1)*v*v*v)
	}

	switch r := h(5) % 1000; {
	case r < 800:
		s.Files = 1
	case r < 980:
		s.Files = 10 + int(h(6)%91)
	default:
		u := unit(h(7))
		s.Files = 1000 + int(u*u*4000)
	}

	if k, ok := p.special(i, p.capCount(), 5); ok {
		s.Files, owner = p.FileCap, k%2
	} else if _, ok := p.special(i, p.inboxCount(), 7); ok {
		s.Kind, s.Files = Inbox, p.InboxCap
	} else if i%10 == 3 {
		s.Kind = Expired
		exp := s.CreatedAt.Add(time.Hour + time.Duration(h(8)%uint64(30*day/time.Second))*time.Second)
		if latest := p.Epoch.Add(-time.Second); exp.After(latest) {
			exp = latest
		}
		s.ExpiresAt = exp
	} else if k, ok := slotKinds[i%100]; ok {
		s.Kind = k
		switch k {
		case Text:
			s.Files = 1
		case Folders:
			s.Files = max(s.Files, 10)
		case Expiring:
			s.ExpiresAt = p.Epoch.Add(time.Duration(400+h(8)%200) * day)
		}
	}
	s.Owner = p.Account(owner)
	return s
}

// Totals is the number of files in the volume and the number of shares of
// each kind.
func (p Plan) Totals() (files int64, byKind map[Kind]int) {
	byKind = map[Kind]int{}
	for i := 0; i < p.Shares; i++ {
		s := p.Share(i)
		files += int64(s.Files)
		byKind[s.Kind]++
	}
	return files, byKind
}

// Largest is the account owning the most shares and how many it owns.
func (p Plan) Largest() (owner string, shares int) {
	count := make([]int, p.Accounts)
	for i := 0; i < p.Shares; i++ {
		var n int
		fmt.Sscanf(p.Share(i).Owner, "u%d", &n)
		count[n]++
	}
	best := 0
	for a, n := range count {
		if n > count[best] {
			best = a
		}
	}
	return p.Account(best), count[best]
}

var (
	plainExts   = []string{".txt", ".pdf", ".jpg", ".zip", ".mp4", ".docx", ".png", ".md"}
	galleryExts = []string{".jpg", ".png", ".mp4"}
)

// FileName is the relative path of file f of a share. Names are lower-case
// ASCII apart from one NFC folder name, unique per share, and carry an
// extension that suits the kind. Shares of many files spread them over
// folders; a Folders share nests them.
func (p Plan) FileName(s ShareSpec, f int) string {
	switch s.Kind {
	case Text:
		return "note.txt"
	case Gallery:
		return fmt.Sprintf("img_%05d%s", f, galleryExts[f%len(galleryExts)])
	case Inbox:
		return fmt.Sprintf("upload_%05d%s", f, plainExts[f%len(plainExts)])
	case Folders:
		top := [...]string{"alpha", "beta", "café", "docs", "misc"}
		return fmt.Sprintf("%s/sub%d/leaf%d/file_%05d%s", top[f%len(top)], (f/5)%7, (f/35)%3, f, plainExts[f%len(plainExts)])
	}
	if s.Files > 50 {
		return fmt.Sprintf("set%03d/file_%05d%s", f/100, f, plainExts[f%len(plainExts)])
	}
	return fmt.Sprintf("file_%05d%s", f, plainExts[f%len(plainExts)])
}

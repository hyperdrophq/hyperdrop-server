package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// What a share's View link opens is ONE question with four answers. The rule
// lives in one place now; these pin it there, so a fourth handler cannot
// implement three of the pairs and quietly skip the rest.

func TestLinkOpensAcceptsAtMostOneAnswer(t *testing.T) {
	for _, o := range []linkOpens{
		{},
		{Listing: true},
		{Entry: true},
		{Gallery: true},
		{Inbox: true},
	} {
		if err := o.refuse(); err != nil {
			t.Errorf("%+v is one answer, refused with %q", o, err)
		}
	}
}

func TestLinkOpensRefusesEveryConflictingPair(t *testing.T) {
	// Every pair of the four, since any two of them answer the same question.
	pairs := []struct {
		o    linkOpens
		says string
	}{
		{linkOpens{Gallery: true, Inbox: true}, "never both"},
		{linkOpens{Listing: true, Inbox: true}, "inbox"},
		{linkOpens{Entry: true, Inbox: true}, "inbox"},
		{linkOpens{Gallery: true, Entry: true}, "gallery has no entry page"},
		{linkOpens{Listing: true, Gallery: true}, "gallery is not a file listing"},
		{linkOpens{Listing: true, Entry: true}, "page is not a file listing"},
	}
	for _, p := range pairs {
		err := p.o.refuse()
		if err == nil {
			t.Errorf("%+v gives two answers and was accepted", p.o)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, p.says) {
			t.Errorf("%+v refused with %q, want it to mention %q", p.o, msg, p.says)
		}
	}
}

// Three answers at once is still a refusal, whichever pair is reported first.
func TestLinkOpensRefusesMoreThanTwo(t *testing.T) {
	if err := (linkOpens{Listing: true, Entry: true, Gallery: true}).refuse(); err == nil {
		t.Fatal("three answers were accepted")
	}
}

func TestLinkOpensRefusalIsABadRequest(t *testing.T) {
	w := httptest.NewRecorder()
	writeRefusal(w, linkOpens{Listing: true, Gallery: true}.refuse())
	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// with folds a PATCH onto the stored answer: a field sent replaces it, an
// absent one keeps it.
func TestLinkOpensWithFoldsTheSentFields(t *testing.T) {
	yes, no, page := true, false, "index.html"
	stored := linkOpens{Listing: true}
	if got := stored.with(nil, nil, nil); got != stored {
		t.Errorf("nothing sent changed %+v into %+v", stored, got)
	}
	if got := stored.with(&no, &yes, nil); got != (linkOpens{Gallery: true}) {
		t.Errorf("listing off, media on = %+v", got)
	}
	if got := stored.with(nil, nil, &page); !got.Entry || !got.Listing {
		t.Errorf("entry sent = %+v", got)
	}
}

// An empty password is "no password", not a bcrypt of the empty string: every
// caller stores "" to mean the share is open.
func TestHashPasswordLeavesAnEmptyOneEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	hash, ok := hashPassword(w, "")
	if !ok || hash != "" {
		t.Fatalf("hash = %q ok = %v", hash, ok)
	}
	hash, ok = hashPassword(w, "hunter2")
	if !ok || hash == "" || hash == "hunter2" {
		t.Fatalf("a real password must hash, got %q", hash)
	}
}

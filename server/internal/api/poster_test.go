package api

import (
	"testing"

	"hyperdrop/server/internal/metadb"
)

func videoShare(pw string) shareView {
	return shareView{
		Share: metadb.Share{ID: "abc", PasswordHash: pw},
		Files: []fileView{{File: metadb.File{Path: "clip.mp4", Mime: "video/mp4"}}},
	}
}

// A protected share must NEVER put a frame of its own video in a link preview.
// og:image is fetched by anonymous bots that carry no cookies and cannot be
// gated, and chat providers cache what they fetch, so one leak outlives
// deleting the share.
func TestAProtectedShareNeverShowsAFrame(t *testing.T) {
	got := pickCardImage(videoShare("$2a$hash"), true, true)
	if got == CardPoster {
		t.Fatal("a protected share leaked a frame of its video into the card")
	}
	if got != CardVideoGeneric {
		t.Errorf("pickCardImage = %v, want CardVideoGeneric", got)
	}
	// …and the URL it resolves to is static, carrying no share id at all.
	if p := got.path("abc"); p != "/card-video.png" {
		t.Errorf("path = %q, want the static tile", p)
	}
}

// Even with a poster stored and the share otherwise ordinary, protection wins.
func TestProtectionOutranksAStoredPoster(t *testing.T) {
	for _, hasVideo := range []bool{true, false} {
		sh := videoShare("$2a$hash")
		if !hasVideo {
			sh.Files = []fileView{{File: metadb.File{Path: "notes.pdf", Mime: "application/pdf"}}}
		}
		if got := pickCardImage(sh, hasVideo, true); got == CardPoster {
			t.Errorf("hasVideo=%v: protected share chose the poster", hasVideo)
		}
	}
}

func TestAnOpenVideoWithAPosterShowsIt(t *testing.T) {
	got := pickCardImage(videoShare(""), true, true)
	if got != CardPoster {
		t.Fatalf("pickCardImage = %v, want CardPoster", got)
	}
	if p := got.path("abc"); p != "/card/abc/poster.jpg" {
		t.Errorf("path = %q", p)
	}
}

// Before the poster lands (or if extraction failed) an open video still says
// it is a video rather than falling back to the plain brand tile.
func TestAnOpenVideoWithoutAPosterGetsThePlayTile(t *testing.T) {
	if got := pickCardImage(videoShare(""), true, false); got != CardVideoGeneric {
		t.Errorf("pickCardImage = %v, want CardVideoGeneric", got)
	}
}

func TestNonVideoSharesKeepTheBrandImage(t *testing.T) {
	sh := shareView{Share: metadb.Share{ID: "abc"},
		Files: []fileView{{File: metadb.File{Path: "a.pdf", Mime: "application/pdf"}}}}
	if got := pickCardImage(sh, false, false); got != CardBrand {
		t.Errorf("pickCardImage = %v, want CardBrand", got)
	}
}

func TestShareHasVideoByMimeAndByExtension(t *testing.T) {
	cases := []struct {
		name string
		f    fileView
		want bool
	}{
		{"committed mp4", fileView{File: metadb.File{Path: "a.mp4", Mime: "video/mp4"}}, true},
		{"mime with parameters", fileView{File: metadb.File{Path: "a", Mime: "video/mp4; codecs=avc1"}}, true},
		// A pending manifest entry has only an extension guess, and an early
		// link previews before the bytes land: the card a chat app caches
		// first is the one it keeps.
		{"pending, no mime", fileView{File: metadb.File{Path: "a.mov", Pending: true}}, true},
		{"pending webm", fileView{File: metadb.File{Path: "a.webm", Pending: true}}, true},
		{"pdf", fileView{File: metadb.File{Path: "a.pdf", Mime: "application/pdf"}}, false},
		{"no extension", fileView{File: metadb.File{Path: "README", Mime: "text/plain"}}, false},
		{"video in the name only", fileView{File: metadb.File{Path: "video.txt", Mime: "text/plain"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sh := shareView{Files: []fileView{c.f}}
			if got := shareHasVideo(sh); got != c.want {
				t.Errorf("shareHasVideo = %v, want %v", got, c.want)
			}
		})
	}
}

// A Receive Inbox's card is the brand mark whatever it holds: its content is
// never public, so not even "it received a video" may reach an unfurler.
func TestAnInboxCardIsTheBrandMarkWhateverItHolds(t *testing.T) {
	for _, pw := range []string{"", "$2a$hash"} {
		for _, hasPoster := range []bool{true, false} {
			sh := videoShare(pw)
			sh.Inbox = true
			if got := pickCardImage(sh, true, hasPoster); got != CardBrand {
				t.Errorf("password %q, poster %v: pickCardImage = %v, want CardBrand", pw, hasPoster, got)
			}
		}
	}
}
